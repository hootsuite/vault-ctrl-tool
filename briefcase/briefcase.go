package briefcase

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/metrics"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

// Briefcase is a serialized file that contains all the information needed for the tool, running in sidecar mode,
// to keep all the associated leases, secrets, etc refreshed. It also keeps a non-serialized copy of secrets that
// are used to populate templates.
type Briefcase struct {
	AuthTokenLease         LeasedAuthToken                `json:"auth"`
	SSHCertificates        map[string]sshCert             `json:"ssh,omitempty"`
	AWSCredentialLeases    map[string]leasedAWSCredential `json:"aws,omitempty"`
	TokenScopedTemplates   map[string]bool                `json:"tokenscoped_templates,omitempty"`
	StaticTemplates        map[string]bool                `json:"static_templates,omitempty"`
	TokenScopedSecrets     map[string]bool                `json:"tokenscoped_secrets,omitempty"`
	StaticScopedSecrets    map[string]bool                `json:"static_secrets,omitempty"`
	VersionScopedSecrets   map[string]int64               `json:"versioned_secrets,omitempty"`
	TokenScopedComposites  map[string]bool                `json:"tokenscoped_composites,omitempty"`
	StaticScopedComposites map[string]bool                `json:"static_composites,omitempty"`

	// cache of secrets, not persisted
	secretCache map[util.SecretLifetime][]SimpleSecret

	log     zerolog.Logger
	metrics *metrics.Metrics
}

// SimpleSecret is a field in a secret, but also contains some important information about the secret itself.
type SimpleSecret struct {
	Key         string
	Field       string
	Value       interface{}
	Version     *int64
	CreatedTime *time.Time
}

type sshCert struct {
	Expiry        time.Time                 `json:"expiry"`
	Cfg           config.SSHCertificateType `json:"cfg"`
	RefreshExpiry *time.Time                `json:"refresh_expiry,omitempty"`
}

type LeasedAuthToken struct {
	Accessor    string    `json:"accessor"`
	Renewable   bool      `json:"renewable"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expiry"`
	NextRefresh time.Time `json:"next_refresh"`
}

type leasedAWSCredential struct {
	AWSCredential config.AWSType `json:"role"`
	Expiry        time.Time      `json:"expiry"`
	RefreshExpiry *time.Time     `json:"refresh_expiry,omitempty"`
}

// NewBriefcase creates an empty briefcase.
func NewBriefcase(mtrics *metrics.Metrics) *Briefcase {
	return &Briefcase{
		AWSCredentialLeases:    make(map[string]leasedAWSCredential),
		SSHCertificates:        make(map[string]sshCert),
		TokenScopedTemplates:   make(map[string]bool),
		StaticTemplates:        make(map[string]bool),
		TokenScopedSecrets:     make(map[string]bool),
		StaticScopedSecrets:    make(map[string]bool),
		VersionScopedSecrets:   make(map[string]int64),
		TokenScopedComposites:  make(map[string]bool),
		StaticScopedComposites: make(map[string]bool),
		log:                    zlog.Logger,
		metrics:                mtrics,
		secretCache:            make(map[util.SecretLifetime][]SimpleSecret),
	}
}

// ResetBriefcase is used when a vault token from a briefcase is no longer usable. This means any secrets
// that weren't "static" will likely soon expire and disappear. By resetting the briefcase, it will cause
// all the non-static secrets to be recreated.
func (b *Briefcase) ResetBriefcase() *Briefcase {

	b.metrics.Increment(metrics.BriefcaseReset)

	newBriefcase := NewBriefcase(b.metrics)
	// AWS Credentials is done through sts:AssumeRole which currently has no reasonable
	// revocation mechanism, so credentials remain valid across tokens.
	newBriefcase.AWSCredentialLeases = b.AWSCredentialLeases

	// SSH certificates expire when their TTL says they expire and there is no CRL mode for them, so they
	// remain valid across tokens.
	newBriefcase.SSHCertificates = b.SSHCertificates

	newBriefcase.StaticScopedSecrets = b.StaticScopedSecrets
	newBriefcase.VersionScopedSecrets = b.VersionScopedSecrets
	newBriefcase.StaticScopedComposites = b.StaticScopedComposites
	newBriefcase.StaticTemplates = b.StaticTemplates
	return newBriefcase
}

func LoadBriefcase(filename string, mtrics *metrics.Metrics) (*Briefcase, error) {
	zlog.Info().Str("filename", filename).Msg("reading briefcase")
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	bc := NewBriefcase(mtrics)
	err = json.Unmarshal(bytes, bc)
	if err != nil {
		return nil, err
	}

	return bc, nil
}

// EnrollVaultToken adds the specified vault token (from Vault) to the briefcase. It captures some expiry information
// so it knows when it needs to be refreshed.
func (b *Briefcase) EnrollVaultToken(ctx context.Context, token *util.WrappedToken) error {

	if token == nil {
		return errors.New("can only enroll non-nil tokens")
	}

	tokenID, err := token.TokenID()
	if err != nil {
		return err
	}

	accessor, err := token.TokenAccessor()
	if err != nil {
		return err
	}

	ttl, err := token.TokenTTL()
	if err != nil {
		return err
	}

	now := clock.Now(ctx)

	authToken := LeasedAuthToken{
		Token:       tokenID,
		Accessor:    accessor,
		Renewable:   token.Renewable,
		ExpiresAt:   now.Add(ttl),
		NextRefresh: now.Add(ttl / 3),
	}

	if b.AuthTokenLease.Token != tokenID {
		b.log = zlog.With().Str("accessor", accessor).Bool("renewable", authToken.Renewable).Logger()
		b.log.Info().Str("ttl", ttl.String()).Str("nextRefresh", authToken.NextRefresh.String()).Msg("enrolling vault token with specified ttl into briefcase")
	} else {
		b.log.Info().Time("expiresAt", authToken.ExpiresAt).Time("nextRefresh", authToken.NextRefresh).Msg("vault token refreshed")
	}

	if authToken.ExpiresAt.Before(now.Add(5 * time.Minute)) {
		b.log.Warn().Time("expiresAt", authToken.ExpiresAt).Msg("token expires in less than five minutes, setting next refresh to now")
		authToken.NextRefresh = now
	}

	b.AuthTokenLease = authToken

	return nil
}

func (b *Briefcase) SaveAs(filename string) error {
	bytes, err := json.Marshal(b)
	if err != nil {
		return err
	}

	b.log.Info().Str("filename", filename).Msg("storing briefcase")
	util.MustMkdirAllForFile(filename)
	if err := ioutil.WriteFile(filename, bytes, 0600); err != nil {
		b.log.Error().Err(err).Str("filename", filename).Msg("failed to write briefcase file")
		return err
	}

	return nil
}

// ShouldRefreshVaultToken will return true if it's time to do periodic refresh of the Vault token being
// used by the tool. This time is established when the token is enrolled into the briefcase. It will return
// false if the token is not renewable. If the token is needs a refresh but is non-renewable, then it will
// log (but not throw) an error.
func (b *Briefcase) ShouldRefreshVaultToken(ctx context.Context) bool {

	expiring := clock.Now(ctx).After(b.AuthTokenLease.NextRefresh)

	if expiring && !b.AuthTokenLease.Renewable {
		// now >= expiredAt
		if !clock.Now(ctx).Before(b.AuthTokenLease.ExpiresAt) {
			b.log.Error().Time("expiresAt", b.AuthTokenLease.ExpiresAt).
				Time("nextRefresh", b.AuthTokenLease.NextRefresh).
				Msg("token has expired and is not renewable - results are unpredictable")
		} else {
			b.log.Error().Time("expiresAt", b.AuthTokenLease.ExpiresAt).
				Time("nextRefresh", b.AuthTokenLease.NextRefresh).
				Msg("token is expiring, but is set to be non-renewable - unpredictable results will occur once it expires.")
		}
		return false
	}

	return expiring
}
