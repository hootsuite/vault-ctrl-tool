package briefcase

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
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
	StaticTemplates        map[string]bool                `json:"templates,omitempty"`
	TokenScopedJSONSecrets map[string]bool                `json:"tokenscoped_json_secrets,omitempty"`
	StaticJSONSecrets      map[string]bool                `json:"json_secrets,omitempty"`

	// cache of secrets, not persisted
	tokenScopedCache  []SimpleSecret
	staticScopedCache []SimpleSecret

	log zerolog.Logger
}

type SimpleSecret struct {
	Key   string
	Field string
	Value interface{}
}

type sshCert struct {
	Expiry time.Time                 `json:"expiry"`
	Cfg    config.SSHCertificateType `json:"cfg"`
}

type LeasedAuthToken struct {
	Accessor    string    `json:"accessor"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expiry"`
	NextRefresh time.Time `json:"next_refresh"`
}

type leasedAWSCredential struct {
	AWSCredential config.AWSType `json:"role"`
	Expiry        time.Time      `json:"expiry"`
}

// NewBriefcase creates an empty briefcase.
func NewBriefcase() *Briefcase {
	return &Briefcase{
		AWSCredentialLeases:    make(map[string]leasedAWSCredential),
		SSHCertificates:        make(map[string]sshCert),
		TokenScopedTemplates:   make(map[string]bool),
		StaticTemplates:        make(map[string]bool),
		TokenScopedJSONSecrets: make(map[string]bool),
		StaticJSONSecrets:      make(map[string]bool),
		log:                    zlog.Logger,
	}
}

// ResetBriefcase is used when a vault token from a briefcase is no longer usable. This means any secrets
// that weren't "static" will likely soon expire and disappear. By resetting the briefcase, it will cause
// all the non-static secrets to be recreated.
func ResetBriefcase(old *Briefcase) *Briefcase {
	newBriefcase := NewBriefcase()
	newBriefcase.StaticJSONSecrets = old.StaticJSONSecrets
	newBriefcase.StaticTemplates = old.StaticTemplates
	newBriefcase.staticScopedCache = old.staticScopedCache
	return newBriefcase
}

func LoadBriefcase(filename string) (*Briefcase, error) {
	zlog.Info().Str("filename", filename).Msg("reading briefcase")
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	bc := NewBriefcase()
	err = json.Unmarshal(bytes, bc)
	if err != nil {
		return nil, err
	}

	return bc, nil
}

// EnrollVaultToken adds the specified vault token (from Vault) to the briefcase. It captures some expiry information
// so it knows when it needs to be refreshed.
func (b *Briefcase) EnrollVaultToken(token *api.Secret) error {

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

	authToken := LeasedAuthToken{
		Token:       tokenID,
		Accessor:    accessor,
		ExpiresAt:   time.Now().Add(ttl),
		NextRefresh: time.Now().Add(ttl / 3),
	}

	if b.AuthTokenLease.Token != tokenID {
		b.log = zlog.With().Str("accessor", accessor).Logger()
		b.log.Info().Str("ttl", ttl.String()).Msg("enrolling vault token with specified ttl into briefcase")
	} else {
		b.log.Info().Time("expiresAt", authToken.ExpiresAt).Time("nextRefresh", authToken.NextRefresh).Msg("vault token refreshed")
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
// used by the tool. This time is established when the token is enrolled into the briefcase.
func (b *Briefcase) ShouldRefreshVaultToken() bool {
	return time.Now().After(b.AuthTokenLease.NextRefresh)
}
