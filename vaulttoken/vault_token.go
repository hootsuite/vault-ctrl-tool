package vaulttoken

import (
	"errors"
	"fmt"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"os"
	"strconv"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/vaultclient"
	"github.com/rs/zerolog"

	zlog "github.com/rs/zerolog/log"
)

var ErrNoValidVaultTokenAvailable = errors.New("no currently valid valid token")

type VaultToken interface {
	CheckAndRefresh() error
	Set(token *util.WrappedToken) error
	Accessor() string
	TokenID() string
	Secret() *api.Secret
	Wrapped() *util.WrappedToken
}
type vaultTokenManager struct {
	log        zerolog.Logger
	validToken *util.WrappedToken

	accessor string
	tokenID  string

	vaultClient          vaultclient.VaultClient
	briefcase            *briefcase.Briefcase
	vaultTokenCliArg     string
	tokenRenewableCliArg bool
}

func NewVaultToken(briefcase *briefcase.Briefcase, vaultClient vaultclient.VaultClient, vaultTokenCliArg string, tokenRenewableCliArg bool) VaultToken {
	log := zlog.With().Str("vaultAddr", vaultClient.Delegate().Address()).Logger()

	return &vaultTokenManager{
		log:                  log,
		briefcase:            briefcase,
		vaultClient:          vaultClient,
		vaultTokenCliArg:     vaultTokenCliArg,
		tokenRenewableCliArg: tokenRenewableCliArg,
	}
}

func (vt *vaultTokenManager) Secret() *api.Secret {
	return vt.validToken.Secret
}

func (vt *vaultTokenManager) Wrapped() *util.WrappedToken {
	return vt.validToken
}

func (vt *vaultTokenManager) Accessor() string {
	return vt.accessor
}

func (vt *vaultTokenManager) TokenID() string {
	return vt.tokenID
}

func (vt *vaultTokenManager) Set(authToken *util.WrappedToken) error {

	token, err := authToken.TokenID()
	if err != nil {
		return err
	}

	accessor, err := authToken.TokenAccessor()
	if err != nil {
		return fmt.Errorf("could not determine token's accessor: %w", err)
	}

	vt.tokenID = token
	vt.accessor = accessor
	vt.validToken = authToken

	return nil
}

// Looks for a valid Vault token and will extend it out if it's going to expire soon. The extension is just long
// enough to use it for things. Returns ErrNoValidVaultTokenAvailable if none is available, or different errors
// if something goes wrong along the way.
func (vt *vaultTokenManager) CheckAndRefresh() error {

	secret, err := vt.determineVaultToken()
	if err != nil {
		return err
	}

	if err := vt.Set(secret); err != nil {
		return err
	}

	return nil
}

// determineVaultToken looks through the various ways a vault token may already exist (briefcase, flag, env variable),
// and checks with the vault server if the token is still good, optionally refreshing it. If there isn't a vault
// token around, it returns ErrNoValidVaultTokenAvailable.
func (vt *vaultTokenManager) determineVaultToken() (*util.WrappedToken, error) {
	if vt.briefcase != nil && vt.briefcase.AuthTokenLease.Token != "" {
		log := vt.log.With().Str("source", "briefcase").Logger()

		log.Info().Str("accessor", vt.briefcase.AuthTokenLease.Accessor).Msg("testing if token is usable")

		secret, err := vt.tryToken(log, vt.briefcase.AuthTokenLease.Token)
		if err != nil {
			log.Warn().Str("accessor", vt.briefcase.AuthTokenLease.Accessor).Err(err).Msg("current briefcase token is not usable")
		} else {
			accessor, _ := secret.TokenAccessor()
			log.Debug().Str("accessor", accessor).Msg("current briefcase token is usable")
			return util.NewWrappedToken(secret, vt.briefcase.AuthTokenLease.Renewable), nil
		}
	}

	if vt.vaultTokenCliArg != "" {
		log := zlog.With().Str("source", "cli-arg").Logger()
		log.Info().Msg("testing if --vault-token is usable")

		secret, err := vt.tryToken(log, vt.vaultTokenCliArg)
		if err != nil {
			log.Info().Err(err).Msg("current cli token is not usable")
		} else {
			accessor, _ := secret.TokenAccessor()
			log.Debug().Str("accessor", accessor).Bool("tokenRenewableCliArg", vt.tokenRenewableCliArg).Msg("current cli token is usable")
			return util.NewWrappedToken(secret, vt.tokenRenewableCliArg), nil
		}
	}

	envVaultToken, ok := os.LookupEnv(api.EnvVaultToken)
	if ok {
		log := zlog.With().Str("source", "env").Logger()
		log.Info().Msg("testing if VAULT_TOKEN is usable")

		secret, err := vt.tryToken(log, envVaultToken)
		if err != nil {
			log.Info().Err(err).Msg("current VAULT_TOKEN is not usable")
		} else {
			accessor, _ := secret.TokenAccessor()
			log.Debug().Str("accessor", accessor).Msg("current VAULT_TOKEN is usable")

			renewable := true

			if renewableOverride, ok := os.LookupEnv("TOKEN_RENEWABLE"); ok {
				renewable, err = strconv.ParseBool(renewableOverride)
				if err != nil {
					log.Warn().Err(err).
						Str("TOKEN_RENEWABLE", renewableOverride).
						Msg("environment variable TOKEN_RENEWABLE is not parsable as boolean - ignoring")
				} else {
					renewable = true
				}
			}

			return util.NewWrappedToken(secret, renewable), nil
		}
	}

	vt.log.Debug().Msg("no current vault token available")
	return nil, ErrNoValidVaultTokenAvailable
}

func (vt *vaultTokenManager) tryToken(log zerolog.Logger, token string) (*api.Secret, error) {
	secret, err := vt.vaultClient.VerifyVaultToken(token)
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("server did not return an error, nor a secret")
	}

	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, err
	}

	log.Debug().Str("ttl", ttl.String()).Msg("checking token ttl")

	if ttl.Seconds() > 2 && ttl.Seconds() < 60 {
		renewedSecret, err := vt.vaultClient.Delegate().Auth().Token().RenewTokenAsSelf(token, 3600)
		if err != nil {
			log.Warn().Err(err).Str("ttl", ttl.String()).Msg("failed to renew token")
			return nil, err
		}

		ttl, err := renewedSecret.TokenTTL()
		if err != nil {
			log.Error().Err(err).Msg("could not get TTL of renewed token")
			return nil, err
		}

		if ttl.Seconds() <= 60 {
			log.Error().Str("ttl", ttl.String()).Msg("new token was given a TTL that is too short")
			return nil, fmt.Errorf("could not renew existing token to make it viable")
		}
		return renewedSecret, nil
	}
	return secret, nil
}
