package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/vaulttoken"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/secrets"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/vaultclient"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

type Syncer struct {
	log         zerolog.Logger
	config      *config.ControlToolConfig
	vaultClient vaultclient.VaultClient
	briefcase   *briefcase.Briefcase
}

func NewSyncer(log zerolog.Logger, cfg *config.ControlToolConfig, vaultClient vaultclient.VaultClient, briefcase *briefcase.Briefcase) *Syncer {
	return &Syncer{
		log:         log,
		config:      cfg,
		vaultClient: vaultClient,
		briefcase:   briefcase,
	}
}

func SetupSyncer(flags util.CliFlags, bc *briefcase.Briefcase) (*Syncer, error) {
	log, cfg, vaultClient, err := configureSyncerDependencies(flags)
	if err != nil {
		return nil, err
	}

	syncer := NewSyncer(log, cfg, vaultClient, bc)

	return syncer, nil
}

func configureSyncerDependencies(flags util.CliFlags) (zerolog.Logger, *config.ControlToolConfig, vaultclient.VaultClient, error) {

	log := zlog.With().Str("cfg", flags.ConfigFile).Logger()

	cfg, err := config.ReadConfig(flags.ConfigFile, flags.InputPrefix, flags.OutputPrefix)
	if err != nil {
		return log, nil, nil, err
	}

	vaultClient, err := vaultclient.NewVaultClient(flags.ServiceSecretPrefix)
	if err != nil {
		log.Error().Err(err).Msg("could not create vault client")
		return log, nil, nil, err
	}

	return log, cfg, vaultClient, nil
}

func (s *Syncer) PerformSync(ctx context.Context, nextSync time.Time, flags util.CliFlags) error {

	vaultToken, err := s.obtainVaultToken(flags)
	if err != nil {
		return err
	}

	s.vaultClient.SetToken(vaultToken.TokenID())

	// First we compare the vault token we're using with the one in the briefcase. If it's different, then
	// we reset the briefcase to start over. We do this here to ease the briefcase compare below. We also
	// write it to a file if configured at this point
	if s.briefcase.AuthTokenLease.Token != vaultToken.TokenID() {
		s.log.Debug().Msg("briefcase token differs from current token, resetting briefcase")
		s.briefcase = s.briefcase.ResetBriefcase()
		if s.config.VaultConfig.VaultToken.Output != "" {
			if err := secrets.WriteVaultToken(s.config.VaultConfig.VaultToken, vaultToken.TokenID()); err != nil {
				s.log.Error().Err(err).Msg("could not write vault token")
				return err
			}
		}
		if err := s.briefcase.EnrollVaultToken(ctx, vaultToken.Wrapped()); err != nil {
			s.log.Error().Err(err).Msg("could not enroll vault token into briefcase")
		}
	}

	if s.briefcase.ShouldRefreshVaultToken(ctx) {
		s.log.Debug().Msg("refreshing vault token against server")
		secret, err := s.vaultClient.RefreshVaultToken()
		if err != nil {
			s.log.Error().Err(err).Msg("could not refresh vault token")
			return err
		}

		if err := s.briefcase.EnrollVaultToken(ctx, util.NewWrappedToken(secret, s.briefcase.AuthTokenLease.Renewable)); err != nil {
			return err
		}
	}

	err = s.compareConfigToBriefcase(nextSync)
	if err != nil {
		s.log.Error().Err(err).Msg("could not compare config file against briefcase")
		return err
	}

	err = s.briefcase.SaveAs(flags.BriefcaseFilename)
	if err != nil {
		s.log.Error().Err(err).Str("filename", flags.BriefcaseFilename).Msg("could not save briefcase")
		return err
	}
	return nil
}

// compareConfigToBriefcase does what it says on the tin. Given the list of secrets expected to exist (listed in the config),
// compare that to the secrets that are being tracked in the briefcase. If they need to be refreshed, then refresh them
// and update the briefcase.
func (s *Syncer) compareConfigToBriefcase(nextSync time.Time) error {
	updates := 0

	if err := s.compareAWS(&updates, nextSync); err != nil {
		return err
	}

	if err := s.compareSSHCertificates(&updates, nextSync); err != nil {
		return err
	}

	if err := s.compareTemplates(&updates, nextSync); err != nil {
		return err
	}

	for _, secret := range s.config.VaultConfig.Secrets {
		log := s.log.With().Interface("secretCfg", secret).Logger()
		log.Debug().Msg("checking secret")

		switch secret.Lifetime {
		// Secrets with "version" lifetime are automatically updated when the secret is updated in Vault. This is
		// different than Token / Static lifetimes, so the code is a bit messier. At some point there could
		// be a desire for version scoped templates/composites/etc/etc at which point it becomes worthwhile
		// to rearrange this code.
		case util.LifetimeVersion:

			simpleSecrets, err := s.readSecret(secret)
			if err != nil {
				return err
			}

			if len(simpleSecrets) > 0 {
				ss := simpleSecrets[0]
				if ss.Version == nil {
					return fmt.Errorf("no version number associated with secret %q and lifetime is %q",
						secret.Key, util.LifetimeVersion)
				}

				briefcaseVersion := s.briefcase.VersionScopedSecrets[secret.Path]
				if briefcaseVersion == 0 {
					if err := secrets.WriteSecret(secret, simpleSecrets); err != nil {
						return fmt.Errorf("could not write secret %q: %w", secret.Path, err)
					}
					s.briefcase.VersionScopedSecrets[secret.Path] = *ss.Version
				}
			} else {
				log.Warn().Msg("no fields returned for secret")
			}
		case util.LifetimeToken, util.LifetimeStatic:
			if s.briefcase.ShouldRefreshSecret(secret) {
				updates++
				log.Debug().Msg("refreshing secret")

				if secret.Lifetime == util.LifetimeToken {
					if err := s.cacheSecrets(util.LifetimeToken); err != nil {
						return err
					}
				}

				if err := s.cacheSecrets(util.LifetimeStatic); err != nil {
					return err
				}

				var kvSecrets []briefcase.SimpleSecret

				// make a copy
				kvSecrets = append(kvSecrets, s.briefcase.GetSecrets(util.LifetimeStatic)...)
				kvSecrets = append(kvSecrets, s.briefcase.GetSecrets(util.LifetimeVersion)...)

				if secret.Lifetime == util.LifetimeToken {
					kvSecrets = append(kvSecrets, s.briefcase.GetSecrets(util.LifetimeToken)...)
				}

				if err := secrets.WriteSecret(secret, kvSecrets); err != nil {
					log.Error().Err(err).Msg("failed to write secret")
					return err
				}
				s.briefcase.EnrollSecret(secret)
			}
		default:
			log.Error().Str("lifetime", string(secret.Lifetime)).Msg("missing code to sync secrets with lifetime")
		}

	}

	for _, composite := range s.config.Composites {
		log := s.log.With().Interface("compositeFilename", composite.Filename).Logger()
		log.Debug().Msg("checking composite secret")
		if s.briefcase.ShouldRefreshComposite(*composite) {
			updates++
			log.Debug().Msg("refreshing composite")
			if composite.Lifetime == util.LifetimeToken {
				if err := s.cacheSecrets(util.LifetimeToken); err != nil {
					return err
				}
			}
			if err := s.cacheSecrets(util.LifetimeStatic); err != nil {
				return err
			}

			if err := secrets.WriteComposite(*composite, s.briefcase); err != nil {
				log.Error().Err(err).Msg("failed to write composite json secret")
				return err
			}
			log.Debug().Msg("enrolling composite secret")
			s.briefcase.EnrollComposite(*composite)
		}
	}

	s.log.Info().Int("updates", updates).Msg("done comparing configuration against briefcase")
	return nil
}

// obtainVaultToken works in conjunction with a "VaultToken" object. This object uses the briefcase, CLI flags,
// and environment variables to try to find a workable vault token. This function will build an "authenticator"
// whose job it is to authenticate against Vault using whatever material is specified and come up with a new
// vault token if needed.
func (s *Syncer) obtainVaultToken(flags util.CliFlags) (vaulttoken.VaultToken, error) {

	log := s.log.With().Str("vaultAddr", s.vaultClient.Address()).Logger()

	log.Info().Msg("obtaining vault token")

	token := vaulttoken.NewVaultToken(s.briefcase, s.vaultClient, flags.VaultTokenArg, flags.CliVaultTokenRenewable)

	if err := token.CheckAndRefresh(); err != nil {
		if errors.Is(err, vaulttoken.ErrNoValidVaultTokenAvailable) {
			log.Debug().Err(err).Msg("no vault token already available, performing authentication")

			authenticator, err := vaultclient.NewAuthenticator(s.vaultClient, flags)
			if err != nil {
				log.Error().Err(err).Msg("unable to create authenticator")
				return nil, err
			}
			log.Debug().Str("authenticator", fmt.Sprintf("%+v", authenticator)).Msg("authenticator created")
			secret, err := authenticator.Authenticate()
			if err != nil {
				log.Error().Err(err).Msg("authentication failed")
				return nil, err
			}

			accessor, err := secret.TokenAccessor()
			if err != nil {
				log.Error().Err(err).Msg("could not get accessor of new vault token")
				return nil, err
			}

			log.Info().Str("accessor", accessor).Msg("authentication successful")

			err = token.Set(secret)
			if err != nil {
				log.Error().Err(err).Msg("could not store vault token")
				return nil, err
			}
		} else {
			log.Error().Err(err).Msg("could not establish vault token")
			return nil, err
		}
	}

	log.Info().Str("accessor", token.Accessor()).Msg("using valid token")

	return token, nil
}

// cacheSecrets has the job of fetching secrets from Vault, if they're needed. The need is based on a few things, but
// mostly on the "lifetime" of the secret. Static secrets are only fetched once, token-lifetime are refetched if the
// token being used changes.
func (s *Syncer) cacheSecrets(lifetime util.SecretLifetime) error {
	if s.briefcase.HasCachedSecrets(lifetime) {
		return nil
	}

	var simpleSecrets []briefcase.SimpleSecret

	for _, secret := range s.config.VaultConfig.Secrets {
		if secret.Lifetime == lifetime {

			// The same key could be in different paths, but we don't allow this because it's confusing.
			for _, s := range simpleSecrets {
				if s.Key == secret.Key {
					return fmt.Errorf("duplicate secret key %q", secret.Key)
				}
			}

			if secretData, err := s.readSecret(secret); err != nil {
				return err
			} else {
				simpleSecrets = append(simpleSecrets, secretData...)
			}
		}
	}

	s.briefcase.StoreSecrets(lifetime, simpleSecrets)

	return nil
}

// readSecret ingests the specified secret with whatever parameters it has. It returns an array of "simplesecret" which is really
// an array of key=value for each field in the secret. Errors will occur if the specified secret is required to be in KVv2
// (for metadata) but it's not.
func (s *Syncer) readSecret(secret config.SecretType) ([]briefcase.SimpleSecret, error) {
	var simpleSecrets []briefcase.SimpleSecret

	key := secret.Key

	log := s.log.With().Str("path", secret.Path).Str("vaultAddr", s.vaultClient.Address()).Logger()

	// Some secrets require metadata to be processed correctly based on their configuration.
	if s.config.VaultConfig.ConfigVersion < 2 && secret.NeedsMetadata() {
		log.Error().Msg("In order to process this secret, metadata is needed, but metadata is only available for config files version 2 and above.")
		return nil, fmt.Errorf("secret %q requires metadata, but version of the config file version is %d and metadata is not available until 2 or later",
			secret.Key, s.config.VaultConfig.ConfigVersion)
	}

	log.Info().Msg("fetching secret")

	var path string

	if !strings.HasPrefix(secret.Path, "/") {
		path = filepath.Join(s.vaultClient.ServiceSecretPrefix(s.config.VaultConfig.ConfigVersion), secret.Path)
	} else {
		path = secret.Path
	}

	log.Debug().Msg("reading secret from Vault")

	var response *api.Secret
	var err error

	if secret.PinnedVersion != nil {
		log.Debug().Int("pinnedVersion", *secret.PinnedVersion).Msg("fetching specific version")
		response, err = s.vaultClient.Delegate().Logical().ReadWithData(path, map[string][]string{
			"version": {strconv.Itoa(*secret.PinnedVersion)},
		})
	} else {
		response, err = s.vaultClient.Delegate().Logical().Read(path)
	}

	if err != nil {
		return nil, fmt.Errorf("error fetching secret %q from %q: %w", path, s.vaultClient.Address(), err)
	}

	if response == nil {
		// For migration purposes, we allow some secrets to not exist.
		if secret.IsMissingOk {
			log.Info().Msg("no response reading secrets from path (either access is denied  or there are no secrets). Ignoring since missingOk is set in the config")
		} else {
			return nil, fmt.Errorf("no response returned fetching secrets")
		}
	} else {

		// If this is a KVv1 secret, then the fields are returned directly in the "data" stanza of the response.
		// If this is a KVv2 secret, then the "data" stanza of the response has two sub-sections: "data" and
		// "metadata". This code breaks if a KVv1 secret has a field called "data".

		var secretData map[string]interface{}
		var secretMetadata map[string]interface{}
		var secretVersion *int64
		var secretCreated *time.Time

		if s.config.VaultConfig.ConfigVersion < 2 {
			secretData = response.Data
		} else {
			var hasMetadata, hasData bool
			// We guess we're in KVv2 if there's both a "data" and "metadata" in the response "data" stanza.
			secretData, hasData = response.Data["data"].(map[string]interface{})
			secretMetadata, hasMetadata = response.Data["metadata"].(map[string]interface{})

			// It's a failure if we need metadata to process this secret, and we're not a KVv2 secret.
			if secret.NeedsMetadata() && (!hasData || !hasMetadata) {
				return nil, fmt.Errorf("error getting KVv2 secret %q from %q: probably not in a KVv2 path", path, s.vaultClient.Address())
			}

			if !(hasData && hasMetadata) {
				secretData = response.Data
				secretMetadata = nil
			}
		}

		if secretMetadata != nil {
			log.Debug().Str("metadata", fmt.Sprintf("%+v", secretMetadata)).Msg("retrieved metadata")

			if v, ok := secretMetadata["version"]; ok {
				vers, err := v.(json.Number).Int64()
				if err != nil {
					log.Error().Err(err).Interface("version", v).Msg("could not convert to integer")
					return nil, fmt.Errorf("could not convert %q to integer: %w", v, err)
				}
				secretVersion = &vers
			} else {
				return nil, fmt.Errorf("no version metadata field for secret %q from %q", path, s.vaultClient.Address())
			}

			if ts, ok := secretMetadata["created_time"]; ok {
				parsedTime, err := time.Parse(time.RFC3339Nano, ts.(string))
				if err != nil {
					return nil, fmt.Errorf("unable to parse created_time timestamp %q for secret %q from %q",
						ts, path, s.vaultClient.Address())
				}
				secretCreated = &parsedTime
			} else {
				return nil, fmt.Errorf("no created_time field for secret %q from %q", path, s.vaultClient.Address())
			}

		} else {
			log.Debug().Msg("no metadata retrieved")
		}

		for f, v := range secretData {
			simpleSecrets = append(simpleSecrets, briefcase.SimpleSecret{
				Key:         key,
				Field:       f,
				Value:       v,
				Version:     secretVersion,
				CreatedTime: secretCreated,
			})
		}
	}

	return simpleSecrets, nil
}
