package syncer

import (
	"errors"
	"fmt"
	"path/filepath"
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

	vaultClient, err := vaultclient.NewVaultClient()
	if err != nil {
		log.Error().Err(err).Msg("could not create vault client")
		return log, nil, nil, err
	}

	return log, cfg, vaultClient, nil
}

func (s *Syncer) PerformSync(nextSync time.Time, flags util.CliFlags) error {

	vaultToken, err := s.obtainVaultToken(flags)
	if err != nil {
		return err
	}

	s.vaultClient.Delegate().SetToken(vaultToken.TokenID())

	// First we compare the vault token we're using with the one in the briefcase. If it's different, then
	// we reset the briefcase to start over. We do this here to ease the briefcase compare below. We also
	// write it to a file if configured at this point
	if s.briefcase.AuthTokenLease.Token != vaultToken.TokenID() {
		s.log.Debug().Msg("briefcase token differs from current token, resetting briefcase")
		s.briefcase = briefcase.ResetBriefcase(s.briefcase)
		if s.config.VaultConfig.VaultToken.Output != "" {
			if err := secrets.WriteVaultToken(s.config.VaultConfig.VaultToken, vaultToken.TokenID()); err != nil {
				s.log.Error().Err(err).Msg("could not write vault token")
				return err
			}
		}
		if err := s.briefcase.EnrollVaultToken(vaultToken.Secret()); err != nil {
			s.log.Error().Err(err).Msg("could not enroll vault token into briefcase")
		}
	}

	if s.briefcase.ShouldRefreshVaultToken() {
		s.log.Debug().Msg("refreshing vault token against server")
		secret, err := s.vaultClient.RefreshVaultToken()
		if err != nil {
			s.log.Error().Err(err).Msg("could not refresh vault token")
			return err
		}

		if err := s.briefcase.EnrollVaultToken(secret); err != nil {
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

	for _, aws := range s.config.VaultConfig.AWS {
		log := s.log.With().Interface("awsCfg", aws).Logger()
		log.Debug().Msg("checking AWS STS credential")

		if s.briefcase.ShouldRefreshAWSCredential(aws, nextSync) {
			updates++
			log.Debug().Msg("refreshing AWS STS credential")
			creds, secret, err := s.vaultClient.FetchAWSSTSCredential(aws)

			if err != nil {
				log.Error().Err(err).Msg("failed to fetch AWS STS credentials")
				return err
			}

			if err := secrets.WriteAWSSTSCreds(creds, aws); err != nil {
				log.Error().Err(err).Msg("failed to write file with AWS STS credentials")
				return err
			}

			s.briefcase.EnrollAWSCredential(secret, aws)
		}
	}

	for _, ssh := range s.config.VaultConfig.SSHCertificates {
		log := s.log.With().Interface("sshCfg", ssh).Logger()
		log.Debug().Msg("checking SSH certificate")

		if s.briefcase.ShouldRefreshSSHCertificate(ssh, nextSync) {
			updates++
			log.Debug().Msg("refreshing ssh certificate")

			if err := s.vaultClient.CreateSSHCertificate(ssh); err != nil {
				log.Error().Err(err).Msg("failed to fetch SSH certificate credentials")
				return err
			}

			if err := s.briefcase.EnrollSSHCertificate(ssh); err != nil {
				log.Error().Err(err).Msg("failed to enroll SSH certificate in briefcase")
				return err
			}
		}
	}

	for _, tmpl := range s.config.VaultConfig.Templates {
		log := s.log.With().Interface("tmplCfg", tmpl).Logger()
		log.Debug().Msg("checking template")
		if s.briefcase.ShouldRefreshTemplate(tmpl) {
			updates++
			log.Debug().Msg("refreshing template")

			if tmpl.Lifetime == util.LifetimeToken {
				if err := s.cacheSecrets(util.LifetimeToken); err != nil {
					return err
				}
			}

			if err := s.cacheSecrets(util.LifetimeStatic); err != nil {
				return err
			}

			if err := secrets.WriteTemplate(tmpl, s.config.Templates, s.briefcase); err != nil {
				log.Error().Err(err).Msg("failed to write template")
				return err
			}
			log.Debug().Msg("enrolling template")
			s.briefcase.EnrollTemplate(tmpl)
		}
	}

	for _, secret := range s.config.VaultConfig.Secrets {
		log := s.log.With().Interface("secretCfg", secret).Logger()
		log.Debug().Msg("checking secret")
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

			if err := secrets.WriteSecret(secret, s.briefcase); err != nil {
				log.Error().Err(err).Msg("failed to write secret")
				return err
			}
			s.briefcase.EnrollSecret(secret)
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

	log := s.log.With().Str("vaultAddr", s.vaultClient.Delegate().Address()).Logger()

	log.Info().Msg("obtaining vault token")

	token := vaulttoken.NewVaultToken(s.briefcase, s.vaultClient, flags.VaultTokenArg)

	if err := token.CheckAndRefresh(); err != nil {
		if errors.Is(err, vaulttoken.ErrNoValidVaultTokenAvailable) {
			log.Debug().Err(err).Msg("no vault token already available, performing authentication")
			authenticator, err := vaultclient.NewAuthenticator(s.vaultClient, flags)
			if err != nil {
				log.Error().Err(err).Msg("unable to create authenticator")
				return nil, err
			}
			log.Debug().Interface("authenticator", authenticator).Msg("authenticator created")
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

	log.Info().Str("accessorToken", token.Accessor()).Msg("using valid token")

	return token, nil
}

func (s *Syncer) cacheSecrets(lifetime util.SecretLifetime) error {
	if s.briefcase.HasCachedSecrets(lifetime) {
		return nil
	}

	var simpleSecrets []briefcase.SimpleSecret

	for _, secret := range s.config.VaultConfig.Secrets {
		if secret.Lifetime == lifetime {

			key := secret.Key

			s.log.Info().Str("path", secret.Path).Msg("fetching secret")

			var path string

			if !strings.HasPrefix(secret.Path, "/") {
				path = filepath.Join(s.vaultClient.ServiceSecretPrefix(s.config.VaultConfig.ConfigVersion), secret.Path)
			} else {
				path = secret.Path
			}

			// The same key could be in different paths, but we don't allow this because it's confusing.
			for _, s := range simpleSecrets {
				if s.Key == key {
					return fmt.Errorf("duplicate secret key %q", key)
				}
			}

			s.log.Debug().Str("path", path).Msg("reading secret from Vault")
			response, err := s.vaultClient.Delegate().Logical().Read(path)

			if err != nil {
				return fmt.Errorf("error fetching secret %q from %q: %w", path, s.vaultClient.Delegate().Address(), err)
			}

			if response == nil {
				if secret.IsMissingOk {
					s.log.Info().Str("vaultAddr", s.vaultClient.Delegate().Address()).Str("path", path).
						Msg("no response reading secrets from path (either access is denied  or there are no secrets). Ignoring since missingOk is set in the config")
				} else {
					return fmt.Errorf("no response returned fetching secrets")
				}
			} else {
				var secretData map[string]interface{}

				if s.config.VaultConfig.ConfigVersion < 2 {
					secretData = response.Data
				} else {
					subData, ok := response.Data["data"].(map[string]interface{})

					if ok {
						secretData = subData
					} else {
						secretData = response.Data
					}
				}

				for f, v := range secretData {
					simpleSecrets = append(simpleSecrets, briefcase.SimpleSecret{
						Key:   key,
						Field: f,
						Value: v,
					})
				}
			}
		}
	}

	s.briefcase.StoreSecrets(lifetime, simpleSecrets)
	return nil
}
