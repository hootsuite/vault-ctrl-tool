package syncer

import (
	"context"
	"fmt"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/secrets"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"
)

func (s *Syncer) compareSecrets(ctx context.Context, updates *int) error {
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

				log.Debug().Int64("secretVersion", *ss.Version).
					Int64("briefcaseSecretVersion", briefcaseVersion).
					Time("secretTimestamp", *ss.CreatedTime).
					Time("now", clock.Now(ctx)).
					Msg("comparing briefcase version of secret to current version")

				if briefcaseVersion == 0 ||
					(briefcaseVersion < *ss.Version &&
						ss.CreatedTime.Add(30*time.Second).Before(clock.Now(ctx))) {

					count, err := secrets.WriteSecretFields(secret, simpleSecrets)
					if err != nil {
						return fmt.Errorf("could not write secret %q: %w", secret.Path, err)
					}
					*updates += count

					if count > 0 {
						if err := util.TouchFile(secret.TouchFile); err != nil {
							log.Warn().Str("touchfile", secret.TouchFile).Err(err).Msg("failed to 'touch' touchfile.")
						}
					}
					s.briefcase.VersionScopedSecrets[secret.Path] = *ss.Version
				} else {
					log.Debug().Msg("not updating secret")
				}
			} else {
				log.Warn().Msg("no fields returned for secret")
			}
		case util.LifetimeToken, util.LifetimeStatic:
			if s.briefcase.ShouldRefreshSecret(secret) {
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

				count, err := secrets.WriteSecretFields(secret, kvSecrets)
				if err != nil {
					log.Error().Err(err).Msg("failed to write secret")
					return err
				}
				*updates += count
				s.briefcase.EnrollSecret(secret)
			}
		default:
			log.Error().Str("lifetime", string(secret.Lifetime)).Msg("internal error: missing code to sync secrets with lifetime")
		}
	}
	return nil
}

func (s *Syncer) compareTemplates(updates *int) error {
	for _, tmpl := range s.config.VaultConfig.Templates {
		log := s.log.With().Interface("tmplCfg", tmpl).Logger()
		log.Debug().Msg("checking template")
		if s.briefcase.ShouldRefreshTemplate(tmpl) {
			if updates != nil {
				*updates++
			}
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
	return nil
}

func (s *Syncer) compareSSHCertificates(ctx context.Context, updates *int, nextSync time.Time, forceRefreshTTL time.Duration) error {
	for _, ssh := range s.config.VaultConfig.SSHCertificates {
		log := s.log.With().Interface("sshCfg", ssh).Logger()
		log.Debug().Msg("checking SSH certificate")

		if s.briefcase.ShouldRefreshSSHCertificate(ssh, nextSync) {
			if updates != nil {
				*updates++
			}
			log.Debug().Msg("refreshing ssh certificate")

			if err := s.vaultClient.CreateSSHCertificate(ssh); err != nil {
				log.Error().Err(err).Msg("failed to fetch SSH certificate credentials")
				return err
			}

			if err := s.briefcase.EnrollSSHCertificate(ctx, ssh, forceRefreshTTL); err != nil {
				log.Error().Err(err).Msg("failed to enroll SSH certificate in briefcase")
				return err
			}
		}
	}
	return nil
}

func (s *Syncer) compareAWS(ctx context.Context, updates *int, nextSync time.Time, stsTTL, forceRefreshTTL time.Duration) error {
	for _, aws := range s.config.VaultConfig.AWS {
		log := s.log.With().Interface("awsCfg", aws).Logger()
		log.Debug().Msg("checking AWS STS credential")

		if s.briefcase.AWSCredentialShouldRefreshBefore(aws, nextSync) || s.briefcase.AWSCredentialExpiresBefore(aws, nextSync) {
			if updates != nil {
				*updates++
			}

			log.Debug().
				Bool("forcedRefreshBeforeNextHearbeat", s.briefcase.AWSCredentialShouldRefreshBefore(aws, nextSync)).
				Bool("credentialExpiresBeforeNextHeartbeat", s.briefcase.AWSCredentialExpiresBefore(aws, nextSync)).
				Msg("refreshing AWS STS credential")

			creds, secret, err := s.vaultClient.FetchAWSSTSCredential(aws, stsTTL)

			if err != nil {
				log.Error().Err(err).Msg("failed to fetch AWS STS credentials")
				return err
			}

			if err := secrets.WriteAWSSTSCreds(creds, aws); err != nil {
				log.Error().Err(err).Msg("failed to write file with AWS STS credentials")
				return err
			}

			s.briefcase.EnrollAWSCredential(ctx, secret.Secret, aws, forceRefreshTTL)
		}
	}
	return nil
}
