package syncer

import (
	"context"
	"github.com/hootsuite/vault-ctrl-tool/v2/secrets"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"time"
)

func (s *Syncer) compareTemplates(updates *int, nextSync time.Time) error {

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

func (s *Syncer) compareSSHCertificates(updates *int, nextSync time.Time) error {

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

			if err := s.briefcase.EnrollSSHCertificate(ssh); err != nil {
				log.Error().Err(err).Msg("failed to enroll SSH certificate in briefcase")
				return err
			}
		}
	}
	return nil
}

func (s *Syncer) compareAWS(updates *int, nextSync time.Time) error {

	for _, aws := range s.config.VaultConfig.AWS {
		log := s.log.With().Interface("awsCfg", aws).Logger()
		log.Debug().Msg("checking AWS STS credential")

		if s.briefcase.AWSCredentialExpiresBefore(aws, nextSync) {
			if updates != nil {
				*updates++
			}
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

			s.briefcase.EnrollAWSCredential(context.TODO(), secret.Secret, aws)
		}
	}
	return nil
}
