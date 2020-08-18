package vaultclient

import (
	"fmt"
	"path/filepath"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
)

type AWSSTSCredential struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
}

func (vc *wrappedVaultClient) FetchAWSSTSCredential(awsConfig config.AWSType) (*AWSSTSCredential, *api.Secret, error) {

	path := filepath.Join(awsConfig.VaultMountPoint, "creds", awsConfig.VaultRole)

	log := vc.log.With().Str("path", path).
		Str("outputPath", awsConfig.OutputPath).Logger()

	log.Info().Msg("fetching AWS STS credentials")

	result, err := vc.delegate.Logical().Write(path, nil)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch AWS credentials")
		return nil, nil, fmt.Errorf("could not fetch AWS credentials from %q: %w", path, err)
	}

	accessKey := result.Data["access_key"]
	secretKey := result.Data["secret_key"]
	// aka sessionToken
	securityToken := result.Data["security_token"]

	log.Debug().Interface("accessKey", accessKey).Msg("received AWS access key")

	return &AWSSTSCredential{
		AccessKey:    accessKey.(string),
		SecretKey:    secretKey.(string),
		SessionToken: securityToken.(string),
	}, result, nil
}
