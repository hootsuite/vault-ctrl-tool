package vaultclient

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

type authenticator struct {
	log         zerolog.Logger
	vaultClient VaultClient
}

type ec2amiAuthenticator struct {
	authenticator
	// ec2ami
	ec2Nonce string
}

type ec2iamAuthenticator struct {
	authenticator
	// ec2iam
	awsRegion           string
	iamAuthRole         string
	iamVaultAuthBackend string
}

type kubernetesAuthenticator struct {
	authenticator
	// kubernetes
	serviceAccountToken string
	k8sLoginPath        string
	k8sAuthRole         string
}
type Authenticator interface {
	Authenticate() (*api.Secret, error)
}

func NewAuthenticator(client VaultClient, cliFlags util.CliFlags) (Authenticator, error) {
	log := zlog.With().Str("vaultAddr", client.Delegate().Address()).Logger()

	shared := authenticator{
		log:         log,
		vaultClient: client,
	}

	mechanism := cliFlags.AuthMechanism()
	switch mechanism {
	case util.EC2IAMAuth:
		region := os.Getenv("AWS_DEFAULT_REGION")
		if region == "" {
			log.Debug().Msg("using hardcoded us-east-1 region")
			region = "us-east-1"
		}
		authn := &ec2iamAuthenticator{
			authenticator:       shared,
			awsRegion:           region,
			iamAuthRole:         cliFlags.IAMAuthRole,
			iamVaultAuthBackend: cliFlags.IAMVaultAuthBackend,
		}
		return authn, nil
	case util.EC2AMIAuth:
		authn := &ec2amiAuthenticator{
			authenticator: shared,
			ec2Nonce:      cliFlags.EC2Nonce,
		}
		return authn, nil
	case util.KubernetesAuth:
		authn := &kubernetesAuthenticator{
			authenticator:       shared,
			serviceAccountToken: cliFlags.ServiceAccountToken,
			k8sLoginPath:        cliFlags.KubernetesLoginPath,
			k8sAuthRole:         cliFlags.KubernetesAuthRole,
		}
		return authn, nil
	case util.UnknownAuth:
		return nil, fmt.Errorf("no authentication mechanism specified")
	default:
		log.Error().Interface("mechanism", mechanism).Msg("internal error: un-coded authentication mechanism")
		return nil, fmt.Errorf("internal error: un-coded authentication mechanism: %v", mechanism)
	}
}
