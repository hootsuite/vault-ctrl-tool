package vaultclient

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

const SecretsServicePathV1 = "/secret/application-config/services/"
const SecretsServicePathV2 = "/kv/data/application-config/services/"

type VaultClient interface {
	VerifyVaultToken(vaultToken string) (*api.Secret, error)
	Delegate() *api.Client
	FetchAWSSTSCredential(awsConfig config.AWSType, stsTTL time.Duration) (*AWSSTSCredential, *util.WrappedToken, error)
	CreateSSHCertificate(sshConfig config.SSHCertificateType) error
	RefreshVaultToken() (*api.Secret, error)
	ServiceSecretPrefix(configVersion int) string

	Address() string
	ReadWithData(string, map[string][]string) (*api.Secret, error)
	Read(string) (*api.Secret, error)
	SetToken(token string)
}

type wrappedVaultClient struct {
	delegate      *api.Client
	secretsPrefix string
	log           zerolog.Logger
}

// NewVaultClient constructs a new VaultClient implementation.
func NewVaultClient(secretsPrefix string, clientTimeout time.Duration, clientRetries int) (VaultClient, error) {
	conf := api.DefaultConfig()
	// Requests are twice with a jitter backoff.
	conf.MaxRetries = clientRetries
	conf.Timeout = clientTimeout

	zlog.Debug().
		Int("vaultClientMaxRetries", clientRetries).
		Int("vaultClientTimeoutSeconds", int(clientTimeout.Seconds())).
		Str("secretsPrefix", secretsPrefix).
		Msg("creating Vault client")

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, fmt.Errorf("could not create Vault client: %w", err)
	}

	log := zlog.With().Str("vaultAddr", client.Address()).Logger()

	return &wrappedVaultClient{
		secretsPrefix: secretsPrefix,
		delegate:      client,
		log:           log,
	}, nil
}

func (vc *wrappedVaultClient) Delegate() *api.Client {
	return vc.delegate
}

func (vc *wrappedVaultClient) Address() string {
	return vc.delegate.Address()
}

func (vc *wrappedVaultClient) SetToken(token string) {
	vc.delegate.SetToken(token)
}
func (vc *wrappedVaultClient) ReadWithData(path string, data map[string][]string) (*api.Secret, error) {
	return vc.delegate.Logical().ReadWithData(path, data)
}

func (vc *wrappedVaultClient) Read(path string) (*api.Secret, error) {
	return vc.delegate.Logical().Read(path)
}

func (vc *wrappedVaultClient) VerifyVaultToken(vaultToken string) (*api.Secret, error) {
	vc.log.Debug().Msg("verifying vault token")
	oldToken := vc.delegate.Token()
	defer vc.delegate.SetToken(oldToken)

	vc.delegate.SetToken(vaultToken)
	secret, err := vc.delegate.Auth().Token().LookupSelf()
	if err != nil {
		vc.log.Debug().Err(err).Msg("verification failed")
		return nil, err
	}
	vc.log.Debug().Msg("verification successful")
	return secret, nil
}

func (vc *wrappedVaultClient) RefreshVaultToken() (*api.Secret, error) {
	return vc.Delegate().Auth().Token().RenewSelf(86400) // this value is basically ignored by the server
}

func (vc *wrappedVaultClient) ServiceSecretPrefix(configVersion int) string {

	if vc.secretsPrefix != "" {
		return vc.secretsPrefix
	}

	if configVersion < 2 {
		return SecretsServicePathV1
	} else {
		return SecretsServicePathV2
	}
}
