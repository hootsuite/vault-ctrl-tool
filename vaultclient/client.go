package vaultclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/kv"

	"github.com/hootsuite/vault-ctrl-tool/util"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/leases"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var ErrPermissionDenied = errors.New("permission denied")
var ErrTokenTTLTooShort = errors.New("could not renew token for full duration")

type VaultClient struct {
	serviceAccountToken string
	serviceSecretPrefix string
	k8sLoginPath        string
	k8sAuthRole         string
	Delegate            *api.Client
	AuthToken           *api.Secret
	Config              *api.Config
}

func NewVaultClient(tokenFile *string, secretPrefix string, loginPath, authRole *string) (*VaultClient, error) {

	var vc VaultClient

	if tokenFile != nil {
		vc.serviceAccountToken = *tokenFile
	}

	vc.serviceSecretPrefix = secretPrefix

	// DefaultConfig will digest VAULT_ environment variables
	vc.Config = api.DefaultConfig()

	if loginPath != nil {
		vc.k8sLoginPath = *loginPath
	}

	if authRole != nil {
		vc.k8sAuthRole = *authRole
	}

	newCli, err := api.NewClient(vc.Config)

	if err != nil {
		return nil, fmt.Errorf("unable to make a Vault client: %w", err)
	}

	vc.Delegate = newCli

	return &vc, nil
}

func (vc *VaultClient) GetTokenID() (string, error) {

	if vc.AuthToken == nil {
		return "", fmt.Errorf("token is not set")
	}

	return vc.AuthToken.TokenID()
}

func (vc *VaultClient) defaultRetryStrategy(max time.Duration) backoff.BackOff {
	strategy := backoff.NewExponentialBackOff()
	strategy.InitialInterval = time.Millisecond * 500
	strategy.MaxElapsedTime = max
	return strategy
}

func (vc *VaultClient) RevokeSelf() {
	jww.DEBUG.Printf("Revoking Vault token.")
	err := vc.Delegate.Auth().Token().RevokeSelf("ignored")
	if err != nil {
		jww.ERROR.Printf("Failed to revoke Vault token. This will leave credentials around in %q Vault and potentially prevent reauthentication: %v", vc.Delegate.Address(), err)
	}
}

func (vc *VaultClient) RenewSelf(ctx context.Context, duration time.Duration) error {

	requestedRenewalSecs := int(duration.Seconds())

	jww.INFO.Print("Renewing Vault authentication token.")
	op := func() error {
		secret, err := vc.Delegate.Auth().Token().RenewSelf(requestedRenewalSecs)
		if err != nil {
			jww.ERROR.Printf("Error renewing authentication token: %v", err)
			if vc.checkPermissionDenied(err) {
				return backoff.Permanent(ErrPermissionDenied)
			}
			return err
		}

		renewalDuration, err := secret.TokenTTL()

		if err != nil {
			jww.ERROR.Printf("Could not determine token TTL: %v", err)
			return backoff.Permanent(err)
		}

		renewalDurationSecs := int(renewalDuration.Seconds())
		delta := renewalDurationSecs - requestedRenewalSecs

		// Wherein I learned there's no abs(int)
		if delta < -5 || delta > 5 {
			jww.WARN.Printf("Tried to renew token for %d seconds, but only got %d seconds.", requestedRenewalSecs, renewalDurationSecs)
			return backoff.Permanent(ErrTokenTTLTooShort)
		}

		jww.INFO.Print("Vault authentication token renewed.")
		leases.EnrollAuthToken(secret)

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(vc.defaultRetryStrategy(duration), ctx))

	return err
}

// Authenticate to the Vault server.
// Note this is also used during sidecar mode if the existing token expires.
// 1. Use the token from the leases file if exists.
// 2. Use the token from --vault-token (if used)
// 3. Use VAULT_TOKEN if set.
// 4. Use K8s ServiceAccountToken against the k8s auth backend if specified.
func (vc *VaultClient) Authenticate() error {

	// If there is a leases token, use it.
	if leases.Current.AuthTokenLease.Token != "" {

		jww.INFO.Printf("Logging into Vault server %q with token from lease", vc.Config.Address)
		err := vc.performTokenAuth(leases.Current.AuthTokenLease.Token)

		if err != nil {
			return fmt.Errorf("failed to authenticate to Vault server %q with token in lease file: %w", vc.Config.Address, err)
		}

		return nil
	}

	// Check if -vault-token was passed in

	if util.Flags.VaultTokenArg != "" {

		jww.INFO.Printf("Logging into Vault server %q with command line token.", vc.Config.Address)

		err := vc.performTokenAuth(util.Flags.VaultTokenArg)

		if err != nil {
			return fmt.Errorf("failed to authenticate to Vault server %q using command line token: %w", vc.Config.Address, err)
		}
		return nil
	}

	// Otherwise, if VAULT_TOKEN is set, use that.

	vaultToken := os.Getenv(api.EnvVaultToken)

	if vaultToken != "" {

		jww.INFO.Printf("Logging into Vault server %q with token in %q", vc.Config.Address, api.EnvVaultToken)

		err := vc.performTokenAuth(vaultToken)
		if err != nil {
			return fmt.Errorf("failed to authenticate to Vault server %q using %q: %w", vc.Config.Address,
				api.EnvVaultToken, err)
		}
		return nil
	}

	// Otherwise, maybe EC2 auth is requested

	if util.Flags.EC2AuthEnabled {

		err := vc.performEC2Auth()

		if err != nil {
			return fmt.Errorf("failed to authenticate to Vault server %q as an EC2 Instance: %w", vc.Config.Address, err)
		}

		return nil
	}

	// Otherwise, if there is a ConfigMap named vault-token in the default namespace, use the token it stores

	// Developers running Kubernetes clusters locally do not have the ability to have their services authenticate to Vault.
	// To work around this, the bootstrapping shell scripts for dev clusters create a configmap called "vault-token"
	// with their Vault token in it. This stanza checks for that special configmap and uses it.
	if util.EnableKubernetesVaultTokenAuthentication {
		config, err := rest.InClusterConfig()
		// If we cannot create the in cluster config, that means we are not running inside of Kubernetes
		if err != nil {
			jww.DEBUG.Print("Could not create cluster config - this will fail if this is running outside of Kubernetes")
		} else {

			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				jww.DEBUG.Print("Could not create clientset to call Kubernetes API")
			} else {
				configMaps, err := clientset.CoreV1().ConfigMaps("default").List(v1.ListOptions{FieldSelector: "metadata.name=vault-token"})
				if err != nil {
					jww.DEBUG.Printf("Failed to get ConfigMaps filtered on the metadata.name=vault-token: %v", err)
				} else if len(configMaps.Items) == 1 {
					if token, exists := configMaps.Items[0].Data["token"]; exists {

						jww.INFO.Printf("Logging into Vault server %q with token from vault-token ConfigMap.", vc.Config.Address)

						err := vc.performTokenAuth(token)
						if err != nil {
							return fmt.Errorf("failed to authenticate to Vault server %q using token from vault-token ConfigMap: %w", vc.Config.Address, err)
						}
						return nil
					}
				} else {
					jww.DEBUG.Print("Multiple ConfigMaps were returned when filtering ConfigMaps with metadata.name=vault-token; please remove all but one.")
				}
			}
		}
	}

	// Lastly, if there's a Kubernetes Auth Role setup, use that...

	if vc.k8sAuthRole != "" {
		return vc.performKubernetesAuth()
	}

	return fmt.Errorf("no authentication mechanism specified and %q is not set", api.EnvVaultToken)
}

func (vc *VaultClient) ReadKVSecrets(currentConfig cfg.Config) ([]kv.SimpleSecret, error) {

	var simpleSecrets []kv.SimpleSecret

	for _, request := range currentConfig.Secrets {

		key := request.Key

		jww.INFO.Printf("Fetching secret: %q", request.Path)

		var path string

		if !strings.HasPrefix(request.Path, "/") {
			path = filepath.Join(vc.serviceSecretPrefix, request.Path)
		} else {
			path = request.Path
		}

		// The same key could be in different paths, but we don't allow this because it's confusing.
		for _, s := range simpleSecrets {
			if s.Key == key {
				return nil, fmt.Errorf("duplicate secret key %q", key)
			}
		}

		jww.DEBUG.Printf("Reading secrets from %q", path)
		response, err := vc.Delegate.Logical().Read(path)

		if err != nil {
			return nil, fmt.Errorf("error fetching secret %q from %q: %w", path, vc.Delegate.Address(), err)
		}

		if response == nil {
			if request.IsMissingOk {
				jww.INFO.Printf("No response reading secrets from %q on path %q (either access is denied "+
					"or there are no secrets). Ignoring since missingOk is set in the config.",
					vc.Delegate.Address(), path)
			} else {
				return nil, fmt.Errorf("no response returned fetching secrets")
			}
		} else {
			var secretData map[string]interface{}

			if currentConfig.ConfigVersion < 2 {
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
				simpleSecrets = append(simpleSecrets, kv.SimpleSecret{
					Key:   key,
					Field: f,
					Value: v,
				})
			}
		}
	}

	return simpleSecrets, nil
}

func (vc *VaultClient) checkPermissionDenied(err error) bool {
	errorString := fmt.Sprintf("%s", err)
	return strings.Contains(errorString, "Code: 403")
}
