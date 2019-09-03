package vaultclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

type VaultClient struct {
	serviceAccountToken string
	serviceSecretPrefix string
	k8sLoginPath        string
	k8sAuthRole         string
	Delegate            *api.Client
	AuthToken           *api.Secret
	Config              *api.Config
}

func NewVaultClient(tokenFile *string, secretPrefix string, loginPath, authRole *string) VaultClient {

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
		jww.FATAL.Printf("Unable to make a Vault client: %v", err)
	}

	vc.Delegate = newCli

	return vc
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
	jww.INFO.Print("Renewing Vault authentication token.")
	op := func() error {
		secret, err := vc.Delegate.Auth().Token().RenewSelf(int(duration.Seconds()))
		if err != nil {
			jww.ERROR.Printf("Error renewing authentication token: %v", err)
			if vc.checkPermissionDenied(err) {
				return backoff.Permanent(ErrPermissionDenied)
			}
			return err
		}

		jww.INFO.Print("Vault authentication token renewed.")
		leases.EnrollAuthToken(secret)

		return nil
	}

	err := backoff.Retry(op, backoff.WithContext(vc.defaultRetryStrategy(duration), ctx))

	return err
}

// Authenticate to the Vault server.
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
			jww.FATAL.Fatalf("Failed to authenticate to vault server %q with token in lease file. Leases will not be renewed. Error: %v",
				vc.Config.Address, err)
		}

		return nil
	}

	// Check if -vault-token was passed in

	if util.Flags.VaultTokenArg != "" {

		jww.INFO.Printf("Logging into Vault server %q with command line token.", vc.Config.Address)

		err := vc.performTokenAuth(util.Flags.VaultTokenArg)

		if err != nil {
			jww.FATAL.Fatalf("Failed to authenticate to Vault Server %q using command line token: %v", vc.Config.Address, err)
		}
		return nil
	}

	// If EC2 auth is requested

	if util.Flags.EC2AuthEnabled {

		err := vc.performEC2Auth()

		if err != nil {
			jww.FATAL.Fatalf("Failed to authenticate to Vault Server %q as an EC2 Instance: %v", vc.Config.Address, err)
		}

		return nil

	}

	// Otherwise, if VAULT_TOKEN is set, use that.

	vaultToken := os.Getenv(api.EnvVaultToken)

	if vaultToken != "" {

		jww.INFO.Printf("Logging into Vault server %q with token in %q", vc.Config.Address, api.EnvVaultToken)

		err := vc.performTokenAuth(vaultToken)
		if err != nil {
			jww.FATAL.Fatalf("Failed to authenticate to Vault Server %q using %q: %v", vc.Config.Address,
				api.EnvVaultToken, err)
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
							jww.FATAL.Fatalf("Failed to authenticate to Vault Server %q using token from vault-token ConfigMap: %v", vc.Config.Address, err)
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

	jww.FATAL.Fatalf("No authentication mechanism specified and %q is not set.", api.EnvVaultToken)
	return nil
}

func (vc *VaultClient) ReadKVSecrets(currentConfig cfg.Config) map[string]api.Secret {

	var vaultSecretsMapping = make(map[string]api.Secret)

	for _, request := range currentConfig.Secrets {

		key := request.Key

		jww.INFO.Printf("Fetching secret: %q", request.Path)

		var path string

		if !strings.HasPrefix(request.Path, "/") {
			path = filepath.Join(vc.serviceSecretPrefix, request.Path)
		} else {
			path = request.Path
		}

		if _, ok := vaultSecretsMapping[key]; ok {
			jww.FATAL.Fatalf("Duplicate secret key %q.", key)
		}

		jww.DEBUG.Printf("Reading secrets from %q", path)
		response, err := vc.Delegate.Logical().Read(path)

		if err != nil {
			jww.FATAL.Fatalf("error fetching secret %q from %q: %v", path, vc.Delegate.Address(), err)
		}

		if response == nil {
			if request.IsMissingOk {
				jww.INFO.Printf("No response reading secrets from %q on path %q (either access is denied "+
					"or there are no secrets). Ignoring since missingOk is set in the config.",
					vc.Delegate.Address(), path)
			} else {
				jww.FATAL.Fatalf("No response returned fetching secrets.")
			}
		} else {
			leases.EnrollSecret(response)
			vaultSecretsMapping[key] = *response
		}
	}

	return vaultSecretsMapping
}

func (vc *VaultClient) checkPermissionDenied(err error) bool {
	errorString := fmt.Sprintf("%s", err)
	return strings.Contains(errorString, "Code: 403")
}
