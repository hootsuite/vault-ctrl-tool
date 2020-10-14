package vaultclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	v12 "k8s.io/api/core/v1"
	"net/http"
	"strconv"

	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func (auth *kubernetesAuthenticator) Authenticate() (*util.WrappedToken, error) {
	secret, err := auth.performKubernetesAuth()
	if err != nil {
		auth.log.Error().Err(err).Msg("kubernetes authentication failed")
		return nil, err
	}

	return secret, nil
}

func (auth *kubernetesAuthenticator) performKubernetesAuth() (*util.WrappedToken, error) {
	type login struct {
		JWT  string `json:"jwt"`
		Role string `json:"role"`
	}

	secret, err := auth.tryHardCodedToken()

	if err == nil {
		return secret, nil
	}

	auth.log.Debug().Err(err).Msg("could not authenticate using hard-coded ConfigMap vault-token - ignoring")

	auth.log.Info().Str("serviceAccountToken", auth.serviceAccountToken).Msg("reading service account token")

	tokenBytes, err := ioutil.ReadFile(auth.serviceAccountToken)
	if err != nil {
		return nil, fmt.Errorf("could not read service account token file %q: %w", auth.serviceAccountToken, err)
	}

	auth.log.Info().Str("authPath", auth.k8sLoginPath).Str("k8sRole", auth.k8sAuthRole).Msg("authenticating")

	req := auth.vaultClient.Delegate().NewRequest(http.MethodPost, fmt.Sprintf("/v1/auth/%s/login", auth.k8sLoginPath))
	err = req.SetJSONBody(&login{JWT: string(tokenBytes), Role: auth.k8sAuthRole})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON body: %w", err)
	}

	resp, err := auth.vaultClient.Delegate().RawRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform Kubernetes auth request: %w", err)
	}

	if resp.Error() != nil {
		return nil, resp.Error()
	}

	var body api.Secret

	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return util.NewWrappedToken(&body, true), nil
}

// If there is a ConfigMap named vault-token in the default namespace, use the token it stores
// Developers running Kubernetes clusters locally do not have the ability to have their services authenticate to Vault.
// To work around this, the bootstrapping shell scripts for dev clusters create a configmap called "vault-token"
// with their Vault token in it. This stanza checks for that special configmap and uses it.
func (auth *kubernetesAuthenticator) tryHardCodedToken() (*util.WrappedToken, error) {
	if util.EnableKubernetesVaultTokenAuthentication {
		config, err := rest.InClusterConfig()
		// If we cannot create the in cluster config, that means we are not running inside of Kubernetes
		if err != nil {
			return nil, fmt.Errorf("could not create cluster config - this will fail if this is running outside of Kubernetes: %w", err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("could not create ClientSet to call Kubernetes API: %w", err)
		}

		configMaps, err := clientset.CoreV1().ConfigMaps("default").List(context.Background(), v1.ListOptions{FieldSelector: "metadata.name=vault-token"})
		if err != nil {
			return nil, fmt.Errorf("failed to get ConfigMaps filtered on the metadata.name=vault-token")
		} else if len(configMaps.Items) == 1 {
			return auth.ProcessConfigMap(configMaps.Items[0])
		} else {
			return nil, errors.New("multiple ConfigMaps were returned when filtering ConfigMaps with metadata.name=vault-token; please remove all but one")
		}
	}

	return nil, errors.New("hard coded vault-token ConfigMap disabled")
}

func (auth *kubernetesAuthenticator) ProcessConfigMap(item v12.ConfigMap) (*util.WrappedToken, error) {
	if token, exists := item.Data["token"]; exists {
		auth.log.Info().Msg("logging into Vault server %q with token from vault-token ConfigMap")

		secret, err := auth.vaultClient.VerifyVaultToken(token)
		if err != nil {
			return nil, fmt.Errorf("failed to authenticate to Vault server %q using token from vault-token ConfigMap: %w", auth.vaultClient.Delegate().Address(), err)
		}
		if secret == nil {
			return nil, fmt.Errorf("got nil secret authenticating to Vault Server %q using token from vault-token ConfigMap", auth.vaultClient.Delegate().Address())
		}

		// For backwards compatibility, tokens are expected to be renewable. This can be overridden if "renewable: false" is set in the configmap.
		renewable := true

		if renewableOverride, exists := item.Data["renewable"]; exists {
			if renewable, err = strconv.ParseBool(renewableOverride); err != nil {
				return nil, fmt.Errorf("ConfigMap vault-token key \"renewable\" has value %q which cannot be parsed as boolean :%w",
					renewableOverride, err)
			}
		}

		if !renewable {
			auth.log.Info().Msg("using non-renewable Vault token from Kubernetes ConfigMap")
		}
		return util.NewWrappedToken(secret, renewable), nil
	} else {
		return nil, errors.New("missing token field in vault-token ConfigMap")
	}
}
