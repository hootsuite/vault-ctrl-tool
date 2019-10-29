package vaultclient

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

func (vc *VaultClient) performKubernetesAuth() error {
	type login struct {
		JWT  string `json:"jwt"`
		Role string `json:"role"`
	}

	jww.INFO.Printf("Reading Kubernetes service account token: %q", vc.serviceAccountToken)
	tokenBytes, err := ioutil.ReadFile(vc.serviceAccountToken)
	if err != nil {
		return fmt.Errorf("could not read service account token file %q: %w", vc.serviceAccountToken, err)
	}

	jww.INFO.Printf("Authenticating to %q as role %q against %q", vc.k8sLoginPath, vc.k8sAuthRole, vc.Config.Address)

	req := vc.Delegate.NewRequest("POST", fmt.Sprintf("/v1/auth/%s/login", vc.k8sLoginPath))
	err = req.SetJSONBody(&login{JWT: string(tokenBytes), Role: vc.k8sAuthRole})
	if err != nil {
		return fmt.Errorf("failed to parse JSON body: %w", err)
	}

	resp, err := vc.Delegate.RawRequest(req)
	if err != nil {
		return fmt.Errorf("failed to perform Kubernetes auth request: %w", err)
	}

	if resp.Error() != nil {
		return resp.Error()
	}

	var secret api.Secret

	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return fmt.Errorf("error parsing response: %w", err)
	}

	token, err := secret.TokenID()
	if err != nil {
		return fmt.Errorf("could not extract Vault token: %w", err)
	}

	vc.AuthToken = &secret
	vc.Delegate.SetToken(token)

	return nil
}
