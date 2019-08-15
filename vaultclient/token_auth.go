package vaultclient

import "github.com/hashicorp/vault/api"
import jww "github.com/spf13/jwalterweatherman"

func (vc *VaultClient) performTokenAuth(vaultToken string) error {

	vc.Delegate.SetToken(vaultToken)

	var secret *api.Secret

	secret, err := vc.Delegate.Auth().Token().LookupSelf()

	if err != nil {
		return err
	}

	vc.AuthToken = secret

	jww.DEBUG.Printf("Token authentication to %q succeeded.", vc.Config.Address)
	return nil
}
