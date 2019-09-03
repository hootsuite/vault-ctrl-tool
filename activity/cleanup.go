package activity

import (
	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

func PerformCleanup(revoke bool) {
	jww.INFO.Print("Performing cleanup.")
	leases.ReadFile()

	if len(leases.Current.ManagedFiles) > 0 {
		scrubber.AddFile(leases.Current.ManagedFiles...)
	}

	if revoke {
		revokeCurrentToken()
	}

	scrubber.AddFile(util.Flags.LeasesFile)
	scrubber.RemoveFiles()
}

func revokeCurrentToken() {
	if leases.Current.AuthTokenLease.Token != "" {
		jww.DEBUG.Print("Attempting to revoke existing Vault token.")

		// To keep things simple, we don't actually use a normal VaultClient here since
		// we don't need any of the login/secret paths when revoking an existing token.
		apiClient, err := api.NewClient(api.DefaultConfig())

		if err != nil {
			jww.WARN.Printf("Unable to create Vault client to revoke current token: %v", err)
		} else {
			apiClient.SetToken(leases.Current.AuthTokenLease.Token)
			if err = apiClient.Auth().Token().RevokeSelf("ignored"); err != nil {
				jww.WARN.Printf("Failed to revoke current Vault token: %v", err)
			} else {
				jww.INFO.Print("Revoked Vault token.")
			}
		}
	}
}
