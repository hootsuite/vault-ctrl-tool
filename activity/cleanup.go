package activity

import (
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"
	"github.com/hootsuite/vault-ctrl-tool/vaultclient"
	jww "github.com/spf13/jwalterweatherman"
)

func PerformCleanup(vc vaultclient.VaultClient) {
	jww.INFO.Print("Performing cleanup.")
	leases.ReadFile()

	if len(leases.Current.ManagedFiles) > 0 {
		scrubber.AddFile(leases.Current.ManagedFiles...)
	}

	jww.DEBUG.Print("Attempting to revoke existing Vault token.")
	vc.Delegate.SetToken(leases.Current.AuthTokenLease.Token)
	vc.RevokeSelf()

	scrubber.AddFile(util.Flags.LeasesFile)
	scrubber.RemoveFiles()
}
