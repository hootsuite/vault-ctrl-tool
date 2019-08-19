package activity

import (
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

func PerformCleanup() {
	jww.INFO.Print("Performing cleanup.")
	leases.ReadFile()

	if len(leases.Current.ManagedFiles) > 0 {
		scrubber.AddFile(leases.Current.ManagedFiles...)
	}

	scrubber.AddFile(util.Flags.LeasesFile)
	scrubber.RemoveFiles()
}