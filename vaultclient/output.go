package vaultclient

import (
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"

	"github.com/hashicorp/errwrap"
	jww "github.com/spf13/jwalterweatherman"
)

func WriteToken(currentConfig cfg.Config, vaultToken string) error {

	outputFilename := currentConfig.VaultToken.Output

	if outputFilename == "" {
		return nil
	}

	jww.INFO.Printf("Writing Vault token to %q", outputFilename)

	mode, err := util.StringToFileMode(currentConfig.VaultToken.Mode)

	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not parse file mode %q for %q: {{err}}", currentConfig.VaultToken.Mode, outputFilename), err)
	}

	util.MakeDirsForFile(outputFilename)
	file, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("failed to create vault token file %q: {{err}}", outputFilename), err)
	}
	scrubber.AddFile(outputFilename)

	_, err = fmt.Fprintf(file, "%s\n", vaultToken)

	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("failed to create vault token file %q: {{err}}", outputFilename), err)
	}

	file.Close()
	return nil
}
