package vaultclient

import (
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"

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
		return fmt.Errorf("could not parse file mode %q for %q: %w", currentConfig.VaultToken.Mode, outputFilename, err)
	}

	util.MakeDirsForFile(outputFilename)
	file, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
	if err != nil {
		return fmt.Errorf("failed to create Vault token file %q: %w", outputFilename, err)
	}
	scrubber.AddFile(outputFilename)

	_, err = fmt.Fprintf(file, "%s\n", vaultToken)

	if err != nil {
		return fmt.Errorf("failed to create Vault token file %q: %w", outputFilename, err)
	}

	file.Close()
	return nil
}
