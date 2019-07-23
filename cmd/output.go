package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/errwrap"
	jww "github.com/spf13/jwalterweatherman"
)

func writeVaultToken(vaultToken string) error {

	outputFilename := config.VaultToken.Output

	if outputFilename == "" {
		return nil
	}

	jww.INFO.Printf("Writing Vault token to %q", outputFilename)

	mode, err := stringToFileMode(config.VaultToken.Mode)

	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not parse file mode %q for %q: {{err}}", config.VaultToken.Mode, outputFilename), err)
	}

	makeDirsForFile(outputFilename)
	file, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("failed to create vault token file %q: {{err}}", outputFilename), err)
	}
	addFileToScrub(outputFilename)

	_, err = fmt.Fprintf(file, "%s\n", vaultToken)

	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("failed to create vault token file %q: {{err}}", outputFilename), err)
	}

	file.Close()
	return nil
}
