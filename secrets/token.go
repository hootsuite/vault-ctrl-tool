package secrets

import (
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	zlog "github.com/rs/zerolog/log"
)

func WriteVaultToken(tokenCfg config.VaultTokenType, vaultToken string) error {

	if tokenCfg.Output == "" {
		zlog.Warn().Interface("tokenCfg", tokenCfg).Msg("no output file specified to write vault token")
		return nil
	}

	zlog.Info().Str("outputFile", tokenCfg.Output).Msg("writing Vault token to file")

	mode, err := util.StringToFileMode(tokenCfg.Mode)

	if err != nil {
		return fmt.Errorf("could not parse file mode %q for %q: %w", tokenCfg.Mode, tokenCfg.Output, err)
	}

	util.MustMkdirAllForFile(tokenCfg.Output)
	util.MakeWritable(tokenCfg.Output)
	file, err := os.OpenFile(tokenCfg.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
	if err != nil {
		return fmt.Errorf("failed to create Vault token file %q: %w", tokenCfg.Output, err)
	}

	defer file.Close()

	_, err = fmt.Fprintf(file, "%s\n", vaultToken)

	if err != nil {
		return fmt.Errorf("failed to create Vault token file %q: %w", tokenCfg.Output, err)
	}

	return nil

}
