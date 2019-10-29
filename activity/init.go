package activity

import (
	"fmt"

	"github.com/hootsuite/vault-ctrl-tool/aws"
	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/kv"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/sshsigning"
	"github.com/hootsuite/vault-ctrl-tool/vaultclient"
	jww "github.com/spf13/jwalterweatherman"
)

func PerformInitTasks(currentConfig cfg.Config, vaultClient vaultclient.VaultClient) error {

	jww.DEBUG.Print("Performing init tasks.")

	if currentConfig.IsEmpty() {
		jww.INFO.Print("Configuration file is empty. Writing empty lease file and skipping authentication.")
		leases.WriteFile()
		scrubber.DisableExitScrubber()
		return nil
	}

	// Read templates first so we don't waste Vault's time if there's an issue.
	if err := ingestTemplates(currentConfig); err != nil {
		return fmt.Errorf("could not ingest templates: %w", err)
	}

	if err := vaultClient.Authenticate(); err != nil {
		return fmt.Errorf("failed to log into Vault: %w", err)
	}

	token, err := vaultClient.GetTokenID()
	if err != nil {
		return fmt.Errorf("could not extract Vault token: %w", err)
	}

	leases.EnrollAuthToken(vaultClient.AuthToken)

	kvSecrets, err := vaultClient.ReadKVSecrets(currentConfig)
	if err != nil {
		return fmt.Errorf("could not read KV secrets: %w", err)
	}

	// Output necessary files
	if err := vaultclient.WriteToken(currentConfig, token); err != nil {
		return fmt.Errorf("could not write Vault token: %w", err)
	}

	if err := kv.WriteOutput(currentConfig, kvSecrets); err != nil {
		return fmt.Errorf("could not write KV secrets: %w", err)
	}

	if err := writeTemplates(currentConfig, kvSecrets); err != nil {
		return fmt.Errorf("could not write templates: %w", err)
	}

	if err := aws.WriteCredentials(currentConfig, vaultClient.Delegate); err != nil {
		return fmt.Errorf("could not write AWS credentials: %w", err)
	}

	if err := sshsigning.WriteKeys(currentConfig, vaultClient.Delegate); err != nil {
		return fmt.Errorf("could not setup SSH certificate: %w", err)
	}

	scrubber.EnrollScrubFiles()

	leases.WriteFile()

	jww.DEBUG.Print("All initialization tasks completed.")
	scrubber.DisableExitScrubber()
	return nil
}
