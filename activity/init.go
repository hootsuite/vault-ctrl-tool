package activity

import (
	"github.com/hootsuite/vault-ctrl-tool/aws"
	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/kv"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/sshsigning"
	"github.com/hootsuite/vault-ctrl-tool/vaultclient"
	jww "github.com/spf13/jwalterweatherman"
)

func PerformInitTasks(currentConfig cfg.Config, serviceAccountToken, serviceSecretPrefix, k8sLoginPath, k8sAuthRole *string) {

	jww.DEBUG.Print("Performing init tasks.")

	if currentConfig.IsEmpty() {
		jww.INFO.Print("Configuration file is empty. Writing empty lease file and skipping authentication.")
		leases.WriteFile()
		scrubber.DisableExitScrubber()
		return
	}

	// Read templates first so we don't waste Vault's time if there's an issue.
	if err := ingestTemplates(currentConfig); err != nil {
		jww.FATAL.Fatalf("Could not ingest templates: %v", err)
	}

	vaultClient := vaultclient.NewVaultClient(serviceAccountToken,
		calculateSecretPrefix(currentConfig, serviceSecretPrefix),
		k8sLoginPath,
		k8sAuthRole)

	if err := vaultClient.Authenticate(); err != nil {
		jww.FATAL.Fatalf("Failed to log into Vault: %v", err)
	}

	token, err := vaultClient.GetTokenID()
	if err != nil {
		jww.FATAL.Fatalf("Could not extract Vault Token: %v", err)
	}

	leases.EnrollAuthToken(vaultClient.AuthToken)

	kvSecrets := vaultClient.ReadKVSecrets(currentConfig)

	// Output necessary files
	if err := vaultclient.WriteToken(currentConfig, token); err != nil {
		jww.FATAL.Fatalf("Could not write vault token: %v", err)
	}

	if err := kv.WriteOutput(currentConfig, kvSecrets); err != nil {
		jww.FATAL.Fatalf("Could not write KV secrets: %v", err)
	}

	if err := writeTemplates(currentConfig, kvSecrets); err != nil {
		jww.FATAL.Fatalf("Could not write templates: %v", err)
	}

	if err := aws.WriteCredentials(currentConfig, vaultClient.Delegate); err != nil {
		jww.FATAL.Fatalf("Could not write AWS credentials: %v", err)
	}

	if err := sshsigning.WriteKeys(currentConfig, vaultClient.Delegate); err != nil {
		jww.FATAL.Fatalf("Could not setup SSH certificate: %v", err)
	}

	scrubber.EnrollScrubFiles()

	leases.WriteFile()

	jww.DEBUG.Print("All initialization tasks completed.")
	scrubber.DisableExitScrubber()
}
