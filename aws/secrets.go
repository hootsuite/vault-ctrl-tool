package aws

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"

	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

func WriteCredentials(currentConfig cfg.Config, client *api.Client) error {

	jww.DEBUG.Printf("Processing AWS credentials")
	wipDirs := make(map[string]bool)

	for _, awsConfig := range currentConfig.AWS {
		if err := generateFiles(client, awsConfig); err != nil {
			return err
		}
		wipDirs[awsConfig.OutputPath] = true
	}

	// All the config and credential files are written off to the side and swapped in so that the processes consuming
	// them don't get incomplete files. This also makes the creation of these files idempotent.
	jww.DEBUG.Printf("Atomically (hopefully) swapping in new config and credentials files.")
	for wipDir := range wipDirs {
		awsFiles := map[string]string{"config.wip": "config", "credentials.wip": "credentials"}

		for tempFile, file := range awsFiles {
			jww.DEBUG.Printf("Renaming %s file in %q to %s.", tempFile, wipDir, file)

			targetFilename := filepath.Join(wipDir, file)
			err := os.Rename(filepath.Join(wipDir, tempFile), targetFilename)
			if err != nil {
				return err
			}
			scrubber.AddFile(targetFilename)
		}
	}

	return nil
}

func generateFiles(client *api.Client, awsConfig cfg.AWSType) error {

	path := filepath.Join(awsConfig.VaultMountPoint, "creds", awsConfig.VaultRole)

	jww.INFO.Printf("Fetching AWS credentials from %q to store in %q.", path, awsConfig.OutputPath)

	result, err := client.Logical().Write(path, nil)
	if err != nil {
		return fmt.Errorf("could not fetch AWS credentials from %q: %w", path, err)
	}

	accessKey := result.Data["access_key"]
	secretKey := result.Data["secret_key"]
	// aka sessionToken
	securityToken := result.Data["security_token"]

	jww.DEBUG.Printf("Received AWS access key %q", accessKey)
	mode, err := util.StringToFileMode(awsConfig.Mode)
	if err != nil {
		return fmt.Errorf("could not parse %q as a file mode: %w", mode, err)
	}

	configFilename := filepath.Join(awsConfig.OutputPath, "config.wip")
	credentialsFilename := filepath.Join(awsConfig.OutputPath, "credentials.wip")

	util.MakeDirsForFile(configFilename)

	jww.DEBUG.Printf("Writing config file %q and credentials file %q", configFilename, credentialsFilename)
	configFile, err := os.OpenFile(configFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, *mode)

	if err != nil {
		return fmt.Errorf("could not create aws config file at %q: %w", configFilename, err)
	}
	defer configFile.Close()

	scrubber.AddFile(configFilename)

	credsFile, err := os.OpenFile(credentialsFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, *mode)

	if err != nil {
		return fmt.Errorf("could not create aws credentials file at %q: %w", credentialsFilename, err)
	}
	defer credsFile.Close()

	scrubber.AddFile(credentialsFilename)

	header := strings.TrimSpace(awsConfig.Profile)

	_, err = fmt.Fprintf(credsFile, "[%s]\naws_access_key_id=%s\naws_secret_access_key=%s\naws_session_token=%s\n\n",
		header, accessKey, secretKey, securityToken)
	if err != nil {
		return fmt.Errorf("could not write contents to %q: %w", credentialsFilename, err)
	}

	_, err = fmt.Fprintf(configFile, "[%s]\nregion=%s\n\n", header, awsConfig.Region)
	if err != nil {
		return fmt.Errorf("could not write contents to %q: %w", configFilename, err)
	}

	leases.EnrollAWS(result, awsConfig)
	return nil
}
