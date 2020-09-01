package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/vaultclient"
	"github.com/rs/zerolog/log"
)

func WriteAWSSTSCreds(creds *vaultclient.AWSSTSCredential, awsConfig config.AWSType) error {

	mode, err := util.StringToFileMode(awsConfig.Mode)
	if err != nil {
		return fmt.Errorf("could not parse %q as a file mode: %w", mode, err)
	}

	wipCfgFilename := filepath.Join(awsConfig.OutputPath, "config.wip")
	wipCredsFilename := filepath.Join(awsConfig.OutputPath, "credentials.wip")

	util.MustMkdirAllForFile(wipCfgFilename)

	if err := writeWIPFiles(wipCfgFilename, wipCredsFilename, creds, awsConfig.Profile, awsConfig.Region, *mode); err != nil {
		_ = os.Remove(wipCredsFilename)
		_ = os.Remove(wipCredsFilename)
		return err
	}

	cfgFilename := strings.TrimSuffix(wipCfgFilename, ".wip")
	credsFilename := strings.TrimSuffix(wipCredsFilename, ".wip")

	log.Debug().Strs("filenames", []string{wipCfgFilename, cfgFilename, wipCredsFilename, credsFilename}).Msg("atomically renaming .wip files")
	err = os.Rename(wipCfgFilename, cfgFilename)
	if err != nil {
		return err
	}

	err = os.Rename(wipCredsFilename, credsFilename)
	if err != nil {
		return err
	}
	return nil
}

func writeWIPFiles(configFilename, credentialsFilename string,
	creds *vaultclient.AWSSTSCredential,
	awsProfile, awsRegion string,
	mode os.FileMode) error {

	log.Debug().Str("awsConfig", configFilename).Str("awsCredentials", credentialsFilename).Msg("writing AWS files")

	util.MustMkdirAllForFile(configFilename)

	configFile, err := os.OpenFile(configFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, mode)

	if err != nil {
		return fmt.Errorf("could not create aws config file at %q: %w", configFilename, err)
	}
	defer configFile.Close()

	credsFile, err := os.OpenFile(credentialsFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, mode)

	if err != nil {
		return fmt.Errorf("could not create aws credentials file at %q: %w", credentialsFilename, err)
	}
	defer credsFile.Close()

	header := strings.TrimSpace(awsProfile)

	_, err = fmt.Fprintf(credsFile, `[%s]
aws_access_key_id=%s
aws_secret_access_key=%s
aws_session_token=%s

`,
		header, creds.AccessKey, creds.SecretKey, creds.SessionToken)
	if err != nil {
		return fmt.Errorf("could not write contents to %q: %w", credentialsFilename, err)
	}

	_, err = fmt.Fprintf(configFile, "[%s]\nregion=%s\n\n", header, awsRegion)
	if err != nil {
		return fmt.Errorf("could not write contents to %q: %w", configFilename, err)
	}

	return nil
}
