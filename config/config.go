package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

// VaultTokenType for writing the contents of a VAULT_TOKEN to the specified file with the specified mode.
type VaultTokenType struct {
	Output string `yaml:"output"`
	Mode   string `yaml:"mode"`
}

// TemplateType for turning Go template files into files with secrets in them.
type TemplateType struct {
	Input    string              `yaml:"input"`
	Output   string              `yaml:"output"`
	Mode     string              `yaml:"mode"`
	Lifetime util.SecretLifetime `yaml:"lifetime,omitempty"`
}

// SecretType for reading from Vault's KV store and writing contents out to various places. The "output" field
// will write everything out as JSON. If "missingOk" is true, then missing secrets path will simply be logged.
type SecretType struct {
	Key            string              `yaml:"key"`
	UseKeyAsPrefix bool                `yaml:"use_key_as_prefix"`
	Path           string              `yaml:"path"`
	Fields         []SecretFieldType   `yaml:"fields"`
	Output         string              `yaml:"output"`
	Lifetime       util.SecretLifetime `yaml:"lifetime"`
	Mode           string              `yaml:"mode"`
	IsMissingOk    bool                `yaml:"missingOk"`
	PinnedVersion  *int                `yaml:"pinnedVersion,omitempty"`
}

// NeedsMetadata determines if the tool needs metadata from Vault in order to correctly process the secret. This will
// cause errors if the metadata for a secret isn't available and it's needed.
func (secretType *SecretType) NeedsMetadata() bool {
	if secretType == nil {
		return false
	}

	if secretType.Lifetime == util.LifetimeVersion || secretType.PinnedVersion != nil {
		return true
	}

	return false
}

// SecretFieldType is used to just output the contents of specific fields to specific files. Their mode will
// be the same as "mode" in the SecretType they belong.
type SecretFieldType struct {
	Name     string `yaml:"name"`
	Output   string `yaml:"output"`
	Encoding string `yaml:"encoding"`
}

// SSHCertificateType for SSH certificate signing. This tool will write private, public, and certificate files to the
// specified OutputPath, asking the public key to be signed for the specified role at the specified mount point in Vault.
type SSHCertificateType struct {
	VaultMount string `yaml:"vaultMountPoint"`
	VaultRole  string `yaml:"vaultRole"`
	OutputPath string `yaml:"outputPath"`
}

// AWSType for AWS credentials obtained by Vault performing sts:AssumeRole on your behalf.
type AWSType struct {
	VaultMountPoint string `yaml:"vaultMountPoint"`
	VaultRole       string `yaml:"vaultRole"`
	Profile         string `yaml:"awsProfile"`
	Region          string `yaml:"awsRegion"`
	OutputPath      string `yaml:"outputPath"`
	Mode            string `yaml:"mode"`
}

// VaultConfig is used to set up the tool and fetch all the appropriate secrets.
type VaultConfig struct {
	// v0 or v1: Default prefix for Secrets is /secret/application-config/services/
	// v2: Default prefix for Secrets is /kv/data/application-config/services/
	// v3: v2 plus requires "lifetime" values for secrets and templates
	ConfigVersion   int                  `yaml:"version"`
	VaultToken      VaultTokenType       `yaml:"vaultToken"`
	Templates       []TemplateType       `yaml:"templates"`
	Secrets         []SecretType         `yaml:"secrets"`
	SSHCertificates []SSHCertificateType `yaml:"sshCertificates"`
	AWS             []AWSType            `yaml:"aws"`

	log zerolog.Logger
}

type CompositeSecretFile struct {
	Filename string
	Mode     os.FileMode
	Lifetime util.SecretLifetime // if one secret is token-scoped, then the whole file becomes token scoped.
	Secrets  []SecretType
}

type ControlToolConfig struct {
	VaultConfig VaultConfig
	Templates   map[string]*template.Template
	Composites  map[string]*CompositeSecretFile
}

func ReadConfig(configFile string, inputPrefix, outputPrefix string) (*ControlToolConfig, error) {
	if configFile == "" {
		return nil, fmt.Errorf("a --config file is required to be specified")
	}

	absConfigFile := util.AbsolutePath(inputPrefix, configFile)

	log := zlog.With().Str("cfg", absConfigFile).Logger()
	log.Debug().Msg("reading config file")

	yamlFile, err := ioutil.ReadFile(absConfigFile)

	if err != nil {
		log.Error().Err(err).Msg("could not read config file")
		return nil, fmt.Errorf("trouble reading config file %q: %w", absConfigFile, err)
	}

	var current VaultConfig

	err = yaml.Unmarshal(yamlFile, &current)

	if err != nil {
		log.Error().Err(err).Msg("could not unmarshal config file")
		return nil, fmt.Errorf("could not unmarshal config file %q: %w", absConfigFile, err)
	}

	current.log = log

	errs := current.prepareConfig(inputPrefix, outputPrefix)

	if len(errs) > 0 {
		for _, err := range errs {
			log.Error().Err(err).Msg("issue with config")
		}
		return nil, fmt.Errorf("%d error(s) processing config", len(errs))
	}

	log.Debug().Interface("cfg", current).Msg("parsed configuration file")
	templates, err := current.ingestTemplates()
	if err != nil {
		return nil, err
	}

	composites, err := current.createCompositeSecrets()
	if err != nil {
		log.Error().Err(err).Msg("failed to create mapping of composite secret files")
		return nil, err
	}

	return &ControlToolConfig{
		VaultConfig: current,
		Templates:   templates,
		Composites:  composites,
	}, nil
}

// createCompositeSecrets brings an obscure feature of v1 where multiple secret stanzas could
// be combined into one JSON secrets file, using the first secret for file mode.
func (cfg *VaultConfig) createCompositeSecrets() (map[string]*CompositeSecretFile, error) {
	composites := make(map[string]*CompositeSecretFile)

	for _, secret := range cfg.Secrets {
		if secret.Output != "" {
			if file, ok := composites[secret.Output]; ok {
				file.Secrets = append(file.Secrets, secret)

				if secret.Lifetime == util.LifetimeToken && file.Lifetime == util.LifetimeStatic {
					secret.Lifetime = util.LifetimeToken
				}
			} else {
				mode, err := util.StringToFileMode(secret.Mode)
				if err != nil {
					return nil, err
				}
				composites[secret.Output] = &CompositeSecretFile{
					Filename: secret.Output,
					Mode:     *mode,
					Lifetime: secret.Lifetime,
					Secrets:  []SecretType{secret},
				}
			}
		}
	}
	return composites, nil
}

// Validate the configuration and do any modifications that make the rest of the code easier.
func (cfg *VaultConfig) prepareConfig(inputPrefix, outputPrefix string) []error {

	var errs []error

	if cfg.isEmpty() {
		cfg.log.Warn().Msg("configuration file lists nothing to output")
	}

	keys := make(map[string]bool)

	if cfg.VaultToken.Output != "" {
		cfg.VaultToken.Output = util.AbsolutePath(outputPrefix, cfg.VaultToken.Output)
	}

	// Go through the template config and clean it up..
	var tidyTpls []TemplateType

	for _, tpl := range cfg.Templates {
		if tpl.Lifetime == "" && cfg.ConfigVersion < 3 {
			tpl.Lifetime = util.LifetimeStatic
		}

		if tpl.Input == "" {
			errs = append(errs, fmt.Errorf("there is a template stanza missing a input file in the configuration file ('input')"))
		} else {
			tpl.Input = util.AbsolutePath(inputPrefix, tpl.Input)
		}

		if tpl.Lifetime == util.LifetimeVersion {
			// If you're seeing this, it's not because it isn't valuable - it surely is - but it's more work than I want
			// to tackle right now.
			errs = append(errs, fmt.Errorf("template %q - templates do not support %q lifetime", tpl.Input, util.LifetimeVersion))
		}

		if tpl.Lifetime != util.LifetimeStatic && tpl.Lifetime != util.LifetimeToken {
			errs = append(errs, fmt.Errorf("template %q - template is missing a lifetime attribute", tpl.Input))
		}

		if tpl.Output == "" {
			cfg.log.Warn().Str("template", tpl.Input).Msg("the template has no output file in the configuration file ('output')")
		} else {
			tpl.Output = util.AbsolutePath(outputPrefix, tpl.Output)
		}
		tidyTpls = append(tidyTpls, tpl)
	}

	cfg.Templates = tidyTpls

	// Go through the secrets config and clean it up...
	var tidySecrets []SecretType

	for _, secret := range cfg.Secrets {

		if secret.Key == "" {
			errs = append(errs, fmt.Errorf("there is a secret stanza missing a 'key' value in the configuration file"))
			continue
		}

		if secret.Path == "" {
			errs = append(errs, fmt.Errorf("secret %q - no Vault path specified for secret in configuration file", secret.Key))
			continue
		}

		if secret.Lifetime == "" && cfg.ConfigVersion < 3 {
			secret.Lifetime = util.LifetimeStatic
		}

		if secret.Lifetime != util.LifetimeStatic && secret.Lifetime != util.LifetimeToken && secret.Lifetime != util.LifetimeVersion {
			errs = append(errs, fmt.Errorf("secret %q - secret is missing a lifetime attribute", secret.Key))
		}

		var tidyFields []SecretFieldType
		for _, field := range secret.Fields {
			if field.Name == "" {
				errs = append(errs, fmt.Errorf("secret %q - there is a field in this secret missing 'name' value in the configuration file", secret.Key))
			}

			field.Encoding = strings.ToLower(field.Encoding)
			if field.Encoding != "" && field.Encoding != util.EncodingBase64 && field.Encoding != util.EncodingNone {
				errs = append(errs, fmt.Errorf("secret %q - field %q - encoding %q - if specified, encoding must be %q or %q",
					secret.Key, field.Name, field.Encoding, util.EncodingBase64, util.EncodingNone))
			}
			if field.Output == "" {
				errs = append(errs, fmt.Errorf("secret %q - field - %q - this field is missing an 'output'",
					secret.Key, field.Name))
			} else {
				field.Output = util.AbsolutePath(outputPrefix, field.Output)
			}
			tidyFields = append(tidyFields, field)
		}

		secret.Fields = tidyFields

		if secret.Output != "" {
			secret.Output = util.AbsolutePath(outputPrefix, secret.Output)
		}

		if secret.Output != "" && secret.Lifetime == util.LifetimeVersion {
			errs = append(errs, fmt.Errorf("secret %q - output %q - cannot use an output file when a secret has a lifetime of %q; this only works with fields of a secret",
				secret.Key, secret.Output, util.LifetimeVersion))
		}

		if secret.Lifetime == util.LifetimeVersion && len(secret.Fields) == 0 {
			errs = append(errs, fmt.Errorf("secret %q - at least one field of a secret must be specified when using a lifetime of %q", secret.Key, util.LifetimeVersion))
		}

		if secret.Key != "" && keys[secret.Key] {
			errs = append(errs, fmt.Errorf("secret %q - duplicate secret key found in configuration file", secret.Key))
		}
		keys[secret.Key] = true
		tidySecrets = append(tidySecrets, secret)
	}

	cfg.Secrets = tidySecrets

	// Go through the SSH config and clean it up..
	var tidySSH []SSHCertificateType

	for _, sshCert := range cfg.SSHCertificates {
		if sshCert.VaultRole == "" {
			errs = append(errs, fmt.Errorf("there is a SSH certificate stanza missing its 'vaultRole'"))
		}

		if sshCert.VaultMount == "" {
			errs = append(errs, fmt.Errorf("vaultRole %q - ssh certificate stanza is missing a 'vaultMountPoint'", sshCert.VaultRole))
		}

		if sshCert.OutputPath == "" {
			errs = append(errs, fmt.Errorf("vaultMount %q vaultRole %q - ssh certificate stanza is missing an 'outputPath'", sshCert.VaultMount, sshCert.VaultRole))
		} else {
			sshCert.OutputPath = util.AbsolutePath(outputPrefix, sshCert.OutputPath)
		}
		tidySSH = append(tidySSH, sshCert)
	}

	cfg.SSHCertificates = tidySSH

	// Go through the AWS config and clean it up...
	var tidyAWS []AWSType

	for _, aws := range cfg.AWS {
		if aws.VaultRole == "" {
			errs = append(errs, errors.New("there is an AWS stanza missing its 'vaultRole'"))
		}
		if aws.VaultMountPoint == "" {
			errs = append(errs, fmt.Errorf("vaultRole %q - aws stanza is missing a Vault mount point", aws.VaultRole))
		}

		if aws.Profile == "" {
			errs = append(errs, fmt.Errorf("vaultRole %q - aws stanza is missing an AWS profile name", aws.VaultRole))
		}
		if aws.Region == "" {
			errs = append(errs, fmt.Errorf("vaultRole %q - aws stanza is missing an AWS region", aws.VaultRole))
		}

		if aws.OutputPath == "" {
			errs = append(errs, fmt.Errorf("vaultRole %q - aws stanza is missing an output path", aws.VaultRole))
		} else {
			aws.OutputPath = util.AbsolutePath(outputPrefix, aws.OutputPath)
		}
		tidyAWS = append(tidyAWS, aws)
	}

	cfg.AWS = tidyAWS

	return errs
}

func (cfg VaultConfig) Cleanup() {

	if cfg.VaultToken.Output != "" {
		if err := os.Remove(cfg.VaultToken.Output); err != nil {
			cfg.log.Warn().Err(err).Str("filename", cfg.VaultToken.Output).Msg("could not remove file")
		}
	}

	for _, tpl := range cfg.Templates {
		if tpl.Output != "" {
			if err := os.Remove(tpl.Output); err != nil {
				cfg.log.Warn().Err(err).Str("filename", tpl.Output).Msg("could not remove file")
			}
		}
	}

	for _, secret := range cfg.Secrets {
		if secret.Output != "" {
			if err := os.Remove(secret.Output); err != nil {
				cfg.log.Warn().Err(err).Str("filename", secret.Output).Msg("could not remove file")
			}
		}
		for _, field := range secret.Fields {
			if field.Output != "" {
				if err := os.Remove(field.Output); err != nil {
					cfg.log.Warn().Err(err).Str("filename", field.Output).Msg("could not remove file")
				}
			}
		}
	}

	for _, ssh := range cfg.SSHCertificates {
		if err := os.Remove(filepath.Join(ssh.OutputPath, util.SSHCertificate)); err != nil {
			cfg.log.Warn().Err(err).Str("filename", filepath.Join(ssh.OutputPath, util.SSHCertificate)).Msg("could not remove file")
		}
	}

	for _, aws := range cfg.AWS {
		if aws.OutputPath != "" {
			if err := os.Remove(filepath.Join(aws.OutputPath, "credentials")); err != nil {
				cfg.log.Warn().Err(err).Str("filename", filepath.Join(aws.OutputPath, "credentials")).Msg("could not remove file")
			}
		}
	}
}

// isEmpty will return true if no secrets are configured. It will also return true if only the top level "version"
// field is set.
func (cfg VaultConfig) isEmpty() bool {
	if cfg.VaultToken.Output == "" &&
		len(cfg.Templates) == 0 &&
		len(cfg.AWS) == 0 &&
		len(cfg.SSHCertificates) == 0 &&
		len(cfg.Secrets) == 0 {
		return true
	}

	return false
}
