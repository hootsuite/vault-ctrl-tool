package main

import (
	"io/ioutil"

	jww "github.com/spf13/jwalterweatherman"
	yaml "gopkg.in/yaml.v2"
)

// VaultTokenType for writing the contents of a VAULT_TOKEN to the specified file with the specified mode.
type VaultTokenType struct {
	Output string `yaml:"output"`
	Mode   string `yaml:"mode"`
}

// TemplateType for turning Go template files into files with secrets in them.
type TemplateType struct {
	Input  string `yaml:"input"`
	Output string `yaml:"output"`
	Mode   string `yaml:"mode"`
}

// SecretType for reading from Vault's KV store and writing contents out to various places. The "output" field
// will write everything out as JSON. If "missingOk" is true, then missing secrets path will simply be logged.
type SecretType struct {
	Key            string            `yaml:"key"`
	UseKeyAsPrefix bool              `yaml:"use_key_as_prefix"`
	Path           string            `yaml:"path"`
	Fields         []SecretFieldType `yaml:"fields"`
	Output         string            `yaml:"output"`
	Mode           string            `yaml:"mode"`
	IsMissingOk    bool              `yaml:"missingOk"`
}

// SecretFieldType is used to just output the contents of specific fields to specific files. Their mode will
// be the same as "mode" in the SecretType they belong.
type SecretFieldType struct {
	Name   string `yaml:"name"`
	Output string `yaml:"output"`
}

// SSHType for SSH certificate signing. This tool will write private, public, and certificate files to the
// specified OutputPath, asking the public key to be signed for the specified role at the specified mount point in Vault.
type SSHType struct {
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

// Config is used to set up the tool and fetch all the appropriate secrets.
type Config struct {
	VaultToken VaultTokenType `yaml:"vaultToken"`
	Templates  []TemplateType `yaml:"templates"`
	Secrets    []SecretType   `yaml:"secrets"`
	SSH        []SSHType      `yaml:"sshCertificates"`
	AWS        []AWSType      `yaml:"aws"`
}

// Globally accessible configuration variable. General sanity check has been performed on it by prepareConfig.
var config Config

func isConfigEmpty() bool {
	if config.VaultToken.Output == "" &&
		len(config.Templates) == 0 &&
		len(config.AWS) == 0 &&
		len(config.SSH) == 0 &&
		len(config.Secrets) == 0 {
		return true
	}

	return false
}

// Validate the configuration and do any modifications that make the rest of the code easier.
func prepareConfig(filename string) {

	if isConfigEmpty() {
		jww.WARN.Print("Configuration file lists nothing to output.")
	}

	keys := make(map[string]bool)
	var happy = true

	if config.VaultToken.Output != "" {
		config.VaultToken.Output = absoluteOutputPath(config.VaultToken.Output)
	}

	// Go through the template config and clean it up..
	var tidyTpls []TemplateType

	for _, tpl := range config.Templates {
		if tpl.Input == "" {
			jww.WARN.Printf("There is a template stanza missing a input file in the configuration file ('imput').")
			happy = false
		} else {
			tpl.Input = absoluteInputPath(tpl.Input)
		}

		if tpl.Output == "" {
			jww.WARN.Printf("The template %q has no output file in the configuration file ('output').", tpl.Input)
		} else {
			tpl.Output = absoluteOutputPath(tpl.Output)
		}
		tidyTpls = append(tidyTpls, tpl)
	}

	config.Templates = tidyTpls

	// Go through the secrets config and clean it up...
	var tidySecrets []SecretType

	for _, secret := range config.Secrets {
		if secret.Key == "" {
			jww.WARN.Printf("There is a secret stanza missing a 'key' value in the configuration file.")
			happy = false
		}

		var tidyFields []SecretFieldType
		for _, field := range secret.Fields {
			if field.Name == "" {
				jww.WARN.Printf("There is a field in the secret %q missing 'name' value in the configuration file.", secret.Key)
				happy = false
			}
			if field.Output == "" {
				jww.WARN.Printf("The field %q in %q is missing an 'output' value", field.Name, secret.Key)
				happy = false
			} else {
				field.Output = absoluteOutputPath(field.Output)
			}
			tidyFields = append(tidyFields, field)
		}

		secret.Fields = tidyFields

		if secret.Output != "" {
			secret.Output = absoluteOutputPath(secret.Output)
		}

		if secret.Path == "" {
			jww.FATAL.Fatalf("No Vault path specified for secrets key %q in configuration file", secret.Key)
		}

		if secret.Key != "" && keys[secret.Key] {
			jww.WARN.Printf("Duplicate secret key %q found in configuration file.", secret.Key)
			happy = false
		}
		keys[secret.Key] = true
		tidySecrets = append(tidySecrets, secret)
	}

	config.Secrets = tidySecrets

	// Go through the SSH config and clean it up..
	var tidySSH []SSHType

	for _, ssh := range config.SSH {
		if ssh.VaultRole == "" {
			jww.WARN.Printf("There is a SSH stanza missing its 'vaultRole'.")
			happy = false
		}
		if ssh.VaultMount == "" {
			jww.WARN.Printf("The SSH stanza for role %q is missing a 'vaultMountPoint'.", ssh.VaultRole)
			happy = false
		}
		if ssh.OutputPath == "" {
			jww.WARN.Printf("The SSH stanza of \"%s/sign/%s\" is missing an 'outputPath'.", ssh.VaultMount, ssh.VaultRole)
			happy = false
		} else {
			ssh.OutputPath = absoluteOutputPath(ssh.OutputPath)
		}
		tidySSH = append(tidySSH, ssh)
	}

	config.SSH = tidySSH

	// Go through the AWS config and clean it up...
	var tidyAWS []AWSType

	for _, aws := range config.AWS {
		if aws.VaultRole == "" {
			jww.WARN.Printf("There is an AWS stanza missing its 'vaultRole'.")
			happy = false
		}
		if aws.VaultMountPoint == "" {
			jww.WARN.Printf("The AWS stanza for role %q is missing a Vault mount point.", aws.VaultRole)
			happy = false
		}
		if aws.Profile == "" {
			jww.WARN.Printf("The AWS stanza for role %q is missing an AWS profile name.", aws.VaultRole)
			happy = false
		}
		if aws.Region == "" {
			jww.WARN.Printf("The AWS stanza for role %q is missing an AWS region.", aws.VaultRole)
			happy = false
		}

		if aws.OutputPath == "" {
			jww.WARN.Printf("The AWS stanza for role %q is missing an output path.", aws.VaultRole)
			happy = false
		} else {
			aws.OutputPath = absoluteOutputPath(aws.OutputPath)
		}
		tidyAWS = append(tidyAWS, aws)
	}

	config.AWS = tidyAWS

	// If we're not happy and we know it, clap^Wfail fatally..
	if !happy {
		jww.FATAL.Fatalf("There are issues that need to be resolved with the configuration file at %q", filename)
	}
}

func parseConfigFile() {

	if configFile == nil || *configFile == "" {
		jww.FATAL.Fatalf("A --config file is required to be specified.")
	}

	absConfigFile := absoluteInputPath(*configFile)
	jww.DEBUG.Printf("Reading config file %q", absConfigFile)
	yamlFile, err := ioutil.ReadFile(absConfigFile)

	if err != nil {
		jww.FATAL.Fatalf("Error reading config file %q: %v", absConfigFile, err)
	}

	err = yaml.Unmarshal(yamlFile, &config)

	if err != nil {
		jww.FATAL.Fatalf("error unmarshalling config file %q: %v", absConfigFile, err)
	}

	prepareConfig(absConfigFile)

}
