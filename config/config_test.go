package config

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

var validConfigs = map[string]string{
	"Empty File": ``,
	"Only with Version 2": `---
version: 2`,
}

var invalidConfigs = map[string]string{
	"Bare word": `kapow`,
	"Missing secret path": `
---
version: 3
secrets:
 - output: path/to/file
   key: some-key
`,
	"Missing key in secret": `
---
version: 3
secrets:
  - path: path/to/secret
    output: path/to/file
`,
	"Missing fields for version scoped secret": `---
version: 1
secrets:
  - key: ex
    path: path/to/secret
    lifetime: version
`,
	"Output specified for version scoped secret": `---
version: 1
secrets:
  - key: ex
    output: path/to/file
    path: path/to/secret
    lifetime: version
    fields:
     - name: api_key
       output: path/to/file
`,
}

var validSubConfig = map[string]string{
	"sub config1": `---
version: 3
secrets:
 - key: test
   path: /secret/test
   lifetime: static`,
	"sub config2": `---
version: 3
secrets:
 - key: test2
   path: /secret/test2
   lifetime: static
`,
}

func TestValidConfigs(t *testing.T) {
	for k, v := range validConfigs {
		t.Run(k, func(t *testing.T) {
			filename := mkConfig(t, t.TempDir(), v)
			_, err := ReadConfigFile(filename, "", "", "")
			if err != nil {
				t.Fatalf("this config must be okay, got error: %v", err)
			}
		})
	}
}

func TestInvalidConfigs(t *testing.T) {
	for k, v := range invalidConfigs {
		t.Run(k, func(t *testing.T) {
			filename := mkConfig(t, t.TempDir(), v)
			_, err := ReadConfigFile(filename, "", "", "")
			if err == nil {
				t.Fatal("this config must generate an error")
			}
		})
	}
}

func TestConfigDir(t *testing.T) {

	dir := t.TempDir()
	for configName, configData := range validSubConfig {
		f := mkConfig(t, dir, configData)
		t.Logf("created config for: %s : %s", configName, f)
	}
	emptyConfig := mkConfig(t, dir, "")
	config, err := ReadConfigFile(emptyConfig, dir, "", "")
	if err != nil {
		t.Log("this config must be okay, got error")
		t.Fail()
	}

	key := SecretType{Key: "test", Path: "/secret/test", Lifetime: "static"}
	assert.Contains(t, config.VaultConfig.Secrets, key)

	key2 := SecretType{Key: "test2", Path: "/secret/test2", Lifetime: "static"}
	assert.Contains(t, config.VaultConfig.Secrets, key2)
}

func mkConfig(t *testing.T, directory string, body string) string {
	f, err := ioutil.TempFile(directory, "config_test_*.yml")

	if err != nil {
		t.Fatalf("could not make temp file: %v", err)
	}

	var filename = f.Name()

	if _, err := f.WriteString(body); err != nil {
		t.Fatalf("could not write to temp file: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("could not close temp file: %v", err)
	}

	return filename
}
