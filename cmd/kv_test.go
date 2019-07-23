package main

import (
	"testing"

	"github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v2"
)

// TestCollectSecrets ensures basic happy path functionality of collectSecrets() works.
func TestCollectSecrets(t *testing.T) {

	configString := `
secrets:
    - key: ex1
      path: example
      use_key_as_prefix: true
      missingOk: true
      output: /target/example.secrets
      fields:
        - name: field1
        - name: field2
      mode: 0777
    - key: ex2
      path: example2
      use_key_as_prefix: false
      output: /target/example.secrets
      mode: 0777
`
	var localConfig Config
	yaml.Unmarshal([]byte(configString), &localConfig)

	vaultSecrets := makeVaultKVSecrets()

	result, err := collectSecrets("TestCollectSecrets", localConfig.Secrets, vaultSecrets)

	// Assert that this static data setup is correct.
	if err != nil {
		t.Error(err)
	}

	// Assert only the correct number of fields are present.
	if len(result) != 6 {
		t.Errorf("incorrect number of fields in output file. Found %d, expected 6. Fields are: %v", len(result), result)
	}

	// Assert the "ex2" fields are not prefixed.
	if _, ok := result["fieldA"]; !ok {
		t.Errorf("Missing %q in output: %v", "fieldA", result)
	}

	// Assert the "ex1" fields are prefixed.
	if _, ok := result["ex1_field1"]; !ok {
		t.Errorf("Missing %q in output: %v", "ex1_field1", result)
	}
}

func makeVaultKVSecrets() map[string]api.Secret {
	vaultSecrets := make(map[string]api.Secret)
	ex1Secret := make(map[string]interface{})
	ex1Secret["field1"] = "one"
	ex1Secret["field2"] = "two"
	ex1Secret["field3"] = "three"
	vaultSecrets["ex1"] = api.Secret{Data: ex1Secret}

	ex2Secret := make(map[string]interface{})
	ex2Secret["fieldA"] = "apples"
	ex2Secret["fieldB"] = "bananas"
	ex2Secret["fieldC"] = "cheese"
	vaultSecrets["ex2"] = api.Secret{Data: ex2Secret}

	ex3Secret := make(map[string]interface{})
	ex3Secret["fieldRed"] = "red"
	ex3Secret["fieldGreen"] = "green"
	ex3Secret["fieldBlue"] = "blue"
	vaultSecrets["ex3"] = api.Secret{Data: ex3Secret}

	return vaultSecrets
}
