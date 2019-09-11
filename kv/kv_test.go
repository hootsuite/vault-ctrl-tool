package kv

import (
	"testing"

	"github.com/hootsuite/vault-ctrl-tool/cfg"

	"gopkg.in/yaml.v2"
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
	var localConfig cfg.Config
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

func makeVaultKVSecrets() []SimpleSecret {

	var secrets []SimpleSecret

	secrets = append(secrets,
		SimpleSecret{Key: "ex1", Field: "field1", Value: "one",},
		SimpleSecret{Key: "ex1", Field: "field2", Value: "two",},
		SimpleSecret{Key: "ex1", Field: "field3", Value: "three",},
		SimpleSecret{Key: "ex2", Field: "fieldA", Value: "aye",},
		SimpleSecret{Key: "ex2", Field: "fieldB", Value: "bee",},
		SimpleSecret{Key: "ex2", Field: "fieldC", Value: "sea",},
		SimpleSecret{Key: "ex3", Field: "fieldRed", Value: "red",},
		SimpleSecret{Key: "ex3", Field: "fieldGreen", Value: "green",},
		SimpleSecret{Key: "ex3", Field: "fieldBlue", Value: "blue",},
	)

	return secrets
}
