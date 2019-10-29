package kv

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"

	jww "github.com/spf13/jwalterweatherman"
)

type SimpleSecret struct {
	Key   string
	Field string
	Value interface{}
}

func WriteOutput(currentConfig cfg.Config, kvSecrets []SimpleSecret) error {

	secretsToFileMap := make(map[string][]cfg.SecretType)
	fileToModeMap := make(map[string]os.FileMode)

	for _, request := range currentConfig.Secrets {

		mode, err := util.StringToFileMode(request.Mode)

		if err != nil {
			return fmt.Errorf("could not parse file mode %q for key %q: %w",
				request.Mode, request.Key, err)
		}

		// output all the field files
		for _, field := range request.Fields {
			value := findSimpleSecretValue(kvSecrets, request.Key, field.Name)

			if value == nil {

				if request.IsMissingOk {
					jww.WARN.Printf("Field %q not found in secret with key %q, but missingOk is set, so %q will not be written.",
						field.Name, request.Key, field.Output)
				} else {
					return fmt.Errorf("field %q not found in secret with key %q", field.Name, request.Key)
				}

			} else {
				util.MakeDirsForFile(field.Output)
				file, err := os.OpenFile(field.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
				if err != nil {
					return fmt.Errorf("couldn't open file %q: %w", field.Output, err)
				}

				scrubber.AddFile(field.Output)

				jww.INFO.Printf("Writing field %q of secret with key %q to %q",
					field.Name, request.Key, field.Output)

				_, err = fmt.Fprint(file, value)

				if err != nil {
					return fmt.Errorf("failed writing secret to file %q: %w", field.Output, err)
				}

				file.Close()
			}
		}

		// If all secrets need to go to an output file, collect them here.
		if request.Output != "" {

			secretsToFileMap[request.Output] = append(secretsToFileMap[request.Output], request)
			if _, ok := fileToModeMap[request.Output]; !ok {
				fileToModeMap[request.Output] = *mode
			}
		}
	}

	// Output all the JSON files.
	return dumpJSON(kvSecrets, secretsToFileMap, fileToModeMap)
}

func findSimpleSecretValue(secrets []SimpleSecret, key, field string) interface{} {
	for _, s := range secrets {
		if s.Key == key && s.Field == field {
			return s.Value
		}
	}

	return nil
}

func dumpJSON(kvSecrets []SimpleSecret, secretsToFileMap map[string][]cfg.SecretType, fileToModeMap map[string]os.FileMode) error {
	for filename, secrets := range secretsToFileMap {
		jww.INFO.Printf("Creating JSON secrets file %q", filename)

		util.MakeDirsForFile(filename)
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileToModeMap[filename])

		if err != nil {
			return fmt.Errorf("couldn't open file %q: %w", filename, err)
		}

		scrubber.AddFile(filename)

		data, err := collectSecrets(filename, secrets, kvSecrets)

		if err != nil {
			return fmt.Errorf("could not output secrets file: %w", err)
		}

		if len(data) > 0 {
			err = json.NewEncoder(file).Encode(&data)

			if err != nil {
				return fmt.Errorf("failed to save secrets into %q: %w", filename, err)
			}
		}

		file.Close()
	}
	return nil
}

func collectSecrets(filename string, secrets []cfg.SecretType, kvSecrets []SimpleSecret) (map[string]interface{}, error) {

	data := make(map[string]interface{})

	for _, request := range secrets {
		jww.INFO.Printf("Adding secrets from %q into %q", request.Key, filename)
		if request.UseKeyAsPrefix {

			for _, s := range kvSecrets {
				if s.Key == request.Key {
					key := request.Key + "_" + s.Field
					if _, dupe := data[key]; dupe {
						return nil, fmt.Errorf("the secret field %q with prefix %q causes there to be a duplicate in the file %q",
							s.Field, request.Key, filename)
					}
					jww.DEBUG.Printf("Writing field %q", key)
					data[key] = s.Value
				}
			}
		} else {
			for _, s := range kvSecrets {
				if s.Key == request.Key {

					if _, dupe := data[s.Field]; dupe {
						return nil, fmt.Errorf("the secret field %q causes there to be a duplicate in the file %q", s.Field, filename)
					}
					data[s.Field] = s.Value
					jww.DEBUG.Printf("Writing field %q", s.Field)
				}
			}
		}
	}

	return data, nil
}
