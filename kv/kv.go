package kv

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

func WriteOutput(kvSecrets map[string]api.Secret) error {

	secretsToFileMap := make(map[string][]cfg.SecretType)
	fileToModeMap := make(map[string]os.FileMode)

	for _, request := range cfg.Current.Secrets {

		mode, err := util.StringToFileMode(request.Mode)

		if err != nil {
			return errwrap.Wrapf(fmt.Sprintf("Could not parse file mode %q for key %q: {{err}}",
				request.Mode, request.Key), err)
		}

		// output all the field files
		for _, field := range request.Fields {
			value := kvSecrets[request.Key].Data[field.Name]

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
					return errwrap.Wrapf(fmt.Sprintf("couldn't open file %q: {{err}}", field.Output), err)
				}

				scrubber.AddFile(field.Output)

				jww.INFO.Printf("Writing field %q of secret with key %q to %q",
					field.Name, request.Key, field.Output)

				_, err = fmt.Fprint(file, value)

				if err != nil {
					return errwrap.Wrapf(fmt.Sprintf("Failed writing secret to file %q: {{err}}", field.Output), err)
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

func dumpJSON(kvSecrets map[string]api.Secret, secretsToFileMap map[string][]cfg.SecretType, fileToModeMap map[string]os.FileMode) error {
	for filename, secrets := range secretsToFileMap {
		jww.INFO.Printf("Creating JSON secrets file %q", filename)

		util.MakeDirsForFile(filename)
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileToModeMap[filename])

		if err != nil {
			return errwrap.Wrapf(fmt.Sprintf("Couldn't open file %q: {{err}}", filename), err)
		}

		scrubber.AddFile(filename)

		data, err := collectSecrets(filename, secrets, kvSecrets)

		if err != nil {
			return errwrap.Wrapf("could not output secrets file: {{err}}", err)
		}

		if len(data) > 0 {
			err = json.NewEncoder(file).Encode(&data)

			if err != nil {
				return errwrap.Wrapf(fmt.Sprintf("failed to save secrets into %q: {{err}}", filename), err)
			}
		}

		file.Close()
	}
	return nil
}

func collectSecrets(filename string, secrets []cfg.SecretType, kvSecrets map[string]api.Secret) (map[string]interface{}, error) {

	data := make(map[string]interface{})

	for _, request := range secrets {
		jww.INFO.Printf("Adding secrets from %q into %q", request.Key, filename)
		if request.UseKeyAsPrefix {
			for k, v := range kvSecrets[request.Key].Data {
				key := request.Key + "_" + k
				if _, dupe := data[key]; dupe {
					return nil, fmt.Errorf("the secret key %q with prefix %q causes there to be a duplicate in the file %q",
						k, request.Key, filename)
				}
				jww.DEBUG.Printf("Writing key %q", key)
				data[key] = v
			}
		} else {
			for k, v := range kvSecrets[request.Key].Data {

				if _, dupe := data[k]; dupe {
					return nil, fmt.Errorf("the secret key %q causes there to be a duplicate in the file %q", k, filename)
				}
				data[k] = v
				jww.DEBUG.Printf("Writing key %q", k)
			}
		}
	}
	return data, nil
}
