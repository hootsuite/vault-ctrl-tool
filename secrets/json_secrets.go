package secrets

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func WriteJSONSecret(secret config.SecretType, cache briefcase.SecretsCache) error {

	var kvSecrets []briefcase.SimpleSecret

	// make a copy
	kvSecrets = append(kvSecrets, cache.StaticSecrets()...)

	if secret.Lifetime == util.LifetimeToken {
		kvSecrets = append(kvSecrets, cache.TokenSecrets()...)
	}

	mode, err := util.StringToFileMode(secret.Mode)

	if err != nil {
		return fmt.Errorf("could not parse file mode %q for key %q: %w",
			secret.Mode, secret.Key, err)
	}

	// output all the field files
	for _, field := range secret.Fields {
		if field.Output != "" {
			if err := writeField(secret, kvSecrets, field, *mode); err != nil {
				return err
			}
		}
	}

	// If all secrets need to go to an output file..
	if secret.Output != "" {

		util.MustMkdirAllForFile(secret.Output)

		file, err := os.OpenFile(secret.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)

		if err != nil {
			return fmt.Errorf("couldn't open file %q: %w", secret.Output, err)
		}

		defer file.Close()

		log := zlog.With().Str("filename", secret.Output).Logger()

		data, err := collectSecrets(log, secret, kvSecrets)

		if err != nil {
			return fmt.Errorf("could not output secrets file: %w", err)
		}

		if len(data) > 0 {
			err = json.NewEncoder(file).Encode(&data)

			if err != nil {
				return fmt.Errorf("failed to save secrets into %q: %w", secret.Output, err)
			}
		}
	}
	return nil
}

func writeField(secret config.SecretType, kvSecrets []briefcase.SimpleSecret, field config.SecretFieldType, mode os.FileMode) error {
	value := findSimpleSecretValue(kvSecrets, secret.Key, field.Name)

	if value == nil {
		if secret.IsMissingOk {
			zlog.Warn().Str("field", field.Name).Str("key", secret.Key).Str("output", field.Output).Msg("no secret found with key and missingOk=true, so no output will be written")
		} else {
			return fmt.Errorf("field %q not found in secret with key %q", field.Name, secret.Key)
		}

	} else {
		util.MustMkdirAllForFile(field.Output)
		file, err := os.OpenFile(field.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return fmt.Errorf("couldn't open file %q: %w", field.Output, err)
		}

		defer file.Close()

		zlog.Info().Str("field", field.Name).Str("key", secret.Key).Str("output", field.Output).Msg("writing field to file")

		_, err = fmt.Fprint(file, value)

		if err != nil {
			return fmt.Errorf("failed writing secret to file %q: %w", field.Output, err)
		}
	}

	return nil
}

func findSimpleSecretValue(secrets []briefcase.SimpleSecret, key, field string) interface{} {
	for _, s := range secrets {
		if s.Key == key && s.Field == field {
			return s.Value
		}
	}
	return nil
}

func collectSecrets(log zerolog.Logger, secret config.SecretType, kvSecrets []briefcase.SimpleSecret) (map[string]interface{}, error) {

	data := make(map[string]interface{})

	log.Info().Str("key", secret.Key).Msg("collecting secret")
	if secret.UseKeyAsPrefix {

		for _, s := range kvSecrets {
			if s.Key == secret.Key {
				key := secret.Key + "_" + s.Field
				if _, dupe := data[key]; dupe {
					log.Error().Str("field", s.Field).Str("prefix", secret.Key).Msg("the secret with this prefix causes there to be a duplicate entry")
					return nil, fmt.Errorf("the secret field %q with prefix %q causes there to be a duplicate",
						s.Field, secret.Key)
				}
				zlog.Debug().Str("key", key).Msg("collecting key")
				data[key] = s.Value
			}
		}
	} else {
		for _, s := range kvSecrets {
			if s.Key == secret.Key {

				if _, dupe := data[s.Field]; dupe {
					log.Error().Str("field", s.Field).Msg("this field causes there to be a duplicate entry")
					return nil, fmt.Errorf("the secret field %q causes there to be a duplicate", s.Field)
				}
				data[s.Field] = s.Value
				zlog.Debug().Str("field", s.Field).Msg("collecting field")
			}
		}
	}
	return data, nil
}
