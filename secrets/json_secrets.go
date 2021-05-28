package secrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func WriteComposite(composite config.CompositeSecretFile, cache briefcase.SecretsCache) error {
	log := zlog.With().Str("filename", composite.Filename).Logger()

	log.Debug().Interface("compositeCfg", composite).Msg("writing composite secrets file")

	util.MustMkdirAllForFile(composite.Filename)

	file, err := os.OpenFile(composite.Filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, composite.Mode)

	if err != nil {
		return fmt.Errorf("couldn't open file %q: %w", composite.Filename, err)
	}

	defer file.Close()

	var kvSecrets []briefcase.SimpleSecret

	// make a copy
	kvSecrets = append(kvSecrets, cache.GetSecrets(util.LifetimeStatic)...)
	kvSecrets = append(kvSecrets, cache.GetSecrets(util.LifetimeVersion)...)

	if composite.Lifetime == util.LifetimeToken {
		kvSecrets = append(kvSecrets, cache.GetSecrets(util.LifetimeToken)...)
	}

	data, err := collectSecrets(log, composite, kvSecrets)

	if err != nil {
		return fmt.Errorf("could not output secrets file: %w", err)
	}

	if len(data) > 0 {
		err = json.NewEncoder(file).Encode(&data)

		if err != nil {
			return fmt.Errorf("failed to save secrets into %q: %w", composite.Filename, err)
		}
	}

	if composite.Secrets.Owner != nil {
        err = os.Chown(composite.Filename, composite.Secrets.Owner , composite.Secrets.Owner)
        if err != nil {
           return fmt.Errorf("failed changing ownership to file %q: %w", composite.Filename, err)
        }
    }

	return nil
}

func WriteSecretFields(secret config.SecretType, kvSecrets []briefcase.SimpleSecret) (int, error) {
	mode, err := util.StringToFileMode(secret.Mode)
	count := 0

	if err != nil {
		return count, fmt.Errorf("could not parse file mode %q for key %q: %w",
			secret.Mode, secret.Key, err)
	}

	// output all the field files
	for _, field := range secret.Fields {
		if field.Output != "" {
			if err := writeField(secret, kvSecrets, field, *mode); err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
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

		zlog.Info().Str("field", field.Name).Str("key", secret.Key).Str("output", field.Output).Str("encoding", field.Encoding).Msg("writing field to file")

		switch field.Encoding {
		case util.EncodingBase64:
			decoded, err := base64.StdEncoding.DecodeString(fmt.Sprint(value))
			if err != nil {
				return fmt.Errorf("failed to base64 decode field %q for secret %q: %w", field.Name, secret.Key, err)
			}
			_, err = fmt.Fprint(file, string(decoded))
		default:
			_, err = fmt.Fprint(file, value)
		}
		if err != nil {
			return fmt.Errorf("failed writing secret to file %q: %w", field.Output, err)
		}

		if secret.Owner != nil {
            err = os.Chown(field.Output, secret.Owner , secret.Owner)
            if err != nil {
                return fmt.Errorf("failed changing ownership to file %q: %w", field.Output, err)
            }
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

func collectSecrets(log zerolog.Logger, composite config.CompositeSecretFile, kvSecrets []briefcase.SimpleSecret) (map[string]interface{}, error) {

	data := make(map[string]interface{})

	log.Info().Msg("collecting composite secrets")

	for _, secret := range composite.Secrets {
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
	}
	return data, nil
}
