package cfg

import "github.com/hootsuite/vault-ctrl-tool/util"

func CalculateSecretPrefix(currentConfig Config, serviceSecretPrefix *string) string {

	if serviceSecretPrefix != nil && *serviceSecretPrefix != "" {
		return *serviceSecretPrefix
	}

	if currentConfig.ConfigVersion < 2 {
		return util.SecretsServicePathV1
	} else {
		return util.SecretsServicePathV2
	}
}
