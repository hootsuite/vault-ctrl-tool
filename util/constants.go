package util

const SecretsServicePathV1 = "/secret/application-config/services/"
const SecretsServicePathV2 = "/kv/data/application-config/services/"
const VaultEC2AuthPath = "/v1/auth/aws-ec2/login"

// EnableKubernetesVaultTokenAuthentication (see references for description)
// Disable this at compile time if you don't use this feature.
const EnableKubernetesVaultTokenAuthentication = true
