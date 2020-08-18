package util

const VaultEC2AuthPath = "/v1/auth/aws-ec2/login"

// EnableKubernetesVaultTokenAuthentication (see references for description)
// Disable this at compile time if you don't use this feature.
const EnableKubernetesVaultTokenAuthentication = true

// SSHCertificate is public key, signed by Vault.
const SSHCertificate = "id_rsa-cert.pub"

type SecretLifetime string

// Secrets and templates can have a lifetime associated with them, those without an explicit lifetime
// have a "static" lifetime for backwards expectations.
const LifetimeStatic = "static"
const LifetimeToken = "token"
