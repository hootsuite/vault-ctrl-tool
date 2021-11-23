package util

const VaultEC2AuthPath = "/v1/auth/aws-ec2/login"

// EnableKubernetesVaultTokenAuthentication (see references for description)
// Disable this at compile time if you don't use this feature.
const EnableKubernetesVaultTokenAuthentication = true

// SSHCertificate is public key, signed by Vault.
const SSHCertificate = "id_rsa-cert.pub"

// SecretLifetime is used to describe secrets lifetime description.
type SecretLifetime string

// Secrets and templates can have a lifetime associated with them, those without an explicit lifetime
// have a "static" lifetime for backwards expectations.
const LifetimeStatic SecretLifetime = "static"
const LifetimeToken SecretLifetime = "token"

// LifetimeVersion is a hack. It will refresh fields of secrets when the version of the secret increases. It
// does not support composite secrets, or anything else. If this winds up being valuable, the interactions
// between briefcase<->config will need to be rewritten since both other lifetimes operate with the exact
// opposite philosophy.
const LifetimeVersion SecretLifetime = "version"

// fields can be encoded - those base64 encoded are decoded before being written to output files. They're not
// decoded if they're part of a template / etc / etc.
const EncodingBase64 = "base64"
const EncodingNone = "none"
