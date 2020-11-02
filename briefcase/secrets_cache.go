package briefcase

import "github.com/hootsuite/vault-ctrl-tool/v2/util"

// SecretsCache is the interface to the non-persisted secrets that are kept in the briefcase. This could probably
// be kept outside the briefcase, but we use the briefcase as blackboard style runtime state right now.
type SecretsCache interface {
	HasCachedSecrets(lifetime util.SecretLifetime) bool
	StoreSecrets(lifetime util.SecretLifetime, secrets []SimpleSecret)
	GetSecrets(lifetime util.SecretLifetime) []SimpleSecret
}

func (b *Briefcase) HasCachedSecrets(lifetime util.SecretLifetime) bool {
	switch lifetime {
	case util.LifetimeToken, util.LifetimeStatic:
		return len(b.secretCache[lifetime]) > 0
	case util.LifetimeVersion:
		b.log.Error().Msgf("secrets with the lifetime of %q are never cached", util.LifetimeVersion)
		return false
	default:
		b.log.Error().Interface("lifetime", lifetime).Msg("internal error: specified lifetime is never cached")
		return false
	}
}

func (b *Briefcase) StoreSecrets(lifetime util.SecretLifetime, secrets []SimpleSecret) {
	b.secretCache[lifetime] = secrets
}

func (b *Briefcase) GetSecrets(lifetime util.SecretLifetime) []SimpleSecret {
	return b.secretCache[lifetime]
}
