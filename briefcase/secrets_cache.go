package briefcase

import "github.com/hootsuite/vault-ctrl-tool/v2/util"

// SecretsCache is the interface to the non-persisted secrets that are kept in the briefcase. This could probably
// be kept outside the briefcase, but we use the briefcase as blackboard style runtime state right now.
type SecretsCache interface {
	HasCachedSecrets(lifetime util.SecretLifetime) bool
	StoreSecrets(lifetime util.SecretLifetime, secrets []SimpleSecret)
	StaticSecrets() []SimpleSecret
	TokenSecrets() []SimpleSecret
}

func (b *Briefcase) HasCachedSecrets(lifetime util.SecretLifetime) bool {
	if lifetime == util.LifetimeToken {
		return len(b.tokenScopedCache) > 0
	} else if lifetime == util.LifetimeStatic {
		return len(b.staticScopedCache) > 0
	}

	b.log.Error().Interface("lifetime", lifetime).Msg("internal error: unknown lifetime")

	return false
}

func (b *Briefcase) StoreSecrets(lifetime util.SecretLifetime, secrets []SimpleSecret) {
	if lifetime == util.LifetimeStatic {
		b.staticScopedCache = secrets
	} else if lifetime == util.LifetimeToken {
		b.tokenScopedCache = secrets
	} else {
		b.log.Error().Interface("lifetime", lifetime).Msg("internal error: unable to cache secrets with unknown lifetime")
	}
}

func (b *Briefcase) StaticSecrets() []SimpleSecret {
	return b.staticScopedCache
}

func (b *Briefcase) TokenSecrets() []SimpleSecret {
	return b.tokenScopedCache
}
