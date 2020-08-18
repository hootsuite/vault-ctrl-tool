package briefcase

import (
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
)

func (b *Briefcase) ShouldRefreshJSONSecret(secret config.SecretType) bool {
	var exists bool

	if secret.Lifetime == util.LifetimeToken {
		_, exists = b.TokenScopedJSONSecrets[secret.Path]
	} else {
		_, exists = b.StaticJSONSecrets[secret.Path]
	}

	return !exists
}

func (b *Briefcase) EnrollJSONSecret(secret config.SecretType) {
	b.log.Info().Str("vaultPath", secret.Path).Interface("lifetime", secret.Lifetime).Msg("enrolling JSON secret")

	if secret.Lifetime == util.LifetimeToken {
		b.TokenScopedJSONSecrets[secret.Path] = true
	} else {
		b.StaticJSONSecrets[secret.Path] = true
	}
}
