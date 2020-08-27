package briefcase

import (
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
)

func (b *Briefcase) ShouldRefreshSecret(secret config.SecretType) bool {
	var exists bool

	b.log.Debug().Interface("briefcase", b).Msg("current briefcase")
	if secret.Lifetime == util.LifetimeToken {
		_, exists = b.TokenScopedSecrets[secret.Path]
	} else {
		_, exists = b.StaticScopedSecrets[secret.Path]
	}

	return !exists
}

func (b *Briefcase) EnrollSecret(secret config.SecretType) {
	b.log.Info().Str("vaultPath", secret.Path).Interface("lifetime", secret.Lifetime).Msg("enrolling secret")

	if secret.Lifetime == util.LifetimeToken {
		b.TokenScopedSecrets[secret.Path] = true
	} else {
		b.StaticScopedSecrets[secret.Path] = true
	}
}

func (b *Briefcase) ShouldRefreshComposite(composite config.CompositeSecretFile) bool {
	var exists bool

	if composite.Lifetime == util.LifetimeToken {
		_, exists = b.TokenScopedComposites[composite.Filename]
	} else {
		_, exists = b.StaticScopedComposites[composite.Filename]
	}

	return !exists
}

func (b *Briefcase) EnrollComposite(composite config.CompositeSecretFile) {
	b.log.Info().Str("filename", composite.Filename).Interface("lifetime", composite.Lifetime).Msg("enrolling composite secret")

	if composite.Lifetime == util.LifetimeToken {
		b.TokenScopedComposites[composite.Filename] = true
	} else {
		b.StaticScopedComposites[composite.Filename] = true
	}

}
