package briefcase

import (
	"fmt"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
)

func (b *Briefcase) ShouldRefreshSecret(secret config.SecretType) bool {
	var exists bool

	b.log.Debug().Interface("briefcase", b).Msg("current briefcase")

	switch secret.Lifetime {
	case util.LifetimeToken:
		_, exists = b.TokenScopedSecrets[secret.Path]
	case util.LifetimeStatic:
		_, exists = b.StaticScopedSecrets[secret.Path]
	default:
		panic(fmt.Sprintf("briefcase does not manage refresh of %q lifetime secrets", secret.Lifetime))
	}

	return !exists
}

func (b *Briefcase) EnrollSecret(secret config.SecretType) {
	b.log.Info().Str("vaultPath", secret.Path).Interface("lifetime", secret.Lifetime).Msg("enrolling secret")

	switch secret.Lifetime {
	case util.LifetimeToken:
		b.TokenScopedSecrets[secret.Path] = true
	case util.LifetimeStatic:
		b.StaticScopedSecrets[secret.Path] = true
	default:
		panic(fmt.Sprintf("lifetime of %q cannot be enrolled in briefcase", secret.Lifetime))
	}
}

func (b *Briefcase) ShouldRefreshComposite(composite config.CompositeSecretFile) bool {
	var exists bool

	switch composite.Lifetime {
	case util.LifetimeToken:
		_, exists = b.TokenScopedComposites[composite.Filename]
	case util.LifetimeStatic:
		_, exists = b.StaticScopedComposites[composite.Filename]
	default:
		panic(fmt.Sprintf("composites cannot have a lifetime of  %q cannot be enrolled in briefcase", composite.Lifetime))

	}

	return !exists
}

func (b *Briefcase) EnrollComposite(composite config.CompositeSecretFile) {
	b.log.Info().Str("filename", composite.Filename).Interface("lifetime", composite.Lifetime).Msg("enrolling composite secret")

	switch composite.Lifetime {
	case util.LifetimeToken:
		b.TokenScopedComposites[composite.Filename] = true
	case util.LifetimeStatic:
		b.StaticScopedComposites[composite.Filename] = true
	default:
		panic(fmt.Sprintf("enrolling composites of lifetime %q is not supported", composite.Lifetime))
	}

}
