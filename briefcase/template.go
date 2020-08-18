package briefcase

import (
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
)

func (b *Briefcase) ShouldRefreshTemplate(tmpl config.TemplateType) bool {
	var exists bool

	if tmpl.Lifetime == util.LifetimeToken {
		_, exists = b.TokenScopedTemplates[tmpl.Output]
	} else {
		_, exists = b.StaticTemplates[tmpl.Output]
	}

	return !exists
}

func (b *Briefcase) EnrollTemplate(tmpl config.TemplateType) {

	b.log.Info().Str("outputFile", tmpl.Output).Interface("lifetime", tmpl.Lifetime).Msg("enrolling template")

	if tmpl.Lifetime == util.LifetimeToken {
		b.TokenScopedTemplates[tmpl.Output] = true
	} else {
		b.StaticTemplates[tmpl.Output] = true
	}
}
