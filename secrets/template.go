package secrets

import (
	"fmt"
	"os"
	"text/template"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	zlog "github.com/rs/zerolog/log"
)

func WriteTemplate(tpl config.TemplateType, templates map[string]*template.Template, cache briefcase.SecretsCache) error {

	log := zlog.With().Str("output", tpl.Output).Logger()

	tplVars := make(map[string]interface{})

	for _, s := range cache.GetSecrets(util.LifetimeStatic) {
		tplVars[s.Key+"_"+s.Field] = s.Value
	}

	if tpl.Lifetime == util.LifetimeToken {
		for _, s := range cache.GetSecrets(util.LifetimeToken) {
			key := s.Key + "_" + s.Field
			if _, dupe := tplVars[key]; dupe {
				log.Warn().Str("key", key).Msg("overwriting static secret key with a value from a token-scoped secret")
			}
			tplVars[key] = s.Value
		}
	}

	if len(tplVars) == 0 {
		log.Warn().Msg("no template variables found. this can be because your secrets are missing and missingOk=true, or if lifetimes of your secrets and template aren't right")
	}

	mode, err := util.StringToFileMode(tpl.Mode)
	if err != nil {
		return fmt.Errorf("could not parse file mode %q for template %q: %w", tpl.Mode, tpl.Input, err)
	}

	log.Info().Str("input", tpl.Input).Msg("resolving template")

	util.MustMkdirAllForFile(tpl.Output)

	file, err := os.OpenFile(tpl.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
	if err != nil {
		return err
	}

	if err := templates[tpl.Input].Option("missingkey=error").Execute(file, tplVars); err != nil {
		return fmt.Errorf("failed to write template %q: %w", tpl.Output, err)
	}

	_ = file.Close()

	log.Debug().Msg("done executing template")

	return nil
}
