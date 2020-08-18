package config

import (
	"text/template"
)

// v1 of vault-ctrl-tool parsed templates on startup so that typos would be caught during initializing,
// we keep this behaviour.
func (cfg *VaultConfig) ingestTemplates() (map[string]*template.Template, error) {

	templates := make(map[string]*template.Template)

	for _, tpl := range cfg.Templates {
		cfg.log.Info().Str("input", tpl.Input).Msg("ingesting template")
		t, err := template.ParseFiles(tpl.Input)
		if err != nil {
			cfg.log.Error().Err(err).Str("input", tpl.Input).Msg("failed to parse template")
			return nil, err
		}
		templates[tpl.Input] = t
	}

	return templates, nil
}
