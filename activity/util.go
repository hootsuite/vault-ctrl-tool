package activity

import (
	"fmt"
	"os"
	"text/template"

	"github.com/hootsuite/vault-ctrl-tool/kv"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

var templates = make(map[string]*template.Template)

func ingestTemplates(currentConfig cfg.Config) error {

	jww.DEBUG.Printf("Templates to ingest: %d", len(currentConfig.Templates))

	for _, tpl := range currentConfig.Templates {

		jww.DEBUG.Printf("Ingesting template: %q", tpl.Input)

		t, err := template.ParseFiles(tpl.Input)

		if err != nil {
			return fmt.Errorf("error parsing template %q: %w", tpl.Input, err)
		}
		templates[tpl.Input] = t
	}
	return nil
}

func writeTemplates(currentConfig cfg.Config, kvSecrets []kv.SimpleSecret) error {

	tplVars := make(map[string]interface{})

	for _, s := range kvSecrets {
		tplVars[s.Key+"_"+s.Field] = s.Value
	}

	for _, tpl := range currentConfig.Templates {

		modeString := tpl.Mode

		var mode *os.FileMode

		mode, err := util.StringToFileMode(modeString)
		if err != nil {
			return fmt.Errorf("could not parse file mode %q for %q: %w", modeString, tpl.Output, err)
		}

		jww.INFO.Printf("Resolving template %q into %q", tpl.Input, tpl.Output)

		util.MakeDirsForFile(tpl.Output)
		file, err := os.OpenFile(tpl.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, *mode)
		if err != nil {
			return err
		}

		scrubber.AddFile(tpl.Output)

		jww.DEBUG.Printf("Executing template %q", tpl.Output)

		err = templates[tpl.Input].Option("missingkey=error").Execute(file, tplVars)

		if err != nil {
			return fmt.Errorf("failed to write template %q: %w", tpl.Output, err)
		}

		_ = file.Close()

		jww.DEBUG.Printf("Done executing template %q", tpl.Output)
	}
	return nil
}
