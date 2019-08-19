package activity

import (
	"fmt"
	"os"
	"text/template"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

var templates = make(map[string]*template.Template)

func calculateSecretPrefix(currentConfig cfg.Config, serviceSecretPrefix *string) string {

	if serviceSecretPrefix != nil {
		return *serviceSecretPrefix
	}

	if currentConfig.ConfigVersion < 2 {
		return util.SecretsServicePathV1
	} else {
		return util.SecretsServicePathV2
	}

}

func ingestTemplates(currentConfig cfg.Config) error {

	jww.DEBUG.Printf("Templates to ingest: %d", len(currentConfig.Templates))

	for _, tpl := range currentConfig.Templates {

		jww.DEBUG.Printf("Ingesting template: %q", tpl.Input)

		t, err := template.ParseFiles(tpl.Input)

		if err != nil {
			return errwrap.Wrapf(fmt.Sprintf("error parsing template %q: {{err}}", tpl.Input), err)
		}
		templates[tpl.Input] = t
	}
	return nil
}

func writeTemplates(currentConfig cfg.Config, kvSecrets map[string]api.Secret) error {

	tplVars := make(map[string]interface{})

	for key, secrets := range kvSecrets {
		for k, v := range secrets.Data {
			tplVars[key+"_"+k] = v
		}
	}

	for _, tpl := range currentConfig.Templates {

		modeString := tpl.Mode

		var mode *os.FileMode

		mode, err := util.StringToFileMode(modeString)
		if err != nil {
			return errwrap.Wrapf(fmt.Sprintf("could not parse file mode %q for %q: {{err}}", modeString, tpl.Output), err)
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
			return errwrap.Wrapf(fmt.Sprintf("failed to write template %q: {{err}}", tpl.Output), err)
		}

		_ = file.Close()

		jww.DEBUG.Printf("Done executing template %q", tpl.Output)
	}
	return nil
}
