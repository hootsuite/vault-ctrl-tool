package main

import (
	"fmt"
	"os"
	"text/template"

	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

var templates = make(map[string]*template.Template)

func ingestTemplates() error {

	jww.DEBUG.Printf("Templates to ingest: %d", len(cfg.Current.Templates))

	for _, tpl := range cfg.Current.Templates {

		jww.DEBUG.Printf("Ingesting template: %q", tpl.Input)

		t, err := template.ParseFiles(tpl.Input)

		if err != nil {
			return errwrap.Wrapf(fmt.Sprintf("error parsing template %q: {{err}}", tpl.Input), err)
		}
		templates[tpl.Input] = t
	}
	return nil
}

func writeTemplates(kvSecrets map[string]api.Secret) error {

	tplVars := make(map[string]interface{})

	for key, secrets := range kvSecrets {
		for k, v := range secrets.Data {
			tplVars[key+"_"+k] = v
		}
	}

	for _, tpl := range cfg.Current.Templates {

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

		file.Close()

		jww.DEBUG.Printf("Done executing template %q", tpl.Output)
	}
	return nil
}
