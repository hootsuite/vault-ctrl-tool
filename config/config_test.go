package config

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestEmptyFile(t *testing.T) {

	filename := mkConfig(t, "")
	defer os.Remove(filename)

	cfg, err := ReadConfig(filename, "", "")

	if err != nil {
		t.Fatalf("empty files must be ok, got error: %v", err)
	}

	if !cfg.VaultConfig.isEmpty() {
		t.Fatalf("empty files must be considered empty by isEmpty")
	}
}

func TestEmptyV2(t *testing.T) {

	filename := mkConfig(t, `---
version: 2`)
	defer os.Remove(filename)

	cfg, err := ReadConfig(filename, "", "")

	if err != nil {
		t.Fatalf("empty files must be ok, got error: %v", err)
	}

	if !cfg.VaultConfig.isEmpty() {
		t.Fatalf("empty files must be considered empty by isEmpty")
	}

}

func mkConfig(t *testing.T, body string) string {

	f, err := ioutil.TempFile("", "config_test_*")

	if err != nil {
		t.Fatalf("could not make temp file: %v", err)
	}

	var filename = f.Name()

	if _, err := f.WriteString(body); err != nil {
		t.Fatalf("could not write to temp file: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("could not close temp file: %v", err)
	}

	return filename
}
