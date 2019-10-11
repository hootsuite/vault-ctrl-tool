package util

import (
	"os"
	"testing"
)

func TestStringToFileMode(t *testing.T) {

	if mode, e := StringToFileMode(""); mode == nil || *mode != os.FileMode(0400) || e != nil {
		t.Errorf("Empty file mode must default to 0400, not %v.", *mode)
	}

	if mode, e := StringToFileMode("777"); mode == nil || *mode != os.FileMode(0777) || e != nil {
		t.Errorf("Mode 777 should yield a filemode of 0777, not %v.", *mode)
	}

	if mode, e := StringToFileMode("a=rwx"); mode != nil || e == nil {
		t.Error("Symbolic mode is not supported.")
	}
}
