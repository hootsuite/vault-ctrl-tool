package main

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestStringToFileMode(t *testing.T) {

	if mode, e := stringToFileMode(""); mode == nil || *mode != os.FileMode(0400) || e != nil {
		t.Errorf("Empty file mode must default to 0400, not %v.", *mode)
	}

	if mode, e := stringToFileMode("777"); mode == nil || *mode != os.FileMode(0777) || e != nil {
		t.Errorf("Mode 777 should yeild a filemode of 0777, not %v.", *mode)
	}

	if mode, e := stringToFileMode("a=rwx"); mode != nil || e == nil {
		t.Error("Symbolic mode is not supported.")
	}
}

func TestAbsoluteOutputPath(t *testing.T) {

	if runtime.GOOS == "windows" {
		fmt.Fprint(os.Stderr, "TestAbsoluteOutputPath needs to be fixed to run ")
	}

	*outputPrefix = "/tmp/"

	if path := absoluteOutputPath("/foo"); path != "/tmp/foo" {
		t.Errorf("Multiple slashes should be removed, not: %v", path)
	}

	*outputPrefix = "/tmp"

	if path := absoluteOutputPath("foo"); path != "/tmp/foo" {
		t.Errorf("Missing slashes should be added, not: %v", path)
	}

	*outputPrefix = ""

	if path := absoluteOutputPath("/foo"); path != "/foo" {
		t.Errorf("When no output prefix is set, the current directory should be used, not: %v", path)
	}
}


func TestAbsoluteInputPath(t *testing.T) {

	if runtime.GOOS == "windows" {
		fmt.Fprint(os.Stderr, "TestAbsoluteInputPath needs to be fixed to run ")
	}

	*inputPrefix = "/tmp/"

	if path := absoluteInputPath("/foo"); path != "/tmp/foo" {
		t.Errorf("Multiple slashes should be removed, not: %v", path)
	}

	*inputPrefix = "/tmp"

	if path := absoluteInputPath("foo"); path != "/tmp/foo" {
		t.Errorf("Missing slashes should be added, not: %v", path)
	}

	*inputPrefix = ""

	if path := absoluteInputPath("/foo"); path != "/foo" {
		t.Errorf("When no input prefix is set, the current directory should be used, not: %v", path)
	}
}
