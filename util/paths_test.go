package util

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestAbsoluteOutputPath(t *testing.T) {

	if runtime.GOOS == "windows" {
		fmt.Fprint(os.Stderr, "TestAbsoluteOutputPath needs to be fixed to run ")
	}

	outputPrefix = "/tmp/"

	if path := AbsoluteOutputPath("/foo"); path != "/tmp/foo" {
		t.Errorf("Multiple slashes should be removed, not: %v", path)
	}

	outputPrefix = "/tmp"

	if path := AbsoluteOutputPath("foo"); path != "/tmp/foo" {
		t.Errorf("Missing slashes should be added, not: %v", path)
	}

	outputPrefix = ""

	if path := AbsoluteOutputPath("/foo"); path != "/foo" {
		t.Errorf("When no output prefix is set, the current directory should be used, not: %v", path)
	}
}

func TestAbsoluteInputPath(t *testing.T) {

	if runtime.GOOS == "windows" {
		fmt.Fprint(os.Stderr, "TestAbsoluteInputPath needs to be fixed to run ")
	}

	inputPrefix = "/tmp/"

	if path := AbsoluteInputPath("/foo"); path != "/tmp/foo" {
		t.Errorf("Multiple slashes should be removed, not: %v", path)
	}

	inputPrefix = "/tmp"

	if path := AbsoluteInputPath("foo"); path != "/tmp/foo" {
		t.Errorf("Missing slashes should be added, not: %v", path)
	}

	inputPrefix = ""

	if path := AbsoluteInputPath("/foo"); path != "/foo" {
		t.Errorf("When no input prefix is set, the current directory should be used, not: %v", path)
	}
}
