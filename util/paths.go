package util

import (
	"os"
	"path"
	"path/filepath"

	jww "github.com/spf13/jwalterweatherman"
)

var outputPrefix, inputPrefix string

func SetPrefixes(in, out *string) {
	if in != nil {
		inputPrefix = *in
	} else {
		inputPrefix = ""
	}

	if out != nil {
		outputPrefix = *out
	} else {
		outputPrefix = ""
	}
}

func AbsoluteOutputPath(filename string) string {
	var outPath string

	if path.IsAbs(filename) {
		// .Abs calls Clean, so even though this is absolute, we still run it through .Abs to
		// remove multiple slashes, ..'s, etc.
		outPath = filename
	} else {
		if outputPrefix != "" {
			outPath = path.Join(outputPrefix, filename)
		} else {
			outPath = filename
		}
	}

	abs, err := filepath.Abs(outPath)
	if err != nil {
		jww.FATAL.Fatalf("Could not determine absolute output path of %q", outPath)
	}

	return abs

}

func AbsoluteInputPath(filename string) string {
	var outPath string

	if path.IsAbs(filename) {
		// .Abs calls Clean, so even though this is absolute, we still run it through .Abs to
		// remove multiple slashes, ..'s, etc.
		outPath = filename
	} else {
		if inputPrefix != "" {
			outPath = path.Join(inputPrefix, filename)
		} else {
			outPath = filename
		}
	}

	abs, err := filepath.Abs(outPath)
	if err != nil {
		jww.FATAL.Fatalf("Could not determine absolute input path of %q", outPath)
	}

	return abs

}

func MakeDirsForFile(filename string) {
	err := os.MkdirAll(filepath.Dir(filename), os.ModePerm)
	if err != nil {
		jww.FATAL.Fatalf("Failed to create all needed directories for file %q: %v", filename, err)
	}
}
