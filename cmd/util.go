package main

import (
	"os"
	"path"
	"path/filepath"
	"strconv"

	jww "github.com/spf13/jwalterweatherman"
)

func stringToFileMode(fileMode string) (*os.FileMode, error) {
	var mode os.FileMode

	if fileMode == "" {
		mode = os.FileMode(0400)
	} else {

		i, err := strconv.ParseInt(fileMode, 8, 32)

		if err != nil {
			return nil, err
		}

		mode = os.FileMode(int32(i))
	}

	return &mode, nil
}

func setupLogging() {

	jww.SetStdoutOutput(os.Stderr)

	if *debug {
		jww.SetStdoutThreshold(jww.LevelDebug)
		jww.DEBUG.Print("Debug logging enabled.")
	} else {
		jww.SetStdoutThreshold(jww.LevelInfo)
	}
}

func absoluteOutputPath(filename string) string {
	var outPath string

	if *outputPrefix != "" {
		outPath = path.Join(*outputPrefix, filename)
	} else {
		outPath = filename
	}

	abs, err := filepath.Abs(outPath)
	if err != nil {
		jww.FATAL.Fatalf("Could not determine absolute output path of %q", outPath)
	}

	return abs

}

func absoluteInputPath(filename string) string {
	var outPath string

	if *inputPrefix != "" {
		outPath = path.Join(*inputPrefix, filename)
	} else {
		outPath = filename
	}

	abs, err := filepath.Abs(outPath)
	if err != nil {
		jww.FATAL.Fatalf("Could not determine absolute input path of %q", outPath)
	}

	return abs

}

func makeDirsForFile(filename string) {
	err := os.MkdirAll(filepath.Dir(filename), os.ModePerm)
	if err != nil {
		jww.FATAL.Fatalf("Failed to create all needed directories for file %q: %v", filename, err)
	}
}
