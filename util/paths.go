package util

import (
	"os"
	"path"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

func AbsolutePath(prefix string, filename string) string {
	var calcPath string

	if path.IsAbs(filename) {
		// .Abs calls Clean, so even though this is absolute, we still run it through .Abs to
		// remove multiple slashes, ..'s, etc.
		calcPath = filename
	} else {
		if prefix != "" {
			calcPath = path.Join(prefix, filename)
		} else {
			calcPath = filename
		}
	}

	abs, err := filepath.Abs(calcPath)
	if err != nil {
		log.Fatal().Err(err).Str("prefix", prefix).Str("calculatedPath", calcPath).Msg("could not determine absolute path")
	}

	return abs
}

func MustMkdirAllForFile(filename string) {
	err := os.MkdirAll(filepath.Dir(filename), os.ModePerm)
	if err != nil {
		log.Fatal().Str("filename", filename).Err(err).Msg("failed to create all needed directories")
	}
}

func MakeWritable(filename string) {
	stat, err := os.Stat(filename)
	if err == nil && stat != nil {
		if err := os.Chmod(filename, stat.Mode()|0222); err != nil {
			log.Warn().Str("filename", filename).Msg("could not chmod file to writable")
		}
	}
}
