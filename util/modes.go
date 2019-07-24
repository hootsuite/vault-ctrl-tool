package util

import (
	"os"
	"strconv"
)

func StringToFileMode(fileMode string) (*os.FileMode, error) {
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
