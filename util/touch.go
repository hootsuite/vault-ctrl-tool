package util

import (
	"os"
	"time"
)

func TouchFile(absFilename string) error {
	_, err := os.Stat(absFilename)
	if os.IsNotExist(err) {
		file, err := os.Create(absFilename)

		if err != nil {
			return err
		}
		defer file.Close()
	} else {
		currentTime := time.Now().Local()
		err = os.Chtimes(absFilename, currentTime, currentTime)
		if err != nil {
			return err
		}
	}
	return nil
}
