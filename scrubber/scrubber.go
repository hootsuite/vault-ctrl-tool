package scrubber

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hootsuite/vault-ctrl-tool/leases"

	jww "github.com/spf13/jwalterweatherman"
)

// The tool will delete any files it created if something goes wrong. This is to prevent a service from reading some
// files where something went wrong.

var runScrubber = make(chan bool, 2)

var scrubFiles []string

func AddFile(filename ...string) {
	scrubFiles = append(scrubFiles, filename...)
}

func SetupExitScrubber() {
	jww.DEBUG.Printf("Setting up exit scrubber.")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		RunExitScrubber()
		os.Exit(0)
	}()
}

func EnrollScrubFiles() {
	leases.EnrollFiles(scrubFiles)
}

func RunExitScrubber() {

	jww.DEBUG.Print("Exit Scrubber called, checking if it should run.")
	select {
	case msg := <-runScrubber:
		if !msg {
			jww.DEBUG.Print("Scrubber does not need to kick in")
			return
		}
	default:
		// needed to make this async
	}

	RemoveFiles()
}

func RemoveFiles() {
	if len(scrubFiles) > 0 {
		jww.INFO.Print("Removing files created with secrets.")
		for _, filename := range scrubFiles {
			jww.DEBUG.Printf("Deleting %q", filename)
			err := os.Remove(filename)
			if err != nil {
				jww.WARN.Printf("Scrubber unable to remove file %q: %v", filename, err)
			}
		}
	} else {
		jww.DEBUG.Print("No files created to scrub.")
	}
}

func DisableExitScrubber() {
	jww.DEBUG.Print("Disabling file scrubber")
	runScrubber <- false
}
