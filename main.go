package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	buildVersion  string
	commitVersion string
)

func setupLogging(debug bool) {
	log.Logger = log.With().Caller().Logger()

	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("debug logging enabled")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	}
}

func main() {
	flags, err := util.ProcessFlags(os.Args[1:])
	if err != nil {
		panic(err)
	}

	setupLogging(flags.DebugLogLevel)

	log.Debug().Interface("flags", flags).Msg("cli flags")

	switch flags.RunMode() {
	case util.ModeShowVersion:
		fmt.Printf("Version: %s\n", buildVersion)
		fmt.Printf("Commit: %s\n", commitVersion)
	case util.ModeInit:
		if err := PerformInit(context.Background(), *flags); err != nil {
			panic(err)
		}
	case util.ModeSidecar:
		if err := PerformSidecar(context.Background(), *flags); err != nil {
			panic(err)
		}
	case util.ModeOneShotSidecar:
		if err := PerformOneShotSidecar(context.Background(), *flags); err != nil {
			panic(err)
		}
	case util.ModeCleanup:
		if err := PerformCleanup(*flags); err != nil {
			fmt.Printf("Cleanup failed: %s\n", err)
		}
	case util.ModeUnknown:
		panic("unknown run mode")
	}
}
