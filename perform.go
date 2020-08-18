package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/syncer"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/vaultclient"
	zlog "github.com/rs/zerolog/log"
)

const ShutdownFileCheckFrequency = 18 * time.Second

func PerformOneShotSidecar(flags util.CliFlags) error {

	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename)
	if err != nil {
		zlog.Warn().Str("briefcase", flags.BriefcaseFilename).Err(err).Msg("could not load briefcase - starting an empty one")
		bc = briefcase.NewBriefcase()
	}

	sync, err := syncer.SetupSyncer(flags, bc)
	if err != nil {
		return err
	}

	return sync.PerformSync(time.Now().Add(flags.RenewInterval).Add(5*time.Minute), flags)
}

func PerformInit(flags util.CliFlags) error {
	sync, err := syncer.SetupSyncer(flags, briefcase.NewBriefcase())

	if err != nil {
		return err
	}

	return sync.PerformSync(time.Now().Add(24*time.Hour), flags)
}

func PerformSidecar(flags util.CliFlags) error {

	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename)
	if err != nil {
		zlog.Warn().Str("briefcase", flags.BriefcaseFilename).Err(err).Msg("could not load briefcase - starting an empty one")
		bc = briefcase.NewBriefcase()
	}

	sync, err := syncer.SetupSyncer(flags, bc)
	if err != nil {
		return err
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {
		zlog.Info().Str("renewInterval", flags.RenewInterval.String()).Msg("starting")

		if err := sync.PerformSync(time.Now().Add(flags.RenewInterval/2), flags); err != nil {
			zlog.Error().Err(err).Msg("initial sync failed")
		}

		renewTicker := time.NewTicker(flags.RenewInterval)
		defer renewTicker.Stop()

		jobCompletionTicker := time.NewTicker(ShutdownFileCheckFrequency)
		defer jobCompletionTicker.Stop()

		for {
			select {
			case <-renewTicker.C:
				zlog.Info().Msg("heartbeat")
				if err := sync.PerformSync(time.Now().Add(flags.RenewInterval/2), flags); err != nil {
					zlog.Error().Err(err).Msg("sync failed")
				}
			case <-jobCompletionTicker.C:
				if flags.ShutdownTriggerFile != "" {
					zlog.Debug().Str("triggerFile", flags.ShutdownTriggerFile).Msg("performing completion check against file")
					if _, err := os.Stat(flags.ShutdownTriggerFile); err == nil {
						zlog.Info().Str("triggerFile", flags.ShutdownTriggerFile).Msg("trigger file present; exiting")
						c <- os.Interrupt
					}
				}
			}
		}
	}()

	<-c
	zlog.Info().Msg("shutting down")
	return nil
}

func PerformCleanup(flags util.CliFlags) error {

	log := zlog.With().Str("configFile", flags.ConfigFile).Str("briefcase", flags.BriefcaseFilename).Logger()

	log.Info().Msg("performing cleanup")

	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename)
	if err != nil {
		log.Warn().Err(err).Msg("could not open briefcase")
	} else {

		if flags.RevokeOnCleanup && bc.AuthTokenLease.Token != "" {
			vaultClient, err := vaultclient.NewVaultClient()
			if err != nil {
				log.Error().Err(err).Msg("could not create new vault client to revoke token")
			} else {
				vaultClient.Delegate().SetToken(bc.AuthTokenLease.Token)
				if err := vaultClient.Delegate().Auth().Token().RevokeSelf("ignored"); err != nil {
					log.Warn().Err(err).Msg("unable to revoke vault token")
				}
			}
		}

		if err := os.Remove(flags.BriefcaseFilename); err != nil {
			log.Warn().Err(err).Msg("could not remove briefcase")
		}
	}

	cfg, err := config.ReadConfig(flags.ConfigFile, flags.InputPrefix, flags.OutputPrefix)
	if err != nil {
		log.Warn().Msg("could not read config file - unsure what to cleanup")
		return fmt.Errorf("could not read config file %q: %w", flags.ConfigFile, err)
	}

	cfg.VaultConfig.Cleanup()

	log.Info().Msg("cleanup finished")

	return nil
}
