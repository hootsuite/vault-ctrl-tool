package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/v2/util/clock"

	"github.com/hootsuite/vault-ctrl-tool/v2/briefcase"
	"github.com/hootsuite/vault-ctrl-tool/v2/config"
	"github.com/hootsuite/vault-ctrl-tool/v2/syncer"
	"github.com/hootsuite/vault-ctrl-tool/v2/util"
	"github.com/hootsuite/vault-ctrl-tool/v2/vaultclient"
	zlog "github.com/rs/zerolog/log"
)

const ShutdownFileCheckFrequency = 18 * time.Second

func PerformOneShotSidecar(ctx context.Context, flags util.CliFlags) error {

	lockHandle, err := createLock(flags.BriefcaseFilename)
	if err != nil {
		zlog.Error().Err(err).Msg("could not create exclusive flock")
		return err
	}
	defer lockHandle.Unlock(false)

	zlog.Debug().Str("briefcase", flags.BriefcaseFilename).Str("buildVersion", buildVersion).Msg("starting oneshot")
	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename)
	if err != nil {
		zlog.Warn().Str("briefcase", flags.BriefcaseFilename).Err(err).Msg("could not load briefcase - starting an empty one")
		bc = briefcase.NewBriefcase()
	}

	sync, err := syncer.SetupSyncer(flags, bc)
	if err != nil {
		return err
	}

	return sync.PerformSync(ctx, clock.Now(ctx).Add(flags.RenewInterval*2), flags)
}

func PerformInit(ctx context.Context, flags util.CliFlags) error {

	zlog.Info().Str("buildVersion", buildVersion).Msg("starting")

	lockHandle, err := createLock(flags.BriefcaseFilename)
	if err != nil {
		zlog.Error().Err(err).Msg("could not create exclusive flock")
		return err
	}
	defer lockHandle.Unlock(false)

	if stat, err := os.Stat(flags.BriefcaseFilename); err == nil && stat != nil {
		zlog.Warn().Str("filename", flags.BriefcaseFilename).Msg("running in init mode, but briefcase file already exists")
		if flags.AuthMechanism() == util.KubernetesAuth {
			zlog.Warn().Msg("running in kuberenetes - performing oneshot sidecar instead of init")
			return PerformOneShotSidecar(ctx, flags)
		}
	}

	sync, err := syncer.SetupSyncer(flags, briefcase.NewBriefcase())

	if err != nil {
		return err
	}

	return sync.PerformSync(ctx, clock.Now(ctx).Add(24*time.Hour), flags)
}

func sidecarSync(ctx context.Context, flags util.CliFlags, c chan os.Signal) {
	lockHandle, err := createLock(flags.BriefcaseFilename)
	if err != nil {
		zlog.Error().Err(err).Msg("could not create exclusive flock")
		c <- os.Interrupt
		return
	}
	defer lockHandle.Unlock(true)

	sync, err := makeSyncer(flags)
	if err != nil {
		zlog.Error().Err(err).Msg("could not create syncer")
		c <- os.Interrupt
		return
	}

	if err := sync.PerformSync(ctx, clock.Now(ctx).Add(flags.RenewInterval*2), flags); err != nil {
		zlog.Error().Err(err).Msg("sync failed")
		c <- os.Interrupt
		return
	}
}

func PerformSidecar(ctx context.Context, flags util.CliFlags) error {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {
		zlog.Info().Str("renewInterval", flags.RenewInterval.String()).Str("buildVersion", buildVersion).Msg("starting")

		sidecarSync(ctx, flags, c)

		renewTicker := time.NewTicker(flags.RenewInterval)
		defer renewTicker.Stop()

		jobCompletionTicker := time.NewTicker(ShutdownFileCheckFrequency)
		defer jobCompletionTicker.Stop()

		for {
			select {
			case <-renewTicker.C:
				zlog.Info().Msg("heartbeat")
				sidecarSync(ctx, flags, c)
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
			vaultClient, err := vaultclient.NewVaultClient(flags.ServiceSecretPrefix)
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

func makeSyncer(flags util.CliFlags) (*syncer.Syncer, error) {
	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename)
	if err != nil {
		zlog.Warn().Str("briefcase", flags.BriefcaseFilename).Err(err).Msg("could not load briefcase - starting an empty one")
		bc = briefcase.NewBriefcase()
	}

	sync, err := syncer.SetupSyncer(flags, bc)
	if err != nil {
		return nil, err
	}

	return sync, nil
}

func createLock(briefcaseFilename string) (*util.LockHandle, error) {

	lockFilename := briefcaseFilename + ".lck"
	zlog.Debug().Str("lockfile", lockFilename).Msg("going to obtain exclusive flock")

	lockHandle, err := util.LockFile(lockFilename)
	if err != nil {
		return nil, err
	}
	zlog.Debug().Str("lockfile", lockFilename).Msg("obtained exclusive flock")

	return lockHandle, nil

}
