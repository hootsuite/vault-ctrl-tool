package main

import (
	"context"
	"fmt"
	"github.com/hootsuite/vault-ctrl-tool/v2/metrics"
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

	mtrics := metrics.NewMetrics()
	lockHandle, err := util.LockFile(flags.BriefcaseFilename + ".lck")
	if err != nil {
		zlog.Error().Err(err).Msg("could not create exclusive flock")
		return err
	}
	defer lockHandle.Unlock(false)

	zlog.Debug().Str("briefcase", flags.BriefcaseFilename).Str("buildVersion", buildVersion).Msg("starting oneshot")
	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename, mtrics)
	if err != nil {
		zlog.Warn().Str("briefcase", flags.BriefcaseFilename).Err(err).Msg("could not load briefcase - starting an empty one")
		bc = briefcase.NewBriefcase(mtrics)
	}

	sync, err := syncer.SetupSyncer(flags, bc, mtrics)
	if err != nil {
		return err
	}

	return sync.PerformSync(ctx, clock.Now(ctx).Add(flags.RenewInterval*2), flags)
}

func PerformInit(ctx context.Context, flags util.CliFlags) error {

	zlog.Info().Str("buildVersion", buildVersion).Msg("starting")
	mtrics := metrics.NewMetrics()

	lockHandle, err := util.LockFile(flags.BriefcaseFilename + ".lck")
	if err != nil {
		zlog.Error().Err(err).Msg("could not create exclusive flock")
		return err
	}
	defer lockHandle.Unlock(false)

	if stat, err := os.Stat(flags.BriefcaseFilename); err == nil && stat != nil {
		zlog.Warn().Str("filename", flags.BriefcaseFilename).Msg("running in init mode, but briefcase file already exists")
		if flags.AuthMechanism() == util.KubernetesAuth {
			zlog.Warn().Msg("running in kuberenetes - performing oneshot sidecar instead of init")
			_ = lockHandle.Unlock(true)
			return PerformOneShotSidecar(ctx, flags)
		}
	}

	sync, err := syncer.SetupSyncer(flags, briefcase.NewBriefcase(mtrics), mtrics)

	if err != nil {
		return err
	}

	return sync.PerformSync(ctx, clock.Now(ctx).Add(24*time.Hour), flags)
}

func sidecarSync(ctx context.Context, mtrcs *metrics.Metrics, flags util.CliFlags, c chan os.Signal) {
	lockHandle, err := util.LockFile(flags.BriefcaseFilename + ".lck")
	if err != nil {
		zlog.Error().Err(err).Msg("could not create exclusive flock")
		c <- os.Interrupt
		return
	}
	defer lockHandle.Unlock(true)

	sync, err := makeSyncer(flags, mtrcs)
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

	mtrcs := metrics.NewMetrics()

	go func() {
		zlog.Info().Str("renewInterval", flags.RenewInterval.String()).Str("buildVersion", buildVersion).Msg("starting")

		sidecarSync(ctx, mtrcs, flags, c)

		renewTicker := time.NewTicker(flags.RenewInterval)
		defer renewTicker.Stop()

		jobCompletionTicker := time.NewTicker(ShutdownFileCheckFrequency)
		defer jobCompletionTicker.Stop()

		for {
			select {
			case <-renewTicker.C:
				zlog.Info().Msg("heartbeat")
				sidecarSync(ctx, mtrcs, flags, c)
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

	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename, nil)
	if err != nil {
		log.Warn().Err(err).Msg("could not open briefcase")
	} else {

		if flags.RevokeOnCleanup && bc.AuthTokenLease.Token != "" {
			vaultClient, err := vaultclient.NewVaultClient(flags.ServiceSecretPrefix)
			if err != nil {
				log.Error().Err(err).Msg("could not create new vault client to revoke token")
			} else {
				vaultClient.SetToken(bc.AuthTokenLease.Token)
				if err := vaultClient.Delegate().Auth().Token().RevokeSelf("ignored"); err != nil {
					log.Warn().Err(err).Msg("unable to revoke vault token")
				}
			}
		}

		if err := os.Remove(flags.BriefcaseFilename); err != nil {
			log.Warn().Err(err).Msg("could not remove briefcase")
		}
	}

	cfg, err := config.ReadConfigFile(flags.ConfigFile, flags.InputPrefix, flags.OutputPrefix)
	if err != nil {
		log.Warn().Msg("could not read config file - unsure what to cleanup")
		return fmt.Errorf("could not read config file %q: %w", flags.ConfigFile, err)
	}

	cfg.VaultConfig.Cleanup()

	log.Info().Msg("cleanup finished")

	return nil
}

func makeSyncer(flags util.CliFlags, mtrcs *metrics.Metrics) (*syncer.Syncer, error) {
	bc, err := briefcase.LoadBriefcase(flags.BriefcaseFilename, mtrcs)
	if err != nil {
		zlog.Warn().Str("briefcase", flags.BriefcaseFilename).Err(err).Msg("could not load briefcase - starting an empty one")
		bc = briefcase.NewBriefcase(mtrcs)
	}

	sync, err := syncer.SetupSyncer(flags, bc, mtrcs)
	if err != nil {
		return nil, err
	}

	return sync, nil
}
