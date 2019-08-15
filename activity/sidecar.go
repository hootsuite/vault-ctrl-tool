package activity

import (
	"context"
	"github.com/hashicorp/errwrap"
	"github.com/hootsuite/vault-ctrl-tool/aws"
	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/sshsigning"
	"github.com/hootsuite/vault-ctrl-tool/util"
	"github.com/hootsuite/vault-ctrl-tool/vaultclient"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/ssh"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func renewLeases(ctx context.Context, currentConfig cfg.Config, vaultClient vaultclient.VaultClient) {

	threshold := time.Now().Add(util.Flags.RenewInterval).Add(util.Flags.SafetyThreshold)
	jww.DEBUG.Printf("Will renew all credentials expiring before %v", threshold)

	jww.DEBUG.Printf("Auth token: expires? %v at %v", leases.Current.AuthTokenLease.CanExpire, leases.Current.AuthTokenLease.ExpiresAt)
	// Does our authentication token expire soon?
	if leases.Current.AuthTokenLease.CanExpire {
		if leases.Current.AuthTokenLease.ExpiresAt.Before(threshold) {

			err := vaultClient.RenewSelf(ctx, util.Flags.RenewLeaseDuration)

			if err != nil {
				jww.ERROR.Printf("error renewing authentication token: %v", err)
			}

			// If the error is a permission denied, then it will never be renewed, so we're hooped.
			if err == vaultclient.ErrPermissionDenied {
				scrubber.RemoveFiles()
				jww.FATAL.Fatalf("Authentication token could no longer be renewed.")
			}
		}
	}

	for _, awsLease := range leases.Current.AWSCredentialLeases {
		jww.DEBUG.Printf("AWS credential for %q expires at: %v", awsLease.AWSCredential.OutputPath, awsLease.Expiry)

		//If an AWS credential lease is going to expire, assume all of them are and rewrite all of them
		//All of our AWS credentials should have the same expiry, as STS expires them after an hour and
		//we wrote all of them at the same time in the init task
		if awsLease.Expiry.Before(threshold) {
			if err := aws.WriteCredentials(currentConfig, vaultClient.Delegate); err != nil {
				jww.FATAL.Fatalf("Could not write AWS credentials to replace expiring credentials: %v", err)
			}
			break
		}
	}

	for _, sshLease := range leases.Current.SSHCertificates {
		certificateFilename := filepath.Join(sshLease.OutputPath, sshsigning.SSHCertificate)
		validBefore, err := sshsigning.ReadCertificateValidBefore(certificateFilename)

		if err != nil {
			jww.ERROR.Printf("could not get expiry date for SSH certificate %q: %v", certificateFilename, err)
			continue
		}

		jww.DEBUG.Printf("SSH certificate %q is valid before %v", certificateFilename, validBefore)

		// If the cert expires before "threshold" o'clock, then we should renew it. If renewing
		// fails, then there are three outcomes. 1) fails because of permission denied, in which case we exit
		// 2) fails because of another reason, but is still not expired (in which case we log, but keep going), or
		// 3) fails because of another reason, but the ssh certificate is now invalid, in which case we exit.
		if validBefore != uint64(ssh.CertTimeInfinity) && validBefore < uint64(threshold.Unix()) {
			err := sshsigning.SignKey(vaultClient.Delegate, sshLease.OutputPath, sshLease.VaultMount, sshLease.VaultRole)

			if errwrap.Contains(err, "Code: 403") {
				jww.FATAL.Fatalf("Permission denied renewing SSH certificate %q.", certificateFilename)
			} else {
				if validBefore < uint64(time.Now().Unix()) {
					jww.FATAL.Fatalf("Could not renew SSH lease for %q and it has expired: %v", certificateFilename, err)
				}
				jww.ERROR.Printf("Error renewing SSH lease for %q: %v", certificateFilename, err)
			}
		}
	}
}

func performPeriodicSidecar(ctx context.Context, currentConfig cfg.Config, vaultClient vaultclient.VaultClient) {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {

		jww.DEBUG.Printf("Performing auto renewal check on startup.")

		renewLeases(ctx, currentConfig, vaultClient)

		renewTicks := time.Tick(util.Flags.RenewInterval)

		jobCompletionTicks := time.Tick(18 * time.Second)

		var checkKubeAPITicks <-chan time.Time

		jww.INFO.Printf("Lease renewal interval %v, completion check 10s", util.Flags.RenewInterval)
		for {
			select {
			case <-ctx.Done():
				jww.INFO.Printf("stopping renewal")
				return
			case <-renewTicks:
				jww.INFO.Printf("Renewal Heartbeat")
				renewLeases(ctx, currentConfig, vaultClient)
			case <-checkKubeAPITicks:
				// @TODO
				jww.INFO.Printf("Performing live check again Kubernetes API")
				// call API to get status
				var status string
				var err error

				status = "Running"
				err = nil

				if err != nil {
					jww.ERROR.Printf("error getting pod status: %s", err)
				}
				if status == "Error" {
					jww.FATAL.Fatalf("primary container has errored, shutting down")
				}
				if status == "Completed" {
					jww.INFO.Printf("received completion signal")
					c <- os.Interrupt
				}
			case <-jobCompletionTicks:
				if util.Flags.ShutdownTriggerFile != "" {
					jww.INFO.Printf("Performing completion check against %q", util.Flags.ShutdownTriggerFile)
					if _, err := os.Stat(util.Flags.ShutdownTriggerFile); err == nil {
						jww.INFO.Printf("Completion file %q present. Exiting", util.Flags.ShutdownTriggerFile)
						c <- os.Interrupt
					}
				}
			}
		}
	}()

	<-c
	jww.INFO.Printf("Shutting down.")
}

func PerformSidecar(currentConfig cfg.Config, serviceAccountToken, serviceSecretPrefix, k8sLoginPath, k8sAuthRole *string) {

	if currentConfig.IsEmpty() {
		if util.Flags.PerformOneShot {
			return
		} else {
			EmptySidecar()
			return
		}
	}

	leases.ReadFile()

	if len(leases.Current.ManagedFiles) > 0 {
		scrubber.AddFile(leases.Current.ManagedFiles...)
	}

	vaultClient := vaultclient.NewVaultClient(serviceAccountToken,
		calculateSecretPrefix(currentConfig, serviceSecretPrefix),
		k8sLoginPath,
		k8sAuthRole)

	err := vaultClient.Authenticate()

	if err != nil {
		jww.FATAL.Fatalf("Failed to authenticate to Vault: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	if util.Flags.PerformOneShot {
		renewLeases(ctx, currentConfig, vaultClient)
		// If the one shot didn't fatal, then it worked, so don't scrub anything on exit.
		scrubber.DisableExitScrubber()
	} else {
		defer vaultClient.RevokeSelf()
		performPeriodicSidecar(ctx, currentConfig, vaultClient)
		cancel()
	}
}

func EmptySidecar() {

	jww.INFO.Print("There are not secrets in Vault to maintain. Sidecar idle.")
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-ctx.Done():
				jww.INFO.Printf("stopping renewal")
				return
			}
		}
	}()

	<-c

	jww.INFO.Printf("Shutting down.")

	cancel()

}
