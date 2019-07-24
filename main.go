package main

import (
	"context"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hootsuite/vault-ctrl-tool/aws"
	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/kv"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/sshsigning"
	"github.com/hootsuite/vault-ctrl-tool/util"
	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	jww "github.com/spf13/jwalterweatherman"
)

var (
	// Mode flags
	initFlag    = kingpin.Flag("init", "Run in init mode, process templates and exit.").Default("false").Bool()
	sidecarFlag = kingpin.Flag("sidecar", "Run in side-car mode, refreshing leases as needed.").Default("false").Bool()
	cleanupFlag = kingpin.Flag("cleanup", "Using the leases file, erase any created output files.").Default("false").Bool()

	// Init options
	configFile          = kingpin.Flag("config", "Full path of the config file to read.").Default("vault-config.yml").String()
	outputPrefix        = kingpin.Flag("output-prefix", "Path to prefix to all output files (such as /etc/secrets)").String()
	inputPrefix         = kingpin.Flag("input-prefix", "Path to prefix on all files being read; including the config file.").String()
	leasesFile          = kingpin.Flag("leases-file", "Full path to file to write with leases.").Default("/tmp/vault-leases/vault-ctrl-tool.leases").String()
	serviceSecretPrefix = kingpin.Flag("secret-prefix", "Vault path to prepend to secrets with relative paths").Default("/secret/application-config/services/").String()

	// Kubernetes authentication
	serviceAccountToken = kingpin.Flag("k8s-token-file", "Service account token path").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").String()
	k8sLoginPath        = kingpin.Flag("k8s-login-path", "Vault path to authenticate against").Default(os.Getenv("K8S_LOGIN_PATH")).String()
	k8sAuthRole         = kingpin.Flag("k8s-auth-role", "Kubernetes authentication role").String()

	// Sidecar options
	shutdownTriggerFile = kingpin.Flag("shutdown-trigger-file", "When running as a daemon, the presence of this file will cause the daemon to stop").String()
	renewInterval       = kingpin.Flag("renew-interval", "Interval to renew credentials").Default("20m").Duration()
	safetyThreshold     = kingpin.Flag("renew-safety-threshold", "Proactively renew leases expiring before the next interval, minus this value.").Default("8m").Duration()
	renewLeaseDuration  = kingpin.Flag("renew-lease-duration", "How long to request leases to be renewed for").Default("1h").Duration()

	// Shared options
	debug         = kingpin.Flag("debug", "Log at debug level").Default("false").Bool()
	vaultTokenArg = kingpin.Flag("vault-token", "Vault token to use during initialization; overrides VAULT_TOKEN environment variable").String()

	// Flags for smoothing out edge cases.
	ignoreNonRenewableAuth = kingpin.Flag("ignore-non-renewable-auth", "Do not fail fatally if the authentication token has a limited life but is not renewable").Default("false").Bool()
	neverScrub             = kingpin.Flag("never-scrub", "Don't delete outputted files if the tool fails").Default("false").Bool()
)

func renewLeases(ctx context.Context, client *api.Client) {

	threshold := time.Now().Add(*renewInterval).Add(*safetyThreshold)
	jww.DEBUG.Printf("Will renew all credentials expiring before %v", threshold)

	jww.DEBUG.Printf("Auth token: expires? %v at %v", leases.Current.AuthTokenLease.CanExpire, leases.Current.AuthTokenLease.ExpiresAt)
	// Does our authentication token expire soon?
	if leases.Current.AuthTokenLease.CanExpire {
		if leases.Current.AuthTokenLease.ExpiresAt.Before(threshold) {

			err := renewSelf(ctx, client, *renewLeaseDuration)

			if err != nil {
				jww.ERROR.Printf("error renewing authentication token: %v", err)
			}

			// If the error is a permission denied, then it will never be renewed, so we're hooped.
			if err == ErrPermissionDenied {
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
			if err := aws.WriteCredentials(client); err != nil {
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
			err := sshsigning.SignKey(client, sshLease.OutputPath, sshLease.VaultMount, sshLease.VaultRole)

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

func performCleanup() {
	jww.INFO.Print("Performing cleanup.")
	leases.ReadFile()

	if len(leases.Current.ManagedFiles) > 0 {
		scrubber.AddFile(leases.Current.ManagedFiles...)
	}

	scrubber.AddFile(*leasesFile)
	scrubber.RemoveFiles()
}

func emptySidecar() {

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

func performSidecar() {

	leases.ReadFile()

	if len(leases.Current.ManagedFiles) > 0 {
		scrubber.AddFile(leases.Current.ManagedFiles...)
	}

	client, _, err := authenticateToVault()

	defer revokeSelf(client)

	if err != nil {
		jww.FATAL.Fatalf("Failed to authenticate to Vault: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	go func() {

		jww.DEBUG.Printf("Performing auto renewal check on startup.")
		renewLeases(ctx, client)

		renewTicks := time.Tick(*renewInterval)

		jobCompletionTicks := time.Tick(18 * time.Second)

		var checkKubeAPITicks <-chan time.Time

		jww.INFO.Printf("Lease renewal interval %v, completion check 10s", *renewInterval)
		for {
			select {
			case <-ctx.Done():
				jww.INFO.Printf("stopping renewal")
				return
			case <-renewTicks:
				jww.INFO.Printf("Renewal Heartbeat")
				renewLeases(ctx, client)
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
				if *shutdownTriggerFile != "" {
					jww.INFO.Printf("Performing completion check against %q", *shutdownTriggerFile)
					if _, err := os.Stat(*shutdownTriggerFile); err == nil {
						jww.INFO.Printf("Completion file %q present. Exiting", *shutdownTriggerFile)
						c <- os.Interrupt
					}
				}
			}
		}
	}()

	<-c

	jww.INFO.Printf("Shutting down.")

	cancel()
}

func performInitTasks() {

	jww.DEBUG.Print("Performing init tasks.")
	cfg.ParseFile(configFile)

	if cfg.IsEmpty() {
		jww.INFO.Print("Configuration file is empty. Writing empty lease file and skipping authentication.")
		leases.WriteFile()
		scrubber.DisableExitScrubber()
		return
	}

	// Read templates first so we don't waste Vault's time if there's an issue.
	if err := ingestTemplates(); err != nil {
		jww.FATAL.Fatalf("Could not ingest templates: %v", err)
	}

	client, secret, err := authenticateToVault()
	if err != nil {
		jww.FATAL.Fatalf("Failed to log into Vault: %v", err)
	}

	token, err := secret.TokenID()
	if err != nil {
		jww.FATAL.Fatalf("Could not extract Vault Token: %v", err)
	}

	leases.EnrollAuthToken(secret)

	kvSecrets := readKVSecrets(client)

	// Output necessary files
	if err := writeVaultToken(token); err != nil {
		jww.FATAL.Fatalf("Could not write vault token: %v", err)
	}

	if err := kv.WriteOutput(kvSecrets); err != nil {
		jww.FATAL.Fatalf("Could not write KV secrets: %v", err)
	}

	if err := writeTemplates(kvSecrets); err != nil {
		jww.FATAL.Fatalf("Could not write templates: %v", err)
	}

	if err := aws.WriteCredentials(client); err != nil {
		jww.FATAL.Fatalf("Could not write AWS credentials: %v", err)
	}

	if err := sshsigning.WriteKeys(client); err != nil {
		jww.FATAL.Fatalf("Could not setup SSH certificate: %v", err)
	}

	scrubber.EnrollScrubFiles()

	leases.WriteFile()

	jww.DEBUG.Print("All initialization tasks completed.")
	scrubber.DisableExitScrubber()
}

func checkArgs() {
	actions := 0
	if *initFlag {
		actions++
	}

	if *sidecarFlag {
		actions++
	}

	if *cleanupFlag {
		actions++
	}

	if actions != 1 {
		jww.FATAL.Fatalf("Specify one of --init, --sidecar, or --cleanup flags.")
	}
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

func main() {

	kingpin.Parse()

	checkArgs()

	util.SetPrefixes(inputPrefix, outputPrefix)
	leases.SetLeasesFile(leasesFile)
	leases.SetIgnoreNonRenewableAuth(ignoreNonRenewableAuth)

	setupLogging()

	jww.INFO.Printf("Tool Starting.")

	if *cleanupFlag {
		performCleanup()
		return
	}

	// Exit scrubber deletes files the tool created in the event of it being aborted or
	// if something goes wrong. The defer (below) takes care of the normal exit, and the setup
	// (above) takes care of exits by signal handling.
	if *neverScrub {
		jww.DEBUG.Print("User requested disabling file scrubber.")
		scrubber.DisableExitScrubber()
	}

	defer scrubber.RunExitScrubber()
	scrubber.SetupExitScrubber()

	if *initFlag {
		performInitTasks()
	} else if *sidecarFlag {
		cfg.ParseFile(configFile)

		if cfg.IsEmpty() {
			emptySidecar()
		} else {
			performSidecar()
		}
	}

	jww.INFO.Printf("Tool Finished.")

}
