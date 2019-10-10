package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	"os"

	"github.com/hootsuite/vault-ctrl-tool/vaultclient"

	"github.com/hootsuite/vault-ctrl-tool/activity"
	"github.com/hootsuite/vault-ctrl-tool/cfg"
	"github.com/hootsuite/vault-ctrl-tool/leases"
	"github.com/hootsuite/vault-ctrl-tool/scrubber"
	"github.com/hootsuite/vault-ctrl-tool/util"
	jww "github.com/spf13/jwalterweatherman"
)

var (
	// Mode flags
	sidecarFlag = kingpin.Flag("sidecar", "Run in side-car mode, refreshing leases as needed.").Default("false").Bool()

	// Init options
	configFile          = kingpin.Flag("config", "Full path of the config file to read.").Default("vault-config.yml").String()
	outputPrefix        = kingpin.Flag("output-prefix", "Path to prefix to all output files (such as /etc/secrets)").String()
	inputPrefix         = kingpin.Flag("input-prefix", "Path to prefix on all files being read; including the config file.").String()
	serviceSecretPrefix = kingpin.Flag("secret-prefix", "Vault path to prepend to secrets with relative paths").String()

	// Kubernetes authentication
	serviceAccountToken = kingpin.Flag("k8s-token-file", "Service account token path").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").String()
	k8sLoginPath        = kingpin.Flag("k8s-login-path", "Vault path to authenticate against").Default(os.Getenv("K8S_LOGIN_PATH")).String()
	k8sAuthRole         = kingpin.Flag("k8s-auth-role", "Kubernetes authentication role").String()

	// Shared options
	debug = kingpin.Flag("debug", "Log at debug level").Default("false").Bool()

	// Flags for smoothing out edge cases.
	ignoreNonRenewableAuth = kingpin.Flag("ignore-non-renewable-auth", "Do not fail fatally if the authentication token has a limited life but is not renewable").Default("false").Bool()
	neverScrub             = kingpin.Flag("never-scrub", "Don't delete outputted files if the tool fails").Default("false").Bool()
)

func checkArgs() {
	actions := 0
	if util.Flags.PerformInit {
		actions++

		if util.Flags.PerformOneShot {
			jww.FATAL.Fatalf("The --one-shot flag can only be used in --sidecar mode.")
		}
	}

	if *sidecarFlag {
		actions++
	}

	if util.Flags.PerformCleanup {
		actions++
		if util.Flags.PerformOneShot {
			jww.FATAL.Fatalf("The --one-shot flag can only be used in --sidecar mode.")
		}
	}

	if actions != 1 {
		jww.FATAL.Fatalf("Specify exactly one of --init, --sidecar, or --cleanup flags.")
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

func processArgs() {
	kingpin.Flag("init", "Run in init mode, process templates and exit.").Default("false").BoolVar(&util.Flags.PerformInit)
	kingpin.Flag("renew-interval", "Interval to renew credentials").Default("20m").DurationVar(&util.Flags.RenewInterval)
	kingpin.Flag("leases-file", "Full path to file to write with leases.").Default("/tmp/vault-leases/vault-ctrl-tool.leases").StringVar(&util.Flags.LeasesFile)
	kingpin.Flag("shutdown-trigger-file", "When running as a daemon, the presence of this file will cause the daemon to stop").StringVar(&util.Flags.ShutdownTriggerFile)
	kingpin.Flag("one-shot", "Combined with --sidecar, will perform one iteration of work and exit. For crontabs, etc.").Default("false").BoolVar(&util.Flags.PerformOneShot)

	kingpin.Flag("cleanup", "Using the leases file, erase any created output files.").Default("false").BoolVar(&util.Flags.PerformCleanup)
	kingpin.Flag("revoke", "During --cleanup, revoke the Vault authentication token.").Default("false").BoolVar(&util.Flags.RevokeOnCleanup)

	// Sidecar options
	kingpin.Flag("renew-safety-threshold", "Proactively renew leases expiring before the next interval, minus this value.").Default("8m").DurationVar(&util.Flags.SafetyThreshold)
	kingpin.Flag("renew-lease-duration", "How long to request leases to be renewed for").Default("1h").DurationVar(&util.Flags.RenewLeaseDuration)
	kingpin.Flag("vault-token", "Vault token to use during initialization; overrides VAULT_TOKEN environment variable").StringVar(&util.Flags.VaultTokenArg)

	// EC2 Authentication
	kingpin.Flag("ec2-auth", "Use EC2 metadata to authenticate to Vault").Default("false").BoolVar(&util.Flags.EC2AuthEnabled)
	kingpin.Flag("ec2-auth-role", "Override the rolename used to authenticate to Vault.").StringVar(&util.Flags.EC2AuthRole)
	kingpin.Flag("ec2-login-path", "Vault path to authenticate against").Default(util.VaultEC2AuthPath).StringVar(&util.Flags.EC2VaultAuthPath)
	kingpin.Flag("ec2-vault-nonce", "Nonce to use if re-authenticating.").Default("").StringVar(&util.Flags.EC2VaultNonce)

	kingpin.Parse()

	checkArgs()
}

func main() {

	processArgs()

	util.SetPrefixes(inputPrefix, outputPrefix)
	leases.SetIgnoreNonRenewableAuth(ignoreNonRenewableAuth)

	setupLogging()

	jww.INFO.Printf("Tool Starting.")

	if util.Flags.PerformCleanup {
		activity.PerformCleanup(util.Flags.RevokeOnCleanup)
		return
	}

	currentConfig, err := cfg.ParseFile(configFile)

	if err != nil {
		jww.FATAL.Fatalf("Could not read config file %s: %v", *configFile, err)
	}

	vaultClient := vaultclient.NewVaultClient(serviceAccountToken,
		cfg.CalculateSecretPrefix(*currentConfig, serviceSecretPrefix),
		k8sLoginPath,
		k8sAuthRole)

	// Exit scrubber deletes files the tool created in the event of it being aborted or
	// if something goes wrong. The defer (below) takes care of the normal exit, and the setup
	// (above) takes care of exits by signal handling.
	if *neverScrub {
		jww.DEBUG.Print("User requested disabling file scrubber.")
		scrubber.DisableExitScrubber()
	}

	defer scrubber.RunExitScrubber()
	scrubber.SetupExitScrubber()

	if util.Flags.PerformInit {

		activity.PerformInitTasks(*currentConfig, vaultClient)

	} else if *sidecarFlag {

		if currentConfig.IsEmpty() {
			activity.EmptySidecar()
		} else {
			activity.PerformSidecar(*currentConfig, vaultClient)
		}

	}

	jww.INFO.Printf("Tool Finished.")

}
