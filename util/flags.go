package util

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
)

// CliFlags contains all flags for the vault-ctrl-tool application.
// v1 of vault-ctrl-tool had some bad ideas about parsing command line arguments. This is kept for compatibility.
type CliFlags struct {
	ShowVersion             bool          // Display version and exit
	PerformInit             bool          // run in "init" mode
	PerformSidecar          bool          // run in "sidecar" mode
	PerformOneShot          bool          // even though running in sidecar mode, only run things once and then exit.
	PerformCleanup          bool          // cleanup everything in the leases file
	RevokeOnCleanup         bool          // also revoke everything when cleaning up
	RenewInterval           time.Duration // when in sidecar mode, this is the expected period between checks
	BriefcaseFilename       string        // absolute location of briefcase
	ShutdownTriggerFile     string        // if this file exists, the sidecar will shutdown
	VaultTokenArg           string        // v-c-t will accept a vault token as a command line arg
	EC2AuthEnabled          bool          // use "registered AMI" to authenticate an EC2 instance
	EC2Nonce                string        // Nonce used for re-authenticating EC2 instances
	IAMAuthRole             string        // Role to use when performing IAM authentication of EC2 instances
	IAMVaultAuthBackend     string        // Override IAM auth path in Vault
	ConfigFile              string        // location of vault-config, either relative to input prefix, or absolute
	OutputPrefix            string        // prefix to use when writing output files
	InputPrefix             string        // prefix to use when looking for input files
	ServiceSecretPrefix     string        // override prefix for relative KV secrets
	KubernetesLoginPath     string        // path to use in Vault for Kubernetes authentication
	ServiceAccountToken     string        // path to the ServiceAccount token file for Kubernetes authentication
	KubernetesAuthRole      string        // enables Kubernetes auth, and sets role to use with Kubernetes authentication
	DebugLogLevel           bool          // enable debug logging
	CliVaultTokenRenewable  bool          // is the vault token supplied on the command line renewable?
	ForceRefreshTTL         time.Duration // secrets will be refreshed after this duration, regardless of their expiry.
	STSTTL                  time.Duration // configures what TTL to use for AWS STS tokens.
	EnablePrometheusMetrics bool          // configures whether to enable prometheus metrics server for sidecar mode.
	PrometheusPort          int           // configures port on which to serve prometheus metrics endpoint
	VaultClientTimeout      time.Duration // configures HTTP timeouts for Vault client connections.
	VaultClientRetries      int           // configures HTTP retries for Vault client connections.
	TerminateOnSyncFailure  bool          // If enabled in sidecar mode, will cause tool to terminate if there is a failure to perform sync.
}

type RunMode int

const (
	ModeShowVersion RunMode = iota
	ModeInit
	ModeSidecar
	ModeOneShotSidecar
	ModeCleanup
	ModeUnknown
)

type AuthMechanismType int

const (
	EC2AMIAuth AuthMechanismType = iota
	EC2IAMAuth
	KubernetesAuth
	UnknownAuth
)

func (f *CliFlags) AuthMechanism() AuthMechanismType {
	if f.KubernetesAuthRole != "" {
		return KubernetesAuth
	}

	if f.EC2AuthEnabled {
		return EC2AMIAuth
	}

	if f.IAMAuthRole != "" {
		return EC2IAMAuth
	}

	return UnknownAuth
}

func (f *CliFlags) RunMode() RunMode {
	if f.ShowVersion {
		return ModeShowVersion
	}

	if f.PerformInit {
		return ModeInit
	}

	if f.PerformSidecar {
		if f.PerformOneShot {
			return ModeOneShotSidecar
		}
		return ModeSidecar
	}

	if f.PerformCleanup {
		return ModeCleanup
	}
	return ModeUnknown
}

func ProcessFlags(args []string) (*CliFlags, error) {
	var flags CliFlags

	app := kingpin.New("vault-ctrl-tool", "A handy tool for interacting with HashiCorp Vault")

	app.Flag("init", "Run in init mode, process templates and exit.").Default("false").BoolVar(&flags.PerformInit)
	app.Flag("config", "Full path of the config file to read.").Default("vault-config.yml").StringVar(&flags.ConfigFile)
	app.Flag("output-prefix", "Path to prefix to all output files (such as /etc/secrets)").StringVar(&flags.OutputPrefix)
	app.Flag("input-prefix", "Path to prefix on all files being read; including the config file.").StringVar(&flags.InputPrefix)
	app.Flag("secret-prefix", "Vault path to prepend to secrets with relative paths").StringVar(&flags.ServiceSecretPrefix)

	app.Flag("renew-interval", "Interval to renew credentials").Default("9m").DurationVar(&flags.RenewInterval)
	app.Flag("leases-file", "Full path to briefcase file.").Default("/tmp/vault-leases/vault-ctrl-tool.leases").StringVar(&flags.BriefcaseFilename)
	app.Flag("shutdown-trigger-file", "When running as a daemon, the presence of this file will cause the daemon to stop").StringVar(&flags.ShutdownTriggerFile)
	app.Flag("one-shot", "Combined with --sidecar, will perform one iteration of work and exit. For crontabs, etc.").Default("false").BoolVar(&flags.PerformOneShot)

	app.Flag("cleanup", "Using the leases file, erase any created output files.").Default("false").BoolVar(&flags.PerformCleanup)
	app.Flag("revoke", "During --cleanup, revoke the Vault authentication token.").Default("false").BoolVar(&flags.RevokeOnCleanup)

	// Sidecar options
	app.Flag("sidecar", "Run in side-car mode, refreshing leases as needed.").Default("false").BoolVar(&flags.PerformSidecar)
	app.Flag("renew-lease-duration", "unused, kept for compatibility").Default("1h").Duration()
	app.Flag("vault-token", "Vault token to use during initialization; overrides VAULT_TOKEN environment variable").StringVar(&flags.VaultTokenArg)
	app.Flag("token-renewable", "Is the token supplied on the command line renewable?").Default("true").BoolVar(&flags.CliVaultTokenRenewable)
	app.Flag("force-refresh-ttl", "If set, secrets will be refreshed after this period regardless of whether they are set to expire (just uses tokenn TTL if zero)").Default("0s").DurationVar(&flags.ForceRefreshTTL)

	// Kubernetes Authentication
	app.Flag("k8s-token-file", "Service account token path").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").StringVar(&flags.ServiceAccountToken)
	app.Flag("k8s-login-path", "Vault path to authenticate against").Default(os.Getenv("K8S_LOGIN_PATH")).StringVar(&flags.KubernetesLoginPath)
	app.Flag("k8s-auth-role", "Kubernetes authentication role").StringVar(&flags.KubernetesAuthRole)

	// EC2 Authentication
	app.Flag("ec2-auth", "Use EC2 metadata to authenticate to Vault").Default("false").BoolVar(&flags.EC2AuthEnabled)
	app.Flag("ec2-vault-nonce", "Nonce to use if re-authenticating.").Default("").StringVar(&flags.EC2Nonce)

	// IAM Authentication
	app.Flag("iam-auth-role", "The role used to perform iam authentication").Default("").StringVar(&flags.IAMAuthRole)
	app.Flag("iam-vault-auth-backend", "The name of the auth backend in Vault to perform iam authentication against. Defaults to `aws`.").Default("aws").StringVar(&flags.IAMVaultAuthBackend)

	// STS Authentication
	app.Flag("sts-ttl", "The TTL to use for generating AWS STS tokens, if set to zero then will not override TTL. Defaults to 0").Default("0s").DurationVar(&flags.STSTTL)

	// Show version
	app.Flag("version", "Display build version").Default("false").BoolVar(&flags.ShowVersion)

	// Shared options
	app.Flag("debug", "Log at debug level").Default("false").BoolVar(&flags.DebugLogLevel)

	// Flags for smoothing out edge cases.
	app.Flag("ignore-non-renewable-auth", "ignored; kept for compatibility").Default("false").Bool()
	app.Flag("never-scrub", "ignored; kept for compatibility").Default("false").Bool()

	// Metrics options
	app.Flag("enable-prometheus-metrics", "enables prometheus metrics to be served on prometheus-metrics port").Default("true").BoolVar(&flags.EnablePrometheusMetrics)
	app.Flag("prometheus-port", "specifies prometheus metrics port").Default("9191").IntVar(&flags.PrometheusPort)

	// Vault client options
	app.Flag("vault-client-timeout", "timeout duration for vault client HTTP timeouts").Default("30s").DurationVar(&flags.VaultClientTimeout)
	app.Flag("vault-client-retries", "number of retries to be performed for vault client operations").Default("2").IntVar(&flags.VaultClientRetries)

	// Sidecar mode options
	app.Flag("terminate-on-sync-failure", "if enabled in sidecar mode, will cause tool to terminate if there is a failure to perform sync").Default("true").BoolVar(&flags.TerminateOnSyncFailure)

	_, err := app.Parse(args)
	if err != nil {
		return nil, fmt.Errorf("could not parse arguments: %w", err)
	}

	if flags.EC2AuthEnabled && flags.IAMAuthRole != "" {
		return nil, errors.New("specify exactly one of --ec2-auth or --iam-auth-role")
	}

	actions := 0
	if flags.PerformInit {
		actions++

		if flags.PerformOneShot {
			return nil, errors.New("the --one-shot flag can only be used in --sidecar mode")
		}
	}

	if flags.PerformSidecar {
		actions++
	}

	if flags.ShowVersion {
		actions++
	}

	if flags.PerformCleanup {
		actions++
		if flags.PerformOneShot {
			return nil, errors.New("the --one-shot flag can only be used in --sidecar mode")
		}
	}

	if actions != 1 {
		return nil, errors.New("specify exactly one of --init, --sidecar, --version  or --cleanup flags")
	}

	return &flags, nil
}
