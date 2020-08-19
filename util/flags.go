package util

import (
	"errors"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"time"
)

// v1 of vault-ctrl-tool had some bad ideas about parsing command line arguments. This is kept for compatibility.
type CliFlags struct {
	ShowVersion         bool          // Display version and exit
	PerformInit         bool          // run in "init" mode
	PerformSidecar      bool          // run in "sidecar" mode
	PerformOneShot      bool          // even though running in sidecar mode, only run things once and then exit.
	PerformCleanup      bool          // cleanup everything in the leases file
	RevokeOnCleanup     bool          // also revoke everything when cleaning up
	RenewInterval       time.Duration // when in sidecar mode, this is the expected period between checks
	BriefcaseFilename   string        // absolute location of briefcase
	ShutdownTriggerFile string        // if this file exists, the sidecar will shutdown
	VaultTokenArg       string        // v-c-t will accept a vault token as a command line arg
	EC2AuthEnabled      bool          // use "registered AMI" to authenticate an EC2 instance
	EC2Nonce            string        // Nonce used for re-authenticating EC2 instances
	IAMAuthRole         string        // Role to use when performing IAM authentication of EC2 instances
	IAMVaultAuthBackend string        // Override IAM auth path in Vault
	ConfigFile          string        // location of vault-config, either relative to input prefix, or absolute
	OutputPrefix        string        // prefix to use when writing output files
	InputPrefix         string        // prefix to use when looking for input files
	ServiceSecretPrefix string        // override prefix for relative KV secrets
	KubernetesLoginPath string        // path to use in Vault for Kubernetes authentication
	ServiceAccountToken string        // path to the ServiceAccount token file for Kubernetes authentication
	KubernetesAuthRole  string        // role to use with Kubernetes authentication
	DebugLogLevel       bool          // enable debug logging
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
		return EC2AMIAuth
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

func ProcessFlags() (*CliFlags, error) {
	var flags CliFlags

	kingpin.Flag("init", "Run in init mode, process templates and exit.").Default("false").BoolVar(&flags.PerformInit)
	kingpin.Flag("config", "Full path of the config file to read.").Default("vault-config.yml").StringVar(&flags.ConfigFile)
	kingpin.Flag("output-prefix", "Path to prefix to all output files (such as /etc/secrets)").StringVar(&flags.OutputPrefix)
	kingpin.Flag("input-prefix", "Path to prefix on all files being read; including the config file.").StringVar(&flags.InputPrefix)
	kingpin.Flag("secret-prefix", "Vault path to prepend to secrets with relative paths").StringVar(&flags.ServiceSecretPrefix)

	kingpin.Flag("renew-interval", "Interval to renew credentials").Default("9m").DurationVar(&flags.RenewInterval)
	kingpin.Flag("leases-file", "Full path to briefcase file.").Default("/tmp/vault-leases/vault-ctrl-tool.leases").StringVar(&flags.BriefcaseFilename)
	kingpin.Flag("shutdown-trigger-file", "When running as a daemon, the presence of this file will cause the daemon to stop").StringVar(&flags.ShutdownTriggerFile)
	kingpin.Flag("one-shot", "Combined with --sidecar, will perform one iteration of work and exit. For crontabs, etc.").Default("false").BoolVar(&flags.PerformOneShot)

	kingpin.Flag("cleanup", "Using the leases file, erase any created output files.").Default("false").BoolVar(&flags.PerformCleanup)
	kingpin.Flag("revoke", "During --cleanup, revoke the Vault authentication token.").Default("false").BoolVar(&flags.RevokeOnCleanup)

	// Sidecar options
	kingpin.Flag("sidecar", "Run in side-car mode, refreshing leases as needed.").Default("false").BoolVar(&flags.PerformSidecar)
	kingpin.Flag("renew-lease-duration", "unused, kept for compatibility").Default("1h").Duration()
	kingpin.Flag("vault-token", "Vault token to use during initialization; overrides VAULT_TOKEN environment variable").StringVar(&flags.VaultTokenArg)

	// Kubernetes Authentication
	kingpin.Flag("k8s-token-file", "Service account token path").Default("/var/run/secrets/kubernetes.io/serviceaccount/token").StringVar(&flags.ServiceAccountToken)
	kingpin.Flag("k8s-login-path", "Vault path to authenticate against").Default(os.Getenv("K8S_LOGIN_PATH")).StringVar(&flags.KubernetesLoginPath)
	kingpin.Flag("k8s-auth-role", "Kubernetes authentication role").StringVar(&flags.KubernetesAuthRole)

	// EC2 Authentication
	kingpin.Flag("ec2-auth", "Use EC2 metadata to authenticate to Vault").Default("false").BoolVar(&flags.EC2AuthEnabled)
	kingpin.Flag("ec2-vault-nonce", "Nonce to use if re-authenticating.").Default("").StringVar(&flags.EC2Nonce)

	// IAM Authentication
	kingpin.Flag("iam-auth-role", "The role used to perform iam authentication").Default("").StringVar(&flags.IAMAuthRole)
	kingpin.Flag("iam-vault-auth-backend", "The name of the auth backend in Vault to perform iam authentication against. Defaults to `aws`.").Default("aws").StringVar(&flags.IAMVaultAuthBackend)

	// Show version
	kingpin.Flag("version", "Display build version").Default("false").BoolVar(&flags.ShowVersion)

	// Shared options
	kingpin.Flag("debug", "Log at debug level").Default("false").BoolVar(&flags.DebugLogLevel)

	// Flags for smoothing out edge cases.
	kingpin.Flag("ignore-non-renewable-auth", "ignored; kept for compatibility").Default("false").Bool()
	kingpin.Flag("never-scrub", "ignored; kept for compatibility").Default("false").Bool()

	kingpin.Parse()

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

	if flags.PerformCleanup {
		actions++
		if flags.PerformOneShot {
			return nil, errors.New("the --one-shot flag can only be used in --sidecar mode")
		}
	}

	if actions != 1 {
		return nil, errors.New("specify exactly one of --init, --sidecar, or --cleanup flags")
	}

	return &flags, nil
}
