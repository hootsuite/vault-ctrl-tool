package util

import "time"

type CliFlags struct {
	PerformInit         bool
	PerformSidecar      bool
	PerformOneShot      bool
	Cleanup             bool
	RenewInterval       time.Duration
	LeasesFile          string
	ShutdownTriggerFile string
	RenewLeaseDuration  time.Duration
	SafetyThreshold     time.Duration
	VaultTokenArg       string
	EC2AuthEnabled      bool
	EC2AuthRole         string
	EC2VaultAuthPath    string
}

var Flags CliFlags
