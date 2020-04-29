package util

import "time"

type CliFlags struct {
	PerformInit         bool
	PerformSidecar      bool
	PerformOneShot      bool
	PerformCleanup      bool
	RevokeOnCleanup     bool
	RenewInterval       time.Duration
	LeasesFile          string
	ShutdownTriggerFile string
	RenewLeaseDuration  time.Duration
	SafetyThreshold     time.Duration
	VaultTokenArg       string
	EC2AuthEnabled      bool
	EC2AuthRole         string
	EC2VaultAuthPath    string
	EC2VaultNonce       string
	IamAuthRole         string
	ShowVersion         bool
}

var Flags CliFlags
