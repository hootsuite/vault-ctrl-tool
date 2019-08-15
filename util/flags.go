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
}

var Flags CliFlags
