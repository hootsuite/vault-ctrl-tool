package metrics

import (
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

type MetricName string

const BriefcaseReset MetricName = "BriefcaseReset"
const VaultTokenWritten MetricName = "VaultTokenWritten"
const VaultTokenRefreshed MetricName = "VaultTokenRefreshed"
const SecretUpdates MetricName = "SecretUpdates"

type Metrics struct {
	mutex    sync.RWMutex
	counters map[MetricName]int

	SidecarSyncErrors       prometheus.Counter
	SidecarVaultTokenErrors prometheus.Counter
	SidecarSecretErrors     prometheus.Counter
}

func metricName(name string) string {
	return fmt.Sprintf("vault_ctrl_tool_%s", name)
}

var (
	// SidecarSyncErrors is incremented each time any part of the sidecar sync loop fails.
	SidecarSyncErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: metricName("sidecar_sync_errors"),
		Help: "errors while any stage of sidecar sync mode",
	})
	// SidecarVaultTokenErrors is incremented each time the sidecar sync loop either fails to
	// find a vault token, or there is an error validating it.
	SidecarVaultTokenErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: metricName("sidecar_vault_token_errors"),
		Help: "errors while fetching and validating vault token stage of sidecar sync",
	})
	// SidecarSecretErrors is incremented each time the sidecar sync loop fails to sync any of
	// its secrets (i.e. secret, aws, ssh, etc...).
	SidecarSecretErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: metricName("sidecar_secret_errors"),
		Help: "errors while renewing secrets",
	})
)

func init() {
	prometheus.MustRegister(
		SidecarSecretErrors,
		SidecarVaultTokenErrors,
		SidecarSyncErrors,
	)
}

// NewMetrics constructs a new metrics object.
func NewMetrics() *Metrics {
	mtrcs := &Metrics{
		counters:                make(map[MetricName]int),
		SidecarSyncErrors:       SidecarSyncErrors,
		SidecarVaultTokenErrors: SidecarVaultTokenErrors,
		SidecarSecretErrors:     SidecarSecretErrors,
	}

	return mtrcs
}

func (m *Metrics) Increment(name MetricName) {
	if m == nil {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.counters[name]++
}

func (m *Metrics) Decrement(name MetricName) {
	if m == nil {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.counters[name]--
}

func (m *Metrics) Counter(name MetricName) int {
	if m == nil {
		return 0
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	val := m.counters[name]
	return val
}

func (m *Metrics) IncrementBy(name MetricName, val int) {
	if m == nil {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.counters[name] += val
}

// MetricsHandler instruments a prometheus metrics handler on "/metrics" and begins
// listening on the specified address.
func MetricsHandler(addr string, term chan os.Signal) {
	log.Info().Str("addr", addr).Msg("starting metrics server")

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		srv := &http.Server{
			Handler:  mux,
			Addr:     addr,
			ErrorLog: stdlog.Default(),
		}

		defer srv.Close()
		if err := srv.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("failed to start metrics server, shutting down")
			term <- os.Interrupt
		}
	}()
}
