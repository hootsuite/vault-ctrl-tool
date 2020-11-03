package metrics

import "sync"

type MetricName string

const BriefcaseReset MetricName = "BriefcaseReset"
const VaultTokenWritten MetricName = "VaultTokenWritten"
const VaultTokenRefreshed MetricName = "VaultTokenRefreshed"
const SecretUpdates MetricName = "SecretUpdates"

type Metrics struct {
	mutex    sync.RWMutex
	counters map[MetricName]int
}

func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[MetricName]int),
	}
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
