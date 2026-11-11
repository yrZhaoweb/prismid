package prismid

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var defaultLatencyBoundsSec = []float64{
	0.0005, // 0.5ms
	0.001,  // 1ms
	0.0025, // 2.5ms
	0.005,  // 5ms
	0.01,   // 10ms
	0.025,  // 25ms
	0.05,   // 50ms
	0.1,    // 100ms
	0.25,   // 250ms
	1.0,    // 1s
}

// Metrics collects lock-free operational counters and latency histograms rendered in standard
// Prometheus text exposition format (`text/plain; version=0.0.4; charset=utf-8`) with zero external dependencies.
type Metrics struct {
	challengesIssued      atomic.Uint64
	challengesRateLimited atomic.Uint64
	rateLimitedRequests   atomic.Uint64
	spoofTrapsTriggered   atomic.Uint64
	recoveriesRequired    atomic.Uint64
	rebindRotations       atomic.Uint64
	rebindStepUps         atomic.Uint64
	rebindDenied          atomic.Uint64
	clearSpoofAllowed     atomic.Uint64
	clearSpoofDenied      atomic.Uint64
	subjectsErased        atomic.Uint64

	identifyBucketCounts [10]atomic.Uint64
	identifyCount        atomic.Uint64
	identifySumMicros    atomic.Uint64

	verdictMu       sync.RWMutex
	verdictCounters map[string]*atomic.Uint64
	rejectCounters  map[string]*atomic.Uint64
}

// NewMetrics creates an initialized Prometheus-compatible Metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{
		verdictCounters: make(map[string]*atomic.Uint64),
		rejectCounters:  make(map[string]*atomic.Uint64),
	}
}

func (m *Metrics) RecordChallengeIssued() {
	if m != nil {
		m.challengesIssued.Add(1)
	}
}

func (m *Metrics) RecordChallengeRateLimited() {
	if m != nil {
		m.challengesRateLimited.Add(1)
	}
}

func (m *Metrics) RecordHTTP429() {
	if m != nil {
		m.rateLimitedRequests.Add(1)
	}
}

func (m *Metrics) RecordIdentifyVerdict(riskStatus string, shadowMode, spoofTrap, recoveryReq bool, dur time.Duration) {
	if m == nil {
		return
	}
	status := strings.ToLower(strings.TrimSpace(riskStatus))
	if status == "" {
		status = "unknown"
	}
	shadowStr := "false"
	if shadowMode {
		shadowStr = "true"
	}
	key := status + "|" + shadowStr

	m.verdictMu.RLock()
	ctr := m.verdictCounters[key]
	m.verdictMu.RUnlock()
	if ctr == nil {
		m.verdictMu.Lock()
		ctr = m.verdictCounters[key]
		if ctr == nil {
			ctr = &atomic.Uint64{}
			m.verdictCounters[key] = ctr
		}
		m.verdictMu.Unlock()
	}
	ctr.Add(1)

	if spoofTrap {
		m.spoofTrapsTriggered.Add(1)
	}
	if recoveryReq {
		m.recoveriesRequired.Add(1)
	}
	m.observeIdentifyDuration(dur)
}

func (m *Metrics) RecordIdentifyRejection(code string, dur time.Duration) {
	if m == nil {
		return
	}
	cleanCode := strings.TrimSpace(code)
	if cleanCode == "" {
		cleanCode = "INVALID_REQUEST"
	}
	m.verdictMu.RLock()
	ctr := m.rejectCounters[cleanCode]
	m.verdictMu.RUnlock()
	if ctr == nil {
		m.verdictMu.Lock()
		ctr = m.rejectCounters[cleanCode]
		if ctr == nil {
			ctr = &atomic.Uint64{}
			m.rejectCounters[cleanCode] = ctr
		}
		m.verdictMu.Unlock()
	}
	ctr.Add(1)
	m.observeIdentifyDuration(dur)
}

func (m *Metrics) RecordRebindOutcome(mode string) {
	if m == nil {
		return
	}
	switch mode {
	case "rotation":
		m.rebindRotations.Add(1)
	case "step_up":
		m.rebindStepUps.Add(1)
	default:
		m.rebindDenied.Add(1)
	}
}

func (m *Metrics) RecordClearSpoof(allowed bool) {
	if m == nil {
		return
	}
	if allowed {
		m.clearSpoofAllowed.Add(1)
	} else {
		m.clearSpoofDenied.Add(1)
	}
}

func (m *Metrics) RecordSubjectErased() {
	if m != nil {
		m.subjectsErased.Add(1)
	}
}

func (m *Metrics) observeIdentifyDuration(dur time.Duration) {
	sec := dur.Seconds()
	if sec < 0 {
		sec = 0
	}
	for i, bound := range defaultLatencyBoundsSec {
		if sec <= bound {
			m.identifyBucketCounts[i].Add(1)
		}
	}
	m.identifyCount.Add(1)
	m.identifySumMicros.Add(uint64(dur.Microseconds()))
}

func escapePromLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// RenderPrometheus formats all metrics plus optional live RiskGraph & FileStateStore gauges
// in Prometheus Exposition Format 0.0.4.
func (m *Metrics) RenderPrometheus(graph *RiskGraph, persistErrors uint64) string {
	var b strings.Builder
	b.Grow(4096)

	b.WriteString("# HELP prismid_challenges_issued_total Total number of single-use challenges issued.\n")
	b.WriteString("# TYPE prismid_challenges_issued_total counter\n")
	fmt.Fprintf(&b, "prismid_challenges_issued_total %d\n", m.challengesIssued.Load())

	b.WriteString("# HELP prismid_challenges_rate_limited_total Challenges rejected by per-IP or per-subnet active quota.\n")
	b.WriteString("# TYPE prismid_challenges_rate_limited_total counter\n")
	fmt.Fprintf(&b, "prismid_challenges_rate_limited_total %d\n", m.challengesRateLimited.Load())

	b.WriteString("# HELP prismid_http_rate_limited_total HTTP requests rejected with 429 Too Many Requests.\n")
	b.WriteString("# TYPE prismid_http_rate_limited_total counter\n")
	fmt.Fprintf(&b, "prismid_http_rate_limited_total %d\n", m.rateLimitedRequests.Load())

	b.WriteString("# HELP prismid_identify_verdicts_total Accepted /identify verdicts partitioned by risk_status and shadow mode.\n")
	b.WriteString("# TYPE prismid_identify_verdicts_total counter\n")
	m.verdictMu.RLock()
	vKeys := make([]string, 0, len(m.verdictCounters))
	for k := range m.verdictCounters {
		vKeys = append(vKeys, k)
	}
	sort.Strings(vKeys)
	for _, k := range vKeys {
		parts := strings.SplitN(k, "|", 2)
		status, shadow := parts[0], "false"
		if len(parts) == 2 {
			shadow = parts[1]
		}
		fmt.Fprintf(&b, "prismid_identify_verdicts_total{risk_status=\"%s\",shadow=\"%s\"} %d\n",
			escapePromLabel(status), escapePromLabel(shadow), m.verdictCounters[k].Load())
	}

	b.WriteString("# HELP prismid_identify_rejections_total Rejected /identify requests partitioned by error code.\n")
	b.WriteString("# TYPE prismid_identify_rejections_total counter\n")
	rKeys := make([]string, 0, len(m.rejectCounters))
	for k := range m.rejectCounters {
		rKeys = append(rKeys, k)
	}
	sort.Strings(rKeys)
	for _, k := range rKeys {
		fmt.Fprintf(&b, "prismid_identify_rejections_total{code=\"%s\"} %d\n",
			escapePromLabel(k), m.rejectCounters[k].Load())
	}
	m.verdictMu.RUnlock()

	b.WriteString("# HELP prismid_spoof_traps_triggered_total Observations where anti-spoof / tampering traps triggered.\n")
	b.WriteString("# TYPE prismid_spoof_traps_triggered_total counter\n")
	fmt.Fprintf(&b, "prismid_spoof_traps_triggered_total %d\n", m.spoofTrapsTriggered.Load())

	b.WriteString("# HELP prismid_device_key_recoveries_required_total Observations requiring TOFU ECDSA device-key recovery.\n")
	b.WriteString("# TYPE prismid_device_key_recoveries_required_total counter\n")
	fmt.Fprintf(&b, "prismid_device_key_recoveries_required_total %d\n", m.recoveriesRequired.Load())

	b.WriteString("# HELP prismid_rebind_requests_total Device-key rebind operations partitioned by authorization mode.\n")
	b.WriteString("# TYPE prismid_rebind_requests_total counter\n")
	fmt.Fprintf(&b, "prismid_rebind_requests_total{mode=\"rotation\"} %d\n", m.rebindRotations.Load())
	fmt.Fprintf(&b, "prismid_rebind_requests_total{mode=\"step_up\"} %d\n", m.rebindStepUps.Load())
	fmt.Fprintf(&b, "prismid_rebind_requests_total{mode=\"denied\"} %d\n", m.rebindDenied.Load())

	b.WriteString("# HELP prismid_clear_spoof_requests_total Step-up spoof clearance attempts.\n")
	b.WriteString("# TYPE prismid_clear_spoof_requests_total counter\n")
	fmt.Fprintf(&b, "prismid_clear_spoof_requests_total{outcome=\"allowed\"} %d\n", m.clearSpoofAllowed.Load())
	fmt.Fprintf(&b, "prismid_clear_spoof_requests_total{outcome=\"denied\"} %d\n", m.clearSpoofDenied.Load())

	b.WriteString("# HELP prismid_subjects_erased_total GDPR/CCPA subject erasure executions.\n")
	b.WriteString("# TYPE prismid_subjects_erased_total counter\n")
	fmt.Fprintf(&b, "prismid_subjects_erased_total %d\n", m.subjectsErased.Load())

	b.WriteString("# HELP prismid_identify_duration_seconds Latency histogram of /api/v1/risk/identify verification.\n")
	b.WriteString("# TYPE prismid_identify_duration_seconds histogram\n")
	totalCount := m.identifyCount.Load()
	for i, bound := range defaultLatencyBoundsSec {
		fmt.Fprintf(&b, "prismid_identify_duration_seconds_bucket{le=\"%g\"} %d\n",
			bound, m.identifyBucketCounts[i].Load())
	}
	fmt.Fprintf(&b, "prismid_identify_duration_seconds_bucket{le=\"+Inf\"} %d\n", totalCount)
	fmt.Fprintf(&b, "prismid_identify_duration_seconds_sum %.6f\n", float64(m.identifySumMicros.Load())/1e6)
	fmt.Fprintf(&b, "prismid_identify_duration_seconds_count %d\n", totalCount)

	if graph != nil {
		st := graph.Stats()
		b.WriteString("# HELP prismid_graph_active_subjects Active subjects cached in RiskGraph.\n")
		b.WriteString("# TYPE prismid_graph_active_subjects gauge\n")
		fmt.Fprintf(&b, "prismid_graph_active_subjects %d\n", st.ActiveSubjects)

		b.WriteString("# HELP prismid_graph_active_slices Active orthogonal slice nodes cached in RiskGraph.\n")
		b.WriteString("# TYPE prismid_graph_active_slices gauge\n")
		fmt.Fprintf(&b, "prismid_graph_active_slices %d\n", st.ActiveSlices)

		b.WriteString("# HELP prismid_graph_evictions_total Cumulative RiskGraph capacity evictions.\n")
		b.WriteString("# TYPE prismid_graph_evictions_total counter\n")
		fmt.Fprintf(&b, "prismid_graph_evictions_total{kind=\"soft_subject\"} %d\n", st.SoftSubjectEvictions)
		fmt.Fprintf(&b, "prismid_graph_evictions_total{kind=\"forced_subject\"} %d\n", st.ForcedSubjectEvictions)
		fmt.Fprintf(&b, "prismid_graph_evictions_total{kind=\"soft_slice\"} %d\n", st.SoftSliceEvictions)
		fmt.Fprintf(&b, "prismid_graph_evictions_total{kind=\"hard_slice\"} %d\n", st.HardSliceEvictions)
	}

	b.WriteString("# HELP prismid_state_persist_errors_total Cumulative FileStateStore WAL/snapshot persistence errors.\n")
	b.WriteString("# TYPE prismid_state_persist_errors_total counter\n")
	fmt.Fprintf(&b, "prismid_state_persist_errors_total %d\n", persistErrors)

	return b.String()
}
