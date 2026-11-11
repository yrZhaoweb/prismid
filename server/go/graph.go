package prismid

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// Canonical account risk status colors produced by the orthogonal slice connected-component graph.
const (
	RiskStatusUnknown = "unknown"
	RiskStatusGreen   = "green"
	RiskStatusYellow  = "yellow"
	RiskStatusRed     = "red"
)

// HardAnchorPolicy controls how accounts sharing per-device hard slices (d_bcn_*, d_key_*, d_nat_*, d_kch_*)
// are linked and scored (DeepSeek S1-2: preventing false-positive bans on shared family/school/kiosk browsers).
type HardAnchorPolicy string

const (
	// HardAnchorPolicySharedStepUp (default) links shared browser/device accounts into ComponentSubjects
	// and elevates 2–3 clean Web accounts sharing a hard anchor to RiskStatusYellow + RiskPending=true
	// (prompting MFA/step-up rather than an immediate hard red ban), while still escalating to RiskStatusRed
	// when cookie-wiping storage resurrection (StorageHealed=true), active tampering, >= 4 accounts, or
	// desktop motherboard hardware multi-accounting (d_nat_*/d_kch_*) is detected.
	HardAnchorPolicySharedStepUp HardAnchorPolicy = "shared_step_up"

	// HardAnchorPolicyStepUpAll keeps any number of clean accounts sharing a hard anchor at
	// RiskStatusYellow + RiskPending=true (suitable for public kiosks, school labs, and shared terminals),
	// escalating to RiskStatusRed only on StorageHealed evasion or active client tampering.
	HardAnchorPolicyStepUpAll HardAnchorPolicy = "step_up_all"

	// HardAnchorPolicyStrictOneToOne enforces strict 1-account-per-device semantics (e.g. fintech signup
	// promos or airdrops): the 2nd account on any shared hard anchor is immediately RiskStatusRed.
	HardAnchorPolicyStrictOneToOne HardAnchorPolicy = "strict_1to1"

	// HardAnchorPolicyDisabled disables cross-account component merging across per-device hard anchors
	// (d_bcn_*, d_key_*, d_nat_*, d_kch_*); single-account tampering/spoof signals and soft-slice
	// subnet/GPU velocity bursts (BurstSuspicion -> yellow) remain active (DeepSeek P3-5).
	HardAnchorPolicyDisabled HardAnchorPolicy = "disabled"

	// DefaultSharedHardAnchorMaxAccounts is the maximum number of clean accounts allowed on one Web
	// browser profile under HardAnchorPolicySharedStepUp before escalating from yellow+step-up to red.
	DefaultSharedHardAnchorMaxAccounts = 3
)

// Default velocity windows, edge TTLs, spoof decay thresholds, burst thresholds, and graph capacity bounds.
const (
	DefaultGPUBurstWindow                = 25 * time.Minute
	DefaultWebProfileWindow              = 2 * time.Hour
	DefaultSameNetFarmingWindow          = 6 * time.Hour
	DefaultSpoofEdgeTTL                  = 24 * time.Hour
	DefaultSoftEdgeTTL                   = 7 * 24 * time.Hour
	DefaultMinCleanStreakInterval        = 1 * time.Hour
	DefaultCleanObservationsToClearSpoof = 3
	HistoricalSpoofLogOdds               = 1.5
	DefaultCleanBeaconBurstCount         = 3
	DefaultMaxGraphSubjects              = 50000
	MaxSlicesPerSubject                  = 16
	MaxSubjectsPerSlice                  = 256
	MaxComponentSize                     = 512
	maxPendingRecoveryBeacons            = 8192
)

// GraphSubject represents an account/user node in the orthogonal slice risk graph.
type GraphSubject struct {
	SubjectID string    `json:"subject_id"`
	CreatedAt time.Time `json:"created_at"`
}

// GraphEdge represents an observed association between a subject and a device slice node.
type GraphEdge struct {
	SubjectID        string    `json:"subject_id"`
	SubjectCreatedAt time.Time `json:"subject_created_at"`
	ObservedAt       time.Time `json:"observed_at,omitempty"`
	SliceID          string    `json:"slice_id"`
	Confidence       float64   `json:"confidence"`
	SpoofTraphit     bool      `json:"spoof_trap_hit,omitempty"`
	SpoofedAt        time.Time `json:"spoofed_at,omitempty"`
	LastCleanAt      time.Time `json:"last_clean_at,omitempty"`
	CleanStreak      int       `json:"clean_streak,omitempty"`
	HistoricalSpoof  bool      `json:"historical_spoof,omitempty"`
	StorageHealed    bool      `json:"storage_healed,omitempty"`
	HasBeacon        bool      `json:"has_beacon,omitempty"`
	BeaconSliceID    string    `json:"beacon_slice_id,omitempty"`
	NativeSliceID    string    `json:"native_slice_id,omitempty"`
	DeviceKeySliceID string    `json:"device_key_slice_id,omitempty"`
}

// RiskEvidence represents an auditable, human-readable evidence item contributing to a risk verdict.
type RiskEvidence struct {
	SliceID     string  `json:"slice_id"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	LogOdds     float64 `json:"log_odds"`
	ObservedAt  string  `json:"observed_at,omitempty"`
	Historical  bool    `json:"historical,omitempty"`
}

// ComponentSnapshot describes the connected component, calibrated log-odds score,
// evidence chain, and risk decision for a subject.
type ComponentSnapshot struct {
	SubjectID                 string         `json:"subject_id"`
	RiskStatus                string         `json:"risk_status"`
	RiskPending               bool           `json:"risk_pending"`
	BurstSuspicion            bool           `json:"burst_suspicion,omitempty"`
	Truncated                 bool           `json:"truncated,omitempty"`
	DeviceKeyRecoveryRequired bool           `json:"device_key_recovery_required,omitempty"`
	LogOddsScore              float64        `json:"log_odds_score"`
	EarliestSubjectID         string         `json:"earliest_subject_id,omitempty"`
	ComponentSubjects         []string       `json:"component_subjects"`
	SliceIDs                  []string       `json:"slice_ids"`
	SharedSliceIDs            []string       `json:"shared_slice_ids"`
	EvidenceChain             []RiskEvidence `json:"evidence_chain,omitempty"`
}

// GraphStats exposes operational capacity and eviction counters for observability (DeepSeek S1-5, S2-15, P2-3).
type GraphStats struct {
	ActiveSubjects         int              `json:"active_subjects"`
	ActiveSlices           int              `json:"active_slices"`
	MaxSubjects            int              `json:"max_subjects"`
	HardAnchorPolicy       HardAnchorPolicy `json:"hard_anchor_policy"`
	SoftSubjectEvictions   uint64           `json:"soft_subject_evictions"`
	ForcedSubjectEvictions uint64           `json:"forced_subject_evictions"`
	SoftSliceEvictions     uint64           `json:"soft_slice_evictions"`
	HardSliceEvictions     uint64           `json:"hard_slice_evictions"`
	CapacityBackpressures  uint64           `json:"capacity_backpressures"`
	HistoryIncomplete      bool             `json:"history_incomplete"`
}

// GraphBackend synchronizes RiskGraph edges across horizontally scaled server replicas and
// persistent external datastores (implemented by RedisStore and SQLGraphStore).
type GraphBackend interface {
	UpsertGraphEdges(ctx context.Context, edges []GraphEdge) error
	DeleteGraphEdges(ctx context.Context, subjectID string, sliceIDs ...string) error
	DeleteSubjectGraphEdges(ctx context.Context, subjectID string) error
	LoadGraphNeighborhood(ctx context.Context, seedSubjectID string, extraSliceIDs []string, maxSubjects int) ([]GraphEdge, error)
}

// GraphOptions configures RiskGraph behavior, persistence hooks, and capacity bounds.
type GraphOptions struct {
	MinConfidence    float64
	MaxSubjects      int
	HardAnchorPolicy HardAnchorPolicy
	NowFunc          func() time.Time
	Store            ChallengeStore
	Backend          GraphBackend
}

// RiskGraph evaluates connected components over deduplicated (SubjectID, SliceID) bipartite
// observations using a strict Hard-Identity vs. Soft-Velocity separation model.
type RiskGraph struct {
	mu                     sync.RWMutex
	minConf                float64
	maxSubjects            int
	hardAnchorPolicy       HardAnchorPolicy
	nowFunc                func() time.Time
	ownerStore             BeaconOwnerStore
	rebindStore            DeviceKeyRebindStore
	backend                GraphBackend
	lastObservedAt         time.Time
	subjectOrder           []string
	subjectEdges           map[string]map[string]GraphEdge
	sliceEdges             map[string]map[string]GraphEdge
	incompleteSubjects     map[string]bool
	incompleteSlices       map[string]bool
	historyIncomplete      bool
	pendingRecovery        map[string]map[string]time.Time
	softSubjectEvictions   uint64
	forcedSubjectEvictions uint64
	softSliceEvictions     uint64
	hardSliceEvictions     uint64
	capacityBackpressures  uint64
}

func normalizeHardAnchorPolicy(p HardAnchorPolicy) HardAnchorPolicy {
	switch p {
	case HardAnchorPolicySharedStepUp, HardAnchorPolicyStepUpAll, HardAnchorPolicyStrictOneToOne, HardAnchorPolicyDisabled:
		return p
	default:
		return HardAnchorPolicySharedStepUp
	}
}

// ParseHardAnchorPolicy parses a CLI/config string into a validated HardAnchorPolicy.
func ParseHardAnchorPolicy(raw string) (HardAnchorPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(HardAnchorPolicySharedStepUp):
		return HardAnchorPolicySharedStepUp, nil
	case string(HardAnchorPolicyStepUpAll):
		return HardAnchorPolicyStepUpAll, nil
	case string(HardAnchorPolicyStrictOneToOne):
		return HardAnchorPolicyStrictOneToOne, nil
	case string(HardAnchorPolicyDisabled):
		return HardAnchorPolicyDisabled, nil
	default:
		return "", fmt.Errorf("unknown hard-anchor policy %q (expected shared_step_up, step_up_all, strict_1to1, or disabled)", raw)
	}
}

// NewRiskGraph creates a standalone thread-safe, deduplicated, capacity-bounded risk graph.
func NewRiskGraph(minConfidence float64) *RiskGraph {
	return NewRiskGraphWithClock(minConfidence, nil)
}

// NewRiskGraphWithClock creates a RiskGraph using an explicit clock for edge TTL and spoof decay.
func NewRiskGraphWithClock(minConfidence float64, nowFunc func() time.Time) *RiskGraph {
	return NewRiskGraphWithOptions(GraphOptions{
		MinConfidence:    minConfidence,
		MaxSubjects:      DefaultMaxGraphSubjects,
		HardAnchorPolicy: HardAnchorPolicySharedStepUp,
		NowFunc:          nowFunc,
	})
}

// NewRiskGraphWithOptions creates a RiskGraph with explicit policy, capacity, and optional store hooks.
func NewRiskGraphWithOptions(opts GraphOptions) *RiskGraph {
	minConf := opts.MinConfidence
	if minConf <= 0 {
		minConf = AuthoritativeConfidenceThreshold
	}
	maxSubjects := opts.MaxSubjects
	if maxSubjects <= 0 {
		maxSubjects = DefaultMaxGraphSubjects
	}
	g := &RiskGraph{
		minConf:            minConf,
		maxSubjects:        maxSubjects,
		hardAnchorPolicy:   normalizeHardAnchorPolicy(opts.HardAnchorPolicy),
		nowFunc:            opts.NowFunc,
		subjectOrder:       make([]string, 0, 256),
		subjectEdges:       make(map[string]map[string]GraphEdge),
		sliceEdges:         make(map[string]map[string]GraphEdge),
		incompleteSubjects: make(map[string]bool),
		incompleteSlices:   make(map[string]bool),
		pendingRecovery:    make(map[string]map[string]time.Time),
	}
	if !isNilInterfaceValue(opts.Store) {
		g.AttachStore(opts.Store)
	}
	if !isNilInterfaceValue(opts.Backend) {
		g.AttachBackend(opts.Backend)
	}
	return g
}

func isNilInterfaceValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// AttachStore connects a ChallengeStore implementing BeaconOwnerStore, DeviceKeyRebindStore,
// and/or GraphBackend so that beacon ownership, TOFU bindings, and connected-component neighborhoods
// survive in-memory graph eviction, restarts, and multi-replica load balancing.
func (g *RiskGraph) AttachStore(store ChallengeStore) {
	if isNilInterfaceValue(store) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if bos, ok := store.(BeaconOwnerStore); ok {
		g.ownerStore = bos
	}
	if rs, ok := store.(DeviceKeyRebindStore); ok {
		g.rebindStore = rs
	}
	if gb, ok := store.(GraphBackend); ok && g.backend == nil {
		g.backend = gb
	}
}

// AttachBackend connects a distributed or persistent GraphBackend (e.g. RedisStore or SQLGraphStore).
func (g *RiskGraph) AttachBackend(backend GraphBackend) {
	if isNilInterfaceValue(backend) {
		backend = nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.backend = backend
}

func (g *RiskGraph) getBackend() GraphBackend {
	g.mu.RLock()
	b := g.backend
	g.mu.RUnlock()
	return b
}

// syncNeighborhoodFromBackend hydrates the 2-hop bipartite neighborhood around `seedSubjectID`
// and `extraSlices` from `g.backend` (if attached) without holding `g.mu` across network/DB I/O.
func (g *RiskGraph) syncNeighborhoodFromBackend(seedSubjectID string, extraSlices []string) {
	backend := g.getBackend()
	if backend == nil {
		return
	}
	edges, err := backend.LoadGraphNeighborhood(context.Background(), seedSubjectID, extraSlices, MaxComponentSize)
	if err != nil {
		return
	}

	bySub := make(map[string]map[string]GraphEdge)
	for _, e := range edges {
		if e.SubjectID == "" || e.SliceID == "" {
			continue
		}
		if bySub[e.SubjectID] == nil {
			bySub[e.SubjectID] = make(map[string]GraphEdge)
		}
		bySub[e.SubjectID][e.SliceID] = e
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	refNow := g.referenceNowLocked()

	// If `seedSubjectID` was deleted on another replica, purge stale local cache for `seedSubjectID`.
	if seedSubjectID != "" && len(bySub[seedSubjectID]) == 0 {
		if _, hadLocal := g.subjectEdges[seedSubjectID]; hadLocal {
			g.removeSubjectLocked(seedSubjectID)
			for i, sid := range g.subjectOrder {
				if sid == seedSubjectID {
					g.subjectOrder = append(g.subjectOrder[:i], g.subjectOrder[i+1:]...)
					break
				}
			}
		}
	}

	for sid, remoteSlices := range bySub {
		if _, exists := g.subjectEdges[sid]; !exists {
			if g.maxSubjects > 0 && len(g.subjectEdges) >= g.maxSubjects {
				if !g.evictOneSubjectByPriorityLocked(refNow, nil) {
					continue
				}
			}
			g.subjectOrder = append(g.subjectOrder, sid)
			g.subjectEdges[sid] = make(map[string]GraphEdge, len(remoteSlices))
		} else {
			// Reconcile any edges removed on another replica (e.g. retired d_key_* after rebind).
			for localSlice := range g.subjectEdges[sid] {
				if _, stillPresent := remoteSlices[localSlice]; !stillPresent {
					delete(g.subjectEdges[sid], localSlice)
					if smap, ok := g.sliceEdges[localSlice]; ok {
						delete(smap, sid)
						if len(smap) == 0 {
							delete(g.sliceEdges, localSlice)
						}
					}
				}
			}
		}
		for sl, edge := range remoteSlices {
			if obs := edgeObservedAt(edge); obs.After(g.lastObservedAt) {
				g.lastObservedAt = obs
			}
			g.subjectEdges[sid][sl] = edge
			if g.sliceEdges[sl] == nil {
				g.sliceEdges[sl] = make(map[string]GraphEdge)
			}
			g.sliceEdges[sl][sid] = edge
		}
	}
}

// SetHardAnchorPolicy updates the hard-anchor multi-account linking policy at runtime.
func (g *RiskGraph) SetHardAnchorPolicy(policy HardAnchorPolicy) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hardAnchorPolicy = normalizeHardAnchorPolicy(policy)
}

// HardAnchorPolicy returns the currently configured hard-anchor linking policy.
func (g *RiskGraph) HardAnchorPolicy() HardAnchorPolicy {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.hardAnchorPolicy
}

// Stats returns a snapshot of current graph cardinality and eviction telemetry.
func (g *RiskGraph) Stats() GraphStats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return GraphStats{
		ActiveSubjects:         len(g.subjectEdges),
		ActiveSlices:           len(g.sliceEdges),
		MaxSubjects:            g.maxSubjects,
		HardAnchorPolicy:       g.hardAnchorPolicy,
		SoftSubjectEvictions:   g.softSubjectEvictions,
		ForcedSubjectEvictions: g.forcedSubjectEvictions,
		SoftSliceEvictions:     g.softSliceEvictions,
		HardSliceEvictions:     g.hardSliceEvictions,
		CapacityBackpressures:  g.capacityBackpressures,
		HistoryIncomplete:      g.historyIncomplete,
	}
}

func edgeObservedAt(e GraphEdge) time.Time {
	if !e.ObservedAt.IsZero() {
		return e.ObservedAt
	}
	return e.SubjectCreatedAt
}

func (g *RiskGraph) referenceNowLocked() time.Time {
	if g.nowFunc != nil {
		return g.nowFunc().UTC()
	}
	return g.lastObservedAt
}

func normalizeEdgeAtTime(edge GraphEdge, refNow time.Time) (GraphEdge, bool) {
	obsAt := edgeObservedAt(edge)
	if !isPerDeviceHardSlice(edge.SliceID) && !refNow.IsZero() && !obsAt.IsZero() && refNow.Sub(obsAt) > DefaultSoftEdgeTTL {
		return edge, false
	}
	if edge.SpoofTraphit {
		spTime := edge.SpoofedAt
		if spTime.IsZero() {
			spTime = obsAt
		}
		if edge.CleanStreak >= DefaultCleanObservationsToClearSpoof ||
			(!refNow.IsZero() && !spTime.IsZero() && refNow.Sub(spTime) > DefaultSpoofEdgeTTL) {
			edge.SpoofTraphit = false
			edge.HistoricalSpoof = true
		}
	}
	return edge, true
}

func (g *RiskGraph) pruneSubjectEdgesLocked(subjectID string, refNow time.Time) {
	subjMap, ok := g.subjectEdges[subjectID]
	if !ok || len(subjMap) == 0 {
		return
	}
	sliceIDs := make([]string, 0, len(subjMap))
	for sl := range subjMap {
		sliceIDs = append(sliceIDs, sl)
	}
	for _, sl := range sliceIDs {
		edge := subjMap[sl]
		updated, alive := normalizeEdgeAtTime(edge, refNow)
		if !alive {
			delete(subjMap, sl)
			if smap, exists := g.sliceEdges[sl]; exists {
				delete(smap, subjectID)
				if len(smap) == 0 {
					delete(g.sliceEdges, sl)
				}
			}
			continue
		}
		if updated.SpoofTraphit != edge.SpoofTraphit || updated.HistoricalSpoof != edge.HistoricalSpoof {
			subjMap[sl] = updated
			if smap, exists := g.sliceEdges[sl]; exists {
				smap[subjectID] = updated
			}
		}
	}
}

// PruneExpired sweeps expired soft edges across all subjects and removes subjects that no longer hold
// any active edges, returning the number of subjects removed.
func (g *RiskGraph) PruneExpired(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.IsZero() {
		now = g.referenceNowLocked()
	}
	return g.pruneAllExpiredLocked(now)
}

func (g *RiskGraph) pruneAllExpiredLocked(refNow time.Time) int {
	if refNow.IsZero() {
		return 0
	}
	removed := 0
	keptOrder := make([]string, 0, len(g.subjectOrder))
	for _, sid := range g.subjectOrder {
		if _, exists := g.subjectEdges[sid]; !exists {
			continue
		}
		g.pruneSubjectEdgesLocked(sid, refNow)
		if len(g.subjectEdges[sid]) == 0 && !g.incompleteSubjects[sid] {
			delete(g.subjectEdges, sid)
			removed++
			continue
		}
		keptOrder = append(keptOrder, sid)
	}
	g.subjectOrder = keptOrder
	return removed
}

// isEvictableIsolatedCleanSubjectLocked returns true when `sid` is a single-account clean user
// with zero active/historical spoofing and zero shared hard anchors or active stateless links.
func (g *RiskGraph) isEvictableIsolatedCleanSubjectLocked(sid string, refNow time.Time) bool {
	if g.incompleteSubjects[sid] {
		return false
	}
	subjMap, ok := g.subjectEdges[sid]
	if !ok {
		return false
	}
	for sl, rawEdge := range subjMap {
		edge, alive := normalizeEdgeAtTime(rawEdge, refNow)
		if !alive {
			continue
		}
		if edge.SpoofTraphit || edge.HistoricalSpoof {
			return false
		}
		smap := g.sliceEdges[sl]
		if isPerDeviceHardSlice(sl) {
			if len(smap) > 1 {
				return false
			}
			continue
		}
		if !edge.HasBeacon {
			for peerID, peerRaw := range smap {
				if peerID == sid {
					continue
				}
				peerEdge, peerAlive := normalizeEdgeAtTime(peerRaw, refNow)
				if peerAlive && shouldMergeStatelessOrSpoofed(sl, edge, peerEdge) {
					return false
				}
			}
		}
	}
	return true
}

// isUnlinkedHardAnchorSubjectLocked returns true when `sid` has NO shared per-device hard anchor
// (`d_key_*`, `d_nat_*`, `d_kch_*`, `d_bcn_*`) with any other subject (even if `sid` self-reported
// `canvas_noise_injected=true` / `SpoofTraphit` — preventing DeepSeek P2-3 burner-spoof DoS!).
func (g *RiskGraph) isUnlinkedHardAnchorSubjectLocked(sid string, refNow time.Time) bool {
	if g.incompleteSubjects[sid] {
		return false
	}
	subjMap, ok := g.subjectEdges[sid]
	if !ok {
		return false
	}
	for sl, rawEdge := range subjMap {
		if _, alive := normalizeEdgeAtTime(rawEdge, refNow); !alive {
			continue
		}
		if isPerDeviceHardSlice(sl) && len(g.sliceEdges[sl]) > 1 {
			return false
		}
	}
	return true
}

func (g *RiskGraph) incomingSharesOccupiedMultiOwnerHardSliceLocked(res *VerifyResult) bool {
	if res == nil {
		return false
	}
	candidates := []string{
		strings.TrimSpace(res.DeviceKeySliceID),
		strings.TrimSpace(res.KeychainSliceID),
		strings.TrimSpace(res.BeaconSliceID),
	}
	if res.IsNative {
		candidates = append(candidates, strings.TrimSpace(res.ExactSliceID))
	}
	for _, sl := range candidates {
		if sl != "" && isPerDeviceHardSlice(sl) && len(g.sliceEdges[sl]) >= 2 {
			return true
		}
	}
	return false
}

// evictOneSubjectByPriorityLocked enforces bounded FIFO/priority eviction at `maxSubjects` (DeepSeek P2-3):
//   - Tier 1: Oldest isolated clean singleton (`softSubjectEvictions++`).
//   - Tier 2: Oldest subject without any shared multi-account hard anchor — e.g. an attacker flooding
//     self-reported `canvas_noise_injected=true` spoofed accounts (`softSubjectEvictions++`).
//   - Tier 3: When 100% of `maxSubjects` are multi-account hard-anchor clusters AND the incoming user
//     does NOT share any already-saturated multi-owner hard slice, evict the oldest subject overall while
//     marking its shared hard slice in `incompleteSlices` so the remaining cluster never turns green,
//     allowing the legitimate new user to be admitted cleanly (`forcedSubjectEvictions++`).
func (g *RiskGraph) evictOneSubjectByPriorityLocked(refNow time.Time, incoming *VerifyResult) bool {
	for i, sid := range g.subjectOrder {
		if g.isEvictableIsolatedCleanSubjectLocked(sid, refNow) {
			g.removeSubjectLocked(sid)
			g.subjectOrder = append(g.subjectOrder[:i], g.subjectOrder[i+1:]...)
			g.softSubjectEvictions++
			return true
		}
	}
	for i, sid := range g.subjectOrder {
		if g.isUnlinkedHardAnchorSubjectLocked(sid, refNow) {
			g.removeSubjectLocked(sid)
			g.subjectOrder = append(g.subjectOrder[:i], g.subjectOrder[i+1:]...)
			g.softSubjectEvictions++
			return true
		}
	}
	if g.incomingSharesOccupiedMultiOwnerHardSliceLocked(incoming) {
		return false
	}
	if len(g.subjectOrder) > 0 {
		oldest := g.subjectOrder[0]
		for sl := range g.subjectEdges[oldest] {
			if isPerDeviceHardSlice(sl) && len(g.sliceEdges[sl]) > 1 {
				g.markEvidenceLossLocked(oldest, sl)
			}
		}
		g.removeSubjectLocked(oldest)
		delete(g.incompleteSubjects, oldest)
		g.subjectOrder = g.subjectOrder[1:]
		g.forcedSubjectEvictions++
		return true
	}
	return false
}

func hasResultFlag(res *VerifyResult, flag string) bool {
	if res == nil {
		return false
	}
	for _, f := range res.PrivacySignals {
		if f == flag {
			return true
		}
	}
	for _, f := range res.SpoofFlags {
		if f == flag {
			return true
		}
	}
	return false
}

func deriveCompositeGpuSysSlice(gpuAudioSliceID, sysNetSliceID string) (string, bool) {
	gpuSuffix, okGPU := strings.CutPrefix(strings.TrimSpace(gpuAudioSliceID), "d_gpu_")
	sysSuffix, okSys := strings.CutPrefix(strings.TrimSpace(sysNetSliceID), "d_sys_")
	if okGPU && gpuSuffix != "" && okSys && sysSuffix != "" {
		return "d_gpusys_" + gpuSuffix + "_" + sysSuffix, true
	}
	return "", false
}

// RecordVerification records or updates a subject's orthogonal slices from a VerifyResult
// and returns the updated ComponentSnapshot for that subject.
func (g *RiskGraph) RecordVerification(subjectID string, observedAt time.Time, res *VerifyResult) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	if observedAt.IsZero() {
		if g.nowFunc != nil {
			observedAt = g.nowFunc().UTC()
		} else {
			observedAt = time.Now().UTC()
		}
	}
	if res != nil && res.DeviceKeyRecoveryRequired {
		// Recovery cannot overwrite authoritative history or link a claimed identity,
		// EXCEPT if the graph holds zero authoritative owners for this beacon (e.g. after a cold
		// restart or isolated-subject eviction without a persistent GraphStore), record a bounded
		// pending recovery claim so step-up + PoP rebind does not deadlock (DeepSeek S1-1).
		bcn := strings.TrimSpace(res.BeaconSliceID)
		g.mu.Lock()
		policy := g.hardAnchorPolicy
		if subjectID != "" && strings.HasPrefix(bcn, "d_bcn_") {
			if smap := g.sliceEdges[bcn]; len(smap) == 0 {
				if _, exists := g.pendingRecovery[bcn]; !exists && len(g.pendingRecovery) >= maxPendingRecoveryBeacons {
					for k := range g.pendingRecovery {
						delete(g.pendingRecovery, k)
						break
					}
				}
				if g.pendingRecovery[bcn] == nil {
					g.pendingRecovery[bcn] = make(map[string]time.Time)
				}
				if len(g.pendingRecovery[bcn]) < 8 {
					g.pendingRecovery[bcn][subjectID] = observedAt
				}
			}
		}
		g.mu.Unlock()
		snap := EvaluateSubjectComponentWithPolicy(nil, subjectID, g.minConf, policy)
		snap.DeviceKeyRecoveryRequired = true
		return snap
	}

	var ownerStoreToRecord BeaconOwnerStore
	var bcnToRecord string
	var backendToSync GraphBackend
	var backendUpsert []GraphEdge
	var backendDeletedSlices []string

	if res != nil && res.Accepted && subjectID != "" && g.getBackend() != nil {
		cand := make([]string, 0, 7)
		cand = append(cand, res.SliceNodes()...)
		if comp, ok := deriveCompositeGpuSysSlice(res.GpuAudioSliceID, res.SysNetSliceID); ok {
			cand = append(cand, comp)
		}
		g.syncNeighborhoodFromBackend(subjectID, cand)
	}

	g.mu.Lock()
	if observedAt.After(g.lastObservedAt) {
		g.lastObservedAt = observedAt
	}
	refNow := g.referenceNowLocked()
	if observedAt.After(refNow) {
		refNow = observedAt
	}

	if res != nil && res.Accepted && subjectID != "" {
		if _, exists := g.subjectEdges[subjectID]; !exists {
			if g.maxSubjects > 0 && len(g.subjectEdges) >= g.maxSubjects {
				g.pruneAllExpiredLocked(refNow)
				if len(g.subjectEdges) >= g.maxSubjects {
					if !g.evictOneSubjectByPriorityLocked(refNow, res) && len(g.subjectOrder) > 0 {
						g.capacityBackpressures++
						policy := g.hardAnchorPolicy
						g.mu.Unlock()
						return markIncompleteSnapshot(EvaluateSubjectComponentWithPolicy(nil, subjectID, g.minConf, policy))
					}
				}
			}
			g.subjectOrder = append(g.subjectOrder, subjectID)
			g.subjectEdges[subjectID] = make(map[string]GraphEdge)
		}

		// Prune expired soft edges and expire past-TTL spoof states before applying the new observation.
		g.pruneSubjectEdgesLocked(subjectID, refNow)

		// S1-3: When a bound device key is presented for a beacon, retire any superseded d_key_* edges
		// previously bound to the same beacon on this subject so rotated/compromised keys do not remain welded.
		bcnClean := strings.TrimSpace(res.BeaconSliceID)
		keyClean := strings.TrimSpace(res.DeviceKeySliceID)
		if res.DeviceKeyBound && strings.HasPrefix(keyClean, "d_key_") && strings.HasPrefix(bcnClean, "d_bcn_") {
			_, deletedKeys := g.retireSubjectDeviceKeyWithDiffLocked(subjectID, bcnClean, "", keyClean)
			backendDeletedSlices = append(backendDeletedSlices, deletedKeys...)
		}
		if strings.HasPrefix(bcnClean, "d_bcn_") && res.Confidence >= g.minConf && !res.SpoofTrapTriggered && !res.IsVirtualGPU {
			delete(g.pendingRecovery, bcnClean)
			if g.ownerStore != nil {
				ownerStoreToRecord = g.ownerStore
				bcnToRecord = bcnClean
			}
		}

		// Determine earliest subject creation timestamp across any existing edges of this subject.
		subjectCreated := observedAt
		for _, prev := range g.subjectEdges[subjectID] {
			if !prev.SubjectCreatedAt.IsZero() && prev.SubjectCreatedAt.Before(subjectCreated) {
				subjectCreated = prev.SubjectCreatedAt
			}
		}

		hasBeacon := bcnClean != ""
		storageHealed := hasResultFlag(res, "storage_healed")
		var nativeSliceID string
		if res.IsNative && strings.HasPrefix(res.ExactSliceID, "d_nat_") {
			nativeSliceID = res.ExactSliceID
		}

		// Anti-Wash Spoof Decay (DeepSeek v1.0, v1.0.1 P1 #2 & S2-9):
		// A clean observation can advance CleanStreak on a previously spoofed edge ONLY when:
		//   1) It presents the exact same strongest per-device hard anchor recorded on that spoofed edge
		//      (or, in stateless no-beacon/no-key mode, matches the same soft hardware/env slice — S2-9), AND
		//   2) At least DefaultMinCleanStreakInterval (1h) of server-observed time has elapsed since the spoof
		//      (and since the previous counted clean step — preventing rapid 3-request scripted washing).
		if !res.SpoofTrapTriggered && res.Confidence >= g.minConf {
			existingKeys := make([]string, 0, len(g.subjectEdges[subjectID]))
			for sl := range g.subjectEdges[subjectID] {
				existingKeys = append(existingKeys, sl)
			}
			for _, sl := range existingKeys {
				prev := g.subjectEdges[subjectID][sl]
				if prev.SpoofTraphit && sharesSameHardAnchorForDecay(prev, res, nativeSliceID) {
					baseTime := prev.SpoofedAt
					if baseTime.IsZero() {
						baseTime = edgeObservedAt(prev)
					}
					if prev.LastCleanAt.After(baseTime) {
						baseTime = prev.LastCleanAt
					}
					if baseTime.IsZero() || observedAt.Sub(baseTime) >= DefaultMinCleanStreakInterval {
						prev.CleanStreak++
						prev.LastCleanAt = observedAt
						if prev.CleanStreak >= DefaultCleanObservationsToClearSpoof {
							prev.SpoofTraphit = false
							prev.HistoricalSpoof = true
						}
						g.subjectEdges[subjectID][sl] = prev
						if smap, exists := g.sliceEdges[sl]; exists {
							smap[subjectID] = prev
						}
					}
				}
			}
		}

		slices := make([]string, 0, 7)
		slices = append(slices, res.SliceNodes()...)
		if compSlice, ok := deriveCompositeGpuSysSlice(res.GpuAudioSliceID, res.SysNetSliceID); ok {
			slices = append(slices, compSlice)
		}

		for _, sliceID := range slices {
			sliceID = strings.TrimSpace(sliceID)
			if sliceID == "" {
				continue
			}
			edge := GraphEdge{
				SubjectID:        subjectID,
				SubjectCreatedAt: subjectCreated,
				ObservedAt:       observedAt,
				SliceID:          sliceID,
				Confidence:       res.Confidence,
				SpoofTraphit:     res.SpoofTrapTriggered,
				StorageHealed:    storageHealed,
				HasBeacon:        hasBeacon,
				BeaconSliceID:    bcnClean,
				NativeSliceID:    nativeSliceID,
				DeviceKeySliceID: keyClean,
			}
			if res.SpoofTrapTriggered {
				edge.SpoofedAt = observedAt
				edge.LastCleanAt = time.Time{}
				edge.CleanStreak = 0
				edge.HistoricalSpoof = false
			}
			subjMap := g.subjectEdges[subjectID]
			if prev, ok := subjMap[sliceID]; ok {
				if !prev.SubjectCreatedAt.IsZero() && prev.SubjectCreatedAt.Before(edge.SubjectCreatedAt) {
					edge.SubjectCreatedAt = prev.SubjectCreatedAt
				}
				if !prev.ObservedAt.IsZero() && prev.ObservedAt.After(edge.ObservedAt) {
					edge.ObservedAt = prev.ObservedAt
				}
				if prev.StorageHealed {
					edge.StorageHealed = true
				}
				if !res.SpoofTrapTriggered {
					if prev.SpoofTraphit {
						edge.SpoofTraphit = true
						edge.SpoofedAt = prev.SpoofedAt
						edge.LastCleanAt = prev.LastCleanAt
						edge.CleanStreak = prev.CleanStreak
						edge.HistoricalSpoof = prev.HistoricalSpoof
						if prev.DeviceKeySliceID != "" {
							edge.DeviceKeySliceID = prev.DeviceKeySliceID
						}
						if prev.NativeSliceID != "" {
							edge.NativeSliceID = prev.NativeSliceID
						}
						if prev.BeaconSliceID != "" {
							edge.BeaconSliceID = prev.BeaconSliceID
							edge.HasBeacon = true
						}
					} else if prev.HistoricalSpoof {
						edge.HistoricalSpoof = true
						edge.SpoofedAt = prev.SpoofedAt
						edge.LastCleanAt = prev.LastCleanAt
						edge.CleanStreak = prev.CleanStreak
					}
				}
				if prev.Confidence > edge.Confidence && !edge.SpoofTraphit {
					edge.Confidence = prev.Confidence
				}
			} else if len(subjMap) >= MaxSlicesPerSubject {
				// Prefer soft evidence, deterministically, and retain uncertainty after eviction.
				evictSlice := ""
				existingSlices := make([]string, 0, len(subjMap))
				for existingSlice := range subjMap {
					existingSlices = append(existingSlices, existingSlice)
				}
				sort.Strings(existingSlices)
				for _, existingSlice := range existingSlices {
					if !isPerDeviceHardSlice(existingSlice) {
						evictSlice = existingSlice
						break
					}
				}
				if evictSlice == "" {
					for _, existingSlice := range existingSlices {
						evictSlice = existingSlice
						break
					}
				}
				if evictSlice != "" {
					if isPerDeviceHardSlice(evictSlice) {
						g.hardSliceEvictions++
						g.markEvidenceLossLocked(subjectID, evictSlice)
					} else {
						g.softSliceEvictions++
					}
					delete(subjMap, evictSlice)
					if smap, ok := g.sliceEdges[evictSlice]; ok {
						delete(smap, subjectID)
						if len(smap) == 0 {
							delete(g.sliceEdges, evictSlice)
						}
					}
				}
			}

			subjMap[sliceID] = edge
			if g.sliceEdges[sliceID] == nil {
				g.sliceEdges[sliceID] = make(map[string]GraphEdge)
			}
			smap := g.sliceEdges[sliceID]
			if _, exists := smap[subjectID]; !exists && len(smap) >= MaxSubjectsPerSlice {
				// S2-15: First purge expired soft edges occupying capacity on this slice!
				if !isPerDeviceHardSlice(sliceID) {
					for sid, e := range smap {
						if _, alive := normalizeEdgeAtTime(e, refNow); !alive {
							delete(smap, sid)
							if emap, ok := g.subjectEdges[sid]; ok {
								delete(emap, sliceID)
							}
						}
					}
				}
			}
			if _, exists := smap[subjectID]; !exists && len(smap) >= MaxSubjectsPerSlice {
				// Preserve the earliest subject on the slice when evicting to bound per-slice fanout,
				// and on soft slices prefer evicting clean edges before active SpoofTraphit edges:
				var earliestSID string
				var earliestTime time.Time
				for sid, e := range smap {
					if earliestSID == "" || e.SubjectCreatedAt.Before(earliestTime) ||
						(e.SubjectCreatedAt.Equal(earliestTime) && sid < earliestSID) {
						earliestSID = sid
						earliestTime = e.SubjectCreatedAt
					}
				}
				evictSID := selectSliceEvictionCandidate(smap, earliestSID, !isPerDeviceHardSlice(sliceID))
				if evictSID != "" {
					if isPerDeviceHardSlice(sliceID) {
						g.hardSliceEvictions++
						g.markEvidenceLossLocked(evictSID, sliceID)
					} else {
						g.softSliceEvictions++
					}
					delete(smap, evictSID)
					if emap, ok := g.subjectEdges[evictSID]; ok {
						delete(emap, sliceID)
					}
				}
			}
			smap[subjectID] = edge
		}
	}
	if g.backend != nil && res != nil && res.Accepted && subjectID != "" {
		backendToSync = g.backend
		for _, e := range g.subjectEdges[subjectID] {
			backendUpsert = append(backendUpsert, e)
		}
	}
	policy := g.hardAnchorPolicy
	subEdges, truncated := g.collectLocalSubgraphEdgesLocked(subjectID)
	g.mu.Unlock()

	if backendToSync != nil {
		if len(backendDeletedSlices) > 0 {
			_ = backendToSync.DeleteGraphEdges(context.Background(), subjectID, backendDeletedSlices...)
		}
		if len(backendUpsert) > 0 {
			_ = backendToSync.UpsertGraphEdges(context.Background(), backendUpsert)
		}
	}
	if ownerStoreToRecord != nil && bcnToRecord != "" {
		_ = ownerStoreToRecord.RecordBeaconOwner(context.Background(), bcnToRecord, subjectID)
	}

	snap := EvaluateSubjectComponentWithPolicy(subEdges, subjectID, g.minConf, policy)
	if truncated {
		return markIncompleteSnapshot(snap)
	}
	return snap
}

func selectSliceEvictionCandidate(smap map[string]GraphEdge, earliestSID string, preferClean bool) string {
	var evictSID string
	var oldestTime time.Time
	if preferClean {
		for sid, e := range smap {
			if sid == earliestSID || e.SpoofTraphit {
				continue
			}
			obsTime := edgeObservedAt(e)
			if evictSID == "" || obsTime.Before(oldestTime) ||
				(obsTime.Equal(oldestTime) && sid < evictSID) {
				evictSID = sid
				oldestTime = obsTime
			}
		}
		if evictSID != "" {
			return evictSID
		}
	}
	for sid, e := range smap {
		if sid == earliestSID {
			continue
		}
		obsTime := edgeObservedAt(e)
		if evictSID == "" || obsTime.Before(oldestTime) ||
			(obsTime.Equal(oldestTime) && sid < evictSID) {
			evictSID = sid
			oldestTime = obsTime
		}
	}
	return evictSID
}

// RetireSubjectDeviceKey removes a subject's superseded/compromised `d_key_*` hard edge upon TOFU
// key rotation or recovery so the subject is no longer welded to the retired key (DeepSeek S1-3),
// and migrates `DeviceKeySliceID` references on that subject's matching beacon edges to `newDeviceKeySliceID`.
func (g *RiskGraph) RetireSubjectDeviceKey(subjectID, beaconSliceID, oldDeviceKeySliceID, newDeviceKeySliceID string) bool {
	subjectID = strings.TrimSpace(subjectID)
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	oldDeviceKeySliceID = strings.TrimSpace(oldDeviceKeySliceID)
	newDeviceKeySliceID = strings.TrimSpace(newDeviceKeySliceID)
	if subjectID == "" {
		return false
	}
	if g.getBackend() != nil {
		g.syncNeighborhoodFromBackend(subjectID, nil)
	}
	g.mu.Lock()
	retired, deletedKeys := g.retireSubjectDeviceKeyWithDiffLocked(subjectID, beaconSliceID, oldDeviceKeySliceID, newDeviceKeySliceID)
	backend := g.backend
	var migrated []GraphEdge
	if backend != nil {
		for _, e := range g.subjectEdges[subjectID] {
			migrated = append(migrated, e)
		}
	}
	g.mu.Unlock()

	if backend != nil {
		if len(deletedKeys) > 0 {
			_ = backend.DeleteGraphEdges(context.Background(), subjectID, deletedKeys...)
		}
		if len(migrated) > 0 {
			_ = backend.UpsertGraphEdges(context.Background(), migrated)
		}
	}
	return retired
}

func (g *RiskGraph) retireSubjectDeviceKeyLocked(subjectID, beaconSliceID, oldDeviceKeySliceID, newDeviceKeySliceID string) bool {
	retired, _ := g.retireSubjectDeviceKeyWithDiffLocked(subjectID, beaconSliceID, oldDeviceKeySliceID, newDeviceKeySliceID)
	return retired
}

func (g *RiskGraph) retireSubjectDeviceKeyWithDiffLocked(subjectID, beaconSliceID, oldDeviceKeySliceID, newDeviceKeySliceID string) (bool, []string) {
	subjMap, ok := g.subjectEdges[subjectID]
	if !ok || len(subjMap) == 0 {
		return false, nil
	}
	retired := false
	var toDelete []string
	for sl, edge := range subjMap {
		if !strings.HasPrefix(sl, "d_key_") {
			continue
		}
		if newDeviceKeySliceID != "" && sl == newDeviceKeySliceID {
			continue
		}
		if (oldDeviceKeySliceID != "" && sl == oldDeviceKeySliceID) ||
			(beaconSliceID != "" && (edge.BeaconSliceID == beaconSliceID || edge.BeaconSliceID == "")) {
			toDelete = append(toDelete, sl)
		}
	}
	for _, oldKey := range toDelete {
		delete(subjMap, oldKey)
		if smap, exists := g.sliceEdges[oldKey]; exists {
			delete(smap, subjectID)
			if len(smap) == 0 {
				delete(g.sliceEdges, oldKey)
			}
		}
		retired = true
	}
	// Migrate DeviceKeySliceID references on remaining edges of this (subjectID, beaconSliceID)
	// so anti-wash spoof decay recognizes subsequent clean visits under the rotated key.
	if newDeviceKeySliceID != "" {
		for sl, edge := range subjMap {
			if (oldDeviceKeySliceID != "" && edge.DeviceKeySliceID == oldDeviceKeySliceID) ||
				(beaconSliceID != "" && edge.BeaconSliceID == beaconSliceID) {
				edge.DeviceKeySliceID = newDeviceKeySliceID
				subjMap[sl] = edge
				if smap, exists := g.sliceEdges[sl]; exists {
					smap[subjectID] = edge
				}
			}
		}
	}
	return retired, toDelete
}

// EvaluateSubject returns the current ComponentSnapshot for a subject using bounded local subgraph traversal.
func (g *RiskGraph) EvaluateSubject(subjectID string) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID != "" && g.getBackend() != nil {
		g.syncNeighborhoodFromBackend(subjectID, nil)
	}
	g.mu.RLock()
	policy := g.hardAnchorPolicy
	subEdges, truncated := g.collectLocalSubgraphEdgesLocked(subjectID)
	g.mu.RUnlock()
	snap := EvaluateSubjectComponentWithPolicy(subEdges, subjectID, g.minConf, policy)
	if truncated {
		return markIncompleteSnapshot(snap)
	}
	return snap
}

func sharesSameHardAnchorForDecay(prev GraphEdge, res *VerifyResult, nativeSliceID string) bool {
	if res == nil {
		return false
	}
	if prev.DeviceKeySliceID != "" {
		return res.DeviceKeySliceID != "" && res.DeviceKeySliceID == prev.DeviceKeySliceID
	}
	if prev.NativeSliceID != "" {
		return nativeSliceID != "" && nativeSliceID == prev.NativeSliceID
	}
	if prev.BeaconSliceID != "" {
		return res.BeaconSliceID != "" && res.BeaconSliceID == prev.BeaconSliceID
	}
	// S2-9: Stateless / storage-blocked observations (no d_key_*, d_nat_*, or d_bcn_*) decay across
	// 3 clean visits spaced >= 1h apart when returning from the identical soft hardware/env slice.
	if prev.SliceID == "" {
		return false
	}
	if prev.SliceID == strings.TrimSpace(res.GpuAudioSliceID) ||
		prev.SliceID == strings.TrimSpace(res.ExactSliceID) ||
		prev.SliceID == strings.TrimSpace(res.SysNetSliceID) {
		return true
	}
	if comp, ok := deriveCompositeGpuSysSlice(res.GpuAudioSliceID, res.SysNetSliceID); ok && prev.SliceID == comp {
		return true
	}
	return false
}

// SubjectOwnsBeacon verifies whether `subjectID` is a registered owner of `beaconSliceID` (supporting
// both shared family/household browsers in S2-11 and persistent/pending recovery after graph loss in S1-1).
func (g *RiskGraph) SubjectOwnsBeacon(subjectID, beaconSliceID string) bool {
	subjectID = strings.TrimSpace(subjectID)
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if subjectID == "" || !strings.HasPrefix(beaconSliceID, "d_bcn_") {
		return false
	}
	g.mu.RLock()
	if subjMap, ok := g.subjectEdges[subjectID]; ok {
		if _, hasBeacon := subjMap[beaconSliceID]; hasBeacon {
			g.mu.RUnlock()
			return true
		}
	}
	if smap := g.sliceEdges[beaconSliceID]; len(smap) > 0 {
		_, isOwner := smap[subjectID]
		g.mu.RUnlock()
		return isOwner
	}
	ownerStore := g.ownerStore
	_, hasPending := g.pendingRecovery[beaconSliceID][subjectID]
	g.mu.RUnlock()

	if ownerStore != nil {
		if owners, err := ownerStore.GetBeaconOwners(context.Background(), beaconSliceID); err == nil && len(owners) > 0 {
			for _, o := range owners {
				if o == subjectID {
					return true
				}
			}
			return false
		}
	}
	return hasPending
}

// SubjectOwnsBeaconExclusively verifies that beaconSliceID belongs solely to subjectID (strict 1:1
// variant; consults persistent BeaconOwnerStore or pending recovery state if in-memory edges were lost).
func (g *RiskGraph) SubjectOwnsBeaconExclusively(subjectID, beaconSliceID string) bool {
	subjectID = strings.TrimSpace(subjectID)
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if subjectID == "" || !strings.HasPrefix(beaconSliceID, "d_bcn_") {
		return false
	}
	g.mu.RLock()
	if smap, exists := g.sliceEdges[beaconSliceID]; exists && len(smap) > 0 {
		_, soleOwner := smap[subjectID]
		excl := len(smap) == 1 && soleOwner
		g.mu.RUnlock()
		return excl
	}
	ownerStore := g.ownerStore
	pendMap := g.pendingRecovery[beaconSliceID]
	_, hasPending := pendMap[subjectID]
	pendExcl := len(pendMap) == 1 && hasPending
	g.mu.RUnlock()

	if ownerStore != nil {
		if owners, err := ownerStore.GetBeaconOwners(context.Background(), beaconSliceID); err == nil && len(owners) > 0 {
			return len(owners) == 1 && owners[0] == subjectID
		}
	}
	return pendExcl
}

// ClearSubjectSpoofAfterStepUp transitions active spoof edges on subjectID to HistoricalSpoof=true
// following server-verified step-up authentication.
func (g *RiskGraph) ClearSubjectSpoofAfterStepUp(subjectID string, clearedAt time.Time) bool {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false
	}
	if clearedAt.IsZero() {
		clearedAt = time.Now().UTC()
	}
	if g.getBackend() != nil {
		g.syncNeighborhoodFromBackend(subjectID, nil)
	}
	g.mu.Lock()
	subjMap, ok := g.subjectEdges[subjectID]
	if !ok {
		g.mu.Unlock()
		return false
	}
	cleared := false
	var updated []GraphEdge
	for sl, edge := range subjMap {
		if edge.SpoofTraphit {
			edge.SpoofTraphit = false
			edge.HistoricalSpoof = true
			edge.CleanStreak = DefaultCleanObservationsToClearSpoof
			edge.LastCleanAt = clearedAt
			subjMap[sl] = edge
			if smap, exists := g.sliceEdges[sl]; exists {
				smap[subjectID] = edge
			}
			updated = append(updated, edge)
			cleared = true
		}
	}
	backend := g.backend
	g.mu.Unlock()
	if backend != nil && len(updated) > 0 {
		_ = backend.UpsertGraphEdges(context.Background(), updated)
	}
	return cleared
}

// RemoveSubjectAndCollectBeacons deletes all graph observations for subjectID and returns ALL
// d_bcn_* beacon slice IDs associated with subjectID (including shared beacons — fixing S2-21 so
// TOFU key bindings can be completely reset without breaking co-owners' automatic TOFU re-bind).
func (g *RiskGraph) RemoveSubjectAndCollectBeacons(subjectID string) (bool, []string) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false, nil
	}
	if g.getBackend() != nil {
		g.syncNeighborhoodFromBackend(subjectID, nil)
	}
	g.mu.Lock()
	subjMap, exists := g.subjectEdges[subjectID]
	beaconSet := make(map[string]struct{})
	if exists {
		for sl := range subjMap {
			if strings.HasPrefix(sl, "d_bcn_") {
				beaconSet[sl] = struct{}{}
			}
		}
		g.removeSubjectLocked(subjectID)
		for i, sid := range g.subjectOrder {
			if sid == subjectID {
				g.subjectOrder = append(g.subjectOrder[:i], g.subjectOrder[i+1:]...)
				break
			}
		}
	}
	for bcn, pmap := range g.pendingRecovery {
		if _, ok := pmap[subjectID]; ok {
			delete(pmap, subjectID)
			if len(pmap) == 0 {
				delete(g.pendingRecovery, bcn)
			}
			beaconSet[bcn] = struct{}{}
		}
	}
	ownerStore := g.ownerStore
	backend := g.backend
	g.mu.Unlock()

	if backend != nil {
		_ = backend.DeleteSubjectGraphEdges(context.Background(), subjectID)
	}

	if ownerStore != nil {
		if _, allOwnerBeacons, err := ownerStore.RemoveSubjectBeaconOwnership(context.Background(), subjectID); err == nil {
			for _, bcn := range allOwnerBeacons {
				beaconSet[bcn] = struct{}{}
				exists = true
			}
		}
	}

	beacons := make([]string, 0, len(beaconSet))
	for bcn := range beaconSet {
		beacons = append(beacons, bcn)
	}
	sort.Strings(beacons)
	return exists, beacons
}

// RemoveSubject deletes all graph observations for a subject (and purges TOFU key bindings when a
// store is attached via AttachStore / NewRiskGraphWithOptions — fixing S2-21).
func (g *RiskGraph) RemoveSubject(subjectID string) bool {
	removed, beacons := g.RemoveSubjectAndCollectBeacons(subjectID)
	g.mu.RLock()
	rs := g.rebindStore
	g.mu.RUnlock()
	if rs != nil && len(beacons) > 0 {
		for _, bcn := range beacons {
			_, _ = rs.ClearBeaconDeviceKey(context.Background(), bcn)
		}
	}
	return removed
}

func (g *RiskGraph) removeSubjectLocked(subjectID string) {
	slices, ok := g.subjectEdges[subjectID]
	if !ok {
		return
	}
	for sliceID := range slices {
		if smap, ok := g.sliceEdges[sliceID]; ok {
			delete(smap, subjectID)
			if len(smap) == 0 {
				delete(g.sliceEdges, sliceID)
			}
		}
	}
	delete(g.subjectEdges, subjectID)
	delete(g.incompleteSubjects, subjectID)
}

// ExportSnapshot exports a deterministic, concurrency-safe snapshot of the RiskGraph (DeepSeek S1-4).
func (g *RiskGraph) ExportSnapshot() GraphSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()

	order := make([]string, len(g.subjectOrder))
	copy(order, g.subjectOrder)

	var edges []GraphEdge
	for _, sid := range g.subjectOrder {
		for _, e := range g.subjectEdges[sid] {
			edges = append(edges, e)
		}
	}
	for sid, smap := range g.subjectEdges {
		inOrder := false
		for _, osid := range g.subjectOrder {
			if osid == sid {
				inOrder = true
				break
			}
		}
		if !inOrder {
			for _, e := range smap {
				edges = append(edges, e)
			}
		}
	}
	sortGraphEdgesCanonical(edges)

	var incSubjects []string
	for sid := range g.incompleteSubjects {
		incSubjects = append(incSubjects, sid)
	}
	sort.Strings(incSubjects)

	var incSlices []string
	for sl := range g.incompleteSlices {
		incSlices = append(incSlices, sl)
	}
	sort.Strings(incSlices)

	var pending map[string][]string
	if len(g.pendingRecovery) > 0 {
		pending = make(map[string][]string, len(g.pendingRecovery))
		for bcn, smap := range g.pendingRecovery {
			list := make([]string, 0, len(smap))
			for sid := range smap {
				list = append(list, sid)
			}
			sort.Strings(list)
			pending[bcn] = list
		}
	}

	return GraphSnapshot{
		Version:            1,
		SavedAt:            time.Now().UTC(),
		MinConfidence:      g.minConf,
		HardAnchorPolicy:   g.hardAnchorPolicy,
		LastObservedAt:     g.lastObservedAt,
		SubjectOrder:       order,
		Edges:              edges,
		IncompleteSubjects: incSubjects,
		IncompleteSlices:   incSlices,
		HistoryIncomplete:  g.historyIncomplete,
		PendingRecovery:    pending,
	}
}

// ImportSnapshot restores a RiskGraph from a persisted GraphSnapshot.
func (g *RiskGraph) ImportSnapshot(snap GraphSnapshot) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if snap.MinConfidence > 0 {
		g.minConf = snap.MinConfidence
	}
	if snap.HardAnchorPolicy != "" {
		g.hardAnchorPolicy = normalizeHardAnchorPolicy(snap.HardAnchorPolicy)
	}
	g.lastObservedAt = snap.LastObservedAt
	g.historyIncomplete = snap.HistoryIncomplete
	g.subjectEdges = make(map[string]map[string]GraphEdge)
	g.sliceEdges = make(map[string]map[string]GraphEdge)
	g.incompleteSubjects = make(map[string]bool, len(snap.IncompleteSubjects))
	g.incompleteSlices = make(map[string]bool, len(snap.IncompleteSlices))
	g.pendingRecovery = make(map[string]map[string]time.Time)

	seenOrder := make(map[string]bool, len(snap.SubjectOrder))
	g.subjectOrder = make([]string, 0, len(snap.SubjectOrder))
	for _, sid := range snap.SubjectOrder {
		sid = strings.TrimSpace(sid)
		if sid != "" && !seenOrder[sid] {
			seenOrder[sid] = true
			g.subjectOrder = append(g.subjectOrder, sid)
		}
	}
	for _, e := range snap.Edges {
		sid := strings.TrimSpace(e.SubjectID)
		sl := strings.TrimSpace(e.SliceID)
		if sid == "" || sl == "" {
			continue
		}
		e.SubjectID = sid
		e.SliceID = sl
		if !seenOrder[sid] {
			seenOrder[sid] = true
			g.subjectOrder = append(g.subjectOrder, sid)
		}
		if g.subjectEdges[sid] == nil {
			g.subjectEdges[sid] = make(map[string]GraphEdge)
		}
		g.subjectEdges[sid][sl] = e
		if g.sliceEdges[sl] == nil {
			g.sliceEdges[sl] = make(map[string]GraphEdge)
		}
		g.sliceEdges[sl][sid] = e
	}
	for _, sid := range snap.IncompleteSubjects {
		g.incompleteSubjects[sid] = true
	}
	for _, sl := range snap.IncompleteSlices {
		g.incompleteSlices[sl] = true
	}
	now := time.Now().UTC()
	for bcn, sids := range snap.PendingRecovery {
		g.pendingRecovery[bcn] = make(map[string]time.Time, len(sids))
		for _, sid := range sids {
			g.pendingRecovery[bcn][sid] = now
		}
	}
	return nil
}

// Retain bounded loss markers even if an evicted slice no longer has cached edges.
func (g *RiskGraph) markEvidenceLossLocked(subjectID, sliceID string) {
	g.incompleteSubjects[subjectID] = true
	const maxLossMarkers = DefaultMaxGraphSubjects * MaxSlicesPerSubject
	if !g.incompleteSlices[sliceID] && len(g.incompleteSlices) >= maxLossMarkers {
		g.historyIncomplete = true
		return
	}
	g.incompleteSlices[sliceID] = true
}

func markIncompleteSnapshot(snap ComponentSnapshot) ComponentSnapshot {
	snap.Truncated = true
	snap.RiskPending = true
	snap.EarliestSubjectID = ""
	if snap.RiskStatus != RiskStatusRed {
		snap.RiskStatus = RiskStatusUnknown
	}
	return snap
}

// Expand eligible identity edges to closure, then add non-linking velocity neighbors.
func (g *RiskGraph) collectLocalSubgraphEdgesLocked(targetSubjectID string) ([]GraphEdge, bool) {
	if targetSubjectID == "" {
		return nil, false
	}
	if _, ok := g.subjectEdges[targetSubjectID]; !ok {
		return nil, false
	}
	refNow := g.referenceNowLocked()
	policy := g.hardAnchorPolicy
	visited := map[string]bool{targetSubjectID: true}
	queue := []string{targetSubjectID}
	processedHard := make(map[string]bool)
	truncated := g.historyIncomplete
	sortedSlices := func(sid string) []string {
		ids := make([]string, 0, len(g.subjectEdges[sid]))
		for id := range g.subjectEdges[sid] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids
	}
	sortedNeighbors := func(slice string) []string {
		ids := make([]string, 0, len(g.sliceEdges[slice]))
		for id := range g.sliceEdges[slice] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids
	}
	for head := 0; head < len(queue); head++ {
		sid := queue[head]
		for _, slice := range sortedSlices(sid) {
			edge, alive := normalizeEdgeAtTime(g.subjectEdges[sid][slice], refNow)
			if !alive || edge.Confidence < g.minConf {
				continue
			}
			hard := isPerDeviceHardSlice(slice)
			if hard {
				if policy == HardAnchorPolicyDisabled {
					continue
				}
				if processedHard[slice] {
					continue
				}
				processedHard[slice] = true
			}
			for _, neighbor := range sortedNeighbors(slice) {
				next, nextAlive := normalizeEdgeAtTime(g.sliceEdges[slice][neighbor], refNow)
				if !nextAlive || visited[neighbor] || next.Confidence < g.minConf ||
					!shouldMergeStatelessOrSpoofedWithPolicy(slice, edge, next, policy) {
					continue
				}
				if len(visited) >= MaxComponentSize {
					truncated = true
					continue
				}
				visited[neighbor] = true
				queue = append(queue, neighbor)
			}
		}
	}
	// Collect bounded velocity-window neighbors on d_gpusys_* (6h) and d_web_* (25m) for targetSubjectID:
	for _, slice := range sortedSlices(targetSubjectID) {
		targetEdge, targetAlive := normalizeEdgeAtTime(g.subjectEdges[targetSubjectID][slice], refNow)
		if !targetAlive {
			continue
		}
		var window time.Duration
		if strings.HasPrefix(slice, "d_gpusys_") {
			window = DefaultSameNetFarmingWindow
		} else if strings.HasPrefix(slice, "d_web_") && targetEdge.DeviceKeySliceID == "" {
			window = DefaultGPUBurstWindow
		} else {
			continue
		}
		velAdded := 0
		for _, neighbor := range sortedNeighbors(slice) {
			if visited[neighbor] {
				continue
			}
			next, nextAlive := normalizeEdgeAtTime(g.sliceEdges[slice][neighbor], refNow)
			if !nextAlive || next.Confidence < g.minConf {
				continue
			}
			dt := edgeObservedAt(next).Sub(edgeObservedAt(targetEdge))
			if dt < 0 {
				dt = -dt
			}
			if dt > window {
				continue
			}
			if len(visited) >= MaxComponentSize || velAdded >= DefaultCleanBeaconBurstCount*2 {
				break
			}
			visited[neighbor] = true
			velAdded++
		}
	}
	out := make([]GraphEdge, 0, len(visited)*4)
	for sid := range visited {
		if g.incompleteSubjects[sid] {
			truncated = true
		}
		for slice, rawEdge := range g.subjectEdges[sid] {
			edge, alive := normalizeEdgeAtTime(rawEdge, refNow)
			if !alive {
				continue
			}
			if isPerDeviceHardSlice(slice) && g.incompleteSlices[slice] {
				truncated = true
			}
			out = append(out, edge)
		}
	}
	sortGraphEdgesCanonical(out)
	return out, truncated
}

func sortGraphEdgesCanonical(edges []GraphEdge) {
	sort.Slice(edges, func(i, j int) bool {
		ti, tj := edges[i].SubjectCreatedAt, edges[j].SubjectCreatedAt
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if edges[i].SubjectID != edges[j].SubjectID {
			return edges[i].SubjectID < edges[j].SubjectID
		}
		return edges[i].SliceID < edges[j].SliceID
	})
}

func isPerDeviceHardSlice(slice string) bool {
	return strings.HasPrefix(slice, "d_key_") ||
		strings.HasPrefix(slice, "d_nat_") ||
		strings.HasPrefix(slice, "d_kch_") ||
		strings.HasPrefix(slice, "d_bcn_")
}

func isNativeHardSlice(slice string) bool {
	return strings.HasPrefix(slice, "d_nat_") || strings.HasPrefix(slice, "d_kch_")
}

func hasActiveSpoof(e GraphEdge) bool {
	return e.SpoofTraphit && e.CleanStreak == 0
}

func hasDifferentCleanNativeAnchors(a, b GraphEdge) bool {
	if hasActiveSpoof(a) || hasActiveSpoof(b) {
		return false
	}
	return a.NativeSliceID != "" && b.NativeSliceID != "" && a.NativeSliceID != b.NativeSliceID
}

func hasDifferentCleanBeacons(a, b GraphEdge) bool {
	if hasActiveSpoof(a) || hasActiveSpoof(b) {
		return false
	}
	if a.BeaconSliceID != "" && b.BeaconSliceID != "" {
		return a.BeaconSliceID != b.BeaconSliceID
	}
	return a.HasBeacon && b.HasBeacon
}

func sharesHardAnchorOnEdge(a, b GraphEdge) bool {
	if a.BeaconSliceID != "" && a.BeaconSliceID == b.BeaconSliceID {
		return true
	}
	if a.DeviceKeySliceID != "" && a.DeviceKeySliceID == b.DeviceKeySliceID {
		return true
	}
	if a.NativeSliceID != "" && a.NativeSliceID == b.NativeSliceID {
		return true
	}
	return false
}

func shouldMergeStatelessOrSpoofed(slice string, a, b GraphEdge) bool {
	return shouldMergeStatelessOrSpoofedWithPolicy(slice, a, b, HardAnchorPolicySharedStepUp)
}

func shouldMergeStatelessOrSpoofedWithPolicy(slice string, a, b GraphEdge, policy HardAnchorPolicy) bool {
	if isPerDeviceHardSlice(slice) {
		return policy != HardAnchorPolicyDisabled
	}
	if hasDifferentCleanNativeAnchors(a, b) {
		return false
	}

	dt := edgeObservedAt(a).Sub(edgeObservedAt(b))
	if dt < 0 {
		dt = -dt
	}
	if dt > DefaultSoftEdgeTTL {
		return false
	}

	if hasActiveSpoof(a) || hasActiveSpoof(b) {
		if dt > DefaultSpoofEdgeTTL {
			return false
		}
		if policy != HardAnchorPolicyDisabled && sharesHardAnchorOnEdge(a, b) {
			return true
		}
		if hasActiveSpoof(a) && hasActiveSpoof(b) &&
			(strings.HasPrefix(slice, "d_gpu_") || strings.HasPrefix(slice, "d_web_") || strings.HasPrefix(slice, "d_gpusys_")) {
			return true
		}
		if strings.HasPrefix(slice, "d_gpusys_") && dt <= DefaultGPUBurstWindow {
			return true
		}
		if !a.HasBeacon && !b.HasBeacon && dt <= DefaultGPUBurstWindow &&
			(strings.HasPrefix(slice, "d_gpu_") || strings.HasPrefix(slice, "d_web_") || strings.HasPrefix(slice, "d_sys_")) {
			return true
		}
		return false
	}
	if hasDifferentCleanBeacons(a, b) || a.HasBeacon || b.HasBeacon {
		return false
	}

	// Stateless / no-beacon observations:
	if strings.HasPrefix(slice, "d_gpusys_") {
		return dt <= DefaultSameNetFarmingWindow
	}
	if strings.HasPrefix(slice, "d_gpu_") {
		return dt <= DefaultGPUBurstWindow
	}
	if strings.HasPrefix(slice, "d_web_") {
		return dt <= DefaultWebProfileWindow
	}
	if strings.HasPrefix(slice, "d_sys_") {
		return (!a.HasBeacon && !b.HasBeacon) && dt <= DefaultGPUBurstWindow
	}
	return false
}

func countDistinctSubjectsInWindow(obs []GraphEdge, refEdge GraphEdge, window time.Duration) int {
	seen := make(map[string]struct{}, len(obs))
	refObs := edgeObservedAt(refEdge)
	for _, o := range obs {
		if hasDifferentCleanNativeAnchors(refEdge, o) {
			continue
		}
		dt := edgeObservedAt(o).Sub(refObs)
		if dt < 0 {
			dt = -dt
		}
		if dt <= window {
			seen[o.SubjectID] = struct{}{}
		}
	}
	return len(seen)
}

func sliceEvidenceWeight(slice string) (string, string, float64) {
	switch {
	case strings.HasPrefix(slice, "d_key_"):
		return "cryptographic_device_key", "Shared ECDSA P-256 non-extractable device key", 6.0
	case strings.HasPrefix(slice, "d_nat_"):
		return "native_hardware_uuid", "Shared OS motherboard UUID + serial + keychain anchor", 6.0
	case strings.HasPrefix(slice, "d_kch_"):
		return "os_keychain_anchor", "Shared persistent OS Keychain / Registry anchor", 5.5
	case strings.HasPrefix(slice, "d_bcn_"):
		return "storage_beacon", "Shared 128-bit 5-silo cryptographic storage beacon", 5.0
	case strings.HasPrefix(slice, "d_gpusys_"):
		return "gpu_subnet_composite", "Shared GPU/Audio signature and /24 subnet profile", 2.5
	case strings.HasPrefix(slice, "d_gpu_"):
		return "gpu_audio_hardware", "Shared GPU rasterization, register limits, and WebAudio profile", 2.2
	case strings.HasPrefix(slice, "d_web_"):
		return "web_composite_profile", "Shared WebGL, Audio, Canvas2D, and Fonts composite profile", 2.0
	case strings.HasPrefix(slice, "d_sys_"):
		return "system_subnet_environment", "Shared OS family, CPU core count, timezone, and /24 subnet", 1.2
	default:
		return "orthogonal_slice", "Shared orthogonal slice observation", 1.0
	}
}

// EvaluateSubjectComponent evaluates a subject's connected component using HardAnchorPolicySharedStepUp.
func EvaluateSubjectComponent(edges []GraphEdge, targetSubjectID string, minConf float64) ComponentSnapshot {
	return EvaluateSubjectComponentWithPolicy(edges, targetSubjectID, minConf, HardAnchorPolicySharedStepUp)
}

// EvaluateSubjectComponentWithPolicy is a pure, deterministic, permutation-invariant function that
// computes the connected identity component, calibrated log-odds score, evidence chain, and risk status
// for targetSubjectID under the specified HardAnchorPolicy.
func EvaluateSubjectComponentWithPolicy(edges []GraphEdge, targetSubjectID string, minConf float64, policy HardAnchorPolicy) ComponentSnapshot {
	if minConf <= 0 {
		minConf = AuthoritativeConfidenceThreshold
	}
	policy = normalizeHardAnchorPolicy(policy)
	targetSubjectID = strings.TrimSpace(targetSubjectID)
	empty := ComponentSnapshot{
		SubjectID:         targetSubjectID,
		RiskStatus:        RiskStatusUnknown,
		RiskPending:       true,
		LogOddsScore:      0,
		ComponentSubjects: []string{},
		SliceIDs:          []string{},
		SharedSliceIDs:    []string{},
	}
	if targetSubjectID == "" || len(edges) == 0 {
		return empty
	}

	var maxObsTime time.Time
	for _, e := range edges {
		if t := edgeObservedAt(e); t.After(maxObsTime) {
			maxObsTime = t
		}
	}

	sortedEdges := make([]GraphEdge, 0, len(edges))
	for _, e := range edges {
		if e.Confidence < minConf {
			continue
		}
		sid := strings.TrimSpace(e.SubjectID)
		slice := strings.TrimSpace(e.SliceID)
		if sid == "" || slice == "" {
			continue
		}
		e.SubjectID = sid
		e.SliceID = slice
		norm, alive := normalizeEdgeAtTime(e, maxObsTime)
		if !alive {
			continue
		}
		sortedEdges = append(sortedEdges, norm)
	}
	sortGraphEdgesCanonical(sortedEdges)

	parent := make(map[string]string)
	createdAt := make(map[string]time.Time)
	spoofedActive := make(map[string]bool)
	spoofedCooldown := make(map[string]bool)
	historicalDecayed := make(map[string]bool)
	subjectStorageHealed := make(map[string]bool)
	latestSpoofedAt := make(map[string]time.Time)
	minCleanStreak := make(map[string]int)
	sliceObs := make(map[string][]GraphEdge)
	subjectSlices := make(map[string]map[string]struct{})
	subjectEdgeBySlice := make(map[string]map[string]GraphEdge)
	activeSharedSlices := make(map[string]bool)

	var find func(string) string
	find = func(x string) string {
		root := x
		for parent[root] != root {
			root = parent[root]
		}
		for x != root {
			next := parent[x]
			parent[x] = root
			x = next
		}
		return root
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if ra < rb {
			parent[rb] = ra
		} else {
			parent[ra] = rb
		}
	}

	// First pass: initialize subjects and deduplicate per-(SubjectID, SliceID) observations
	for _, e := range sortedEdges {
		sid := e.SubjectID
		slice := e.SliceID
		if _, ok := parent[sid]; !ok {
			parent[sid] = sid
		}
		if prev, ok := createdAt[sid]; !ok || (!e.SubjectCreatedAt.IsZero() && e.SubjectCreatedAt.Before(prev)) {
			createdAt[sid] = e.SubjectCreatedAt
		}
		if subjectEdgeBySlice[sid] == nil {
			subjectEdgeBySlice[sid] = make(map[string]GraphEdge)
		}
		if prevEdge, exists := subjectEdgeBySlice[sid][slice]; exists {
			if !prevEdge.SubjectCreatedAt.IsZero() && prevEdge.SubjectCreatedAt.Before(e.SubjectCreatedAt) {
				e.SubjectCreatedAt = prevEdge.SubjectCreatedAt
			}
			if !prevEdge.ObservedAt.IsZero() && prevEdge.ObservedAt.After(e.ObservedAt) {
				e.ObservedAt = prevEdge.ObservedAt
			}
			if prevEdge.StorageHealed {
				e.StorageHealed = true
			}
			if prevEdge.SpoofTraphit && !e.SpoofTraphit {
				e.SpoofTraphit = true
				e.CleanStreak = prevEdge.CleanStreak
				if e.SpoofedAt.IsZero() || prevEdge.SpoofedAt.After(e.SpoofedAt) {
					e.SpoofedAt = prevEdge.SpoofedAt
				}
			} else if prevEdge.SpoofTraphit && e.SpoofTraphit {
				if prevEdge.CleanStreak < e.CleanStreak {
					e.CleanStreak = prevEdge.CleanStreak
				}
				if prevEdge.SpoofedAt.After(e.SpoofedAt) {
					e.SpoofedAt = prevEdge.SpoofedAt
				}
			}
			if prevEdge.HistoricalSpoof {
				e.HistoricalSpoof = true
				if e.SpoofedAt.IsZero() {
					e.SpoofedAt = prevEdge.SpoofedAt
				}
			}
		}
		subjectEdgeBySlice[sid][slice] = e

		if subjectSlices[sid] == nil {
			subjectSlices[sid] = make(map[string]struct{})
		}
		if !strings.HasPrefix(slice, "d_gpusys_") {
			subjectSlices[sid][slice] = struct{}{}
		}
	}

	if _, ok := parent[targetSubjectID]; !ok {
		return empty
	}

	subjectIDs := make([]string, 0, len(subjectEdgeBySlice))
	for sid := range subjectEdgeBySlice {
		subjectIDs = append(subjectIDs, sid)
	}
	sort.Strings(subjectIDs)
	for _, sid := range subjectIDs {
		for slice, e := range subjectEdgeBySlice[sid] {
			sliceObs[slice] = append(sliceObs[slice], e)
			if e.StorageHealed {
				subjectStorageHealed[sid] = true
			}
			spAt := e.SpoofedAt
			if spAt.IsZero() && (e.SpoofTraphit || e.HistoricalSpoof) {
				spAt = edgeObservedAt(e)
			}
			if !spAt.IsZero() && spAt.After(latestSpoofedAt[sid]) {
				latestSpoofedAt[sid] = spAt
			}
			if e.SpoofTraphit {
				if e.CleanStreak == 0 {
					spoofedActive[sid] = true
				} else {
					spoofedCooldown[sid] = true
					if cur, seen := minCleanStreak[sid]; !seen || e.CleanStreak < cur {
						minCleanStreak[sid] = e.CleanStreak
					}
				}
			} else if e.HistoricalSpoof {
				historicalDecayed[sid] = true
			}
		}
	}

	sliceKeys := make([]string, 0, len(sliceObs))
	for slice := range sliceObs {
		sliceKeys = append(sliceKeys, slice)
		sortGraphEdgesCanonical(sliceObs[slice])
	}
	sort.Strings(sliceKeys)

	// Second pass: O(N) linear Union-Find per slice for hard identity & tampered/stateless links
	for _, slice := range sliceKeys {
		obsList := sliceObs[slice]
		if len(obsList) < 2 {
			continue
		}
		if isPerDeviceHardSlice(slice) {
			if policy == HardAnchorPolicyDisabled {
				continue
			}
			firstSID := obsList[0].SubjectID
			for k := 1; k < len(obsList); k++ {
				if obsList[k].SubjectID != firstSID {
					union(firstSID, obsList[k].SubjectID)
				}
			}
			continue
		}

		obsByTime := make([]GraphEdge, len(obsList))
		copy(obsByTime, obsList)
		sort.Slice(obsByTime, func(i, j int) bool {
			ti, tj := edgeObservedAt(obsByTime[i]), edgeObservedAt(obsByTime[j])
			if !ti.Equal(tj) {
				return ti.Before(tj)
			}
			return obsByTime[i].SubjectID < obsByTime[j].SubjectID
		})
		for i := 0; i < len(obsByTime); i++ {
			a := obsByTime[i]
			for j := i + 1; j < len(obsByTime); j++ {
				b := obsByTime[j]
				if edgeObservedAt(b).Sub(edgeObservedAt(a)) > DefaultSoftEdgeTTL {
					break
				}
				if a.SubjectID != b.SubjectID && shouldMergeStatelessOrSpoofedWithPolicy(slice, a, b, policy) {
					union(a.SubjectID, b.SubjectID)
				}
			}
		}
	}

	targetRoot := find(targetSubjectID)
	var members []string
	sliceSet := make(map[string]struct{})
	componentSpoofedActive := false
	componentSpoofedCooldown := false
	var compLatestSpoofAt time.Time
	compMinCleanStreak := 0

	for sid := range parent {
		if find(sid) == targetRoot {
			members = append(members, sid)
			if spoofedActive[sid] {
				componentSpoofedActive = true
				if latestSpoofedAt[sid].After(compLatestSpoofAt) {
					compLatestSpoofAt = latestSpoofedAt[sid]
				}
			} else if spoofedCooldown[sid] {
				componentSpoofedCooldown = true
				if latestSpoofedAt[sid].After(compLatestSpoofAt) {
					compLatestSpoofAt = latestSpoofedAt[sid]
				}
				if compMinCleanStreak == 0 || (minCleanStreak[sid] > 0 && minCleanStreak[sid] < compMinCleanStreak) {
					compMinCleanStreak = minCleanStreak[sid]
				}
			}
			for sl := range subjectSlices[sid] {
				sliceSet[sl] = struct{}{}
			}
		}
	}

	for _, slice := range sliceKeys {
		inTargetComp := 0
		for _, e := range sliceObs[slice] {
			if find(e.SubjectID) == targetRoot {
				inTargetComp++
			}
		}
		if inTargetComp >= 2 {
			if isPerDeviceHardSlice(slice) && policy == HardAnchorPolicyDisabled {
				continue
			}
			if !strings.HasPrefix(slice, "d_gpusys_") {
				activeSharedSlices[slice] = true
			} else if gpuSlice := findSubjectPrefixSlice(subjectSlices[targetSubjectID], "d_gpu_"); gpuSlice != "" {
				activeSharedSlices[gpuSlice] = true
			}
		}
	}

	sort.Slice(members, func(i, j int) bool {
		ti, tj := createdAt[members[i]], createdAt[members[j]]
		if ti.Equal(tj) {
			return members[i] < members[j]
		}
		return ti.Before(tj)
	})

	burstSuspicion := false
	var evidenceChain []RiskEvidence
	logOdds := -2.0 // Baseline benign prior

	for _, slice := range sliceKeys {
		targetEdge, hasSlice := subjectEdgeBySlice[targetSubjectID][slice]
		if !hasSlice {
			continue
		}
		obsList := sliceObs[slice]
		if len(obsList) < DefaultCleanBeaconBurstCount {
			continue
		}
		var window time.Duration
		if strings.HasPrefix(slice, "d_gpusys_") {
			window = DefaultSameNetFarmingWindow
		} else if strings.HasPrefix(slice, "d_web_") && targetEdge.DeviceKeySliceID == "" {
			window = DefaultGPUBurstWindow
		} else {
			continue
		}
		burstCount := countDistinctSubjectsInWindow(obsList, targetEdge, window)
		if burstCount >= DefaultCleanBeaconBurstCount {
			burstSuspicion = true
			if !strings.HasPrefix(slice, "d_gpusys_") {
				activeSharedSlices[slice] = true
			} else if targetGPU := findSubjectPrefixSlice(subjectSlices[targetSubjectID], "d_gpu_"); targetGPU != "" {
				activeSharedSlices[targetGPU] = true
			}
			cat, desc, w := sliceEvidenceWeight(slice)
			obsStr := ""
			if t := edgeObservedAt(targetEdge); !t.IsZero() {
				obsStr = t.UTC().Format(time.RFC3339)
			}
			evidenceChain = append(evidenceChain, RiskEvidence{
				SliceID:     slice,
				Category:    cat + "_velocity_burst",
				Description: desc + " (clean-beacon velocity burst >= 3 accounts; queued for step-up review)",
				LogOdds:     w,
				ObservedAt:  obsStr,
			})
			logOdds += w
		}
	}

	allSlices := make([]string, 0, len(sliceSet))
	var sharedSlices []string
	for sl := range sliceSet {
		allSlices = append(allSlices, sl)
		if activeSharedSlices[sl] {
			sharedSlices = append(sharedSlices, sl)
		}
	}
	sort.Strings(allSlices)
	sort.Strings(sharedSlices)
	if sharedSlices == nil {
		sharedSlices = []string{}
	}
	for _, sl := range sharedSlices {
		alreadyBurst := false
		for _, ev := range evidenceChain {
			if ev.SliceID == sl {
				alreadyBurst = true
				break
			}
		}
		if alreadyBurst {
			continue
		}
		cat, desc, w := sliceEvidenceWeight(sl)
		obsStr := ""
		if te, ok := subjectEdgeBySlice[targetSubjectID][sl]; ok {
			if t := edgeObservedAt(te); !t.IsZero() {
				obsStr = t.UTC().Format(time.RFC3339)
			}
		}
		evidenceChain = append(evidenceChain, RiskEvidence{
			SliceID:     sl,
			Category:    cat,
			Description: desc,
			LogOdds:     w,
			ObservedAt:  obsStr,
		})
		logOdds += w
	}

	compSpoofTimeStr := ""
	if !compLatestSpoofAt.IsZero() {
		compSpoofTimeStr = compLatestSpoofAt.UTC().Format(time.RFC3339)
	}
	if componentSpoofedActive {
		evidenceChain = append(evidenceChain, RiskEvidence{
			SliceID:     "spoof_trap",
			Category:    "active_tampering_detected",
			Description: "Active client tampering, cross-thread Worker mismatch, or raw noise injection on current observation",
			LogOdds:     5.5,
			ObservedAt:  compSpoofTimeStr,
			Historical:  false,
		})
		logOdds += 5.5
	} else if componentSpoofedCooldown {
		evidenceChain = append(evidenceChain, RiskEvidence{
			SliceID:  "spoof_trap",
			Category: "historical_tampering_cooldown",
			Description: fmt.Sprintf(
				"Prior tampering signal cooling down (%d/%d subsequent clean observations before full recovery)",
				compMinCleanStreak, DefaultCleanObservationsToClearSpoof,
			),
			LogOdds:    2.0,
			ObservedAt: compSpoofTimeStr,
			Historical: true,
		})
		logOdds += 2.0
	} else if historicalDecayed[targetSubjectID] {
		decayedTimeStr := ""
		if !latestSpoofedAt[targetSubjectID].IsZero() {
			decayedTimeStr = latestSpoofedAt[targetSubjectID].UTC().Format(time.RFC3339)
		}
		evidenceChain = append(evidenceChain, RiskEvidence{
			SliceID:     "spoof_trap",
			Category:    "historical_tampering_decayed",
			Description: "Historical tampering signal decayed from active block; retained as residual risk factor",
			LogOdds:     HistoricalSpoofLogOdds,
			ObservedAt:  decayedTimeStr,
			Historical:  true,
		})
		logOdds += HistoricalSpoofLogOdds
	}

	earliest := members[0]
	status := RiskStatusGreen
	riskPending := false

	targetHasBeacon := false
	sharesHardWithMember := false
	sharesNativeHardWithMember := false
	nonEarliestStorageHealed := false
	for _, mid := range members {
		if mid != earliest && subjectStorageHealed[mid] {
			nonEarliestStorageHealed = true
		}
	}
	for sl := range subjectSlices[targetSubjectID] {
		if strings.HasPrefix(sl, "d_bcn_") {
			targetHasBeacon = true
		}
		if isPerDeviceHardSlice(sl) && policy != HardAnchorPolicyDisabled {
			for _, otherSID := range members {
				if otherSID != targetSubjectID {
					if _, ok := subjectSlices[otherSID][sl]; ok {
						sharesHardWithMember = true
						if isNativeHardSlice(sl) {
							sharesNativeHardWithMember = true
						}
						break
					}
				}
			}
		}
	}

	if len(members) > 1 {
		if spoofedActive[targetSubjectID] {
			status = RiskStatusRed
		} else if targetHasBeacon && !sharesHardWithMember {
			// Clean user with its own distinct beacon pulled into component ONLY via soft slice:
			status = RiskStatusYellow
			riskPending = true
		} else if componentSpoofedActive {
			status = RiskStatusRed
		} else if sharesHardWithMember && !nonEarliestStorageHealed &&
			(policy == HardAnchorPolicyStepUpAll ||
				(policy == HardAnchorPolicySharedStepUp && !sharesNativeHardWithMember && len(members) <= DefaultSharedHardAnchorMaxAccounts)) {
			// S1-2 Fix: Legitimate shared household/lab browser profile (no cookie-wiping StorageHealed
			// resurrection and no client tampering) elevates to yellow + RiskPending=true for step-up
			// verification rather than banning the 2nd family member as red.
			status = RiskStatusYellow
			riskPending = true
		} else if targetSubjectID == earliest {
			status = RiskStatusYellow
			if componentSpoofedCooldown {
				riskPending = true
			}
		} else {
			status = RiskStatusRed
		}
	} else if componentSpoofedActive {
		status = RiskStatusRed
	} else if componentSpoofedCooldown {
		status = RiskStatusYellow
		riskPending = true
	} else if burstSuspicion {
		status = RiskStatusYellow
		riskPending = true
	}

	logOdds = math.Round(logOdds*100) / 100

	return ComponentSnapshot{
		SubjectID:         targetSubjectID,
		RiskStatus:        status,
		RiskPending:       riskPending,
		BurstSuspicion:    burstSuspicion,
		LogOddsScore:      logOdds,
		EarliestSubjectID: earliest,
		ComponentSubjects: members,
		SliceIDs:          allSlices,
		SharedSliceIDs:    sharedSlices,
		EvidenceChain:     evidenceChain,
	}
}

func findSubjectPrefixSlice(slices map[string]struct{}, prefix string) string {
	var matches []string
	for sl := range slices {
		if strings.HasPrefix(sl, prefix) {
			matches = append(matches, sl)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[0]
}
