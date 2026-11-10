package prismid

import (
	"math"
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

// Default velocity windows, edge TTLs, burst thresholds, and graph capacity bounds.
const (
	DefaultGPUBurstWindow        = 25 * time.Minute
	DefaultWebProfileWindow      = 2 * time.Hour
	DefaultSameNetFarmingWindow  = 6 * time.Hour
	DefaultSpoofEdgeTTL          = 24 * time.Hour
	DefaultSoftEdgeTTL           = 7 * 24 * time.Hour
	DefaultCleanBeaconBurstCount = 3
	DefaultMaxGraphSubjects      = 50000
	MaxSlicesPerSubject          = 16
	MaxSubjectsPerSlice          = 256
	MaxComponentSize             = 512
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
	SliceID          string    `json:"slice_id"`
	Confidence       float64   `json:"confidence"`
	SpoofTraphit     bool      `json:"spoof_trap_hit,omitempty"`
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

// RiskGraph evaluates connected components over deduplicated (SubjectID, SliceID) bipartite
// observations using a strict Hard-Identity vs. Soft-Velocity separation model:
//
//  1. Per-Device Hard Identity Slices (Always merge into ComponentSubjects when Confidence >= 0.60):
//     - d_key_* (WebCrypto ECDSA P-256 non-extractable private key attestation)
//     - d_nat_* (Desktop Motherboard UUID + Serial + Keychain)
//     - d_kch_* (Desktop OS Keychain / Registry persistent anchor)
//     - d_bcn_* (Web 128-bit 5-Silo Self-Healing Cryptographic Storage Beacon)
//
//  2. Shared Model / Environment Soft Slices (d_gpu_*, d_web_*, d_sys_*, d_gpusys_*):
//     - Accounts possessing distinct, un-spoofed hard beacons (d_bcn_A != d_bcn_B) or distinct
//     native anchors (d_nat_A != d_nat_B) are NEVER merged into the same identity component
//     by shared model/network soft slices, and are NEVER marked red by soft slices alone.
//     - When >= 3 distinct clean-beacon accounts share d_gpusys_* (within 6h) or d_web_* (within 25m),
//     the graph sets BurstSuspicion=true, RiskPending=true, and elevates green -> yellow for
//     step-up verification without falsely merging colleagues into a red identity component.
//     - Soft slices merge into ComponentSubjects ONLY when active tampering (SpoofTraphit=true)
//     is detected on that hardware slice, or when both accounts lack a storage beacon in
//     stateless/blocked-storage mode within the burst window.
type RiskGraph struct {
	mu                 sync.RWMutex
	minConf            float64
	maxSubjects        int
	subjectOrder       []string
	subjectEdges       map[string]map[string]GraphEdge
	sliceEdges         map[string]map[string]GraphEdge
	incompleteSubjects map[string]bool
	incompleteSlices   map[string]bool
	historyIncomplete  bool
}

// NewRiskGraph creates a standalone thread-safe, deduplicated, capacity-bounded risk graph.
func NewRiskGraph(minConfidence float64) *RiskGraph {
	if minConfidence <= 0 {
		minConfidence = AuthoritativeConfidenceThreshold
	}
	return &RiskGraph{
		minConf:            minConfidence,
		maxSubjects:        DefaultMaxGraphSubjects,
		subjectOrder:       make([]string, 0, 256),
		subjectEdges:       make(map[string]map[string]GraphEdge),
		sliceEdges:         make(map[string]map[string]GraphEdge),
		incompleteSubjects: make(map[string]bool),
		incompleteSlices:   make(map[string]bool),
	}
}

// RecordVerification records or updates a subject's orthogonal slices from a VerifyResult
// and returns the updated ComponentSnapshot for that subject.
func (g *RiskGraph) RecordVerification(subjectID string, subjectCreatedAt time.Time, res *VerifyResult) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	if res != nil && res.DeviceKeyRecoveryRequired {
		// Recovery cannot overwrite authoritative history or link a claimed identity.
		snap := EvaluateSubjectComponent(nil, subjectID, g.minConf)
		snap.DeviceKeyRecoveryRequired = true
		return snap
	}
	if subjectCreatedAt.IsZero() {
		subjectCreatedAt = time.Now().UTC()
	}

	g.mu.Lock()
	if res != nil && res.Accepted && subjectID != "" {
		if _, exists := g.subjectEdges[subjectID]; !exists {
			if g.maxSubjects > 0 && len(g.subjectEdges) >= g.maxSubjects && len(g.subjectOrder) > 0 {
				g.mu.Unlock()
				return markIncompleteSnapshot(EvaluateSubjectComponent(nil, subjectID, g.minConf))
			}
			g.subjectOrder = append(g.subjectOrder, subjectID)
			g.subjectEdges[subjectID] = make(map[string]GraphEdge)
		}

		hasBeacon := strings.TrimSpace(res.BeaconSliceID) != ""
		var nativeSliceID string
		if res.IsNative && strings.HasPrefix(res.ExactSliceID, "d_nat_") {
			nativeSliceID = res.ExactSliceID
		}

		slices := make([]string, 0, 7)
		slices = append(slices, res.SliceNodes()...)
		if res.GpuAudioSliceID != "" && res.SysNetSliceID != "" {
			slices = append(slices, "d_gpusys_"+res.GpuAudioSliceID[6:]+"_"+res.SysNetSliceID[6:])
		}

		for _, sliceID := range slices {
			sliceID = strings.TrimSpace(sliceID)
			if sliceID == "" {
				continue
			}
			edge := GraphEdge{
				SubjectID:        subjectID,
				SubjectCreatedAt: subjectCreatedAt,
				SliceID:          sliceID,
				Confidence:       res.Confidence,
				SpoofTraphit:     res.SpoofTrapTriggered,
				HasBeacon:        hasBeacon,
				BeaconSliceID:    res.BeaconSliceID,
				NativeSliceID:    nativeSliceID,
				DeviceKeySliceID: res.DeviceKeySliceID,
			}
			subjMap := g.subjectEdges[subjectID]
			if prev, ok := subjMap[sliceID]; ok {
				if !prev.SubjectCreatedAt.IsZero() && prev.SubjectCreatedAt.Before(edge.SubjectCreatedAt) {
					edge.SubjectCreatedAt = prev.SubjectCreatedAt
				}
				if prev.SpoofTraphit {
					edge.SpoofTraphit = true
				}
				if prev.Confidence > edge.Confidence {
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
						g.markEvidenceLossLocked(subjectID, evictSlice)
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
				// Preserve the earliest subject on the slice when evicting to bound per-slice fanout:
				var earliestSID string
				var earliestTime time.Time
				for sid, e := range smap {
					if earliestSID == "" || e.SubjectCreatedAt.Before(earliestTime) ||
						(e.SubjectCreatedAt.Equal(earliestTime) && sid < earliestSID) {
						earliestSID = sid
						earliestTime = e.SubjectCreatedAt
					}
				}
				var evictSID string
				var oldestNonEarliest time.Time
				for sid, e := range smap {
					if sid == earliestSID {
						continue
					}
					if evictSID == "" || e.SubjectCreatedAt.Before(oldestNonEarliest) ||
						(e.SubjectCreatedAt.Equal(oldestNonEarliest) && sid < evictSID) {
						evictSID = sid
						oldestNonEarliest = e.SubjectCreatedAt
					}
				}
				if evictSID != "" {
					if isPerDeviceHardSlice(sliceID) {
						g.markEvidenceLossLocked(evictSID, sliceID)
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
	subEdges, truncated := g.collectLocalSubgraphEdgesLocked(subjectID)
	g.mu.Unlock()

	snap := EvaluateSubjectComponent(subEdges, subjectID, g.minConf)
	if truncated {
		return markIncompleteSnapshot(snap)
	}
	return snap
}

// EvaluateSubject returns the current ComponentSnapshot for a subject using bounded local subgraph traversal.
func (g *RiskGraph) EvaluateSubject(subjectID string) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	g.mu.RLock()
	subEdges, truncated := g.collectLocalSubgraphEdgesLocked(subjectID)
	g.mu.RUnlock()
	snap := EvaluateSubjectComponent(subEdges, subjectID, g.minConf)
	if truncated {
		return markIncompleteSnapshot(snap)
	}
	return snap
}

// RemoveSubject deletes all graph observations for a subject (supporting GDPR/CCPA erasure requests).
func (g *RiskGraph) RemoveSubject(subjectID string) bool {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.subjectEdges[subjectID]; !exists {
		return false
	}
	g.removeSubjectLocked(subjectID)
	for i, sid := range g.subjectOrder {
		if sid == subjectID {
			g.subjectOrder = append(g.subjectOrder[:i], g.subjectOrder[i+1:]...)
			break
		}
	}
	return true
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

// Retain bounded loss markers even if an evicted slice no longer has cached edges.
// A subsequent observation must not mistake forgotten evidence for a clean first visit.
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
// Soft neighbors that can merge enter the queue and expand their hard anchors too.
func (g *RiskGraph) collectLocalSubgraphEdgesLocked(targetSubjectID string) ([]GraphEdge, bool) {
	if targetSubjectID == "" {
		return nil, false
	}
	if _, ok := g.subjectEdges[targetSubjectID]; !ok {
		return nil, false
	}
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
			edge := g.subjectEdges[sid][slice]
			if edge.Confidence < g.minConf {
				continue
			}
			hard := isPerDeviceHardSlice(slice)
			if hard && processedHard[slice] {
				continue
			}
			if hard {
				processedHard[slice] = true
			}
			for _, neighbor := range sortedNeighbors(slice) {
				next := g.sliceEdges[slice][neighbor]
				if visited[neighbor] || next.Confidence < g.minConf ||
					!shouldMergeStatelessOrSpoofed(slice, edge, next) {
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
		targetEdge := g.subjectEdges[targetSubjectID][slice]
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
			next := g.sliceEdges[slice][neighbor]
			if next.Confidence < g.minConf {
				continue
			}
			dt := next.SubjectCreatedAt.Sub(targetEdge.SubjectCreatedAt)
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
		for slice, edge := range g.subjectEdges[sid] {
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

func hasDifferentCleanNativeAnchors(a, b GraphEdge) bool {
	if a.SpoofTraphit || b.SpoofTraphit {
		return false
	}
	return a.NativeSliceID != "" && b.NativeSliceID != "" && a.NativeSliceID != b.NativeSliceID
}

func hasDifferentCleanBeacons(a, b GraphEdge) bool {
	if a.SpoofTraphit || b.SpoofTraphit {
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

// shouldMergeStatelessOrSpoofed determines whether two observations `a` and `b`
// on a soft slice should merge into the same identity connected component.
//
// P0 Invariant (DeepSeek v0.5 Review):
//   - A spoofed observation (SpoofTraphit=true) NEVER unconditionally merges across a model-wide
//     slice (d_gpu_* / d_web_*), which would allow one privacy-extension user or griefing attacker
//     to poison all clean users of the same laptop model.
//   - Instead, a spoofed observation on a soft slice merges ONLY when:
//     1) The two observations share a hard anchor (d_bcn_*, d_key_*, d_nat_*), OR
//     2) They share the same /24 subnet + GPU/OS (d_gpusys_*) within DefaultGPUBurstWindow (25m), OR
//     3) Both observations are stateless (no storage beacon) within DefaultGPUBurstWindow (25m);
//     AND their time delta is within DefaultSpoofEdgeTTL (24h).
func shouldMergeStatelessOrSpoofed(slice string, a, b GraphEdge) bool {
	if isPerDeviceHardSlice(slice) {
		return true
	}
	if hasDifferentCleanNativeAnchors(a, b) {
		return false
	}

	dt := a.SubjectCreatedAt.Sub(b.SubjectCreatedAt)
	if dt < 0 {
		dt = -dt
	}
	// Soft-slice edges expire after DefaultSoftEdgeTTL (7 days) to prevent permanent slice poisoning:
	if dt > DefaultSoftEdgeTTL {
		return false
	}

	if a.SpoofTraphit || b.SpoofTraphit {
		// Spoofed soft-slice edges expire after DefaultSpoofEdgeTTL (24 hours):
		if dt > DefaultSpoofEdgeTTL {
			return false
		}
		if sharesHardAnchorOnEdge(a, b) {
			return true
		}
		if a.SpoofTraphit && b.SpoofTraphit &&
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
	// Never merge two accounts with distinct clean beacons on a soft slice (GPT R2 & DeepSeek #3):
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

// countDistinctSubjectsInWindow counts how many distinct non-native-conflicting subjects on `obs`
// have observations within `window` of `refTime`. Because `obs` is canonical-sorted, this is
// 100% deterministic and order-invariant (fixing GPT R1).
func countDistinctSubjectsInWindow(obs []GraphEdge, refEdge GraphEdge, window time.Duration) int {
	seen := make(map[string]struct{}, len(obs))
	for _, o := range obs {
		if hasDifferentCleanNativeAnchors(refEdge, o) {
			continue
		}
		dt := o.SubjectCreatedAt.Sub(refEdge.SubjectCreatedAt)
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

// EvaluateSubjectComponent is a pure, deterministic, permutation-invariant function that computes
// the connected identity component, calibrated log-odds score, evidence chain, and risk status
// for targetSubjectID from a slice of GraphEdges with Confidence >= minConf.
func EvaluateSubjectComponent(edges []GraphEdge, targetSubjectID string, minConf float64) ComponentSnapshot {
	if minConf <= 0 {
		minConf = AuthoritativeConfidenceThreshold
	}
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

	// Canonical-sort a copy of input edges by (SubjectCreatedAt, SubjectID, SliceID) so that
	// any permutation of input edges produces the exact same output (GPT R1 fix).
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
		sortedEdges = append(sortedEdges, e)
	}
	sortGraphEdgesCanonical(sortedEdges)

	parent := make(map[string]string)
	createdAt := make(map[string]time.Time)
	spoofed := make(map[string]bool)
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
		if e.SpoofTraphit {
			spoofed[sid] = true
		}
		if subjectEdgeBySlice[sid] == nil {
			subjectEdgeBySlice[sid] = make(map[string]GraphEdge)
		}
		if prevEdge, exists := subjectEdgeBySlice[sid][slice]; exists {
			if !prevEdge.SubjectCreatedAt.IsZero() && prevEdge.SubjectCreatedAt.Before(e.SubjectCreatedAt) {
				e.SubjectCreatedAt = prevEdge.SubjectCreatedAt
			}
			if prevEdge.SpoofTraphit {
				e.SpoofTraphit = true
			}
			subjectEdgeBySlice[sid][slice] = e
		} else {
			subjectEdgeBySlice[sid][slice] = e
			sliceObs[slice] = append(sliceObs[slice], e)
		}

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

	// Collect all slice keys in sorted order for deterministic processing
	sliceKeys := make([]string, 0, len(sliceObs))
	for slice := range sliceObs {
		sliceKeys = append(sliceKeys, slice)
	}
	sort.Strings(sliceKeys)

	// Second pass: O(N) linear Union-Find per slice for hard identity & tampered/stateless links
	for _, slice := range sliceKeys {
		obsList := sliceObs[slice]
		if len(obsList) < 2 {
			continue
		}
		if isPerDeviceHardSlice(slice) {
			// Linear O(N) union across all observations sharing this per-device hard anchor:
			firstSID := obsList[0].SubjectID
			for k := 1; k < len(obsList); k++ {
				if obsList[k].SubjectID != firstSID {
					union(firstSID, obsList[k].SubjectID)
				}
			}
			continue
		}

		// For soft slices: evaluate bounded sliding-window pairs (obsList is canonical-sorted by SubjectCreatedAt)
		// using shouldMergeStatelessOrSpoofed so spoofed observations NEVER poison unrelated clean users across d_gpu_*/d_web_*.
		for i := 0; i < len(obsList); i++ {
			a := obsList[i]
			for j := i + 1; j < len(obsList); j++ {
				b := obsList[j]
				if b.SubjectCreatedAt.Sub(a.SubjectCreatedAt) > DefaultSoftEdgeTTL {
					break
				}
				if a.SubjectID != b.SubjectID && shouldMergeStatelessOrSpoofed(slice, a, b) {
					union(a.SubjectID, b.SubjectID)
				}
			}
		}
	}

	targetRoot := find(targetSubjectID)
	var members []string
	sliceSet := make(map[string]struct{})
	componentSpoofed := false

	for sid := range parent {
		if find(sid) == targetRoot {
			members = append(members, sid)
			if spoofed[sid] {
				componentSpoofed = true
			}
			for sl := range subjectSlices[sid] {
				sliceSet[sl] = struct{}{}
			}
		}
	}

	// Mark activeSharedSlices ONLY for slices shared by >= 2 members inside targetRoot's component:
	for _, slice := range sliceKeys {
		inTargetComp := 0
		for _, e := range sliceObs[slice] {
			if find(e.SubjectID) == targetRoot {
				inTargetComp++
			}
		}
		if inTargetComp >= 2 {
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

	// Evaluate soft-slice velocity burst around targetSubjectID for distinct clean-beacon accounts:
	// Importantly, this NEVER merges ComponentSubjects or marks red (fixing GPT R2 & DeepSeek #3);
	// instead it sets BurstSuspicion=true, RiskPending=true, and elevates green -> yellow.
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
			evidenceChain = append(evidenceChain, RiskEvidence{
				SliceID:     slice,
				Category:    cat + "_velocity_burst",
				Description: desc + " (clean-beacon velocity burst >= 3 accounts; queued for step-up review)",
				LogOdds:     w,
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
			cat, desc, w := sliceEvidenceWeight(sl)
			evidenceChain = append(evidenceChain, RiskEvidence{
				SliceID:     sl,
				Category:    cat,
				Description: desc,
				LogOdds:     w,
			})
			logOdds += w
		}
	}
	sort.Strings(allSlices)
	sort.Strings(sharedSlices)
	if sharedSlices == nil {
		sharedSlices = []string{}
	}

	if componentSpoofed {
		evidenceChain = append(evidenceChain, RiskEvidence{
			SliceID:     "spoof_trap",
			Category:    "active_tampering_detected",
			Description: "Active client tampering, cross-thread Worker mismatch, raw noise injection, or device-key TOFU violation",
			LogOdds:     5.5,
		})
		logOdds += 5.5
	}

	earliest := members[0]
	status := RiskStatusGreen
	riskPending := false

	targetHasBeacon := false
	sharesHardWithMember := false
	for sl := range subjectSlices[targetSubjectID] {
		if strings.HasPrefix(sl, "d_bcn_") {
			targetHasBeacon = true
		}
		if isPerDeviceHardSlice(sl) {
			for _, otherSID := range members {
				if otherSID != targetSubjectID {
					if _, ok := subjectSlices[otherSID][sl]; ok {
						sharesHardWithMember = true
						break
					}
				}
			}
		}
	}

	if len(members) > 1 {
		if spoofed[targetSubjectID] {
			status = RiskStatusRed
		} else if targetHasBeacon && !sharesHardWithMember {
			// P0 Fix (DeepSeek v0.5 Review): A clean user with its own distinct beacon who was
			// pulled into a component ONLY via a soft slice (d_gpusys_* within 25m on the same /24)
			// due to a spoofed neighbor is capped at yellow + RiskPending=true (never red).
			status = RiskStatusYellow
			riskPending = true
		} else if componentSpoofed {
			status = RiskStatusRed
		} else if targetSubjectID == earliest {
			status = RiskStatusYellow
		} else {
			status = RiskStatusRed
		}
	} else if componentSpoofed {
		// Single account with active spoofing/tampering trap triggered
		status = RiskStatusRed
	} else if burstSuspicion {
		// Clean-beacon velocity burst on shared hardware/network slice:
		// Elevate to yellow + RiskPending=true for step-up verification; NEVER mark red!
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
