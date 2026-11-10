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

// Default velocity windows, burst thresholds, and graph capacity bounds.
const (
	DefaultGPUBurstWindow        = 25 * time.Minute
	DefaultWebProfileWindow      = 2 * time.Hour
	DefaultSameNetFarmingWindow  = 6 * time.Hour
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
	SubjectID         string         `json:"subject_id"`
	RiskStatus        string         `json:"risk_status"`
	RiskPending       bool           `json:"risk_pending"`
	BurstSuspicion    bool           `json:"burst_suspicion,omitempty"`
	Truncated         bool           `json:"truncated,omitempty"`
	LogOddsScore      float64        `json:"log_odds_score"`
	EarliestSubjectID string         `json:"earliest_subject_id,omitempty"`
	ComponentSubjects []string       `json:"component_subjects"`
	SliceIDs          []string       `json:"slice_ids"`
	SharedSliceIDs    []string       `json:"shared_slice_ids"`
	EvidenceChain     []RiskEvidence `json:"evidence_chain,omitempty"`
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
//       native anchors (d_nat_A != d_nat_B) are NEVER merged into the same identity component
//       by shared model/network soft slices, and are NEVER marked red by soft slices alone.
//     - When >= 3 distinct clean-beacon accounts share d_gpusys_* (within 6h) or d_web_* (within 25m),
//       the graph sets BurstSuspicion=true, RiskPending=true, and elevates green -> yellow for
//       step-up verification without falsely merging colleagues into a red identity component.
//     - Soft slices merge into ComponentSubjects ONLY when active tampering (SpoofTraphit=true)
//       is detected on that hardware slice, or when both accounts lack a storage beacon in
//       stateless/blocked-storage mode within the burst window.
type RiskGraph struct {
	mu           sync.RWMutex
	minConf      float64
	maxSubjects  int
	subjectOrder []string
	subjectEdges map[string]map[string]GraphEdge
	sliceEdges   map[string]map[string]GraphEdge
}

// NewRiskGraph creates a standalone thread-safe, deduplicated, capacity-bounded risk graph.
func NewRiskGraph(minConfidence float64) *RiskGraph {
	if minConfidence <= 0 {
		minConfidence = AuthoritativeConfidenceThreshold
	}
	return &RiskGraph{
		minConf:      minConfidence,
		maxSubjects:  DefaultMaxGraphSubjects,
		subjectOrder: make([]string, 0, 256),
		subjectEdges: make(map[string]map[string]GraphEdge),
		sliceEdges:   make(map[string]map[string]GraphEdge),
	}
}

// RecordVerification records or updates a subject's orthogonal slices from a VerifyResult
// and returns the updated ComponentSnapshot for that subject.
func (g *RiskGraph) RecordVerification(subjectID string, subjectCreatedAt time.Time, res *VerifyResult) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	if subjectCreatedAt.IsZero() {
		subjectCreatedAt = time.Now().UTC()
	}

	g.mu.Lock()
	if res != nil && res.Accepted && subjectID != "" {
		if _, exists := g.subjectEdges[subjectID]; !exists {
			if g.maxSubjects > 0 && len(g.subjectEdges) >= g.maxSubjects && len(g.subjectOrder) > 0 {
				oldest := g.subjectOrder[0]
				g.subjectOrder = g.subjectOrder[1:]
				g.removeSubjectLocked(oldest)
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
				// Enforce per-subject slice bound (evict a soft slice so hard anchors are preserved):
				evictSlice := ""
				for existingSlice := range subjMap {
					if !isPerDeviceHardSlice(existingSlice) {
						evictSlice = existingSlice
						break
					}
				}
				if evictSlice == "" {
					for existingSlice := range subjMap {
						evictSlice = existingSlice
						break
					}
				}
				if evictSlice != "" {
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
		snap.Truncated = true
		snap.RiskPending = true
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
		snap.Truncated = true
		snap.RiskPending = true
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
}

// collectLocalSubgraphEdgesLocked extracts the connected identity component of targetSubjectID
// across all hops of hard identity / tampered slices (up to MaxComponentSize=512, avoiding
// 3-hop truncation on chains like A-B-C-D-E), plus 1-hop soft-slice neighbors for burst counting.
// The returned edges slice is deterministically sorted by (SubjectCreatedAt, SubjectID, SliceID).
func (g *RiskGraph) collectLocalSubgraphEdgesLocked(targetSubjectID string) ([]GraphEdge, bool) {
	if targetSubjectID == "" {
		return nil, false
	}
	if _, ok := g.subjectEdges[targetSubjectID]; !ok {
		return nil, false
	}

	visitedSubjects := map[string]bool{targetSubjectID: true}
	visitedHardSlices := make(map[string]bool)
	frontier := []string{targetSubjectID}
	truncated := false

	// Phase 1: Full multi-hop BFS across hard identity slices and tampered slices (no 3-hop limit!)
	for len(frontier) > 0 && !truncated {
		sort.Strings(frontier)
		var nextFrontier []string
		for _, sid := range frontier {
			for sliceID, edge := range g.subjectEdges[sid] {
				if visitedHardSlices[sliceID] {
					continue
				}
				canMultiHop := isPerDeviceHardSlice(sliceID) || edge.SpoofTraphit || !edge.HasBeacon
				if !canMultiHop {
					continue
				}
				visitedHardSlices[sliceID] = true
				for neighborSID, neighborEdge := range g.sliceEdges[sliceID] {
					if !isPerDeviceHardSlice(sliceID) && !edge.SpoofTraphit && !neighborEdge.SpoofTraphit &&
						(edge.HasBeacon && neighborEdge.HasBeacon) {
						continue
					}
					if !visitedSubjects[neighborSID] {
						if len(visitedSubjects) >= MaxComponentSize {
							truncated = true
							break
						}
						visitedSubjects[neighborSID] = true
						nextFrontier = append(nextFrontier, neighborSID)
					}
				}
				if truncated {
					break
				}
			}
			if truncated {
				break
			}
		}
		frontier = nextFrontier
	}

	// Phase 2: Include 1-hop soft-slice neighbors of targetSubjectID so velocity burst density
	// on d_gpusys_* / d_web_* / d_gpu_* can be evaluated deterministically.
	for sliceID := range g.subjectEdges[targetSubjectID] {
		if visitedHardSlices[sliceID] {
			continue
		}
		for neighborSID := range g.sliceEdges[sliceID] {
			if !visitedSubjects[neighborSID] {
				if len(visitedSubjects) >= MaxComponentSize {
					truncated = true
					break
				}
				visitedSubjects[neighborSID] = true
			}
		}
	}

	out := make([]GraphEdge, 0, len(visitedSubjects)*4)
	for sid := range visitedSubjects {
		for _, edge := range g.subjectEdges[sid] {
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

// shouldMergeStatelessOrSpoofed determines whether two consecutive observations `a` and `b`
// on a soft slice should merge into the same identity connected component.
// Note: Accounts with distinct, un-spoofed beacons (hasDifferentCleanBeacons == true) NEVER
// merge into ComponentSubjects via soft slices; instead they are evaluated by velocity scoring.
func shouldMergeStatelessOrSpoofed(slice string, a, b GraphEdge) bool {
	if isPerDeviceHardSlice(slice) {
		return true
	}
	if hasDifferentCleanNativeAnchors(a, b) {
		return false
	}
	if a.SpoofTraphit || b.SpoofTraphit {
		// Active spoofing/tampering trap triggered on shared hardware slice:
		if strings.HasPrefix(slice, "d_gpu_") || strings.HasPrefix(slice, "d_web_") || strings.HasPrefix(slice, "d_gpusys_") {
			return true
		}
		return false
	}
	// Never merge two accounts with distinct clean beacons on a soft slice (GPT R2 & DeepSeek #3):
	if hasDifferentCleanBeacons(a, b) {
		return false
	}

	dt := a.SubjectCreatedAt.Sub(b.SubjectCreatedAt)
	if dt < 0 {
		dt = -dt
	}

	// Stateless / no-beacon observations (or identical beacon):
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
			linked := false
			for k := 1; k < len(obsList); k++ {
				if obsList[k].SubjectID != firstSID {
					union(firstSID, obsList[k].SubjectID)
					linked = true
				}
			}
			if linked {
				activeSharedSlices[slice] = true
			}
			continue
		}

		// For soft slices:
		// 1) Any observation with SpoofTraphit=true merges with compatible observations on this hardware slice in O(N)
		var spoofedAnchor *GraphEdge
		for idx := range obsList {
			if obsList[idx].SpoofTraphit {
				spoofedAnchor = &obsList[idx]
				break
			}
		}
		if spoofedAnchor != nil && (strings.HasPrefix(slice, "d_gpu_") || strings.HasPrefix(slice, "d_web_") || strings.HasPrefix(slice, "d_gpusys_")) {
			linked := false
			for k := 0; k < len(obsList); k++ {
				if obsList[k].SubjectID == spoofedAnchor.SubjectID {
					continue
				}
				if !hasDifferentCleanNativeAnchors(*spoofedAnchor, obsList[k]) {
					union(spoofedAnchor.SubjectID, obsList[k].SubjectID)
					linked = true
				}
			}
			if linked {
				activeSharedSlices[slice] = true
			}
		}

		// 2) Stateless / no-beacon observations sorted by SubjectCreatedAt link adjacent items in O(N)
		var statelessObs []GraphEdge
		for _, o := range obsList {
			if !o.HasBeacon && !o.SpoofTraphit {
				statelessObs = append(statelessObs, o)
			}
		}
		for k := 1; k < len(statelessObs); k++ {
			a, b := statelessObs[k-1], statelessObs[k]
			if a.SubjectID != b.SubjectID && shouldMergeStatelessOrSpoofed(slice, a, b) {
				union(a.SubjectID, b.SubjectID)
				activeSharedSlices[slice] = true
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
		} else if strings.HasPrefix(slice, "d_web_") {
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

	if len(members) > 1 {
		if componentSpoofed {
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
