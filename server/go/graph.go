package prismid

import (
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

// Default velocity windows and burst thresholds for conditional soft-slice promotion.
const (
	DefaultGPUBurstWindow        = 25 * time.Minute
	DefaultWebProfileWindow      = 2 * time.Hour
	DefaultSameNetFarmingWindow  = 6 * time.Hour
	DefaultCleanBeaconBurstCount = 3
	DefaultMaxGraphSubjects      = 50000
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
}

// ComponentSnapshot describes the connected component and risk decision for a subject.
type ComponentSnapshot struct {
	SubjectID         string   `json:"subject_id"`
	RiskStatus        string   `json:"risk_status"`
	RiskPending       bool     `json:"risk_pending"`
	EarliestSubjectID string   `json:"earliest_subject_id,omitempty"`
	ComponentSubjects []string `json:"component_subjects"`
	SliceIDs          []string `json:"slice_ids"`
	SharedSliceIDs    []string `json:"shared_slice_ids"`
}

// RiskGraph evaluates connected components over deduplicated (SubjectID, SliceID) bipartite
// observations using a strict Identity-Anchor vs. Shared-Model separation model:
//
//  1. Per-Device Identity Slices (Always link unconditionally when Confidence >= 0.60):
//     - d_nat_* (Desktop Motherboard UUID + Serial + Keychain)
//     - d_kch_* (Desktop OS Keychain / Registry persistent anchor)
//     - d_bcn_* (Web 128-bit 5-Silo Self-Healing Cryptographic Storage Beacon)
//
//  2. Shared Model / Environment Soft Slices (d_gpu_*, d_web_*, d_sys_*, d_gpusys_*):
//     - Two accounts that possess distinct, un-spoofed native anchors (d_nat_A != d_nat_B)
//     are NEVER merged by model-level d_gpu_* or network-level d_sys_*.
//     - Two accounts that possess distinct, un-spoofed Web beacons (d_bcn_A != d_bcn_B)
//     are NEVER merged pairwise by model-level d_gpu_* or d_gpusys_* (preventing false
//     positives between colleagues with company-issued MacBooks or strangers registering
//     simultaneously across cities).
//     - Soft slices promote to active links ONLY when:
//     a) Active tampering / lie trap was triggered (SpoofTraphit == true), OR
//     b) Beacons are absent/stripped in stateless mode within the burst window, OR
//     c) A multi-account Incognito farming batch (>= 3 distinct-beacon accounts sharing the
//     exact same hardware/environment profile) arrives within the burst window.
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

		slices := make([]string, 0, 6)
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
			}
			if prev, ok := g.subjectEdges[subjectID][sliceID]; ok {
				if !prev.SubjectCreatedAt.IsZero() && prev.SubjectCreatedAt.Before(edge.SubjectCreatedAt) {
					edge.SubjectCreatedAt = prev.SubjectCreatedAt
				}
				if prev.SpoofTraphit {
					edge.SpoofTraphit = true
				}
				if prev.Confidence > edge.Confidence {
					edge.Confidence = prev.Confidence
				}
			}
			g.subjectEdges[subjectID][sliceID] = edge
			if g.sliceEdges[sliceID] == nil {
				g.sliceEdges[sliceID] = make(map[string]GraphEdge)
			}
			g.sliceEdges[sliceID][subjectID] = edge
		}
	}
	subEdges := g.collectLocalSubgraphEdgesLocked(subjectID)
	g.mu.Unlock()

	return EvaluateSubjectComponent(subEdges, subjectID, g.minConf)
}

// EvaluateSubject returns the current ComponentSnapshot for a subject using bounded local subgraph traversal.
func (g *RiskGraph) EvaluateSubject(subjectID string) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	g.mu.RLock()
	subEdges := g.collectLocalSubgraphEdgesLocked(subjectID)
	g.mu.RUnlock()
	return EvaluateSubjectComponent(subEdges, subjectID, g.minConf)
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

// collectLocalSubgraphEdgesLocked extracts only the connected neighborhood of targetSubjectID
// (up to 3 hops) so evaluation does not copy or scan unrelated subjects across the entire graph.
func (g *RiskGraph) collectLocalSubgraphEdgesLocked(targetSubjectID string) []GraphEdge {
	if targetSubjectID == "" {
		return nil
	}
	if _, ok := g.subjectEdges[targetSubjectID]; !ok {
		return nil
	}

	visitedSubjects := map[string]bool{targetSubjectID: true}
	visitedSlices := make(map[string]bool)
	frontier := []string{targetSubjectID}

	for hop := 0; hop < 3 && len(frontier) > 0; hop++ {
		var nextFrontier []string
		for _, sid := range frontier {
			for sliceID := range g.subjectEdges[sid] {
				if visitedSlices[sliceID] {
					continue
				}
				visitedSlices[sliceID] = true
				for neighborSID := range g.sliceEdges[sliceID] {
					if !visitedSubjects[neighborSID] {
						visitedSubjects[neighborSID] = true
						nextFrontier = append(nextFrontier, neighborSID)
					}
				}
			}
		}
		frontier = nextFrontier
	}

	out := make([]GraphEdge, 0, len(visitedSubjects)*4)
	for sid := range visitedSubjects {
		for _, edge := range g.subjectEdges[sid] {
			out = append(out, edge)
		}
	}
	return out
}

func isPerDeviceHardSlice(slice string) bool {
	return strings.HasPrefix(slice, "d_nat_") ||
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

// shouldLinkOnSliceWithContext determines whether two observations `a` and `b` sharing `slice`
// should be merged into the same connected component, taking into account the burst density
// (`burstClusterCount`) on that slice when distinct clean beacons are present.
func shouldLinkOnSliceWithContext(slice string, a, b GraphEdge, burstClusterCount int) bool {
	// 1. Per-device unique anchors (Motherboard UUID, OS Keychain, 128-bit 5-silo Beacon) always link:
	if isPerDeviceHardSlice(slice) {
		return true
	}

	// 2. Two distinct un-spoofed Desktop Native machines (d_nat_A != d_nat_B) never merge on soft slices:
	if hasDifferentCleanNativeAnchors(a, b) {
		return false
	}

	// 3. If either observation triggered an active spoofing/lie/noise trap, promote shared hardware slices:
	if a.SpoofTraphit || b.SpoofTraphit {
		return true
	}

	dt := a.SubjectCreatedAt.Sub(b.SubjectCreatedAt)
	if dt < 0 {
		dt = -dt
	}

	// 4. When both observations carry distinct, intact Web beacons (d_bcn_A != d_bcn_B) and no spoof traps:
	//    - Never merge a pair of users (burstClusterCount < 3) on shared model/network slices!
	//      This guarantees 0% false positives when 2 office colleagues use identical company MacBooks
	//      or 2 strangers in different cities register within 5 minutes of each other.
	//    - Only link when a multi-account Incognito farming batch (>= 3 distinct-beacon accounts)
	//      accumulates within the farming window on the same hardware/network slice.
	if hasDifferentCleanBeacons(a, b) {
		if burstClusterCount < DefaultCleanBeaconBurstCount {
			return false
		}
		if strings.HasPrefix(slice, "d_gpusys_") {
			return dt <= DefaultSameNetFarmingWindow
		}
		if strings.HasPrefix(slice, "d_web_") {
			return dt <= DefaultGPUBurstWindow
		}
		return false
	}

	// 5. Stateless / no-beacon observations (BeaconSliceID == ""):
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
		return (!a.HasBeacon || !b.HasBeacon) && dt <= DefaultGPUBurstWindow
	}

	return false
}

// countSliceBurstSubjects counts how many distinct subjects observed on `slice` fall within `window`
// of `refTime`. Used to distinguish a 2-person coincidence from a >=3-account Incognito farming batch.
func countSliceBurstSubjects(obs []GraphEdge, refTime time.Time, window time.Duration) int {
	seen := make(map[string]struct{}, len(obs))
	for _, o := range obs {
		dt := o.SubjectCreatedAt.Sub(refTime)
		if dt < 0 {
			dt = -dt
		}
		if dt <= window {
			seen[o.SubjectID] = struct{}{}
		}
	}
	return len(seen)
}

// EvaluateSubjectComponent is a pure, stateless function that computes the connected component
// and risk color for targetSubjectID from a slice of GraphEdges with Confidence >= minConf.
func EvaluateSubjectComponent(edges []GraphEdge, targetSubjectID string, minConf float64) ComponentSnapshot {
	if minConf <= 0 {
		minConf = AuthoritativeConfidenceThreshold
	}
	targetSubjectID = strings.TrimSpace(targetSubjectID)
	empty := ComponentSnapshot{
		SubjectID:         targetSubjectID,
		RiskStatus:        RiskStatusUnknown,
		RiskPending:       true,
		ComponentSubjects: []string{},
		SliceIDs:          []string{},
		SharedSliceIDs:    []string{},
	}
	if targetSubjectID == "" {
		return empty
	}

	parent := make(map[string]string)
	createdAt := make(map[string]time.Time)
	spoofed := make(map[string]bool)
	sliceObs := make(map[string][]GraphEdge)
	subjectSlices := make(map[string]map[string]struct{})
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

	// First pass: group valid observations by slice and initialize subject nodes
	for _, e := range edges {
		if e.Confidence < minConf {
			continue
		}
		sid := strings.TrimSpace(e.SubjectID)
		slice := strings.TrimSpace(e.SliceID)
		if sid == "" || slice == "" {
			continue
		}
		if _, ok := parent[sid]; !ok {
			parent[sid] = sid
		}
		if prev, ok := createdAt[sid]; !ok || (!e.SubjectCreatedAt.IsZero() && e.SubjectCreatedAt.Before(prev)) {
			createdAt[sid] = e.SubjectCreatedAt
		}
		if e.SpoofTraphit {
			spoofed[sid] = true
		}
		sliceObs[slice] = append(sliceObs[slice], e)

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

	// Second pass: evaluate links per slice with full burst-count context
	for slice, obsList := range sliceObs {
		if len(obsList) < 2 {
			continue
		}
		window := DefaultGPUBurstWindow
		if strings.HasPrefix(slice, "d_gpusys_") {
			window = DefaultSameNetFarmingWindow
		} else if strings.HasPrefix(slice, "d_web_") {
			window = DefaultWebProfileWindow
		}

		for i := 0; i < len(obsList); i++ {
			e := obsList[i]
			burstCount := countSliceBurstSubjects(obsList, e.SubjectCreatedAt, window)
			for j := 0; j < i; j++ {
				prevObs := obsList[j]
				if prevObs.SubjectID == e.SubjectID {
					continue
				}
				if shouldLinkOnSliceWithContext(slice, e, prevObs, burstCount) {
					ra, rb := find(e.SubjectID), find(prevObs.SubjectID)
					if ra != rb {
						parent[ra] = rb
					}
					activeSharedSlices[slice] = true
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

	sort.Slice(members, func(i, j int) bool {
		ti, tj := createdAt[members[i]], createdAt[members[j]]
		if ti.Equal(tj) {
			return members[i] < members[j]
		}
		return ti.Before(tj)
	})

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

	earliest := members[0]
	status := RiskStatusGreen
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
	}

	return ComponentSnapshot{
		SubjectID:         targetSubjectID,
		RiskStatus:        status,
		RiskPending:       false,
		EarliestSubjectID: earliest,
		ComponentSubjects: members,
		SliceIDs:          allSlices,
		SharedSliceIDs:    sharedSlices,
	}
}
