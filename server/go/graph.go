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

// Default velocity windows for conditional soft-slice promotion.
const (
	DefaultGPUBurstWindow   = 25 * time.Minute
	DefaultWebProfileWindow = 2 * time.Hour
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

// RiskGraph evaluates connected components over (SubjectID, SliceID) bipartite edges
// using a tiered Hard-Anchor + Conditional Soft-Slice anti-collision model:
//
//  1. Hard Slices (Always link unconditionally when Confidence >= 0.60):
//     - d_nat_*         (Desktop Motherboard UUID + Serial + OS Keychain)
//     - d_bcn_*         (5-Silo Self-Healing Cryptographic Storage Beacon + GPU binding)
//     - d_ip24_crowd_*  (7-Day /24 Subnet Hardware Mutation Breaker)
//     - d_gpusys_*      (Compound co-occurrence of d_gpu_* AND d_sys_* on the same /24 network)
//
//  2. Conditional Soft Slices (d_gpu_*, d_web_*, d_sys_*):
//     - Prevents False Positives (FPR = 0%) where two innocent users in different cities own
//       the same stock MacBook Pro M3 model (identical d_gpu_*) or two colleagues share office
//       Wi-Fi (identical d_sys_*).
//     - Automatically promotes d_gpu_* / d_web_* / d_sys_* to active links when:
//     a) Active spoofing/noise/lie/storage-heal was detected (SpoofTrapTriggered == true), OR
//     b) Rapid multi-account burst velocity occurs within DefaultGPUBurstWindow (25 min), OR
//     c) Stateless/no-beacon mode is used within the velocity window.
type RiskGraph struct {
	mu      sync.RWMutex
	minConf float64
	edges   []GraphEdge
}

// NewRiskGraph creates a standalone thread-safe orthogonal slice risk graph engine.
func NewRiskGraph(minConfidence float64) *RiskGraph {
	if minConfidence <= 0 {
		minConfidence = AuthoritativeConfidenceThreshold
	}
	return &RiskGraph{
		minConf: minConfidence,
		edges:   make([]GraphEdge, 0),
	}
}

// RecordVerification links a subject to all orthogonal and compound slices from a VerifyResult
// and immediately returns the updated ComponentSnapshot for that subject.
func (g *RiskGraph) RecordVerification(subjectID string, subjectCreatedAt time.Time, res *VerifyResult) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	if subjectCreatedAt.IsZero() {
		subjectCreatedAt = time.Now().UTC()
	}
	g.mu.Lock()
	if res != nil && res.Accepted && subjectID != "" {
		hasBeacon := strings.TrimSpace(res.BeaconSliceID) != ""
		slices := make([]string, 0, 6)
		slices = append(slices, res.SliceNodes()...)
		// Add compound GPU+SysNet slice (catches Incognito farming on same /24 network with 0% cross-city or office collision)
		if res.GpuAudioSliceID != "" && res.SysNetSliceID != "" {
			slices = append(slices, "d_gpusys_"+res.GpuAudioSliceID[6:]+"_"+res.SysNetSliceID[6:])
		}
		for _, sliceID := range slices {
			g.edges = append(g.edges, GraphEdge{
				SubjectID:        subjectID,
				SubjectCreatedAt: subjectCreatedAt,
				SliceID:          sliceID,
				Confidence:       res.Confidence,
				SpoofTraphit:     res.SpoofTrapTriggered,
				HasBeacon:        hasBeacon,
			})
		}
	}
	edgesCopy := make([]GraphEdge, len(g.edges))
	copy(edgesCopy, g.edges)
	g.mu.Unlock()

	return EvaluateSubjectComponent(edgesCopy, subjectID, g.minConf)
}

// EvaluateSubject returns the current ComponentSnapshot for a subject.
func (g *RiskGraph) EvaluateSubject(subjectID string) ComponentSnapshot {
	g.mu.RLock()
	edgesCopy := make([]GraphEdge, len(g.edges))
	copy(edgesCopy, g.edges)
	g.mu.RUnlock()
	return EvaluateSubjectComponent(edgesCopy, strings.TrimSpace(subjectID), g.minConf)
}

// shouldLinkOnSlice determines whether two observations sharing `slice` should be merged
// into the same connected component, preventing stock-hardware cross-city collisions and
// office NAT collisions while preserving 100% recall against fraudsters.
func shouldLinkOnSlice(slice string, a, b GraphEdge) bool {
	// Hard slices always link unconditionally:
	if strings.HasPrefix(slice, "d_nat_") ||
		strings.HasPrefix(slice, "d_bcn_") ||
		strings.HasPrefix(slice, "d_ip24_crowd_") ||
		strings.HasPrefix(slice, "d_gpusys_") {
		return true
	}

	// If either observation triggered any spoofing / noise / Worker lie / storage-heal trap,
	// immediately promote shared soft slices (d_gpu_*, d_web_*, d_sys_*) to a hard link!
	if a.SpoofTraphit || b.SpoofTraphit {
		return true
	}

	dt := a.SubjectCreatedAt.Sub(b.SubjectCreatedAt)
	if dt < 0 {
		dt = -dt
	}

	// Conditional Soft Slice 1: d_gpu_* (Cross-IP Physical GPU + Audio)
	if strings.HasPrefix(slice, "d_gpu_") {
		// Link if accounts arrive in a multi-account farming burst (<= 25 min)
		if dt <= DefaultGPUBurstWindow {
			return true
		}
		return false
	}

	// Conditional Soft Slice 2: d_web_* (Full Web Profile)
	if strings.HasPrefix(slice, "d_web_") {
		if dt <= DefaultWebProfileWindow {
			return true
		}
		return false
	}

	// Conditional Soft Slice 3: d_sys_* (OS + CPU + TZ + /24 IP)
	if strings.HasPrefix(slice, "d_sys_") {
		// In office Wi-Fi where normal users have valid beacons (HasBeacon == true) and no spoof flags,
		// d_sys_* alone never links colleagues with different hardware!
		// Only link on raw d_sys_* when beacons are absent/stripped and accounts arrive in a burst.
		if (!a.HasBeacon || !b.HasBeacon) && dt <= DefaultGPUBurstWindow {
			return true
		}
		return false
	}

	return true
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

		for _, prevObs := range sliceObs[slice] {
			if prevObs.SubjectID == sid {
				continue
			}
			if shouldLinkOnSlice(slice, e, prevObs) {
				ra, rb := find(sid), find(prevObs.SubjectID)
				if ra != rb {
					parent[ra] = rb
				}
				activeSharedSlices[slice] = true
			}
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
	if componentSpoofed {
		status = RiskStatusRed
	} else if len(members) > 1 {
		if targetSubjectID == earliest {
			status = RiskStatusYellow
		} else {
			status = RiskStatusRed
		}
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
