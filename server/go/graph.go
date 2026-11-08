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

// GraphSubject represents an account/user node in the orthogonal slice risk graph.
type GraphSubject struct {
	SubjectID string    `json:"subject_id"`
	CreatedAt time.Time `json:"created_at"`
}

// GraphEdge represents an observed association between a subject and a device slice node.
type GraphEdge struct {
	SubjectID         string    `json:"subject_id"`
	SubjectCreatedAt  time.Time `json:"subject_created_at"`
	SliceID           string    `json:"slice_id"`
	Confidence        float64   `json:"confidence"`
	SpoofTraphit      bool      `json:"spoof_trap_hit,omitempty"`
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

// RiskGraph evaluates connected components over (SubjectID, SliceID) bipartite edges.
//
// Any two subjects sharing at least one authoritative orthogonal slice (Confidence >= 0.60,
// such as d_nat_*, d_web_*, d_gpu_*, d_sys_*, or d_ip24_crowd_*) are transitively merged
// into the same connected component:
//   - No authoritative slice (e.g., virtual GPU Confidence 0.30) -> "unknown" (RiskPending = true)
//   - Singleton component (1 subject, no spoof trap)             -> "green"
//   - Multi-subject component, earliest registered subject       -> "yellow"
//   - Multi-subject component, later registered subject(s)       -> "red"
//   - Subject that triggered an active spoof/honeypot trap       -> "red"
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

// RecordVerification links a subject to all orthogonal slices from a VerifyResult
// and immediately returns the updated ComponentSnapshot for that subject.
func (g *RiskGraph) RecordVerification(subjectID string, subjectCreatedAt time.Time, res *VerifyResult) ComponentSnapshot {
	subjectID = strings.TrimSpace(subjectID)
	if subjectCreatedAt.IsZero() {
		subjectCreatedAt = time.Now().UTC()
	}
	g.mu.Lock()
	if res != nil && res.Accepted && subjectID != "" {
		for _, sliceID := range res.SliceNodes() {
			g.edges = append(g.edges, GraphEdge{
				SubjectID:        subjectID,
				SubjectCreatedAt: subjectCreatedAt,
				SliceID:          sliceID,
				Confidence:       res.Confidence,
				SpoofTraphit:     res.SpoofTrapTriggered,
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
	sliceSubjects := make(map[string]map[string]struct{})
	subjectSlices := make(map[string]map[string]struct{})

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
		if sliceSubjects[slice] == nil {
			sliceSubjects[slice] = make(map[string]struct{})
		}
		for other := range sliceSubjects[slice] {
			ra, rb := find(sid), find(other)
			if ra != rb {
				parent[ra] = rb
			}
			break
		}
		sliceSubjects[slice][sid] = struct{}{}

		if subjectSlices[sid] == nil {
			subjectSlices[sid] = make(map[string]struct{})
		}
		subjectSlices[sid][slice] = struct{}{}
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
		if len(sliceSubjects[sl]) > 1 {
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
