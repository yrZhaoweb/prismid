package prismid

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SQLDialect specifies SQL parameter placeholder syntax (`$1` for PostgreSQL/CockroachDB vs `?` for SQLite/MySQL).
type SQLDialect string

const (
	SQLDialectPostgres SQLDialect = "postgres"
	SQLDialectSQLite   SQLDialect = "sqlite"
)

// SQLGraphStore persists multi-million-subject RiskGraph edges, TOFU device-key bindings,
// beacon ownership, and security audit logs in any standard-library `*sql.DB` (PostgreSQL,
// CockroachDB, or SQLite) with zero third-party dependencies in `prismid-go`.
type SQLGraphStore struct {
	db      *sql.DB
	dialect SQLDialect
	nowFunc func() time.Time
}

// NewSQLGraphStore wraps an opened `*sql.DB` with the specified SQLDialect (defaults to SQLDialectPostgres).
func NewSQLGraphStore(db *sql.DB, dialect SQLDialect) (*SQLGraphStore, error) {
	if db == nil {
		return nil, errors.New("sql.DB is required")
	}
	switch dialect {
	case "", SQLDialectPostgres:
		dialect = SQLDialectPostgres
	case SQLDialectSQLite:
	default:
		return nil, fmt.Errorf("unsupported SQL dialect %q", dialect)
	}
	return &SQLGraphStore{
		db:      db,
		dialect: dialect,
		nowFunc: time.Now,
	}, nil
}

func (s *SQLGraphStore) ph(index1Based int) string {
	if s.dialect == SQLDialectPostgres {
		return fmt.Sprintf("$%d", index1Based)
	}
	return "?"
}

// InitSchema creates the PrismID graph, TOFU binding, beacon ownership, and audit tables and indexes if absent.
func (s *SQLGraphStore) InitSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS prismid_graph_edges (
			subject_id TEXT NOT NULL,
			slice_id TEXT NOT NULL,
			observed_at_ms BIGINT NOT NULL,
			edge_json TEXT NOT NULL,
			PRIMARY KEY (subject_id, slice_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_prismid_graph_edges_slice ON prismid_graph_edges (slice_id, observed_at_ms DESC)`,
		`CREATE TABLE IF NOT EXISTS prismid_beacon_bindings (
			beacon_slice_id TEXT PRIMARY KEY,
			device_key_slice_id TEXT NOT NULL,
			updated_at_ms BIGINT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS prismid_beacon_owners (
			beacon_slice_id TEXT NOT NULL,
			subject_id TEXT NOT NULL,
			updated_at_ms BIGINT NOT NULL,
			PRIMARY KEY (beacon_slice_id, subject_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_prismid_beacon_owners_subject ON prismid_beacon_owners (subject_id)`,
		`CREATE TABLE IF NOT EXISTS prismid_audit_events (
			audit_id TEXT PRIMARY KEY,
			created_at_ms BIGINT NOT NULL,
			event_json TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_prismid_audit_events_created ON prismid_audit_events (created_at_ms DESC)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	return nil
}

// UpsertGraphEdges writes or updates `(subject_id, slice_id)` edges in a single SQL transaction.
func (s *SQLGraphStore) UpsertGraphEdges(ctx context.Context, edges []GraphEdge) error {
	if len(edges) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	query := fmt.Sprintf(
		`INSERT INTO prismid_graph_edges (subject_id, slice_id, observed_at_ms, edge_json) VALUES (%s, %s, %s, %s)
		 ON CONFLICT (subject_id, slice_id) DO UPDATE SET observed_at_ms = EXCLUDED.observed_at_ms, edge_json = EXCLUDED.edge_json`,
		s.ph(1), s.ph(2), s.ph(3), s.ph(4),
	)
	for _, e := range edges {
		if e.SubjectID == "" || e.SliceID == "" {
			continue
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		obsMs := edgeObservedAt(e).UnixMilli()
		if _, err := tx.ExecContext(ctx, query, e.SubjectID, e.SliceID, obsMs, string(raw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteGraphEdges removes specific `(subjectID, sliceID)` edges.
func (s *SQLGraphStore) DeleteGraphEdges(ctx context.Context, subjectID string, sliceIDs ...string) error {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" || len(sliceIDs) == 0 {
		return nil
	}
	query := fmt.Sprintf(`DELETE FROM prismid_graph_edges WHERE subject_id = %s AND slice_id = %s`, s.ph(1), s.ph(2))
	for _, sl := range sliceIDs {
		sl = strings.TrimSpace(sl)
		if sl == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, query, subjectID, sl); err != nil {
			return err
		}
	}
	return nil
}

// DeleteSubjectGraphEdges deletes all graph edges for `subjectID`.
func (s *SQLGraphStore) DeleteSubjectGraphEdges(ctx context.Context, subjectID string) error {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil
	}
	query := fmt.Sprintf(`DELETE FROM prismid_graph_edges WHERE subject_id = %s`, s.ph(1))
	_, err := s.db.ExecContext(ctx, query, subjectID)
	return err
}

// LoadGraphNeighborhood queries the 2-hop bipartite neighborhood around `seedSubjectID` and `extraSliceIDs`.
func (s *SQLGraphStore) LoadGraphNeighborhood(ctx context.Context, seedSubjectID string, extraSliceIDs []string, maxSubjects int) ([]GraphEdge, error) {
	if maxSubjects <= 0 {
		maxSubjects = MaxComponentSize
	}
	seedSubjectID = strings.TrimSpace(seedSubjectID)
	sliceSet := make(map[string]struct{})
	for _, sl := range extraSliceIDs {
		if trimmed := strings.TrimSpace(sl); trimmed != "" {
			sliceSet[trimmed] = struct{}{}
		}
	}

	var edges []GraphEdge
	seenSubjects := make(map[string]struct{})

	if seedSubjectID != "" {
		seenSubjects[seedSubjectID] = struct{}{}
		qSeed := fmt.Sprintf(`SELECT edge_json FROM prismid_graph_edges WHERE subject_id = %s`, s.ph(1))
		rows, err := s.db.QueryContext(ctx, qSeed, seedSubjectID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err == nil {
				var e GraphEdge
				if json.Unmarshal([]byte(raw), &e) == nil && e.SubjectID != "" && e.SliceID != "" {
					edges = append(edges, e)
					sliceSet[e.SliceID] = struct{}{}
				}
			}
		}
		_ = rows.Close()
	}

	if len(sliceSet) == 0 {
		return edges, nil
	}

	slices := make([]string, 0, len(sliceSet))
	for sl := range sliceSet {
		slices = append(slices, sl)
	}
	sort.Strings(slices)

	var peerSubjects []string
	qSlice := fmt.Sprintf(`SELECT subject_id FROM prismid_graph_edges WHERE slice_id = %s ORDER BY observed_at_ms DESC LIMIT %d`, s.ph(1), MaxSubjectsPerSlice)
	for _, sl := range slices {
		rows, err := s.db.QueryContext(ctx, qSlice, sl)
		if err != nil {
			return edges, err
		}
		for rows.Next() {
			var sid string
			if rows.Scan(&sid) == nil && sid != "" {
				if _, seen := seenSubjects[sid]; !seen {
					seenSubjects[sid] = struct{}{}
					peerSubjects = append(peerSubjects, sid)
					if len(seenSubjects) >= maxSubjects {
						break
					}
				}
			}
		}
		_ = rows.Close()
		if len(seenSubjects) >= maxSubjects {
			break
		}
	}

	sort.Strings(peerSubjects)
	qPeer := fmt.Sprintf(`SELECT edge_json FROM prismid_graph_edges WHERE subject_id = %s`, s.ph(1))
	for _, sid := range peerSubjects {
		rows, err := s.db.QueryContext(ctx, qPeer, sid)
		if err != nil {
			return edges, err
		}
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) == nil {
				var e GraphEdge
				if json.Unmarshal([]byte(raw), &e) == nil && e.SubjectID != "" && e.SliceID != "" {
					edges = append(edges, e)
				}
			}
		}
		_ = rows.Close()
	}
	return edges, nil
}

// CheckOrBindBeaconDeviceKey enforces atomic TOFU binding in SQL via `ON CONFLICT DO NOTHING`.
func (s *SQLGraphStore) CheckOrBindBeaconDeviceKey(ctx context.Context, beaconSliceID, deviceKeySliceID string) (bool, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	deviceKeySliceID = strings.TrimSpace(deviceKeySliceID)
	if beaconSliceID == "" {
		return true, nil
	}
	if deviceKeySliceID == "" {
		bound, err := s.GetBoundBeaconDeviceKey(ctx, beaconSliceID)
		if err != nil {
			return false, err
		}
		return bound == "", nil
	}
	ins := fmt.Sprintf(
		`INSERT INTO prismid_beacon_bindings (beacon_slice_id, device_key_slice_id, updated_at_ms) VALUES (%s, %s, %s) ON CONFLICT (beacon_slice_id) DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3),
	)
	if _, err := s.db.ExecContext(ctx, ins, beaconSliceID, deviceKeySliceID, s.nowFunc().UnixMilli()); err != nil {
		return false, err
	}
	bound, err := s.GetBoundBeaconDeviceKey(ctx, beaconSliceID)
	if err != nil {
		return false, err
	}
	return bound == "" || bound == deviceKeySliceID, nil
}

// GetBoundBeaconDeviceKey returns the currently bound `d_key_*` slice for `beaconSliceID`.
func (s *SQLGraphStore) GetBoundBeaconDeviceKey(ctx context.Context, beaconSliceID string) (string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if beaconSliceID == "" {
		return "", nil
	}
	q := fmt.Sprintf(`SELECT device_key_slice_id FROM prismid_beacon_bindings WHERE beacon_slice_id = %s`, s.ph(1))
	var keySlice string
	err := s.db.QueryRowContext(ctx, q, beaconSliceID).Scan(&keySlice)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return keySlice, err
}

// RebindBeaconDeviceKey replaces the TOFU device-key binding for `beaconSliceID` inside a SQL transaction.
func (s *SQLGraphStore) RebindBeaconDeviceKey(ctx context.Context, beaconSliceID, newDeviceKeySliceID string) (string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	newDeviceKeySliceID = strings.TrimSpace(newDeviceKeySliceID)
	if beaconSliceID == "" || newDeviceKeySliceID == "" {
		return "", errors.New("beacon_slice_id and new_device_key_slice_id are required")
	}
	prev, err := s.GetBoundBeaconDeviceKey(ctx, beaconSliceID)
	if err != nil {
		return "", err
	}
	q := fmt.Sprintf(
		`INSERT INTO prismid_beacon_bindings (beacon_slice_id, device_key_slice_id, updated_at_ms) VALUES (%s, %s, %s)
		 ON CONFLICT (beacon_slice_id) DO UPDATE SET device_key_slice_id = EXCLUDED.device_key_slice_id, updated_at_ms = EXCLUDED.updated_at_ms`,
		s.ph(1), s.ph(2), s.ph(3),
	)
	_, err = s.db.ExecContext(ctx, q, beaconSliceID, newDeviceKeySliceID, s.nowFunc().UnixMilli())
	return prev, err
}

// ClearBeaconDeviceKey removes the TOFU device-key binding for `beaconSliceID`.
func (s *SQLGraphStore) ClearBeaconDeviceKey(ctx context.Context, beaconSliceID string) (string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if beaconSliceID == "" {
		return "", errors.New("beacon_slice_id is required")
	}
	prev, err := s.GetBoundBeaconDeviceKey(ctx, beaconSliceID)
	if err != nil {
		return "", err
	}
	q := fmt.Sprintf(`DELETE FROM prismid_beacon_bindings WHERE beacon_slice_id = %s`, s.ph(1))
	_, err = s.db.ExecContext(ctx, q, beaconSliceID)
	return prev, err
}

// RecordBeaconOwner records `(beaconSliceID, subjectID)` ownership in SQL.
func (s *SQLGraphStore) RecordBeaconOwner(ctx context.Context, beaconSliceID, subjectID string) error {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	subjectID = strings.TrimSpace(subjectID)
	if beaconSliceID == "" || subjectID == "" {
		return nil
	}
	q := fmt.Sprintf(
		`INSERT INTO prismid_beacon_owners (beacon_slice_id, subject_id, updated_at_ms) VALUES (%s, %s, %s)
		 ON CONFLICT (beacon_slice_id, subject_id) DO UPDATE SET updated_at_ms = EXCLUDED.updated_at_ms`,
		s.ph(1), s.ph(2), s.ph(3),
	)
	_, err := s.db.ExecContext(ctx, q, beaconSliceID, subjectID, s.nowFunc().UnixMilli())
	return err
}

// GetBeaconOwners returns sorted subject IDs owning `beaconSliceID`.
func (s *SQLGraphStore) GetBeaconOwners(ctx context.Context, beaconSliceID string) ([]string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if beaconSliceID == "" {
		return nil, nil
	}
	q := fmt.Sprintf(`SELECT subject_id FROM prismid_beacon_owners WHERE beacon_slice_id = %s ORDER BY subject_id ASC`, s.ph(1))
	rows, err := s.db.QueryContext(ctx, q, beaconSliceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err == nil && sid != "" {
			owners = append(owners, sid)
		}
	}
	return owners, rows.Err()
}

// RemoveSubjectBeaconOwnership removes `subjectID` from all beacon ownership rows.
func (s *SQLGraphStore) RemoveSubjectBeaconOwnership(ctx context.Context, subjectID string) ([]string, []string, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, nil, nil
	}
	qList := fmt.Sprintf(`SELECT beacon_slice_id FROM prismid_beacon_owners WHERE subject_id = %s ORDER BY beacon_slice_id ASC`, s.ph(1))
	rows, err := s.db.QueryContext(ctx, qList, subjectID)
	if err != nil {
		return nil, nil, err
	}
	var beacons []string
	for rows.Next() {
		var bcn string
		if rows.Scan(&bcn) == nil && bcn != "" {
			beacons = append(beacons, bcn)
		}
	}
	_ = rows.Close()
	if len(beacons) == 0 {
		return nil, nil, nil
	}

	qDel := fmt.Sprintf(`DELETE FROM prismid_beacon_owners WHERE subject_id = %s`, s.ph(1))
	if _, err := s.db.ExecContext(ctx, qDel, subjectID); err != nil {
		return nil, beacons, err
	}
	var orphaned []string
	for _, bcn := range beacons {
		rem, err := s.GetBeaconOwners(ctx, bcn)
		if err == nil && len(rem) == 0 {
			orphaned = append(orphaned, bcn)
		}
	}
	return orphaned, beacons, nil
}

// AppendAuditEvent persists a structured security audit record to `prismid_audit_events`.
func (s *SQLGraphStore) AppendAuditEvent(ctx context.Context, ev KeyRebindAuditEvent) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	q := fmt.Sprintf(
		`INSERT INTO prismid_audit_events (audit_id, created_at_ms, event_json) VALUES (%s, %s, %s) ON CONFLICT (audit_id) DO NOTHING`,
		s.ph(1), s.ph(2), s.ph(3),
	)
	_, err = s.db.ExecContext(ctx, q, ev.AuditID, ev.Timestamp.UnixMilli(), string(raw))
	return err
}

// ListAuditEvents returns up to `limit` most recent audit events ordered chronologically.
func (s *SQLGraphStore) ListAuditEvents(ctx context.Context, limit int) ([]KeyRebindAuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	q := fmt.Sprintf(`SELECT event_json FROM prismid_audit_events ORDER BY created_at_ms DESC LIMIT %d`, limit)
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var desc []KeyRebindAuditEvent
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) == nil {
			var ev KeyRebindAuditEvent
			if json.Unmarshal([]byte(raw), &ev) == nil {
				desc = append(desc, ev)
			}
		}
	}
	for i, j := 0, len(desc)-1; i < j; i, j = i+1, j-1 {
		desc[i], desc[j] = desc[j], desc[i]
	}
	return desc, rows.Err()
}
