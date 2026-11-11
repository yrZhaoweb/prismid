package prismid

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GraphSnapshot is a versioned, deterministic serialization of RiskGraph state for persistence
// across server restarts or multi-instance synchronization (DeepSeek S1-4).
type GraphSnapshot struct {
	Version            int                 `json:"version"`
	SavedAt            time.Time           `json:"saved_at"`
	MinConfidence      float64             `json:"min_confidence"`
	HardAnchorPolicy   HardAnchorPolicy    `json:"hard_anchor_policy"`
	LastObservedAt     time.Time           `json:"last_observed_at,omitempty"`
	SubjectOrder       []string            `json:"subject_order"`
	Edges              []GraphEdge         `json:"edges"`
	IncompleteSubjects []string            `json:"incomplete_subjects,omitempty"`
	IncompleteSlices   []string            `json:"incomplete_slices,omitempty"`
	HistoryIncomplete  bool                `json:"history_incomplete,omitempty"`
	PendingRecovery    map[string][]string `json:"pending_recovery,omitempty"`
}

// ChallengeStoreSnapshot is a versioned serialization of persistent anti-spoofing and TOFU state
// in MemoryChallengeStore (beacon-to-key bindings, beacon owners, native split sets, and subnet GPUs).
type ChallengeStoreSnapshot struct {
	Version      int                         `json:"version"`
	SavedAt      time.Time                   `json:"saved_at"`
	BeaconToKey  map[string]string           `json:"beacon_to_key"`
	BeaconSeenAt map[string]int64            `json:"beacon_seen_at,omitempty"`
	BeaconOwners map[string]map[string]int64 `json:"beacon_owners,omitempty"`
	GPUToNative  map[string][]string         `json:"gpu_to_native,omitempty"`
	SubnetToGPU  map[string]map[string]int64 `json:"subnet_to_gpu,omitempty"`
}

// ReplayGuardSnapshot persists consumed single-use step-up JTIs and revoked bearer tokens/subjects
// so restarts do not reopen the 5-minute step-up replay window or un-revoke tokens (DeepSeek P3-2).
type ReplayGuardSnapshot struct {
	ConsumedStepUp  map[string]int64 `json:"consumed_step_up,omitempty"`
	RevokedTokenSHA map[string]int64 `json:"revoked_token_sha,omitempty"`
	RevokedSubjects map[string]int64 `json:"revoked_subjects,omitempty"`
}

// PersistedEngineState bundles RiskGraph, ChallengeStore, and ReplayGuard snapshots for atomic single-file storage.
type PersistedEngineState struct {
	Version        int                     `json:"version"`
	SavedAt        time.Time               `json:"saved_at"`
	Graph          *GraphSnapshot          `json:"graph,omitempty"`
	ChallengeStore *ChallengeStoreSnapshot `json:"challenge_store,omitempty"`
	ReplayGuard    *ReplayGuardSnapshot    `json:"replay_guard,omitempty"`
}

// StateWALOp enumerates incremental append-only write-ahead log operations (DeepSeek P1).
type StateWALOp string

const (
	WALOpIdentify      StateWALOp = "identify"
	WALOpRebind        StateWALOp = "rebind"
	WALOpClearSpoof    StateWALOp = "clear_spoof"
	WALOpEraseSubject  StateWALOp = "erase_subject"
	WALOpPrune         StateWALOp = "prune"
	WALOpConsumeStepUp StateWALOp = "consume_stepup"
	WALOpRevokeToken   StateWALOp = "revoke_token"
)

// StateWALRecord is a compact O(1) (~300-700B) JSONL mutation record appended to `<state-file>.wal`
// so `/identify` never serializes or fsyncs the full RiskGraph on the HTTP request path (DeepSeek P1).
type StateWALRecord struct {
	Op            StateWALOp    `json:"op"`
	At            time.Time     `json:"at"`
	SubjectID     string        `json:"sid,omitempty"`
	BeaconSliceID string        `json:"bcn,omitempty"`
	KeySliceID    string        `json:"key,omitempty"`
	OwnerRecorded bool          `json:"own,omitempty"`
	VerifyResult  *VerifyResult `json:"res,omitempty"`
	JTI           string        `json:"jti,omitempty"`
	TokenSHAHex   string        `json:"tsha,omitempty"`
	ExpUnix       int64         `json:"exp,omitempty"`
}

// GraphStore abstracts durable persistence for RiskGraph state (e.g. FileStateStore, Redis, PostgreSQL).
type GraphStore interface {
	LoadGraphSnapshot(ctx context.Context) (*GraphSnapshot, error)
	SaveGraphSnapshot(ctx context.Context, snap GraphSnapshot) error
}

// AuditStore abstracts durable append-only storage for security audit events (DeepSeek S3-50).
type AuditStore interface {
	AppendAuditEvent(ctx context.Context, ev KeyRebindAuditEvent) error
	ListAuditEvents(ctx context.Context, limit int) ([]KeyRebindAuditEvent, error)
}

const (
	defaultWALCompactRecords = 2048
	defaultWALCompactBytes   = 4 << 20 // 4 MiB
)

// FileStateStore provides crash-safe, O(1) incremental WAL (`<path>.wal`) + background atomic JSON
// snapshot compaction (`0600` permissions) for single-instance deployments (DeepSeek S1-4, P1, P3-2, P3-3, P3-7).
type FileStateStore struct {
	mu                     sync.Mutex
	compactMu              sync.Mutex
	path                   string
	walPath                string
	walCompactPath         string
	walFile                *os.File
	walRecords             int
	walBytes               int64
	dirtySync              bool
	lastCompactAt          time.Time
	minCompactInterval     time.Duration
	compactRecordThreshold int
	compactByteThreshold   int64
	onError                func(error)
	persistErrors          atomic.Uint64

	bgRunning bool
	compactCh chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
}

// NewFileStateStore creates a crash-safe WAL + atomic snapshot file state store at path.
func NewFileStateStore(path string) (*FileStateStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("state file path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	return &FileStateStore{
		path:                   path,
		walPath:                path + ".wal",
		walCompactPath:         path + ".wal.compacting",
		minCompactInterval:     30 * time.Second,
		compactRecordThreshold: defaultWALCompactRecords,
		compactByteThreshold:   defaultWALCompactBytes,
	}, nil
}

// SetErrorHandler registers an error callback invoked whenever a WAL write, sync, or background snapshot fails.
func (fs *FileStateStore) SetErrorHandler(fn func(error)) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.onError = fn
}

// SetCompactionPolicy customizes the minimum interval and WAL size thresholds for background compaction.
func (fs *FileStateStore) SetCompactionPolicy(minInterval time.Duration, maxWALRecords int, maxWALBytes int64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if minInterval > 0 {
		fs.minCompactInterval = minInterval
	}
	if maxWALRecords > 0 {
		fs.compactRecordThreshold = maxWALRecords
	}
	if maxWALBytes > 0 {
		fs.compactByteThreshold = maxWALBytes
	}
}

// PersistErrors returns the total number of WAL or snapshot persistence errors observed.
func (fs *FileStateStore) PersistErrors() uint64 {
	if fs == nil {
		return 0
	}
	return fs.persistErrors.Load()
}

func (fs *FileStateStore) recordError(err error) {
	if err == nil {
		return
	}
	fs.persistErrors.Add(1)
	fs.mu.Lock()
	cb := fs.onError
	fs.mu.Unlock()
	if cb != nil {
		cb(err)
	}
}

func (fs *FileStateStore) ensureWALOpenLocked() error {
	if fs.walFile != nil {
		return nil
	}
	f, err := os.OpenFile(fs.walPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open state wal: %w", err)
	}
	_ = f.Chmod(0o600)
	if info, statErr := f.Stat(); statErr == nil {
		fs.walBytes = info.Size()
	}
	fs.walFile = f
	return nil
}

// AppendWAL appends a single O(1) JSONL mutation record (~300-700 bytes) to `<path>.wal` without
// serializing the full RiskGraph (fixing DeepSeek P1 write amplification).
// When `syncImmediate` is false (used on high-frequency `/identify`), `fsync` is coalesced by the
// background worker; when true (used on low-frequency `rebind`, `clear_spoof`, `consume_stepup`, `revoke`),
// the tiny WAL record is synced immediately.
func (fs *FileStateStore) AppendWAL(rec StateWALRecord, syncImmediate bool) error {
	if rec.At.IsZero() {
		rec.At = time.Now().UTC()
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		wErr := fmt.Errorf("encode wal record: %w", err)
		fs.recordError(wErr)
		return wErr
	}
	raw = append(raw, '\n')

	fs.mu.Lock()
	if err := fs.ensureWALOpenLocked(); err != nil {
		fs.mu.Unlock()
		fs.recordError(err)
		return err
	}
	n, err := fs.walFile.Write(raw)
	if err != nil {
		fs.mu.Unlock()
		wErr := fmt.Errorf("write wal record: %w", err)
		fs.recordError(wErr)
		return wErr
	}
	fs.walRecords++
	fs.walBytes += int64(n)
	fs.dirtySync = true

	var syncErr error
	if syncImmediate {
		syncErr = fs.walFile.Sync()
		if syncErr == nil {
			fs.dirtySync = false
		}
	}

	shouldTriggerCompact := fs.bgRunning &&
		(fs.walRecords >= fs.compactRecordThreshold || fs.walBytes >= fs.compactByteThreshold) &&
		(fs.lastCompactAt.IsZero() || time.Since(fs.lastCompactAt) >= fs.minCompactInterval)
	compactCh := fs.compactCh
	fs.mu.Unlock()

	if syncErr != nil {
		wErr := fmt.Errorf("fsync wal record: %w", syncErr)
		fs.recordError(wErr)
		return wErr
	}
	if shouldTriggerCompact && compactCh != nil {
		select {
		case compactCh <- struct{}{}:
		default:
		}
	}
	return nil
}

// StartBackgroundWorker launches a single background goroutine that coalesces WAL `fsync` calls
// and asynchronously compacts the WAL into `<path>` without blocking HTTP request handlers (DeepSeek P1, P3-7).
func (fs *FileStateStore) StartBackgroundWorker(
	graph *RiskGraph,
	store *MemoryChallengeStore,
	guardProvider func() *ReplayGuardSnapshot,
	walSyncInterval time.Duration,
	minCompactInterval time.Duration,
) {
	if walSyncInterval <= 0 {
		walSyncInterval = 250 * time.Millisecond
	}
	if minCompactInterval <= 0 {
		minCompactInterval = 30 * time.Second
	}
	fs.mu.Lock()
	if fs.bgRunning {
		fs.mu.Unlock()
		return
	}
	fs.minCompactInterval = minCompactInterval
	fs.compactCh = make(chan struct{}, 1)
	fs.stopCh = make(chan struct{})
	fs.doneCh = make(chan struct{})
	fs.bgRunning = true
	compactCh := fs.compactCh
	stopCh := fs.stopCh
	doneCh := fs.doneCh
	fs.mu.Unlock()

	go func() {
		defer close(doneCh)
		syncTicker := time.NewTicker(walSyncInterval)
		compactTicker := time.NewTicker(minCompactInterval)
		defer syncTicker.Stop()
		defer compactTicker.Stop()

		syncWAL := func() {
			fs.mu.Lock()
			var err error
			if fs.dirtySync && fs.walFile != nil {
				err = fs.walFile.Sync()
				if err == nil {
					fs.dirtySync = false
				}
			}
			fs.mu.Unlock()
			if err != nil {
				fs.recordError(fmt.Errorf("background wal sync: %w", err))
			}
		}

		maybeCompact := func(force bool) {
			fs.mu.Lock()
			hasWAL := fs.walRecords > 0 || fs.walBytes > 0
			overSize := fs.walRecords >= fs.compactRecordThreshold || fs.walBytes >= fs.compactByteThreshold
			due := force || overSize || (hasWAL && (fs.lastCompactAt.IsZero() || time.Since(fs.lastCompactAt) >= minCompactInterval))
			fs.mu.Unlock()
			if !due || !hasWAL {
				return
			}
			var gs *ReplayGuardSnapshot
			if guardProvider != nil {
				gs = guardProvider()
			}
			_ = fs.Compact(context.Background(), graph, store, gs)
		}

		for {
			select {
			case <-stopCh:
				syncWAL()
				return
			case <-syncTicker.C:
				syncWAL()
			case <-compactCh:
				maybeCompact(true)
			case <-compactTicker.C:
				maybeCompact(false)
			}
		}
	}()
}

// Compact rotates `<path>.wal` to `<path>.wal.compacting` under a microsecond lock so concurrent
// `/identify` appends never stall, writes a fresh atomic snapshot to `<path>`, and deletes `<path>.wal.compacting`.
func (fs *FileStateStore) Compact(_ context.Context, graph *RiskGraph, store *MemoryChallengeStore, guard *ReplayGuardSnapshot) error {
	fs.compactMu.Lock()
	defer fs.compactMu.Unlock()

	fs.mu.Lock()
	if fs.walFile != nil {
		_ = fs.walFile.Sync()
		_ = fs.walFile.Close()
		fs.walFile = nil
	}
	if _, err := os.Stat(fs.walPath); err == nil {
		_ = os.Rename(fs.walPath, fs.walCompactPath)
	}
	fs.walRecords = 0
	fs.walBytes = 0
	fs.dirtySync = false
	fs.lastCompactAt = time.Now().UTC()
	fs.mu.Unlock()

	state := buildPersistedState(graph, store, guard)
	if err := writeJSONFileAtomic(fs.path, state); err != nil {
		fs.recordError(err)
		return err
	}
	_ = os.Remove(fs.walCompactPath)
	return nil
}

// FlushAndClose stops any background worker, writes a final compacted snapshot, removes WAL files, and closes handles.
func (fs *FileStateStore) FlushAndClose(ctx context.Context, graph *RiskGraph, store *MemoryChallengeStore, guard *ReplayGuardSnapshot) error {
	fs.StopBackgroundWorker()
	return fs.SaveStateWithGuard(ctx, graph, store, guard)
}

// StopBackgroundWorker stops the background WAL sync/compaction goroutine cleanly.
func (fs *FileStateStore) StopBackgroundWorker() {
	fs.mu.Lock()
	if !fs.bgRunning {
		if fs.walFile != nil {
			_ = fs.walFile.Sync()
			_ = fs.walFile.Close()
			fs.walFile = nil
		}
		fs.mu.Unlock()
		return
	}
	stopCh := fs.stopCh
	doneCh := fs.doneCh
	fs.bgRunning = false
	fs.mu.Unlock()

	close(stopCh)
	<-doneCh

	fs.mu.Lock()
	if fs.walFile != nil {
		_ = fs.walFile.Sync()
		_ = fs.walFile.Close()
		fs.walFile = nil
	}
	fs.mu.Unlock()
}

func buildPersistedState(graph *RiskGraph, store *MemoryChallengeStore, guard *ReplayGuardSnapshot) PersistedEngineState {
	state := PersistedEngineState{
		Version:     2,
		SavedAt:     time.Now().UTC(),
		ReplayGuard: guard,
	}
	if graph != nil {
		gs := graph.ExportSnapshot()
		state.Graph = &gs
	}
	if store != nil {
		cs := store.ExportSnapshot()
		state.ChallengeStore = &cs
	}
	return state
}

// SaveState atomically writes RiskGraph and MemoryChallengeStore snapshots and clears superseded WAL files.
func (fs *FileStateStore) SaveState(ctx context.Context, graph *RiskGraph, store *MemoryChallengeStore) error {
	return fs.SaveStateWithGuard(ctx, graph, store, nil)
}

// SaveStateWithGuard atomically writes RiskGraph, MemoryChallengeStore, and ReplayGuard snapshots and clears superseded WAL files.
func (fs *FileStateStore) SaveStateWithGuard(_ context.Context, graph *RiskGraph, store *MemoryChallengeStore, guard *ReplayGuardSnapshot) error {
	fs.compactMu.Lock()
	defer fs.compactMu.Unlock()

	state := buildPersistedState(graph, store, guard)

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.walFile != nil {
		_ = fs.walFile.Close()
		fs.walFile = nil
	}
	if err := writeJSONFileAtomic(fs.path, state); err != nil {
		fs.persistErrors.Add(1)
		if fs.onError != nil {
			fs.onError(err)
		}
		return err
	}
	_ = os.Remove(fs.walCompactPath)
	_ = os.Remove(fs.walPath)
	fs.walRecords = 0
	fs.walBytes = 0
	fs.dirtySync = false
	fs.lastCompactAt = time.Now().UTC()
	return nil
}

func readBaseStateFile(path string) (*PersistedEngineState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var state PersistedEngineState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("decode state file: %w", err)
	}
	return &state, nil
}

func readWALRecordsFromFile(walPath string) ([]StateWALRecord, error) {
	f, err := os.Open(walPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open wal file %s: %w", walPath, err)
	}
	defer f.Close()

	var records []StateWALRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec StateWALRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Tolerate a truncated trailing line caused by an abrupt OS power loss mid-write,
			// while still returning an error if earlier corruption occurred only when strict.
			continue
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan wal file %s: %w", walPath, err)
	}
	return records, nil
}

func applyWALRecords(records []StateWALRecord, graph *RiskGraph, store *MemoryChallengeStore, guard *ReplayGuardSnapshot) {
	ctx := context.Background()
	for _, rec := range records {
		switch rec.Op {
		case WALOpIdentify:
			if store != nil && rec.VerifyResult != nil {
				store.applyIdentifyForWALReplay(rec.VerifyResult, rec.SubjectID, rec.OwnerRecorded, rec.At)
			}
			if graph != nil && rec.SubjectID != "" && rec.VerifyResult != nil {
				graph.RecordVerification(rec.SubjectID, rec.At, rec.VerifyResult)
			}
		case WALOpRebind:
			if store != nil && rec.BeaconSliceID != "" && rec.KeySliceID != "" {
				_, _ = store.RebindBeaconDeviceKey(ctx, rec.BeaconSliceID, rec.KeySliceID)
				if rec.SubjectID != "" {
					_ = store.RecordBeaconOwner(ctx, rec.BeaconSliceID, rec.SubjectID)
				}
			}
			if graph != nil && rec.SubjectID != "" && rec.BeaconSliceID != "" {
				graph.RetireSubjectDeviceKey(rec.SubjectID, rec.BeaconSliceID, "", rec.KeySliceID)
			}
		case WALOpClearSpoof:
			if graph != nil && rec.SubjectID != "" {
				graph.ClearSubjectSpoofAfterStepUp(rec.SubjectID, rec.At)
			}
		case WALOpEraseSubject:
			beaconSet := make(map[string]struct{})
			if graph != nil && rec.SubjectID != "" {
				_, bs := graph.RemoveSubjectAndCollectBeacons(rec.SubjectID)
				for _, b := range bs {
					beaconSet[b] = struct{}{}
				}
			}
			if store != nil && rec.SubjectID != "" {
				_, obs, _ := store.RemoveSubjectBeaconOwnership(ctx, rec.SubjectID)
				for _, b := range obs {
					beaconSet[b] = struct{}{}
				}
				for b := range beaconSet {
					_, _ = store.ClearBeaconDeviceKey(ctx, b)
				}
			}
		case WALOpPrune:
			if graph != nil {
				graph.PruneExpired(rec.At)
			}
		case WALOpConsumeStepUp:
			if guard != nil && rec.JTI != "" {
				if guard.ConsumedStepUp == nil {
					guard.ConsumedStepUp = make(map[string]int64)
				}
				guard.ConsumedStepUp[rec.JTI] = rec.ExpUnix
			}
		case WALOpRevokeToken:
			if guard != nil {
				if rec.TokenSHAHex != "" {
					if guard.RevokedTokenSHA == nil {
						guard.RevokedTokenSHA = make(map[string]int64)
					}
					guard.RevokedTokenSHA[rec.TokenSHAHex] = rec.ExpUnix
				}
				if rec.SubjectID != "" {
					if guard.RevokedSubjects == nil {
						guard.RevokedSubjects = make(map[string]int64)
					}
					guard.RevokedSubjects[rec.SubjectID] = rec.ExpUnix
				}
			}
		}
	}
}

// RestoreInto loads the base snapshot from `<path>` and replays `<path>.wal.compacting` + `<path>.wal`
// directly into `graph` and `store`, returning any restored `ReplayGuardSnapshot` and surfacing
// decode/import errors explicitly instead of silently ignoring them (DeepSeek P1, P3-2, P3-3).
func (fs *FileStateStore) RestoreInto(_ context.Context, graph *RiskGraph, store *MemoryChallengeStore) (*ReplayGuardSnapshot, bool, error) {
	fs.mu.Lock()
	if fs.walFile != nil {
		_ = fs.walFile.Sync()
	}
	basePath := fs.path
	compactWAL := fs.walCompactPath
	liveWAL := fs.walPath
	fs.mu.Unlock()

	base, err := readBaseStateFile(basePath)
	if err != nil {
		return nil, false, err
	}
	compactRecs, err := readWALRecordsFromFile(compactWAL)
	if err != nil {
		return nil, false, err
	}
	liveRecs, err := readWALRecordsFromFile(liveWAL)
	if err != nil {
		return nil, false, err
	}

	if base == nil && len(compactRecs) == 0 && len(liveRecs) == 0 {
		return nil, false, nil
	}

	guard := &ReplayGuardSnapshot{
		ConsumedStepUp:  make(map[string]int64),
		RevokedTokenSHA: make(map[string]int64),
		RevokedSubjects: make(map[string]int64),
	}
	if base != nil {
		if base.ChallengeStore != nil && store != nil {
			if err := store.ImportSnapshot(*base.ChallengeStore); err != nil {
				return nil, false, fmt.Errorf("import challenge store snapshot: %w", err)
			}
		}
		if base.Graph != nil && graph != nil {
			if err := graph.ImportSnapshot(*base.Graph); err != nil {
				return nil, false, fmt.Errorf("import risk graph snapshot: %w", err)
			}
		}
		if base.ReplayGuard != nil {
			for k, v := range base.ReplayGuard.ConsumedStepUp {
				guard.ConsumedStepUp[k] = v
			}
			for k, v := range base.ReplayGuard.RevokedTokenSHA {
				guard.RevokedTokenSHA[k] = v
			}
			for k, v := range base.ReplayGuard.RevokedSubjects {
				guard.RevokedSubjects[k] = v
			}
		}
	}

	if len(compactRecs) > 0 {
		applyWALRecords(compactRecs, graph, store, guard)
	}
	if len(liveRecs) > 0 {
		applyWALRecords(liveRecs, graph, store, guard)
	}
	return guard, true, nil
}

// LoadState loads both the base snapshot and any pending WAL records into a unified PersistedEngineState.
// Returns (nil, nil) when neither snapshot nor WAL exists yet.
func (fs *FileStateStore) LoadState(ctx context.Context) (*PersistedEngineState, error) {
	fs.mu.Lock()
	if fs.walFile != nil {
		_ = fs.walFile.Sync()
	}
	basePath := fs.path
	compactWAL := fs.walCompactPath
	liveWAL := fs.walPath
	fs.mu.Unlock()

	base, err := readBaseStateFile(basePath)
	if err != nil {
		return nil, err
	}
	compactRecs, err := readWALRecordsFromFile(compactWAL)
	if err != nil {
		return nil, err
	}
	liveRecs, err := readWALRecordsFromFile(liveWAL)
	if err != nil {
		return nil, err
	}
	if len(compactRecs) == 0 && len(liveRecs) == 0 {
		return base, nil
	}

	mem := NewMemoryChallengeStore()
	graph := NewRiskGraphWithOptions(GraphOptions{Store: mem})
	guard, ok, err := fs.RestoreInto(ctx, graph, mem)
	if err != nil || !ok {
		return nil, err
	}
	merged := buildPersistedState(graph, mem, guard)
	return &merged, nil
}

// LoadGraphSnapshot implements GraphStore.
func (fs *FileStateStore) LoadGraphSnapshot(ctx context.Context) (*GraphSnapshot, error) {
	st, err := fs.LoadState(ctx)
	if err != nil || st == nil {
		return nil, err
	}
	return st.Graph, nil
}

// SaveGraphSnapshot implements GraphStore while preserving any existing ChallengeStoreSnapshot in the file.
func (fs *FileStateStore) SaveGraphSnapshot(_ context.Context, snap GraphSnapshot) error {
	fs.compactMu.Lock()
	defer fs.compactMu.Unlock()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	var state PersistedEngineState
	if raw, err := os.ReadFile(fs.path); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &state)
	}
	state.Version = 2
	state.SavedAt = time.Now().UTC()
	state.Graph = &snap
	return writeJSONFileAtomic(fs.path, state)
}

func writeJSONFileAtomic(targetPath string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode state json: %w", err)
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".prismid-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("rename temp state file: %w", err)
	}
	cleanup = false
	return nil
}

// FileAuditStore is a durable, owner-only (`0600`) append-only JSON Lines implementation of AuditStore.
type FileAuditStore struct {
	mu   sync.Mutex
	path string
}

// NewFileAuditStore creates or opens an append-only JSONL security audit log at path.
func NewFileAuditStore(path string) (*FileAuditStore, error) {
	if path == "" {
		return nil, errors.New("audit log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	_ = f.Chmod(0o600)
	_ = f.Close()
	return &FileAuditStore{path: path}, nil
}

// AppendAuditEvent appends a JSONL security audit line and flushes it to disk.
func (fa *FileAuditStore) AppendAuditEvent(_ context.Context, ev KeyRebindAuditEvent) error {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(fa.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}

// ListAuditEvents reads up to the most recent `limit` audit events from the JSONL log.
func (fa *FileAuditStore) ListAuditEvents(_ context.Context, limit int) ([]KeyRebindAuditEvent, error) {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	f, err := os.Open(fa.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []KeyRebindAuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev KeyRebindAuditEvent
		if err := json.Unmarshal(raw, &ev); err == nil {
			all = append(all, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}
