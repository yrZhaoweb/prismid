package prismid

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// In-Process Concurrent RESP2 Server for Multi-Instance RedisStore Tests
// ============================================================================

type miniZSet map[string]float64

type miniRESPServer struct {
	ln     net.Listener
	mu     sync.Mutex
	kv     map[string]string
	hashes map[string]map[string]string
	sets   map[string]map[string]struct{}
	zsets  map[string]miniZSet
	closed bool
	wg     sync.WaitGroup
}

func startMiniRESPServer(t *testing.T) *miniRESPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen miniRESPServer: %v", err)
	}
	s := &miniRESPServer{
		ln:     ln,
		kv:     make(map[string]string),
		hashes: make(map[string]map[string]string),
		sets:   make(map[string]map[string]struct{}),
		zsets:  make(map[string]miniZSet),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *miniRESPServer) URL() string {
	return "redis://" + s.ln.Addr().String() + "/0"
}

func (s *miniRESPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.serveConn(conn)
	}
}

func (s *miniRESPServer) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	var inMulti bool
	var multiQueue [][]string

	for {
		val, err := readRESPValue(br)
		if err != nil {
			return
		}
		if val.kind != '*' || len(val.array) == 0 {
			return
		}
		args := make([]string, len(val.array))
		for i, item := range val.array {
			args[i] = item.str
		}
		cmd := strings.ToUpper(args[0])

		if cmd == "MULTI" {
			inMulti = true
			multiQueue = nil
			_, _ = bw.WriteString("+OK\r\n")
			_ = bw.Flush()
			continue
		}
		if cmd == "EXEC" {
			inMulti = false
			_, _ = fmt.Fprintf(bw, "*%d\r\n", len(multiQueue))
			for _, qArgs := range multiQueue {
				s.writeReply(bw, s.handleCmd(qArgs))
			}
			multiQueue = nil
			_ = bw.Flush()
			continue
		}
		if inMulti {
			multiQueue = append(multiQueue, args)
			_, _ = bw.WriteString("+QUEUED\r\n")
			_ = bw.Flush()
			continue
		}

		s.writeReply(bw, s.handleCmd(args))
		if br.Buffered() == 0 {
			if err := bw.Flush(); err != nil {
				return
			}
		}
	}
}

func (s *miniRESPServer) writeReply(bw *bufio.Writer, rep respValue) {
	switch rep.kind {
	case '+', '-':
		_, _ = fmt.Fprintf(bw, "%c%s\r\n", rep.kind, rep.str)
	case ':':
		_, _ = fmt.Fprintf(bw, ":%d\r\n", rep.integer)
	case '$':
		if rep.isNull {
			_, _ = bw.WriteString("$-1\r\n")
		} else {
			_, _ = fmt.Fprintf(bw, "$%d\r\n%s\r\n", len(rep.str), rep.str)
		}
	case '*':
		if rep.isNull {
			_, _ = bw.WriteString("*-1\r\n")
		} else {
			_, _ = fmt.Fprintf(bw, "*%d\r\n", len(rep.array))
			for _, el := range rep.array {
				s.writeReply(bw, el)
			}
		}
	}
}

func (s *miniRESPServer) handleCmd(args []string) respValue {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "PING":
		return respValue{kind: '+', str: "PONG"}
	case "AUTH", "SELECT":
		return respValue{kind: '+', str: "OK"}
	case "EXPIRE", "PEXPIRE":
		return respValue{kind: ':', integer: 1}
	case "GET":
		v, ok := s.kv[args[1]]
		if !ok {
			return respValue{kind: '$', isNull: true}
		}
		return respValue{kind: '$', str: v}
	case "GETDEL":
		v, ok := s.kv[args[1]]
		if !ok {
			return respValue{kind: '$', isNull: true}
		}
		delete(s.kv, args[1])
		return respValue{kind: '$', str: v}
	case "GETSET":
		old, ok := s.kv[args[1]]
		s.kv[args[1]] = args[2]
		if !ok {
			return respValue{kind: '$', isNull: true}
		}
		return respValue{kind: '$', str: old}
	case "SET":
		key, val := args[1], args[2]
		nx := false
		for _, opt := range args[3:] {
			if strings.EqualFold(opt, "NX") {
				nx = true
			}
		}
		if nx {
			if _, exists := s.kv[key]; exists {
				return respValue{kind: '$', isNull: true}
			}
		}
		s.kv[key] = val
		return respValue{kind: '+', str: "OK"}
	case "DEL":
		var deleted int64
		for _, k := range args[1:] {
			if _, ok := s.kv[k]; ok {
				delete(s.kv, k)
				deleted++
			}
			if _, ok := s.hashes[k]; ok {
				delete(s.hashes, k)
				deleted++
			}
			if _, ok := s.sets[k]; ok {
				delete(s.sets, k)
				deleted++
			}
			if _, ok := s.zsets[k]; ok {
				delete(s.zsets, k)
				deleted++
			}
		}
		return respValue{kind: ':', integer: deleted}
	case "EXISTS":
		var n int64
		for _, k := range args[1:] {
			if _, ok := s.kv[k]; ok {
				n++
			}
		}
		return respValue{kind: ':', integer: n}
	case "INCR":
		cur, _ := strconv.ParseInt(s.kv[args[1]], 10, 64)
		cur++
		s.kv[args[1]] = strconv.FormatInt(cur, 10)
		return respValue{kind: ':', integer: cur}
	case "DECR":
		cur, _ := strconv.ParseInt(s.kv[args[1]], 10, 64)
		cur--
		s.kv[args[1]] = strconv.FormatInt(cur, 10)
		return respValue{kind: ':', integer: cur}
	case "SADD":
		set := s.sets[args[1]]
		if set == nil {
			set = make(map[string]struct{})
			s.sets[args[1]] = set
		}
		var added int64
		for _, m := range args[2:] {
			if _, exists := set[m]; !exists {
				set[m] = struct{}{}
				added++
			}
		}
		return respValue{kind: ':', integer: added}
	case "SREM":
		set := s.sets[args[1]]
		var removed int64
		if set != nil {
			for _, m := range args[2:] {
				if _, exists := set[m]; exists {
					delete(set, m)
					removed++
				}
			}
		}
		return respValue{kind: ':', integer: removed}
	case "SCARD":
		return respValue{kind: ':', integer: int64(len(s.sets[args[1]]))}
	case "SMEMBERS":
		set := s.sets[args[1]]
		arr := make([]respValue, 0, len(set))
		for m := range set {
			arr = append(arr, respValue{kind: '$', str: m})
		}
		return respValue{kind: '*', array: arr}
	case "HSET":
		h := s.hashes[args[1]]
		if h == nil {
			h = make(map[string]string)
			s.hashes[args[1]] = h
		}
		var added int64
		for i := 2; i+1 < len(args); i += 2 {
			if _, exists := h[args[i]]; !exists {
				added++
			}
			h[args[i]] = args[i+1]
		}
		return respValue{kind: ':', integer: added}
	case "HDEL":
		h := s.hashes[args[1]]
		var removed int64
		if h != nil {
			for _, f := range args[2:] {
				if _, exists := h[f]; exists {
					delete(h, f)
					removed++
				}
			}
		}
		return respValue{kind: ':', integer: removed}
	case "HKEYS":
		h := s.hashes[args[1]]
		arr := make([]respValue, 0, len(h))
		for f := range h {
			arr = append(arr, respValue{kind: '$', str: f})
		}
		return respValue{kind: '*', array: arr}
	case "HGETALL":
		h := s.hashes[args[1]]
		arr := make([]respValue, 0, len(h)*2)
		for f, v := range h {
			arr = append(arr, respValue{kind: '$', str: f}, respValue{kind: '$', str: v})
		}
		return respValue{kind: '*', array: arr}
	case "ZADD":
		z := s.zsets[args[1]]
		if z == nil {
			z = make(miniZSet)
			s.zsets[args[1]] = z
		}
		score, _ := strconv.ParseFloat(args[2], 64)
		z[args[3]] = score
		return respValue{kind: ':', integer: 1}
	case "ZREMRANGEBYSCORE":
		z := s.zsets[args[1]]
		maxScore, err := strconv.ParseFloat(args[3], 64)
		var removed int64
		if err == nil && z != nil {
			for m, sc := range z {
				if sc <= maxScore {
					delete(z, m)
					removed++
				}
			}
		}
		return respValue{kind: ':', integer: removed}
	case "ZCARD":
		return respValue{kind: ':', integer: int64(len(s.zsets[args[1]]))}
	default:
		return respValue{kind: '-', str: "ERR unknown command " + cmd}
	}
}

// ============================================================================
// In-Process Standard-Library database/sql Driver for SQLGraphStore Tests
// ============================================================================

type memSQLState struct {
	mu       sync.Mutex
	edges    map[string]map[string]memEdgeRow // subject -> slice -> row
	bindings map[string]string                // beacon -> key
	owners   map[string]map[string]int64      // beacon -> subject -> ts
	audits   map[string]memAuditRow           // audit_id -> row
}

type memEdgeRow struct {
	obsMs int64
	json  string
}

type memAuditRow struct {
	createdMs int64
	json      string
}

var (
	memSQLRegistryMu sync.Mutex
	memSQLRegistry   = make(map[string]*memSQLState)
	memSQLDriverOnce sync.Once
)

func openMemSQLDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	memSQLDriverOnce.Do(func() {
		sql.Register("prismid_mem_sql", &memSQLDriver{})
	})
	memSQLRegistryMu.Lock()
	memSQLRegistry[name] = &memSQLState{
		edges:    make(map[string]map[string]memEdgeRow),
		bindings: make(map[string]string),
		owners:   make(map[string]map[string]int64),
		audits:   make(map[string]memAuditRow),
	}
	memSQLRegistryMu.Unlock()

	db, err := sql.Open("prismid_mem_sql", name)
	if err != nil {
		t.Fatalf("sql.Open prismid_mem_sql: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type memSQLDriver struct{}

func (d *memSQLDriver) Open(name string) (driver.Conn, error) {
	memSQLRegistryMu.Lock()
	st := memSQLRegistry[name]
	memSQLRegistryMu.Unlock()
	if st == nil {
		return nil, fmt.Errorf("unknown mem sql db %q", name)
	}
	return &memSQLConn{st: st}, nil
}

type memSQLConn struct{ st *memSQLState }
type memSQLTx struct{}

func (t *memSQLTx) Commit() error   { return nil }
func (t *memSQLTx) Rollback() error { return nil }

func (c *memSQLConn) Prepare(query string) (driver.Stmt, error) {
	return &memSQLStmt{st: c.st, query: query}, nil
}
func (c *memSQLConn) Close() error              { return nil }
func (c *memSQLConn) Begin() (driver.Tx, error) { return &memSQLTx{}, nil }

type memSQLStmt struct {
	st    *memSQLState
	query string
}

func (s *memSQLStmt) Close() error  { return nil }
func (s *memSQLStmt) NumInput() int { return -1 }

func asStr(v driver.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(x)
	}
}

func asInt64(v driver.Value) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	default:
		n, _ := strconv.ParseInt(fmt.Sprint(x), 10, 64)
		return n
	}
}

func (s *memSQLStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	q := strings.ToUpper(strings.TrimSpace(s.query))
	switch {
	case strings.HasPrefix(q, "CREATE TABLE"), strings.HasPrefix(q, "CREATE INDEX"):
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(q, "INSERT INTO PRISMID_GRAPH_EDGES"):
		sub, sl, obsMs, js := asStr(args[0]), asStr(args[1]), asInt64(args[2]), asStr(args[3])
		if s.st.edges[sub] == nil {
			s.st.edges[sub] = make(map[string]memEdgeRow)
		}
		s.st.edges[sub][sl] = memEdgeRow{obsMs: obsMs, json: js}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "DELETE FROM PRISMID_GRAPH_EDGES WHERE SUBJECT_ID =") && strings.Contains(q, "AND SLICE_ID ="):
		sub, sl := asStr(args[0]), asStr(args[1])
		if s.st.edges[sub] != nil {
			delete(s.st.edges[sub], sl)
		}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "DELETE FROM PRISMID_GRAPH_EDGES WHERE SUBJECT_ID ="):
		delete(s.st.edges, asStr(args[0]))
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "INSERT INTO PRISMID_BEACON_BINDINGS"):
		bcn, key := asStr(args[0]), asStr(args[1])
		if strings.Contains(q, "DO NOTHING") {
			if _, exists := s.st.bindings[bcn]; !exists {
				s.st.bindings[bcn] = key
			}
		} else {
			s.st.bindings[bcn] = key
		}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "DELETE FROM PRISMID_BEACON_BINDINGS"):
		delete(s.st.bindings, asStr(args[0]))
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "INSERT INTO PRISMID_BEACON_OWNERS"):
		bcn, sub, ts := asStr(args[0]), asStr(args[1]), asInt64(args[2])
		if s.st.owners[bcn] == nil {
			s.st.owners[bcn] = make(map[string]int64)
		}
		s.st.owners[bcn][sub] = ts
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "DELETE FROM PRISMID_BEACON_OWNERS WHERE SUBJECT_ID ="):
		sub := asStr(args[0])
		for _, m := range s.st.owners {
			delete(m, sub)
		}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(q, "INSERT INTO PRISMID_AUDIT_EVENTS"):
		aid, ts, js := asStr(args[0]), asInt64(args[1]), asStr(args[2])
		if _, exists := s.st.audits[aid]; !exists {
			s.st.audits[aid] = memAuditRow{createdMs: ts, json: js}
		}
		return driver.RowsAffected(1), nil
	default:
		return nil, fmt.Errorf("unhandled memSQL Exec: %s", s.query)
	}
}

func (s *memSQLStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	q := strings.ToUpper(strings.TrimSpace(s.query))
	switch {
	case strings.HasPrefix(q, "SELECT EDGE_JSON FROM PRISMID_GRAPH_EDGES WHERE SUBJECT_ID ="):
		sub := asStr(args[0])
		var rows [][]driver.Value
		for _, r := range s.st.edges[sub] {
			rows = append(rows, []driver.Value{r.json})
		}
		return &memSQLRows{cols: []string{"edge_json"}, rows: rows}, nil
	case strings.HasPrefix(q, "SELECT SUBJECT_ID FROM PRISMID_GRAPH_EDGES WHERE SLICE_ID ="):
		sl := asStr(args[0])
		type pair struct {
			sid string
			ms  int64
		}
		var list []pair
		for sid, smap := range s.st.edges {
			if r, ok := smap[sl]; ok {
				list = append(list, pair{sid: sid, ms: r.obsMs})
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ms > list[j].ms })
		var rows [][]driver.Value
		for _, p := range list {
			rows = append(rows, []driver.Value{p.sid})
		}
		return &memSQLRows{cols: []string{"subject_id"}, rows: rows}, nil
	case strings.HasPrefix(q, "SELECT DEVICE_KEY_SLICE_ID FROM PRISMID_BEACON_BINDINGS"):
		bcn := asStr(args[0])
		var rows [][]driver.Value
		if key, ok := s.st.bindings[bcn]; ok {
			rows = append(rows, []driver.Value{key})
		}
		return &memSQLRows{cols: []string{"device_key_slice_id"}, rows: rows}, nil
	case strings.HasPrefix(q, "SELECT SUBJECT_ID FROM PRISMID_BEACON_OWNERS WHERE BEACON_SLICE_ID ="):
		bcn := asStr(args[0])
		var subs []string
		for sid := range s.st.owners[bcn] {
			subs = append(subs, sid)
		}
		sort.Strings(subs)
		var rows [][]driver.Value
		for _, sid := range subs {
			rows = append(rows, []driver.Value{sid})
		}
		return &memSQLRows{cols: []string{"subject_id"}, rows: rows}, nil
	case strings.HasPrefix(q, "SELECT BEACON_SLICE_ID FROM PRISMID_BEACON_OWNERS WHERE SUBJECT_ID ="):
		sub := asStr(args[0])
		var bcns []string
		for bcn, m := range s.st.owners {
			if _, ok := m[sub]; ok {
				bcns = append(bcns, bcn)
			}
		}
		sort.Strings(bcns)
		var rows [][]driver.Value
		for _, bcn := range bcns {
			rows = append(rows, []driver.Value{bcn})
		}
		return &memSQLRows{cols: []string{"beacon_slice_id"}, rows: rows}, nil
	case strings.HasPrefix(q, "SELECT EVENT_JSON FROM PRISMID_AUDIT_EVENTS"):
		var list []memAuditRow
		for _, r := range s.st.audits {
			list = append(list, r)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].createdMs > list[j].createdMs })
		var rows [][]driver.Value
		for _, r := range list {
			rows = append(rows, []driver.Value{r.json})
		}
		return &memSQLRows{cols: []string{"event_json"}, rows: rows}, nil
	default:
		return nil, fmt.Errorf("unhandled memSQL Query: %s", s.query)
	}
}

type memSQLRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *memSQLRows) Columns() []string { return r.cols }
func (r *memSQLRows) Close() error      { return nil }
func (r *memSQLRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

// ============================================================================
// Commercial-Grade Verification Tests
// ============================================================================

func TestCommercial_MultiInstanceRedisStoreCluster(t *testing.T) {
	ctx := context.Background()
	respSrv := startMiniRESPServer(t)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	secret := []byte("commercial-cluster-secret-32byte")

	redisA, err := NewRedisStore(RedisOptions{URL: respSrv.URL(), NowFunc: func() time.Time { return now }, MaxPerIP: 8})
	if err != nil {
		t.Fatalf("NewRedisStore A: %v", err)
	}
	defer redisA.Close()

	redisB, err := NewRedisStore(RedisOptions{URL: respSrv.URL(), NowFunc: func() time.Time { return now }, MaxPerIP: 8})
	if err != nil {
		t.Fatalf("NewRedisStore B: %v", err)
	}
	defer redisB.Close()

	vA := NewVerifier(Config{HMACSecret: secret, NowFunc: func() time.Time { return now }}, redisA)
	gA := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: redisA, Backend: redisA})
	vA.BindRiskGraph(gA)

	vB := NewVerifier(Config{HMACSecret: secret, NowFunc: func() time.Time { return now }}, redisB)
	gB := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: redisB, Backend: redisB})
	vB.BindRiskGraph(gB)

	// 1. Issue challenge on Node A, consume on Node B, and reject replay on Node A!
	ch1, err := vA.IssueChallenge(ctx, "203.0.113.10")
	if err != nil {
		t.Fatalf("IssueChallenge on Node A: %v", err)
	}
	sharedBeacon := "aabbccddeeff00112233445566778899"
	sharedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p1 := buildValidPayload(ch1)
	p1.BeaconID = sharedBeacon
	p1.DeviceKey = signDeviceKeyForTest(t, sharedKey, ch1.Nonce, sharedBeacon, p1.WebGL.StaticWebGLFpHash, p1.AudioCompressorHash)
	req1 := IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}

	resAlice, err := vB.VerifyAndDerive(ctx, req1, "203.0.113.10")
	if err != nil || !resAlice.Accepted || !resAlice.DeviceKeyBound {
		t.Fatalf("Node B VerifyAndDerive failed: res=%+v err=%v", resAlice, err)
	}
	vB.RecordVerifiedBeaconOwner(ctx, "alice", resAlice)
	snapAlice := gB.RecordVerification("alice", now, resAlice)
	if snapAlice.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected alice green on Node B, got %+v", snapAlice)
	}

	// Replay same packet on Node A -> MUST fail with CHALLENGE_INVALID_OR_EXPIRED!
	if _, err := vA.VerifyAndDerive(ctx, req1, "203.0.113.10"); err == nil {
		t.Fatalf("expected cross-node challenge replay on Node A to be rejected")
	}

	// 2. Cross-node TOFU protection: Mallory tries stolen `sharedBeacon` with `malloryKey` on Node A!
	malloryKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chMal, _ := vA.IssueChallenge(ctx, "198.51.100.88")
	pMal := buildValidPayload(chMal)
	pMal.BeaconID = sharedBeacon
	pMal.DeviceKey = signDeviceKeyForTest(t, malloryKey, chMal.Nonce, sharedBeacon, pMal.WebGL.StaticWebGLFpHash, pMal.AudioCompressorHash)
	resMal, err := vA.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chMal.Nonce, SealedPayload: sealProbePayload(t, chMal.Nonce, pMal)}, "198.51.100.88")
	if err != nil || !resMal.DeviceKeyRecoveryRequired {
		t.Fatalf("expected Node A to enforce TOFU key mismatch set on Node B, got res=%+v err=%v", resMal, err)
	}

	// 3. Cross-node RiskGraph hydration: Bob identifies on Node A (which has ZERO local in-memory state for Alice!)
	// sharing `(sharedBeacon, sharedKey)` -> Node A hydrates Alice from RedisStore and links ["alice", "bob"]!
	chBob, _ := vA.IssueChallenge(ctx, "203.0.113.10")
	pBob := buildValidPayload(chBob)
	pBob.BeaconID = sharedBeacon
	pBob.DeviceKey = signDeviceKeyForTest(t, sharedKey, chBob.Nonce, sharedBeacon, pBob.WebGL.StaticWebGLFpHash, pBob.AudioCompressorHash)
	resBob, err := vA.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chBob.Nonce, SealedPayload: sealProbePayload(t, chBob.Nonce, pBob)}, "203.0.113.10")
	if err != nil {
		t.Fatalf("Bob VerifyAndDerive on Node A: %v", err)
	}
	vA.RecordVerifiedBeaconOwner(ctx, "bob", resBob)
	snapBob := gA.RecordVerification("bob", now.Add(time.Minute), resBob)
	if len(snapBob.ComponentSubjects) != 2 || snapBob.RiskStatus != RiskStatusYellow || !snapBob.RiskPending {
		t.Fatalf("expected Node A RiskGraph to hydrate Alice from RedisStore and flag shared_step_up yellow, got %+v", snapBob)
	}

	// 4. DistributedReplayGuard: JTI consumed on Node A is rejected on Node B; token revoked on Node A is revoked on Node B!
	ok1, err := redisA.ConsumeStepUpJTI(ctx, "jti-cluster-1", now.Add(5*time.Minute).Unix(), now.Unix())
	if err != nil || !ok1 {
		t.Fatalf("expected first JTI consume on Node A to succeed, ok=%v err=%v", ok1, err)
	}
	ok2, err := redisB.ConsumeStepUpJTI(ctx, "jti-cluster-1", now.Add(5*time.Minute).Unix(), now.Unix())
	if err != nil || ok2 {
		t.Fatalf("expected replay JTI consume on Node B to fail, ok=%v err=%v", ok2, err)
	}
	if err := redisA.RevokeTokenHash(ctx, "deadbeefcafebabe", now.Add(time.Hour).Unix(), now.Unix()); err != nil {
		t.Fatalf("RevokeTokenHash: %v", err)
	}
	if rev, err := redisB.IsRevoked(ctx, "deadbeefcafebabe", "", now.Unix()); err != nil || !rev {
		t.Fatalf("expected token hash revoked on Node A to be visible on Node B, rev=%v err=%v", rev, err)
	}

	// 5. Cross-node GDPR erasure: Erase Alice on Node B -> fresh Node C sees only Bob!
	removed, _ := vB.EraseSubject(ctx, gB, "alice", "203.0.113.10")
	if !removed {
		t.Fatalf("expected EraseSubject(alice) on Node B to return removed=true")
	}
	gC := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: redisA, Backend: redisA})
	snapBobOnC := gC.EvaluateSubject("bob")
	if len(snapBobOnC.ComponentSubjects) != 1 || snapBobOnC.ComponentSubjects[0] != "bob" {
		t.Fatalf("expected fresh Node C to see only bob after alice erasure, got %+v", snapBobOnC)
	}
}

func TestCommercial_SQLGraphStoreFullLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 13, 0, 0, 0, time.UTC)

	for _, dialect := range []SQLDialect{SQLDialectPostgres, SQLDialectSQLite} {
		t.Run(string(dialect), func(t *testing.T) {
			db := openMemSQLDB(t, "test_sql_"+string(dialect))
			sqlStore, err := NewSQLGraphStore(db, dialect)
			if err != nil {
				t.Fatalf("NewSQLGraphStore: %v", err)
			}
			if err := sqlStore.InitSchema(ctx); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}

			// TOFU bind, lookup, rebind & clear:
			ok, err := sqlStore.CheckOrBindBeaconDeviceKey(ctx, "d_bcn_sql1", "d_key_1")
			if err != nil || !ok {
				t.Fatalf("first TOFU bind failed: ok=%v err=%v", ok, err)
			}
			okMismatch, err := sqlStore.CheckOrBindBeaconDeviceKey(ctx, "d_bcn_sql1", "d_key_attacker")
			if err != nil || okMismatch {
				t.Fatalf("expected mismatched key to fail TOFU check: ok=%v err=%v", okMismatch, err)
			}
			prev, err := sqlStore.RebindBeaconDeviceKey(ctx, "d_bcn_sql1", "d_key_2")
			if err != nil || prev != "d_key_1" {
				t.Fatalf("RebindBeaconDeviceKey: prev=%q err=%v", prev, err)
			}

			// Beacon ownership & audit log:
			_ = sqlStore.RecordBeaconOwner(ctx, "d_bcn_sql1", "u1")
			_ = sqlStore.RecordBeaconOwner(ctx, "d_bcn_sql1", "u2")
			owners, err := sqlStore.GetBeaconOwners(ctx, "d_bcn_sql1")
			if err != nil || len(owners) != 2 {
				t.Fatalf("GetBeaconOwners: %v err=%v", owners, err)
			}
			_ = sqlStore.AppendAuditEvent(ctx, KeyRebindAuditEvent{
				AuditID:   "aud_sql_1",
				Timestamp: now,
				Action:    "rebind_key_rotation",
				SubjectID: "u1",
				Outcome:   "rebound",
			})
			audits, err := sqlStore.ListAuditEvents(ctx, 10)
			if err != nil || len(audits) != 1 || audits[0].Action != "rebind_key_rotation" {
				t.Fatalf("ListAuditEvents: %+v err=%v", audits, err)
			}

			// RiskGraph neighborhood hydration across stateless RiskGraph instances:
			gWriter := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Backend: sqlStore})
			resShared := &VerifyResult{
				Accepted:         true,
				Confidence:       0.95,
				DeviceKeyBound:   true,
				DeviceKeySliceID: "d_key_2",
				BeaconSliceID:    "d_bcn_sql1",
				ExactSliceID:     "d_web_sql1",
				GpuAudioSliceID:  "d_gpu_sql1",
				SysNetSliceID:    "d_sys_sql1",
			}
			gWriter.RecordVerification("u1", now, resShared)
			gWriter.RecordVerification("u2", now.Add(time.Minute), resShared)

			gStatelessReader := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Backend: sqlStore})
			snapU1 := gStatelessReader.EvaluateSubject("u1")
			if len(snapU1.ComponentSubjects) != 2 || snapU1.RiskStatus != RiskStatusYellow {
				t.Fatalf("expected stateless SQL reader to hydrate [u1, u2] component, got %+v", snapU1)
			}
		})
	}
}

func TestCommercial_MitMKeySwapRotationRejectionAndAuditAction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 14, 0, 0, 0, time.UTC)
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v := NewVerifier(Config{HMACSecret: []byte("commercial-mitm-secret-32-bytes!"), NowFunc: func() time.Time { return now }}, store)
	g := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: store})
	v.BindRiskGraph(g)

	bcn := "0123456789abcdef0123456789abcdef"
	keyOrig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyLegitNew, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyAttacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ch1, _ := v.IssueChallenge(ctx, "203.0.113.20")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = bcn
	p1.DeviceKey = signDeviceKeyForTest(t, keyOrig, ch1.Nonce, bcn, p1.WebGL.StaticWebGLFpHash, p1.AudioCompressorHash)
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "203.0.113.20")
	if err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	v.RecordVerifiedBeaconOwner(ctx, "alice", res1)
	g.RecordVerification("alice", now, res1)

	chRot, _ := v.IssueChallenge(ctx, "203.0.113.20")
	legitNewProof := signRebindForTest(t, keyLegitNew, "prismid-v2-rebind", chRot.Nonce, "alice", bcn)
	attackerNewProof := signRebindForTest(t, keyAttacker, "prismid-v2-rebind", chRot.Nonce, "alice", bcn)
	prevProofBoundToLegit := signRebindForTest(t, keyOrig, "prismid-v2-rebind-prev", chRot.Nonce, "alice", bcn, legitNewProof.PubKey)
	legacyUnboundPrevProof := signRebindForTest(t, keyOrig, "prismid-v2-rebind-prev", chRot.Nonce, "alice", bcn)

	// 1. Legacy 4-segment unbound rotation proof MUST be rejected!
	if v.HasValidPreviousKeyProof(ctx, KeyRebindRequest{
		ChallengeNonce:    chRot.Nonce,
		SubjectID:         "alice",
		BeaconID:          bcn,
		DeviceKey:         legitNewProof,
		PreviousDeviceKey: legacyUnboundPrevProof,
	}) {
		t.Fatalf("expected legacy 4-segment unbound rotation proof to be rejected")
	}

	// 2. MitM attacker intercepts `prevProofBoundToLegit` and substitutes `attackerNewProof` -> MUST be rejected!
	if v.HasValidPreviousKeyProof(ctx, KeyRebindRequest{
		ChallengeNonce:    chRot.Nonce,
		SubjectID:         "alice",
		BeaconID:          bcn,
		DeviceKey:         attackerNewProof,
		PreviousDeviceKey: prevProofBoundToLegit,
	}) {
		t.Fatalf("SECURITY REGRESSION: MitM key-swap during rotation was accepted!")
	}

	// 3. Legitimate 5-segment bound rotation succeeds and records `rebind_key_rotation` audit action!
	legitReq := KeyRebindRequest{
		ChallengeNonce:    chRot.Nonce,
		SubjectID:         "alice",
		BeaconID:          bcn,
		DeviceKey:         legitNewProof,
		PreviousDeviceKey: prevProofBoundToLegit,
	}
	if !v.HasValidPreviousKeyProof(ctx, legitReq) {
		t.Fatalf("expected legitimate 5-segment bound rotation proof to pass")
	}
	rotRes, err := v.RebindDeviceKeyWithProof(ctx, legitReq, v.BeaconOwnerCheck(g), "203.0.113.20")
	if err != nil || !rotRes.Rebound || !rotRes.RetiredPreviousKey {
		t.Fatalf("expected legitimate rotation to succeed, got res=%+v err=%v", rotRes, err)
	}
	audits := v.RebindAuditEvents()
	if len(audits) == 0 || audits[len(audits)-1].Action != "rebind_key_rotation" {
		t.Fatalf("expected audit action 'rebind_key_rotation', got %+v", audits)
	}
}

func TestCommercial_DynamicStratifiedSamplePoints(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryChallengeStore()
	v := NewVerifier(Config{HMACSecret: []byte("commercial-sample-points-secret!")}, store)

	ch1, err := v.IssueChallenge(ctx, "203.0.113.30")
	if err != nil {
		t.Fatalf("IssueChallenge 1: %v", err)
	}
	ch2, err := v.IssueChallenge(ctx, "203.0.113.30")
	if err != nil {
		t.Fatalf("IssueChallenge 2: %v", err)
	}
	sameCoords := len(ch1.SamplePoints) == len(ch2.SamplePoints)
	if sameCoords {
		for i := range ch1.SamplePoints {
			if ch1.SamplePoints[i] != ch2.SamplePoints[i] {
				sameCoords = false
				break
			}
		}
	}
	if sameCoords {
		t.Fatalf("expected CSPRNG stratified SamplePoints to vary per challenge, got identical %v", ch1.SamplePoints)
	}
	for i, pt := range ch1.SamplePoints {
		if pt[0] < 8 || pt[0] > 247 || pt[1] < 8 || pt[1] > 247 {
			t.Fatalf("sample point %d out of safe inner bounds [8, 247]: %v", i, pt)
		}
	}

	// Verify genuine render at dynamic `ch1.SamplePoints` passes:
	pValid := buildValidPayload(ch1)
	resValid, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch1.Nonce,
		SealedPayload:  sealProbePayload(t, ch1.Nonce, pValid),
	}, "203.0.113.30")
	if err != nil || !resValid.Accepted {
		t.Fatalf("expected dynamic sample point verification to pass, got %v", err)
	}

	// Verify attacker hardcoding legacy DefaultSamplePoints fails when SamplePoints are dynamic:
	pStaleCoords := buildValidPayload(ch2)
	pStaleCoords.WebGL.SpotPixels = ComputeAllExpectedSpotPixels(DefaultSamplePoints, ch2.RenderSeed)
	if _, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch2.Nonce,
		SealedPayload:  sealProbePayload(t, ch2.Nonce, pStaleCoords),
	}, "203.0.113.30"); err == nil {
		t.Fatalf("expected hardcoded DefaultSamplePoints to fail against randomized challenge coordinates")
	}
}

func TestCommercial_GPULaws8To10AndTransportJA4HTTP2Verification(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryChallengeStore()
	v := NewVerifier(Config{HMACSecret: []byte("commercial-laws-transport-secret")}, store)

	// 1. Law 8: maxCubeMap > maxTex -> rejected by VerifyGPURegisterLaws!
	vLaw8 := VerifyGPURegisterLaws(&ProbePayload{
		WebGL: WebGLProbeData{
			GPUVendor:         "Apple",
			GPURenderer:       "Apple M3",
			WebGLLimitsVector: "8192|16384|8192,8192|8192|4096|1024|31|1,1|1,511|16|23,23,23,23",
		},
		System: SystemProbeData{Platform: "MacIntel"},
	})
	if !strings.Contains(strings.Join(vLaw8, ","), "inconsistent_cubemap_vs_texture_size") {
		t.Fatalf("expected Law 8 cubemap violation, got %v", vLaw8)
	}

	// 2. Law 9: Cross-vendor GPU (Vendor=NVIDIA, Renderer=AMD Radeon) & mobile Adreno on Win32!
	vLaw9a := VerifyGPURegisterLaws(&ProbePayload{
		WebGL: WebGLProbeData{
			GPUVendor:         "NVIDIA Corporation",
			GPURenderer:       "ANGLE (AMD, AMD Radeon RX 7900 XTX Direct3D11)",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,1024|16|23,23,23,23",
		},
		System: SystemProbeData{Platform: "Win32"},
	})
	if !strings.Contains(strings.Join(vLaw9a, ","), "vendor_renderer_brand_mismatch") {
		t.Fatalf("expected Law 9 cross-vendor violation, got %v", vLaw9a)
	}
	vLaw9b := VerifyGPURegisterLaws(&ProbePayload{
		WebGL: WebGLProbeData{
			GPUVendor:         "Qualcomm",
			GPURenderer:       "Adreno (TM) 740",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,1024|16|23,23,23,23",
		},
		System: SystemProbeData{Platform: "Win32"},
	})
	if !strings.Contains(strings.Join(vLaw9b, ","), "mobile_gpu_on_desktop_platform") {
		t.Fatalf("expected Law 9 mobile-SoC-on-desktop violation, got %v", vLaw9b)
	}
	// Genuine Windows on ARM (Snapdragon X Elite Adreno X1-85 Direct3D11 on Win32) & ARM Chromebook/Android Desktop-site must NOT false-positive:
	vWinARM := VerifyGPURegisterLaws(&ProbePayload{
		WebGL: WebGLProbeData{
			GPUVendor:         "Google Inc. (Qualcomm)",
			GPURenderer:       "ANGLE (Qualcomm, Qualcomm(R) Adreno(TM) X1-85 GPU (0x36334330) Direct3D11 vs_5_0 ps_5_0, D3D11)",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,1024|16|23,23,23,23",
		},
		System: SystemProbeData{Platform: "Win32", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"},
	})
	if len(vWinARM) != 0 {
		t.Fatalf("expected 0 violations on genuine Snapdragon X Elite Windows on ARM laptop, got %v", vWinARM)
	}
	vARMChromebook := VerifyGPURegisterLaws(&ProbePayload{
		WebGL: WebGLProbeData{
			GPUVendor:         "Google Inc. (ARM)",
			GPURenderer:       "ANGLE (ARM, Mali-G720-Immortalis MC12, OpenGL ES 3.2)",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,1024|16|23,23,23,23",
		},
		System: SystemProbeData{Platform: "Linux x86_64", UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"},
	})
	if len(vARMChromebook) != 0 {
		t.Fatalf("expected 0 violations on ARM Chromebook / Android Chrome Desktop-site, got %v", vARMChromebook)
	}

	// 3. Law 10: Chromium-only `navigator.deviceMemory` leaked while claiming Safari JSC!
	vLaw10 := VerifyGPURegisterLaws(&ProbePayload{
		WebGL: WebGLProbeData{
			GPUVendor:         "Apple",
			GPURenderer:       "Apple GPU",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23",
		},
		System: SystemProbeData{
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
			Platform:     "MacIntel",
			DeviceMemory: 8, // Safari JSC never exposes navigator.deviceMemory!
		},
		Lies: LieProbeData{MathEngineSignature: "jsc"},
	})
	if !strings.Contains(strings.Join(vLaw10, ","), "device_memory_on_non_chromium") {
		t.Fatalf("expected Law 10 deviceMemory leak detection on JSC, got %v", vLaw10)
	}

	// 4. Transport JA4 + HTTP/2 mismatch triggers spoof trap in VerifyAndDeriveWithTransport!
	chT, _ := v.IssueChallenge(ctx, "203.0.113.40")
	pT := buildValidPayload(chT)
	pT.System.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	resT, err := v.VerifyAndDeriveWithTransport(
		ctx,
		IdentifyRequest{ChallengeNonce: chT.Nonce, SealedPayload: sealProbePayload(t, chT.Nonce, pT)},
		"203.0.113.40",
		TransportSignals{
			TLSJA4:           "t12d040300_aabbccddeeff_112233445566", // TLS 1.2 + 4 ciphers + no ALPN from Python script!
			HTTP2Fingerprint: "1:65536;4:6291456|15663105|0|m,p,a,s", // Go/Python m,p,a,s pseudo-header order instead of Chrome m,a,s,p!
		},
	)
	if err != nil {
		t.Fatalf("VerifyAndDeriveWithTransport error: %v", err)
	}
	if !resT.SpoofTrapTriggered || len(resT.SpoofFlags) < 2 {
		t.Fatalf("expected JA4 + HTTP/2 mismatch to trigger SpoofTrapTriggered, got %+v", resT)
	}

	// 5. TrustedProxyChecker right-to-left X-Forwarded-For stripping & untrusted peer rejection:
	checker, err := ParseTrustedProxyCIDRs("10.0.0.0/8, 172.16.0.0/12")
	if err != nil {
		t.Fatalf("ParseTrustedProxyCIDRs: %v", err)
	}
	// Request arriving through trusted ingress `10.1.2.3`, with client-forged `1.1.1.1` prepended before real `198.51.100.77`:
	reqTrusted := httptest.NewRequest("POST", "/api/v1/risk/identify", nil)
	reqTrusted.RemoteAddr = "10.1.2.3:44321"
	reqTrusted.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.77, 172.16.5.4")
	reqTrusted.Header.Set("X-TLS-JA4", "t13d1516h2_8daaf6152771_e5627efa2ab1")
	if gotIP := ExtractRealClientIP(reqTrusted, checker, false); gotIP != "198.51.100.77" {
		t.Fatalf("expected right-to-left XFF stripping to extract 198.51.100.77, got %q", gotIP)
	}
	if sig := ExtractTrustedTransportSignals(reqTrusted, checker, false); sig.TLSJA4 == "" {
		t.Fatalf("expected trusted proxy JA4 header to be extracted")
	}

	// Request arriving directly from untrusted attacker `198.51.100.99` forging XFF & X-TLS-JA4 -> MUST ignore headers!
	reqUntrusted := httptest.NewRequest("POST", "/api/v1/risk/identify", nil)
	reqUntrusted.RemoteAddr = "198.51.100.99:55123"
	reqUntrusted.Header.Set("X-Forwarded-For", "8.8.8.8")
	reqUntrusted.Header.Set("X-TLS-JA4", "t13d1516h2_forged_ja4")
	if gotIP := ExtractRealClientIP(reqUntrusted, checker, true); gotIP != "198.51.100.99" {
		t.Fatalf("SECURITY REGRESSION: untrusted peer forged X-Forwarded-For -> got %q", gotIP)
	}
	if sig := ExtractTrustedTransportSignals(reqUntrusted, checker, true); sig.TLSJA4 != "" {
		t.Fatalf("SECURITY REGRESSION: untrusted peer forged X-TLS-JA4 -> got %+v", sig)
	}
}

func TestCommercial_MultiTenantIsolationAndPrometheusMetrics(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryChallengeStore()
	baseVerifier := NewVerifier(Config{HMACSecret: []byte("commercial-saas-master-secret-32")}, store)
	vTenantA := baseVerifier.WithTenant("acme_corp")
	vTenantB := baseVerifier.WithTenant("globex_inc")

	bcn := "fedcba9876543210fedcba9876543210"
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	chA, _ := vTenantA.IssueChallenge(ctx, "203.0.113.55")
	pA := buildValidPayload(chA)
	pA.BeaconID = bcn
	pA.DeviceKey = signDeviceKeyForTest(t, devKey, chA.Nonce, bcn, pA.WebGL.StaticWebGLFpHash, pA.AudioCompressorHash)
	resA, err := vTenantA.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chA.Nonce, SealedPayload: sealProbePayload(t, chA.Nonce, pA)}, "203.0.113.55")
	if err != nil {
		t.Fatalf("Tenant A verify: %v", err)
	}

	chB, _ := vTenantB.IssueChallenge(ctx, "203.0.113.55")
	pB := buildValidPayload(chB)
	pB.BeaconID = bcn
	pB.DeviceKey = signDeviceKeyForTest(t, devKey, chB.Nonce, bcn, pB.WebGL.StaticWebGLFpHash, pB.AudioCompressorHash)
	resB, err := vTenantB.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chB.Nonce, SealedPayload: sealProbePayload(t, chB.Nonce, pB)}, "203.0.113.55")
	if err != nil {
		t.Fatalf("Tenant B verify: %v", err)
	}

	if resA.BeaconSliceID == resB.BeaconSliceID ||
		resA.DeviceKeySliceID == resB.DeviceKeySliceID ||
		resA.GpuAudioSliceID == resB.GpuAudioSliceID ||
		resA.SysNetSliceID == resB.SysNetSliceID {
		t.Fatalf("cross-tenant correlation leak: Tenant A and Tenant B produced identical slice IDs! A=%+v B=%+v", resA, resB)
	}

	// Verify Prometheus metrics exposition format:
	m := NewMetrics()
	m.RecordChallengeIssued()
	m.RecordIdentifyVerdict("green", false, false, false, 1200*time.Microsecond)
	m.RecordIdentifyVerdict("red", true, true, false, 3400*time.Microsecond)
	m.RecordRebindOutcome("rotation")
	g := NewRiskGraph(AuthoritativeConfidenceThreshold)
	g.RecordVerification("acme:u1", time.Now().UTC(), resA)

	promText := m.RenderPrometheus(g, 0)
	for _, mustContain := range []string{
		"prismid_challenges_issued_total 1",
		`prismid_identify_verdicts_total{risk_status="green",shadow="false"} 1`,
		`prismid_identify_verdicts_total{risk_status="red",shadow="true"} 1`,
		"prismid_spoof_traps_triggered_total 1",
		`prismid_rebind_requests_total{mode="rotation"} 1`,
		"prismid_identify_duration_seconds_count 2",
		"prismid_graph_active_subjects 1",
	} {
		if !strings.Contains(promText, mustContain) {
			t.Fatalf("expected Prometheus output to contain %q, got:\n%s", mustContain, promText)
		}
	}

	// Regression guard: passing a typed-nil *RedisStore as GraphOptions.Backend or AttachBackend
	// must be normalized to nil and never panic on RecordVerification / Snapshot / ForgetSubject.
	var typedNilRedis *RedisStore
	gTypedNil := NewRiskGraphWithOptions(GraphOptions{
		MinConfidence: AuthoritativeConfidenceThreshold,
		Store:         store,
		Backend:       typedNilRedis,
	})
	gTypedNil.AttachBackend(typedNilRedis)
	snap := gTypedNil.RecordVerification("acme:u_typed_nil", time.Now().UTC(), resA)
	if snap.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected green verdict with typed-nil backend normalized to nil, got %s", snap.RiskStatus)
	}
	if !gTypedNil.RemoveSubject("acme:u_typed_nil") {
		t.Fatalf("expected RemoveSubject to succeed with normalized nil backend")
	}
}
