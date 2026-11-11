package prismid

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DistributedReplayGuard provides cluster-wide single-use step-up JTI consumption and
// immediate bearer token / subject revocation across horizontally scaled server instances.
type DistributedReplayGuard interface {
	ConsumeStepUpJTI(ctx context.Context, jti string, expUnix, nowUnix int64) (bool, error)
	RevokeTokenHash(ctx context.Context, tokenSHAHex string, untilUnix, nowUnix int64) error
	RevokeSubject(ctx context.Context, subjectID string, untilUnix, nowUnix int64) error
	IsRevoked(ctx context.Context, tokenSHAHex, subjectID string, nowUnix int64) (bool, error)
}

// RedisOptions configures the zero-dependency RESP2 pooled client and RedisStore quotas/TTLs.
type RedisOptions struct {
	// URL in standard format: redis://[:password@]host:port[/db] or rediss://[:password@]host:port[/db]
	URL          string
	KeyPrefix    string
	MaxIdleConns int
	DialTimeout  time.Duration
	OpTimeout    time.Duration
	TLSConfig    *tls.Config
	MaxPerIP     int
	MaxPerSubnet int
	BeaconTTL    time.Duration
	GraphEdgeTTL time.Duration
	NowFunc      func() time.Time
}

type respValue struct {
	kind    byte // '+', '-', ':', '$', '*'
	str     string
	integer int64
	isNull  bool
	array   []respValue
}

type respConn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
}

func (c *respConn) close() {
	if c != nil && c.conn != nil {
		_ = c.conn.Close()
	}
}

// RedisStore is a zero-external-dependency, Redis Cluster-compatible distributed store
// implementing ChallengeStore, DeviceKeyBindingStore, DeviceKeyRebindStore, DeviceKeyLookupStore,
// BeaconOwnerStore, DistributedReplayGuard, and GraphBackend over pooled TCP/TLS RESP2 connections.
type RedisStore struct {
	addr         string
	username     string
	password     string
	db           int
	useTLS       bool
	tlsCfg       *tls.Config
	prefix       string
	dialTimeout  time.Duration
	opTimeout    time.Duration
	maxIdle      int
	maxPerIP     int
	maxPerSubnet int
	beaconTTLSec int64
	graphTTLSec  int64
	nowFunc      func() time.Time

	poolMu sync.Mutex
	idle   []*respConn
	closed bool
}

// NewRedisStore parses `opts.URL`, verifies connectivity via `PING`, and returns a pooled RedisStore.
func NewRedisStore(opts RedisOptions) (*RedisStore, error) {
	rawURL := strings.TrimSpace(opts.URL)
	if rawURL == "" {
		return nil, errors.New("redis URL is required")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "redis://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	var useTLS bool
	switch strings.ToLower(u.Scheme) {
	case "redis":
		useTLS = false
	case "rediss":
		useTLS = true
	default:
		return nil, fmt.Errorf("unsupported redis scheme %q (expected redis:// or rediss://)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	addr := net.JoinHostPort(host, port)

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	db := 0
	if path := strings.Trim(u.Path, "/"); path != "" {
		parsedDB, err := strconv.Atoi(path)
		if err != nil || parsedDB < 0 {
			return nil, fmt.Errorf("invalid redis db index %q", path)
		}
		db = parsedDB
	}

	prefix := opts.KeyPrefix
	if prefix == "" {
		prefix = "prismid:"
	}
	maxIdle := opts.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 32
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 2 * time.Second
	}
	opTimeout := opts.OpTimeout
	if opTimeout <= 0 {
		opTimeout = 2 * time.Second
	}
	maxPerIP := opts.MaxPerIP
	if maxPerIP <= 0 {
		maxPerIP = DefaultMaxChallengesPerIP
	}
	maxPerSubnet := opts.MaxPerSubnet
	if maxPerSubnet <= 0 {
		maxPerSubnet = DefaultMaxChallengesPerIPSub
	}
	beaconTTL := opts.BeaconTTL
	if beaconTTL <= 0 {
		beaconTTL = 180 * 24 * time.Hour
	}
	graphTTL := opts.GraphEdgeTTL
	if graphTTL <= 0 {
		graphTTL = 30 * 24 * time.Hour
	}
	nowFn := opts.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}

	var tlsCfg *tls.Config
	if useTLS {
		if opts.TLSConfig != nil {
			tlsCfg = opts.TLSConfig.Clone()
		} else {
			tlsCfg = &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: host,
			}
		}
	}

	rs := &RedisStore{
		addr:         addr,
		username:     username,
		password:     password,
		db:           db,
		useTLS:       useTLS,
		tlsCfg:       tlsCfg,
		prefix:       prefix,
		dialTimeout:  dialTimeout,
		opTimeout:    opTimeout,
		maxIdle:      maxIdle,
		maxPerIP:     maxPerIP,
		maxPerSubnet: maxPerSubnet,
		beaconTTLSec: int64(beaconTTL.Seconds()),
		graphTTLSec:  int64(graphTTL.Seconds()),
		nowFunc:      nowFn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout+opTimeout)
	defer cancel()
	if err := rs.Ping(ctx); err != nil {
		_ = rs.Close()
		return nil, fmt.Errorf("redis ping %s: %w", addr, err)
	}
	return rs, nil
}

// Close closes all pooled connections on the RedisStore.
func (r *RedisStore) Close() error {
	r.poolMu.Lock()
	r.closed = true
	conns := r.idle
	r.idle = nil
	r.poolMu.Unlock()
	for _, c := range conns {
		c.close()
	}
	return nil
}

// Ping verifies live connectivity to the Redis server.
func (r *RedisStore) Ping(ctx context.Context) error {
	rep, err := r.exec(ctx, "PING")
	if err != nil {
		return err
	}
	if rep.kind == '-' {
		return errors.New(rep.str)
	}
	return nil
}

func (r *RedisStore) key(parts ...string) string {
	return r.prefix + strings.Join(parts, ":")
}

func (r *RedisStore) deadlineFor(ctx context.Context) time.Time {
	dl := time.Now().Add(r.opTimeout)
	if ctx != nil {
		if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
			dl = ctxDL
		}
	}
	return dl
}

func (r *RedisStore) dial(ctx context.Context) (*respConn, error) {
	dialer := &net.Dialer{Timeout: r.dialTimeout}
	var rawConn net.Conn
	var err error
	if r.useTLS {
		rawConn, err = tls.DialWithDialer(dialer, "tcp", r.addr, r.tlsCfg)
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", r.addr)
	}
	if err != nil {
		return nil, err
	}
	rc := &respConn{
		conn: rawConn,
		br:   bufio.NewReaderSize(rawConn, 16*1024),
		bw:   bufio.NewWriterSize(rawConn, 16*1024),
	}
	_ = rawConn.SetDeadline(r.deadlineFor(ctx))

	if r.password != "" {
		var authCmd []string
		if r.username != "" {
			authCmd = []string{"AUTH", r.username, r.password}
		} else {
			authCmd = []string{"AUTH", r.password}
		}
		if err := writeRESPCommand(rc.bw, authCmd...); err != nil {
			rc.close()
			return nil, err
		}
		if err := rc.bw.Flush(); err != nil {
			rc.close()
			return nil, err
		}
		rep, err := readRESPValue(rc.br)
		if err != nil {
			rc.close()
			return nil, err
		}
		if rep.kind == '-' {
			rc.close()
			return nil, fmt.Errorf("redis AUTH failed: %s", rep.str)
		}
	}
	if r.db > 0 {
		if err := writeRESPCommand(rc.bw, "SELECT", strconv.Itoa(r.db)); err != nil {
			rc.close()
			return nil, err
		}
		if err := rc.bw.Flush(); err != nil {
			rc.close()
			return nil, err
		}
		rep, err := readRESPValue(rc.br)
		if err != nil {
			rc.close()
			return nil, err
		}
		if rep.kind == '-' {
			rc.close()
			return nil, fmt.Errorf("redis SELECT %d failed: %s", r.db, rep.str)
		}
	}
	return rc, nil
}

func (r *RedisStore) getConn(ctx context.Context) (*respConn, bool, error) {
	r.poolMu.Lock()
	if r.closed {
		r.poolMu.Unlock()
		return nil, false, errors.New("redis store is closed")
	}
	n := len(r.idle)
	if n > 0 {
		c := r.idle[n-1]
		r.idle = r.idle[:n-1]
		r.poolMu.Unlock()
		return c, true, nil
	}
	r.poolMu.Unlock()

	c, err := r.dial(ctx)
	return c, false, err
}

func (r *RedisStore) putConn(c *respConn) {
	if c == nil {
		return
	}
	r.poolMu.Lock()
	if r.closed || len(r.idle) >= r.maxIdle {
		r.poolMu.Unlock()
		c.close()
		return
	}
	r.idle = append(r.idle, c)
	r.poolMu.Unlock()
}

func (r *RedisStore) execPipeline(ctx context.Context, cmds [][]string) ([]respValue, error) {
	if len(cmds) == 0 {
		return nil, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		c, reused, err := r.getConn(ctx)
		if err != nil {
			return nil, err
		}
		_ = c.conn.SetDeadline(r.deadlineFor(ctx))

		writeErr := error(nil)
		for _, cmd := range cmds {
			if err := writeRESPCommand(c.bw, cmd...); err != nil {
				writeErr = err
				break
			}
		}
		if writeErr == nil {
			writeErr = c.bw.Flush()
		}
		if writeErr != nil {
			c.close()
			if reused && attempt == 0 {
				continue
			}
			return nil, writeErr
		}

		replies := make([]respValue, len(cmds))
		readErr := error(nil)
		for i := range cmds {
			rep, err := readRESPValue(c.br)
			if err != nil {
				readErr = err
				break
			}
			replies[i] = rep
		}
		if readErr != nil {
			c.close()
			if reused && attempt == 0 && (errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)) {
				continue
			}
			return nil, readErr
		}
		r.putConn(c)
		return replies, nil
	}
	return nil, errors.New("redis pipeline failed after reconnect")
}

func (r *RedisStore) exec(ctx context.Context, args ...string) (respValue, error) {
	reps, err := r.execPipeline(ctx, [][]string{args})
	if err != nil {
		return respValue{}, err
	}
	if reps[0].kind == '-' {
		return reps[0], errors.New(reps[0].str)
	}
	return reps[0], nil
}

func writeRESPCommand(w *bufio.Writer, args ...string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, a := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(a), a); err != nil {
			return err
		}
	}
	return nil
}

func readRESPValue(r *bufio.Reader) (respValue, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return respValue{}, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return respValue{}, errors.New("malformed RESP line")
	}
	prefix := line[0]
	payload := line[1 : len(line)-2]

	switch prefix {
	case '+', '-':
		return respValue{kind: prefix, str: payload}, nil
	case ':':
		n, err := strconv.ParseInt(payload, 10, 64)
		if err != nil {
			return respValue{}, err
		}
		return respValue{kind: ':', integer: n}, nil
	case '$':
		size, err := strconv.Atoi(payload)
		if err != nil {
			return respValue{}, err
		}
		if size < 0 {
			return respValue{kind: '$', isNull: true}, nil
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return respValue{}, err
		}
		return respValue{kind: '$', str: string(buf[:size])}, nil
	case '*':
		count, err := strconv.Atoi(payload)
		if err != nil {
			return respValue{}, err
		}
		if count < 0 {
			return respValue{kind: '*', isNull: true}, nil
		}
		arr := make([]respValue, count)
		for i := 0; i < count; i++ {
			elem, err := readRESPValue(r)
			if err != nil {
				return respValue{}, err
			}
			arr[i] = elem
		}
		return respValue{kind: '*', array: arr}, nil
	default:
		return respValue{}, fmt.Errorf("unexpected RESP prefix %q", prefix)
	}
}

func (r *RedisStore) atomicGetDel(ctx context.Context, k string) (string, bool, error) {
	rep, err := r.exec(ctx, "GETDEL", k)
	if err == nil {
		if rep.isNull {
			return "", false, nil
		}
		return rep.str, true, nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "unknown command") {
		reps, pErr := r.execPipeline(ctx, [][]string{
			{"MULTI"},
			{"GET", k},
			{"DEL", k},
			{"EXEC"},
		})
		if pErr != nil {
			return "", false, pErr
		}
		execRep := reps[len(reps)-1]
		if execRep.kind == '*' && len(execRep.array) >= 1 {
			if execRep.array[0].isNull {
				return "", false, nil
			}
			return execRep.array[0].str, true, nil
		}
		return "", false, errors.New("redis MULTI/EXEC GET+DEL failed")
	}
	return "", false, err
}

// SaveChallenge enforces cluster-wide per-IP and per-subnet active challenge quotas and stores `ch` with TTL.
func (r *RedisStore) SaveChallenge(ctx context.Context, ch Challenge, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	ttlMs := ttl.Milliseconds()
	if ttlMs < 1 {
		ttlMs = 1
	}
	ttlMsStr := strconv.FormatInt(ttlMs, 10)

	host := normalizeChallengeHost(ch.ClientIP)
	subnet := ExtractIPSubnet(ch.ClientIP)

	if host != "" && r.maxPerIP > 0 {
		ipKey := r.key("q", "ip", host)
		reps, err := r.execPipeline(ctx, [][]string{
			{"INCR", ipKey},
			{"PEXPIRE", ipKey, ttlMsStr, "NX"},
		})
		if err != nil {
			return err
		}
		// Fallback for Redis < 7.0 where PEXPIRE does not accept NX:
		if reps[1].kind == '-' {
			_, _ = r.exec(ctx, "PEXPIRE", ipKey, ttlMsStr)
		}
		if reps[0].integer > int64(r.maxPerIP) {
			_, _ = r.exec(ctx, "DECR", ipKey)
			return &VerificationError{
				Code:   ErrCodeChallengeRateLimited,
				Detail: "too many active challenges for client IP",
			}
		}
	}

	if subnet != "" && subnet != "unknown" && r.maxPerSubnet > 0 {
		subKey := r.key("q", "sub", subnet)
		reps, err := r.execPipeline(ctx, [][]string{
			{"INCR", subKey},
			{"PEXPIRE", subKey, ttlMsStr, "NX"},
		})
		if err != nil {
			return err
		}
		if reps[1].kind == '-' {
			_, _ = r.exec(ctx, "PEXPIRE", subKey, ttlMsStr)
		}
		if reps[0].integer > int64(r.maxPerSubnet) {
			_, _ = r.exec(ctx, "DECR", subKey)
			if host != "" && r.maxPerIP > 0 {
				_, _ = r.exec(ctx, "DECR", r.key("q", "ip", host))
			}
			return &VerificationError{
				Code:   ErrCodeChallengeRateLimited,
				Detail: "too many active challenges for client subnet",
			}
		}
	}

	raw, err := json.Marshal(ch)
	if err != nil {
		return err
	}
	_, err = r.exec(ctx, "SET", r.key("ch", ch.Nonce), string(raw), "PX", ttlMsStr)
	return err
}

// ConsumeChallenge atomically fetches and deletes `nonce` once across all cluster nodes.
func (r *RedisStore) ConsumeChallenge(ctx context.Context, nonce string) (*Challenge, error) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return nil, nil
	}
	raw, found, err := r.atomicGetDel(ctx, r.key("ch", nonce))
	if err != nil || !found {
		return nil, err
	}
	var ch Challenge
	if err := json.Unmarshal([]byte(raw), &ch); err != nil {
		return nil, err
	}

	// Decrement active challenge quota counters best-effort so legitimate high-throughput clients are not throttled.
	var decrCmds [][]string
	if host := normalizeChallengeHost(ch.ClientIP); host != "" && r.maxPerIP > 0 {
		decrCmds = append(decrCmds, []string{"DECR", r.key("q", "ip", host)})
	}
	if sub := ExtractIPSubnet(ch.ClientIP); sub != "" && sub != "unknown" && r.maxPerSubnet > 0 {
		decrCmds = append(decrCmds, []string{"DECR", r.key("q", "sub", sub)})
	}
	if len(decrCmds) > 0 {
		_, _ = r.execPipeline(ctx, decrCmds)
	}
	return &ch, nil
}

// RecordNativeAnchorForGPU records a native hardware slice observed for a keychain/beacon scope.
func (r *RedisStore) RecordNativeAnchorForGPU(ctx context.Context, anchorScopeKey, nativeSliceID string) (int, error) {
	if anchorScopeKey == "" || nativeSliceID == "" {
		return 0, nil
	}
	k := r.key("g2n", anchorScopeKey)
	reps, err := r.execPipeline(ctx, [][]string{
		{"SADD", k, nativeSliceID},
		{"EXPIRE", k, strconv.FormatInt(r.graphTTLSec, 10)},
		{"SCARD", k},
	})
	if err != nil {
		return 0, err
	}
	return int(reps[2].integer), nil
}

// RecordSubnetGPU records a GPU slice observed on an IP subnet within a rolling window.
func (r *RedisStore) RecordSubnetGPU(ctx context.Context, ipSubnet, gpuSliceID string, window time.Duration) (int, error) {
	if ipSubnet == "" || ipSubnet == "unknown" || gpuSliceID == "" {
		return 0, nil
	}
	if window <= 0 {
		window = 7 * 24 * time.Hour
	}
	nowMs := r.nowFunc().UnixMilli()
	cutoffMs := nowMs - window.Milliseconds()
	k := r.key("subgpu", ipSubnet)
	reps, err := r.execPipeline(ctx, [][]string{
		{"ZREMRANGEBYSCORE", k, "-inf", strconv.FormatInt(cutoffMs, 10)},
		{"ZADD", k, strconv.FormatInt(nowMs, 10), gpuSliceID},
		{"PEXPIRE", k, strconv.FormatInt(window.Milliseconds(), 10)},
		{"ZCARD", k},
	})
	if err != nil {
		return 0, err
	}
	return int(reps[3].integer), nil
}

// CheckOrBindBeaconDeviceKey enforces atomic cluster-wide TOFU binding between `d_bcn_*` and `d_key_*`.
func (r *RedisStore) CheckOrBindBeaconDeviceKey(ctx context.Context, beaconSliceID, deviceKeySliceID string) (bool, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	deviceKeySliceID = strings.TrimSpace(deviceKeySliceID)
	if beaconSliceID == "" {
		return true, nil
	}
	k := r.key("tofu", beaconSliceID)
	ttlStr := strconv.FormatInt(r.beaconTTLSec, 10)

	if deviceKeySliceID == "" {
		rep, err := r.exec(ctx, "GET", k)
		if err != nil {
			return false, err
		}
		return rep.isNull || rep.str == "", nil
	}

	// Atomic first-use claim via SET ... NX EX:
	setRep, err := r.exec(ctx, "SET", k, deviceKeySliceID, "NX", "EX", ttlStr)
	if err != nil {
		return false, err
	}
	if !setRep.isNull && setRep.str == "OK" {
		return true, nil
	}

	// Already bound — verify equality and refresh TTL on match:
	getRep, err := r.exec(ctx, "GET", k)
	if err != nil {
		return false, err
	}
	if getRep.isNull || getRep.str == "" {
		return true, nil
	}
	if getRep.str != deviceKeySliceID {
		return false, nil
	}
	_, _ = r.exec(ctx, "EXPIRE", k, ttlStr)
	return true, nil
}

// GetBoundBeaconDeviceKey returns the currently bound `d_key_*` slice for `beaconSliceID`.
func (r *RedisStore) GetBoundBeaconDeviceKey(ctx context.Context, beaconSliceID string) (string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if beaconSliceID == "" {
		return "", nil
	}
	rep, err := r.exec(ctx, "GET", r.key("tofu", beaconSliceID))
	if err != nil || rep.isNull {
		return "", err
	}
	return rep.str, nil
}

// RebindBeaconDeviceKey atomically swaps the bound `d_key_*` slice for `beaconSliceID`.
func (r *RedisStore) RebindBeaconDeviceKey(ctx context.Context, beaconSliceID, newDeviceKeySliceID string) (string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	newDeviceKeySliceID = strings.TrimSpace(newDeviceKeySliceID)
	if beaconSliceID == "" || newDeviceKeySliceID == "" {
		return "", errors.New("beacon_slice_id and new_device_key_slice_id are required")
	}
	k := r.key("tofu", beaconSliceID)
	reps, err := r.execPipeline(ctx, [][]string{
		{"GETSET", k, newDeviceKeySliceID},
		{"EXPIRE", k, strconv.FormatInt(r.beaconTTLSec, 10)},
	})
	if err != nil {
		return "", err
	}
	if reps[0].isNull {
		return "", nil
	}
	return reps[0].str, nil
}

// ClearBeaconDeviceKey atomically removes the TOFU device-key binding for `beaconSliceID`.
func (r *RedisStore) ClearBeaconDeviceKey(ctx context.Context, beaconSliceID string) (string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if beaconSliceID == "" {
		return "", errors.New("beacon_slice_id is required")
	}
	prev, _, err := r.atomicGetDel(ctx, r.key("tofu", beaconSliceID))
	return prev, err
}

// RecordBeaconOwner persists `(beaconSliceID <-> subjectID)` ownership in Redis sets.
func (r *RedisStore) RecordBeaconOwner(ctx context.Context, beaconSliceID, subjectID string) error {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	subjectID = strings.TrimSpace(subjectID)
	if beaconSliceID == "" || subjectID == "" {
		return nil
	}
	bcnKey := r.key("own", "bcn", beaconSliceID)
	subKey := r.key("own", "sub", subjectID)
	ttlStr := strconv.FormatInt(r.beaconTTLSec, 10)
	_, err := r.execPipeline(ctx, [][]string{
		{"SADD", bcnKey, subjectID},
		{"EXPIRE", bcnKey, ttlStr},
		{"SADD", subKey, beaconSliceID},
		{"EXPIRE", subKey, ttlStr},
	})
	return err
}

// GetBeaconOwners returns sorted subject IDs recorded as owners of `beaconSliceID`.
func (r *RedisStore) GetBeaconOwners(ctx context.Context, beaconSliceID string) ([]string, error) {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	if beaconSliceID == "" {
		return nil, nil
	}
	rep, err := r.exec(ctx, "SMEMBERS", r.key("own", "bcn", beaconSliceID))
	if err != nil || rep.isNull {
		return nil, err
	}
	out := make([]string, 0, len(rep.array))
	for _, elem := range rep.array {
		if elem.str != "" {
			out = append(out, elem.str)
		}
	}
	sort.Strings(out)
	return out, nil
}

// RemoveSubjectBeaconOwnership deletes `subjectID` from all beacon ownership sets (GDPR erasure).
func (r *RedisStore) RemoveSubjectBeaconOwnership(ctx context.Context, subjectID string) ([]string, []string, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, nil, nil
	}
	subKey := r.key("own", "sub", subjectID)
	rep, err := r.exec(ctx, "SMEMBERS", subKey)
	if err != nil || rep.isNull || len(rep.array) == 0 {
		return nil, nil, err
	}
	beacons := make([]string, 0, len(rep.array))
	for _, elem := range rep.array {
		if elem.str != "" {
			beacons = append(beacons, elem.str)
		}
	}
	sort.Strings(beacons)

	var cmds [][]string
	for _, bcn := range beacons {
		bcnKey := r.key("own", "bcn", bcn)
		cmds = append(cmds, []string{"SREM", bcnKey, subjectID})
		cmds = append(cmds, []string{"SCARD", bcnKey})
	}
	cmds = append(cmds, []string{"DEL", subKey})
	reps, err := r.execPipeline(ctx, cmds)
	if err != nil {
		return nil, beacons, err
	}
	var orphaned []string
	for i, bcn := range beacons {
		if reps[i*2+1].integer == 0 {
			orphaned = append(orphaned, bcn)
		}
	}
	return orphaned, beacons, nil
}

// ConsumeStepUpJTI atomically marks a `stepup_v2` JTI as consumed across all server replicas.
func (r *RedisStore) ConsumeStepUpJTI(ctx context.Context, jti string, expUnix, nowUnix int64) (bool, error) {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false, nil
	}
	ttlSec := expUnix - nowUnix + 5
	if ttlSec < 1 {
		ttlSec = 1
	}
	rep, err := r.exec(ctx, "SET", r.key("jti", jti), "1", "NX", "EX", strconv.FormatInt(ttlSec, 10))
	if err != nil {
		return false, err
	}
	return !rep.isNull && rep.str == "OK", nil
}

// RevokeTokenHash immediately revokes a bearer token SHA-256 digest across all server replicas.
func (r *RedisStore) RevokeTokenHash(ctx context.Context, tokenSHAHex string, untilUnix, nowUnix int64) error {
	tokenSHAHex = strings.TrimSpace(tokenSHAHex)
	if tokenSHAHex == "" {
		return nil
	}
	ttlSec := untilUnix - nowUnix
	if ttlSec < 1 {
		ttlSec = 1
	}
	_, err := r.exec(ctx, "SET", r.key("rev", "tok", tokenSHAHex), "1", "EX", strconv.FormatInt(ttlSec, 10))
	return err
}

// RevokeSubject immediately revokes all tokens for `subjectID` until `untilUnix` across all replicas.
func (r *RedisStore) RevokeSubject(ctx context.Context, subjectID string, untilUnix, nowUnix int64) error {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil
	}
	ttlSec := untilUnix - nowUnix
	if ttlSec < 1 {
		ttlSec = 1
	}
	_, err := r.exec(ctx, "SET", r.key("rev", "sub", subjectID), "1", "EX", strconv.FormatInt(ttlSec, 10))
	return err
}

// IsRevoked checks cluster-wide token and subject revocation keys in a single pipelined round-trip.
func (r *RedisStore) IsRevoked(ctx context.Context, tokenSHAHex, subjectID string, _ int64) (bool, error) {
	var cmds [][]string
	if tokenSHAHex != "" {
		cmds = append(cmds, []string{"EXISTS", r.key("rev", "tok", tokenSHAHex)})
	}
	if subjectID != "" {
		cmds = append(cmds, []string{"EXISTS", r.key("rev", "sub", subjectID)})
	}
	if len(cmds) == 0 {
		return false, nil
	}
	reps, err := r.execPipeline(ctx, cmds)
	if err != nil {
		return false, err
	}
	for _, rep := range reps {
		if rep.integer > 0 {
			return true, nil
		}
	}
	return false, nil
}

// UpsertGraphEdges persists updated RiskGraph edges and reverse slice->subject indexes in 1 pipeline round-trip.
func (r *RedisStore) UpsertGraphEdges(ctx context.Context, edges []GraphEdge) error {
	if r == nil || len(edges) == 0 {
		return nil
	}
	ttlStr := strconv.FormatInt(r.graphTTLSec, 10)
	cmds := make([][]string, 0, len(edges)*4)
	for _, e := range edges {
		if e.SubjectID == "" || e.SliceID == "" {
			continue
		}
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		subKey := r.key("g", "sub", e.SubjectID)
		slKey := r.key("g", "sl", e.SliceID)
		obsMs := strconv.FormatInt(edgeObservedAt(e).UnixMilli(), 10)
		cmds = append(cmds,
			[]string{"HSET", subKey, e.SliceID, string(raw)},
			[]string{"EXPIRE", subKey, ttlStr},
			[]string{"HSET", slKey, e.SubjectID, obsMs},
			[]string{"EXPIRE", slKey, ttlStr},
		)
	}
	_, err := r.execPipeline(ctx, cmds)
	return err
}

// DeleteGraphEdges removes specific `(subjectID, sliceID)` edges from Redis.
func (r *RedisStore) DeleteGraphEdges(ctx context.Context, subjectID string, sliceIDs ...string) error {
	if r == nil {
		return nil
	}
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" || len(sliceIDs) == 0 {
		return nil
	}
	subKey := r.key("g", "sub", subjectID)
	var cmds [][]string
	for _, sl := range sliceIDs {
		sl = strings.TrimSpace(sl)
		if sl == "" {
			continue
		}
		cmds = append(cmds,
			[]string{"HDEL", subKey, sl},
			[]string{"HDEL", r.key("g", "sl", sl), subjectID},
		)
	}
	if len(cmds) == 0 {
		return nil
	}
	_, err := r.execPipeline(ctx, cmds)
	return err
}

// DeleteSubjectGraphEdges deletes all RiskGraph edges and reverse slice index entries for `subjectID`.
func (r *RedisStore) DeleteSubjectGraphEdges(ctx context.Context, subjectID string) error {
	if r == nil {
		return nil
	}
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil
	}
	subKey := r.key("g", "sub", subjectID)
	rep, err := r.exec(ctx, "HKEYS", subKey)
	if err != nil {
		return err
	}
	var cmds [][]string
	for _, elem := range rep.array {
		if elem.str != "" {
			cmds = append(cmds, []string{"HDEL", r.key("g", "sl", elem.str), subjectID})
		}
	}
	cmds = append(cmds, []string{"DEL", subKey})
	_, err = r.execPipeline(ctx, cmds)
	return err
}

// LoadGraphNeighborhood fetches the 2-hop bipartite neighborhood around `seedSubjectID` and
// `extraSliceIDs` in at most 3 pipelined round-trips.
func (r *RedisStore) LoadGraphNeighborhood(ctx context.Context, seedSubjectID string, extraSliceIDs []string, maxSubjects int) ([]GraphEdge, error) {
	if r == nil {
		return nil, nil
	}
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

	// Round-trip 1: Load seed subject's existing edges.
	if seedSubjectID != "" {
		seenSubjects[seedSubjectID] = struct{}{}
		rep, err := r.exec(ctx, "HGETALL", r.key("g", "sub", seedSubjectID))
		if err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(rep.array); i += 2 {
			var e GraphEdge
			if json.Unmarshal([]byte(rep.array[i+1].str), &e) == nil && e.SubjectID != "" && e.SliceID != "" {
				edges = append(edges, e)
				sliceSet[e.SliceID] = struct{}{}
			}
		}
	}

	if len(sliceSet) == 0 {
		return edges, nil
	}

	// Round-trip 2: Discover peer subjects connected to any of those slices.
	slices := make([]string, 0, len(sliceSet))
	for sl := range sliceSet {
		slices = append(slices, sl)
	}
	sort.Strings(slices)
	slCmds := make([][]string, len(slices))
	for i, sl := range slices {
		slCmds[i] = []string{"HKEYS", r.key("g", "sl", sl)}
	}
	slReps, err := r.execPipeline(ctx, slCmds)
	if err != nil {
		return edges, err
	}

	var peerSubjects []string
	for _, rep := range slReps {
		for _, elem := range rep.array {
			sid := strings.TrimSpace(elem.str)
			if sid == "" {
				continue
			}
			if _, seen := seenSubjects[sid]; !seen {
				seenSubjects[sid] = struct{}{}
				peerSubjects = append(peerSubjects, sid)
				if len(seenSubjects) >= maxSubjects {
					break
				}
			}
		}
		if len(seenSubjects) >= maxSubjects {
			break
		}
	}
	if len(peerSubjects) == 0 {
		return edges, nil
	}

	// Round-trip 3: Fetch all edges of discovered peer subjects.
	sort.Strings(peerSubjects)
	peerCmds := make([][]string, len(peerSubjects))
	for i, sid := range peerSubjects {
		peerCmds[i] = []string{"HGETALL", r.key("g", "sub", sid)}
	}
	peerReps, err := r.execPipeline(ctx, peerCmds)
	if err != nil {
		return edges, err
	}
	for _, rep := range peerReps {
		for i := 0; i+1 < len(rep.array); i += 2 {
			var e GraphEdge
			if json.Unmarshal([]byte(rep.array[i+1].str), &e) == nil && e.SubjectID != "" && e.SliceID != "" {
				edges = append(edges, e)
			}
		}
	}
	return edges, nil
}
