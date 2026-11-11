package prismid

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// TransportSignals carries TLS ClientHello (JA3/JA4) and HTTP/2 ALPN/SETTINGS fingerprints
// extracted by a trusted ingress reverse proxy (Cloudflare, Envoy, Nginx, HAProxy, AWS ALB).
type TransportSignals struct {
	TLSJA4           string `json:"tls_ja4,omitempty"`
	TLSJA3           string `json:"tls_ja3,omitempty"`
	HTTP2Fingerprint string `json:"http2_fingerprint,omitempty"`
}

// VerifyTransportConsistency cross-checks transport-layer TLS JA4 and HTTP/2 frame fingerprints
// against the application-layer User-Agent and JS engine signature inside the decrypted payload,
// catching protocol-replay bots (Python requests/httpx, curl, Go net/http, Node axios) that solve
// WebGL math in CPU or hijack tokens from a non-browser TLS stack.
func VerifyTransportConsistency(ts TransportSignals, payload *ProbePayload) []string {
	if payload == nil {
		return nil
	}
	var violations []string
	uaLower := strings.ToLower(strings.TrimSpace(payload.System.UserAgent))
	mathSig := strings.ToLower(strings.TrimSpace(payload.Lies.MathEngineSignature))

	claimsModernBrowser := strings.Contains(uaLower, "chrome/") ||
		strings.Contains(uaLower, "firefox/") ||
		(strings.Contains(uaLower, "safari/") && strings.Contains(uaLower, "version/")) ||
		strings.Contains(uaLower, "edg/")

	// 1. FoxIO JA4 ClientHello inspection:
	// Canonical JA4_a segment (10 chars before first '_'):
	//   [0]     protocol ('t' = TCP/TLS, 'q' = QUIC)
	//   [1:3]   TLS version ("13" = TLS 1.3, "12" = TLS 1.2, "11" = TLS 1.1)
	//   [3]     SNI ('d' = domain, 'i' = IP literal)
	//   [4:6]   2-digit cipher count (excluding GREASE)
	//   [6:8]   2-digit extension count (excluding GREASE)
	//   [8:10]  2-char first ALPN ("h2", "h3", "h1", "00" = no ALPN)
	ja4 := strings.ToLower(strings.TrimSpace(ts.TLSJA4))
	if ja4 != "" && claimsModernBrowser {
		parts := strings.Split(ja4, "_")
		ja4a := parts[0]
		if len(ja4a) == 10 && (ja4a[0] == 't' || ja4a[0] == 'q') {
			tlsVer := ja4a[1:3]
			cipherCnt, errCipher := strconv.Atoi(ja4a[4:6])
			extCnt, errExt := strconv.Atoi(ja4a[6:8])
			alpn := ja4a[8:10]

			if tlsVer != "13" {
				violations = appendUniqueFlag(violations, "tls_ja4_browser_mismatch:legacy_tls_version")
			}
			if errCipher == nil && errExt == nil && (cipherCnt < 6 || extCnt < 8) {
				violations = appendUniqueFlag(violations, "tls_ja4_browser_mismatch:minimal_client_hello")
			}
			if alpn == "00" {
				violations = appendUniqueFlag(violations, "tls_ja4_browser_mismatch:missing_alpn")
			}
		}
	}

	// 2. Akamai HTTP/2 Fingerprint inspection:
	// Format: `<SETTINGS>|<WINDOW_UPDATE>|<PRIORITY>|<pseudo_header_order>`
	//   - Chromium (V8): `m,a,s,p` (`:method,:authority,:scheme,:path`)
	//   - Firefox (SpiderMonkey): `m,p,a,s` (`:method,:path,:authority,:scheme`)
	//   - Safari/WebKit (JSC): `m,s,p,a` or `m,s,a,p`
	//   - Go x/net/http2 & Python h2/httpx default: `m,p,a,s` or `m,s,a,p` with small window update
	h2 := strings.ToLower(strings.TrimSpace(ts.HTTP2Fingerprint))
	if h2 != "" {
		h2Parts := strings.Split(h2, "|")
		if len(h2Parts) == 4 {
			pseudoOrder := strings.ReplaceAll(strings.TrimSpace(h2Parts[3]), " ", "")
			claimsChromium := (strings.Contains(uaLower, "chrome/") || strings.Contains(uaLower, "edg/")) &&
				!strings.Contains(uaLower, "firefox/")
			if claimsChromium && mathSig == "v8" && pseudoOrder != "" && pseudoOrder != "m,a,s,p" {
				violations = appendUniqueFlag(violations, "http2_fingerprint_browser_mismatch:pseudo_header_order")
			}
			if strings.Contains(uaLower, "firefox/") && mathSig == "spidermonkey" && pseudoOrder != "" && pseudoOrder != "m,p,a,s" {
				violations = appendUniqueFlag(violations, "http2_fingerprint_browser_mismatch:pseudo_header_order")
			}
		}
	}

	return violations
}

// TrustedProxyChecker validates reverse-proxy peer IPs against an explicit CIDR allowlist and
// performs spoof-resistant right-to-left X-Forwarded-For client IP extraction.
type TrustedProxyChecker struct {
	trustAll bool
	nets     []*net.IPNet
}

// ParseTrustedProxyCIDRs parses a comma-separated list of CIDRs or single IP addresses
// (e.g., "127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12").
func ParseTrustedProxyCIDRs(spec string) (*TrustedProxyChecker, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, token := range strings.Split(trimmed, ",") {
		entry := strings.TrimSpace(token)
		if entry == "" {
			continue
		}
		if entry == "*" {
			return &TrustedProxyChecker{trustAll: true}, nil
		}
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipNet)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid trusted proxy IP %q", entry)
		}
		if ip4 := ip.To4(); ip4 != nil {
			nets = append(nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}
	if len(nets) == 0 {
		return nil, nil
	}
	return &TrustedProxyChecker{nets: nets}, nil
}

// IsTrustedPeer reports whether `addrOrIP` belongs to a trusted ingress reverse proxy.
func (t *TrustedProxyChecker) IsTrustedPeer(addrOrIP string) bool {
	if t == nil {
		return false
	}
	if t.trustAll {
		return true
	}
	host := strings.TrimSpace(addrOrIP)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractRealClientIP extracts the true client IP from an HTTP request:
//   - If `checker != nil`: proxy headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) are ONLY
//     honored when `r.RemoteAddr` matches `checker.IsTrustedPeer`, and `X-Forwarded-For` is walked
//     right-to-left skipping trusted proxy hops so client-injected fake XFF prefixes are ignored.
//   - Else if `legacyTrustAllProxy`: preserves legacy `-trust-proxy` behavior for local/lab setups.
//   - Otherwise: ignores all proxy headers and uses `r.RemoteAddr`.
func ExtractRealClientIP(r *http.Request, checker *TrustedProxyChecker, legacyTrustAllProxy bool) string {
	remoteHost := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(remoteHost); err == nil {
		remoteHost = h
	}

	trusted := false
	if checker != nil {
		trusted = checker.IsTrustedPeer(remoteHost)
	} else if legacyTrustAllProxy {
		trusted = true
	}
	if !trusted {
		return remoteHost
	}

	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		hops := strings.Split(xff, ",")
		if checker != nil && !checker.trustAll {
			// Walk right-to-left and return the rightmost valid IP that is NOT itself a trusted proxy hop.
			var fallbackValid string
			for i := len(hops) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(hops[i])
				if candidate == "" || net.ParseIP(candidate) == nil {
					continue
				}
				fallbackValid = candidate
				if !checker.IsTrustedPeer(candidate) {
					return candidate
				}
			}
			if fallbackValid != "" {
				return fallbackValid
			}
		} else {
			if ip := strings.TrimSpace(hops[0]); ip != "" {
				return ip
			}
		}
	}
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" && net.ParseIP(cfIP) != nil {
		return cfIP
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	return remoteHost
}

func firstNonEmptyHeader(r *http.Request, names ...string) string {
	for _, name := range names {
		if v := strings.TrimSpace(r.Header.Get(name)); v != "" {
			return v
		}
	}
	return ""
}

// ExtractTrustedTransportSignals reads TLS JA4/JA3 and HTTP/2 fingerprint headers ONLY when the
// HTTP request arrived from a verified trusted ingress proxy.
func ExtractTrustedTransportSignals(r *http.Request, checker *TrustedProxyChecker, legacyTrustAllProxy bool) TransportSignals {
	trusted := false
	if checker != nil {
		trusted = checker.IsTrustedPeer(r.RemoteAddr)
	} else if legacyTrustAllProxy {
		trusted = true
	}
	if !trusted {
		return TransportSignals{}
	}
	return TransportSignals{
		TLSJA4:           firstNonEmptyHeader(r, "X-PrismID-JA4", "X-TLS-JA4", "CF-JA4"),
		TLSJA3:           firstNonEmptyHeader(r, "X-PrismID-JA3", "X-TLS-JA3"),
		HTTP2Fingerprint: firstNonEmptyHeader(r, "X-PrismID-H2-Fingerprint", "X-HTTP2-Fingerprint"),
	}
}
