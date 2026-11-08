package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

//go:embed static/prismid.bundle.js
var embeddedPrismBundleJS []byte

func main() {
	addr := flag.String("addr", ":8090", "HTTP listen address")
	hmacSecret := flag.String("secret", "", "HMAC secret key (or PRISMID_HMAC_SECRET env)")
	flag.Parse()

	secret := strings.TrimSpace(*hmacSecret)
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("PRISMID_HMAC_SECRET"))
	}
	if secret == "" {
		secret = "prismid-standalone-server-hmac-secret-key-v1"
	}

	verifier := prismid.NewVerifier(prismid.Config{
		HMACSecret:   []byte(secret),
		ChallengeTTL: 60 * time.Second,
	}, prismid.NewMemoryChallengeStore())

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "engine": "prismid-go"})
	})

	mux.HandleFunc("/prismid.bundle.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(embeddedPrismBundleJS)
	})

	mux.HandleFunc("/api/v1/risk/should-collect", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"should_collect": true,
		})
	})

	mux.HandleFunc("/api/v1/risk/challenge", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		ch, err := verifier.IssueChallenge(r.Context(), extractClientIP(r))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ch)
	})

	mux.HandleFunc("/api/v1/risk/identify", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		var req prismid.IdentifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
			return
		}
		res, err := verifier.VerifyAndDerive(r.Context(), req, extractClientIP(r))
		if err != nil {
			status := http.StatusBadRequest
			if vErr, ok := err.(*prismid.VerificationError); ok {
				if vErr.Code == prismid.ErrCodeChallengeInvalid {
					status = http.StatusConflict
				}
				writeJSON(w, status, map[string]any{
					"accepted": false,
					"code":     vErr.Code,
					"message":  vErr.Detail,
				})
				return
			}
			writeJSON(w, status, map[string]any{"accepted": false, "message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(standaloneIndexHTML))
	})

	log.Printf("PrismID standalone verification server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func extractClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func enableCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Forwarded-For")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

const standaloneIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PrismID Standalone Verification &amp; Adversarial Lab</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0f172a; color: #e2e8f0; max-width: 1040px; margin: 32px auto; padding: 0 20px; line-height: 1.5; }
  h1 { color: #38bdf8; margin-bottom: 4px; }
  .subtitle { color: #94a3b8; margin-bottom: 24px; font-size: 14px; }
  .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
  button { background: #0284c7; color: #fff; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; }
  button:hover { background: #0369a1; }
  button.secondary { background: #334155; }
  button.secondary:hover { background: #475569; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .card { background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; }
  .card h3 { margin-top: 0; color: #7dd3fc; font-size: 15px; }
  pre { background: #090d16; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #a7f3d0; max-height: 420px; }
</style>
</head>
<body>
  <h1>PrismID Standalone Verification Console</h1>
  <div class="subtitle">Zero-cost Orthogonal Hardware Fingerprinting, Dynamic WebGL Shader Challenge &amp; Cross-Thread Lie Detector</div>
  <div class="actions">
    <button id="btn-identify">1. Run Live Browser Identify (prismid-js)</button>
    <button id="btn-proxy" class="secondary">2. Simulate Residential Proxy Rotation + Canvas Noise</button>
    <button id="btn-replay" class="secondary">3. Simulate Nonce Replay Attack</button>
  </div>
  <div class="grid">
    <div class="card">
      <h3>Server Verification &amp; Orthogonal Spectral Slices</h3>
      <pre id="server-out">Click "Run Live Browser Identify" to execute full Challenge -> WebGL Shader -> AEAD -> Go Verify pipeline...</pre>
    </div>
    <div class="card">
      <h3>Client Probe Telemetry &amp; AEAD Envelope</h3>
      <pre id="client-out">Waiting for probe execution...</pre>
    </div>
  </div>
  <script type="module">
    import { createPrismClient, sealPayload } from '/prismid.bundle.js';
    const prism = createPrismClient({ baseUrl: '' });
    let lastWireReq = null;

    document.getElementById('btn-identify').onclick = async () => {
      const chRes = await fetch('/api/v1/risk/challenge', { method: 'POST' });
      const ch = await chRes.json();
      const { request, payload } = await prism.collectAndSeal(ch);
      lastWireReq = request;
      document.getElementById('client-out').textContent = JSON.stringify({
        wire_request_preview: { c: request.c, p_length: request.p.length, p_head: request.p.slice(0, 48) + '...' },
        decrypted_payload: payload,
      }, null, 2);

      const idRes = await fetch('/api/v1/risk/identify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      const verifyResult = await idRes.json();
      document.getElementById('server-out').textContent = JSON.stringify(verifyResult, null, 2);
    };

    document.getElementById('btn-proxy').onclick = async () => {
      const chRes = await fetch('/api/v1/risk/challenge', { method: 'POST' });
      const ch = await chRes.json();
      const { payload } = await prism.collectAndSeal(ch);
      payload.system.canvas_2d_hash = 'spoofed_canvas_' + Math.random().toString(16).slice(2);
      payload.system.fonts_bitmap_hash = 'spoofed_fonts_' + Math.random().toString(16).slice(2);
      payload.system.screen_spec = '3840x2160x24@2';
      const p = await sealPayload(ch.nonce, JSON.stringify(payload));
      const randomIp = '198.51.' + Math.floor(Math.random() * 250) + '.42';
      const idRes = await fetch('/api/v1/risk/identify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': randomIp },
        body: JSON.stringify({ c: ch.nonce, p }),
      });
      const verifyResult = await idRes.json();
      document.getElementById('server-out').textContent = JSON.stringify({
        simulated_proxy_ip: randomIp,
        note: 'Notice that gpu_audio_slice_id (d_gpu_*) remains 100% identical despite new IP & mutated Canvas/Fonts/Screen!',
        result: verifyResult,
      }, null, 2);
    };

    document.getElementById('btn-replay').onclick = async () => {
      if (!lastWireReq) {
        alert('Run step 1 first to capture a valid packet.');
        return;
      }
      const idRes = await fetch('/api/v1/risk/identify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lastWireReq),
      });
      const verifyResult = await idRes.json();
      document.getElementById('server-out').textContent = JSON.stringify(verifyResult, null, 2);
    };
  </script>
</body>
</html>`
