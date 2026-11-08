package main

import (
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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
<title>PrismID Standalone Verification Console</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0f172a; color: #e2e8f0; max-width: 880px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #38bdf8; }
  pre { background: #1e293b; padding: 16px; border-radius: 8px; overflow-x: auto; border: 1px solid #334155; }
  button { background: #0284c7; color: #fff; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: 600; }
</style>
</head>
<body>
  <h1>PrismID Standalone Server</h1>
  <p>Orthogonal Hardware Fingerprinting &amp; Dynamic WebGL Shader Challenge Engine</p>
  <button id="btn">Issue Challenge</button>
  <pre id="out">Click "Issue Challenge" to inspect live challenge parameters...</pre>
  <script>
    document.getElementById('btn').onclick = async () => {
      const res = await fetch('/api/v1/risk/challenge', { method: 'POST' });
      const data = await res.json();
      document.getElementById('out').textContent = JSON.stringify(data, null, 2);
    };
  </script>
</body>
</html>`
