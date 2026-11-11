.PHONY: all test test-go test-web test-rust bench build run-server run-demo

all: test build

test: test-go test-rust test-web

test-go:
	cd server/go && go vet ./... && go test -v -race -shuffle=on ./...

bench:
	cd server/go && go run ./cmd/prismid-bench

test-rust:
	cd crates/prismid-native && cargo test --locked && cargo test --locked --no-default-features

test-web:
	cd packages/web-sdk && pnpm typecheck && pnpm build && pnpm test

build:
	cd packages/web-sdk && pnpm build
	cd crates/prismid-native && cargo build --release
	cd server/go && go build -o ../../dist/prismid-server ./cmd/prismid-server

# Secure production-like local server (binds 127.0.0.1:8090, demo mode disabled; requires PRISMID_HMAC_SECRET >= 32 bytes, plus recommended PRISMID_AUTH_SECRET / PRISMID_STEPUP_SECRET)
run-server:
	@test -n "$$PRISMID_HMAC_SECRET" || (echo "Error: set PRISMID_HMAC_SECRET (>= 32 bytes), and recommended PRISMID_AUTH_SECRET / PRISMID_STEPUP_SECRET, before running make run-server" >&2; exit 1)
	cd server/go && go run ./cmd/prismid-server -addr 127.0.0.1:8090

# Local interactive browser console (explicitly opts into -demo-mode=true on loopback only)
run-demo:
	cd server/go && go run ./cmd/prismid-server -addr 127.0.0.1:8090 -demo-mode=true
