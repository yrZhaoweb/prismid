.PHONY: all test test-go test-web test-rust bench build run-server

all: test build

test: test-go test-rust test-web

test-go:
	cd server/go && go test -v -race ./...

bench:
	cd server/go && go run ./cmd/prismid-bench

test-rust:
	cd crates/prismid-native && cargo test

test-web:
	cd packages/web-sdk && pnpm test

build:
	cd packages/web-sdk && pnpm build
	cd crates/prismid-native && cargo build --release
	cd server/go && go build -o ../../dist/prismid-server ./cmd/prismid-server

run-server:
	cd server/go && go run ./cmd/prismid-server -addr :8090
