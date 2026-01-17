default:
    @just --list

build:
    go build -o cc-allow ./cmd/cc-allow
    go build -o print-ast ./cmd/print-ast

run:
    go run ./cmd/cc-allow

tidy:
    go mod tidy

test:
    go test ./...

test-v:
    go test -v ./...
