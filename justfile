default:
    @just --list

build:
    go build -o cc-allow .
    go build -o print-ast ./cmd/print-ast

run:
    go run .

tidy:
    go mod tidy

test:
    go test ./...

test-v:
    go test -v ./...
