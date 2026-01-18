default:
    @just --list

build:
    go build -o cc-allow ./cmd/cc-allow
    go build -o print-ast ./cmd/print-ast

# Validate and display config rules sorted by specificity
fmt *args:
    go run ./cmd/cc-allow --fmt {{args}}

run:
    go run ./cmd/cc-allow

tidy:
    go mod tidy

test:
    go test ./...

test-v:
    go test -v ./...

# Run the test harness (matrix of commands × rulesets)
harness:
    go test ./cmd/cc-allow/... -run TestHarness -v

# Run harness for a specific ruleset (strict, permissive, default)
harness-ruleset ruleset:
    go test ./cmd/cc-allow/... -run "TestHarness/{{ruleset}}" -v

# Run harness for a specific test case
harness-case ruleset name:
    go test ./cmd/cc-allow/... -run "TestHarness/{{ruleset}}/{{name}}" -v

# Validate goreleaser config
release-check:
    goreleaser check

# Build snapshot (test release locally)
release-snapshot:
    goreleaser build --snapshot --clean

# Full release (requires git tag)
release:
    goreleaser release --clean
