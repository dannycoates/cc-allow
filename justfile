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

# Bump version, commit, tag, and push (bump_type: major, minor, or patch)
bump bump_type="patch":
    #!/usr/bin/env bash
    set -euo pipefail

    # Ensure we're on main branch
    branch=$(git branch --show-current)
    if [[ "$branch" != "main" ]]; then
        echo "Error: must be on main branch (currently on '$branch')"
        exit 1
    fi

    # Get current version from plugin.json
    current=$(jq -r .version .claude-plugin/plugin.json)

    # Parse semver
    IFS='.' read -r major minor patch <<< "$current"

    # Increment based on bump type
    case "{{bump_type}}" in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            echo "Invalid bump type: {{bump_type}} (use major, minor, or patch)"
            exit 1
            ;;
    esac

    new_version="${major}.${minor}.${patch}"
    echo "Bumping version: $current -> $new_version"

    # Update both JSON files
    jq --arg v "$new_version" '.version = $v' .claude-plugin/plugin.json > .claude-plugin/plugin.json.tmp
    mv .claude-plugin/plugin.json.tmp .claude-plugin/plugin.json

    jq --arg v "$new_version" '.plugins[0].version = $v' .claude-plugin/marketplace.json > .claude-plugin/marketplace.json.tmp
    mv .claude-plugin/marketplace.json.tmp .claude-plugin/marketplace.json

    # Commit, tag, and push
    git add .claude-plugin/plugin.json .claude-plugin/marketplace.json
    git commit -m "v${new_version}"
    git tag "v${new_version}"
    git push && git push --tags

    echo "Released v${new_version}"
