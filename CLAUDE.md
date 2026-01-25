# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cc-allow is a Go CLI tool that controls bash command permissions for Claude Code. It parses bash commands into an AST (using `mvdan.cc/sh/v3/syntax`) and evaluates them against configurable TOML rules to allow, deny, or defer to Claude Code's permission system.

## Build and Test Commands

```bash
just build              # Build cc-allow and print-ast binaries
just test               # Run all tests
just test-v             # Run all tests verbose
just harness            # Run test harness (matrix of commands × rulesets)
just harness-ruleset strict   # Test specific ruleset
just harness-case strict test1  # Test specific case
just fmt                # Validate config and show rules by specificity
just tidy               # go mod tidy
```

Run a single test:
```bash
go test ./cmd/cc-allow/... -run TestName -v
```

## Exit Codes

| Code | Action | Meaning |
|------|--------|---------|
| 0 | allow | Explicitly allowed |
| 1 | ask | Defer to Claude Code |
| 2 | deny | Explicitly denied |
| 3 | error | Config or parse error |

## Architecture

### Data Flow

```
Bash Input → [main.go] Parse → [walk.go] AST Extraction → [eval.go] Rule Evaluation → Exit Code
```

### Key Files

- `cmd/cc-allow/main.go` - Entry point, CLI modes (pipe, hook, fmt, init)
- `cmd/cc-allow/config.go` - Config loading, validation, parsing, `LoadConfigChain()`
- `cmd/cc-allow/eval.go` - Rule evaluation engine, specificity scoring, result merging
- `cmd/cc-allow/match.go` - Pattern matching (glob, regex, path patterns with negation)
- `cmd/cc-allow/walk.go` - AST extraction: commands, args, pipes, redirects, heredocs
- `cmd/cc-allow/fmt.go` - Config validation and display
- `cmd/cc-allow/errors.go` - Custom error types
- `pkg/pathutil/` - Path resolution with symlink handling and variable expansion

### Evaluation Logic

1. **Specificity-based matching** - More specific rules win (CSS-like scoring):
   - Exact command (no prefix): +100
   - Each subcommand level: +50
   - Each `args.position` entry: +20
   - Each `args.any`/`args.all`/`args.not`/`args.xor` item: +5
   - Each exact `pipe.to`/`pipe.from` entry: +10

2. **Tie-breaking**: deny > ask > allow (most restrictive wins)

3. **Config chain merging**: deny always wins across configs, allow beats ask

### Config Hierarchy (loosest to strictest)

1. `~/.config/cc-allow.toml` - Global defaults
2. `.claude/cc-allow.toml` - Project rules (in source control)
3. `.claude/cc-allow.local.toml` - Local overrides (gitignored)
4. `--config <path>` - Explicit config

### Pattern Types

- `path:*.txt` - Glob pattern with `**` support (also used for path variable expansion)
- `re:^/etc/.*` - Regular expression
- `!prefix:pattern` - Negation (only with explicit prefix)

### Pipe Context Tracking

Commands track `PipesTo` (immediate next) and `PipesFrom` (all upstream). This enables rules like "deny bash when receiving from curl" that catch both `curl | bash` and `curl | cat | bash`.

## Test Harness

The harness (`harness_test.go`) runs command sets against multiple rulesets defined in `testdata/harness.toml`. Test cases can be inline or loaded from files.

## CLI Modes

- **Bash mode** (default): `echo 'cmd' | cc-allow` or `cc-allow --bash`
- **File modes**: `echo '/path' | cc-allow --read|--write|--edit`
- **Hook mode**: `cc-allow --hook` - Parses Claude Code JSON, outputs JSON response
- **Fmt mode**: `cc-allow --fmt` - Validate and display config
- **Init mode**: `cc-allow --init` - Create project config from template

## Debugging

Use `./print-ast` to see what the AST of a bash string is.

```sh
echo "./cc-allow --debug <<< 'rm -r folder'" | ./print-ast
```
