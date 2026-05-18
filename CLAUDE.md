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
- `cmd/cc-allow/session.go` - Session config cleanup and duration parsing
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
2. `.config/cc-allow.toml` - Project rules (in source control)
3. `.config/cc-allow.local.toml` - Local overrides (gitignored)
4. `.config/cc-allow/sessions/<session-id>.toml` - Session rules (auto-cleaned)
5. `--config <path>` or `--agent <type>` - Explicit config

### Agent-Specific Configs

Use `--agent <type>` to load configs from `.config/cc-allow/<type>.toml`. This allows different permission sets for different subagent types (e.g., `playwright`, `Explore`). If the agent config doesn't exist, the normal config chain applies.

### Pattern Types

- `path:*.txt` - Glob pattern with `**` support (also used for path variable expansion)
- `re:^/etc/.*` - Regular expression
- `!prefix:pattern` - Negation (only with explicit prefix)
- `flags:xyz` - Single-dash flag matching: `flags:rf` matches `-rf`, `-fr`, `-vrf`, or separate `-r -f`
- `flags[--]:name` - Long flag matching: `flags[--]:recursive` matches `--recursive`
- `flags[-]:x` - Explicit single-dash delimiter (same as `flags:x`)
- `ref:section.field` - Cross-reference other config values (OR semantics, cannot be negated)

#### `ref:` Cross-References

Supported ref paths:
- `ref:read.allow.paths`, `ref:read.deny.paths` (and `write`, `edit`, `glob`, `grep`)
- `ref:bash.allow.commands`, `ref:bash.deny.commands`
- `ref:aliases.<name>` — resolves alias patterns

#### `args.sequence` (Sliding Window)

Matches consecutive arguments at any position in the arg list:
```toml
[[bash.deny.git]]
args.sequence = {"0" = "commit", "1" = "-m"}
```
Keys are string-encoded offsets (`"0"`, `"1"`, ...). The window slides through args until all positions match simultaneously.

### Pipe Context Tracking

Commands track `PipesTo` (immediate next) and `PipesFrom` (all upstream). This enables rules like "deny bash when receiving from curl" that catch both `curl | bash` and `curl | cat | bash`.

### Alias System

Aliases are defined in `[aliases]` and referenced via `alias:name` in any pattern field (commands, paths, pipe rules). An alias can be a single string or array of strings. Built-in variables available in path patterns:

- `$HOME` — user home directory
- `$PROJECT_ROOT` — project root (detected from `.claude/` or `.git/`)

```toml
[aliases]
project = "path:$PROJECT_ROOT/**"
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key"]
```

### Template Messages

Rule messages support Go `text/template` syntax with these variables:

| Variable | Context | Description |
|----------|---------|-------------|
| `{{.Command}}` | command | Command name |
| `{{.Args}}` | command | All args (including command name) |
| `{{.ArgsStr}}` | command | Args joined by space |
| `{{.Arg 0}}` | command | Arg at position (0-indexed, excludes command name) |
| `{{.ResolvedPath}}` | command | Absolute path to binary |
| `{{.Cwd}}` | command | Effective working directory |
| `{{.PipesTo}}` | command | Commands piped to |
| `{{.PipesFrom}}` | command | Commands piped from |
| `{{.Target}}` | redirect | Redirect target path |
| `{{.Append}}` | redirect | True if `>>` mode |
| `{{.TargetFileName}}` | redirect | Base name of target |
| `{{.TargetDir}}` | redirect | Directory of target |
| `{{.Delimiter}}` | heredoc | Heredoc delimiter |
| `{{.Body}}` | heredoc | Content (truncated to 100 chars) |
| `{{.FilePath}}` | file | File path being accessed |
| `{{.FileName}}` | file | Base name of file |
| `{{.FileDir}}` | file | Directory of file |
| `{{.Tool}}` | file | `"Read"`, `"Write"`, or `"Edit"` |
| `{{.Home}}` | always | `$HOME` |
| `{{.ProjectRoot}}` | always | `$PROJECT_ROOT` |

### Default File Access Type Inference

When bash commands have path arguments, cc-allow automatically checks file tool rules based on the command's inferred access type:

- **Read:** `cat`, `less`, `more`, `head`, `tail`, `grep`, `egrep`, `fgrep`, `find`, `file`, `wc`, `diff`, `cmp`, `stat`, `od`, `xxd`, `hexdump`, `strings`
- **Write:** `rm`, `rmdir`, `touch`, `mkdir`, `chmod`, `chown`, `chgrp`, `ln`, `unlink`
- **Edit:** `sed`

### Config Merge: `mode = "replace"`

By default, configs merge additively (union). Setting `mode = "replace"` on `[bash.allow]` clears all previous allow commands and allow-action rules from earlier configs:

```toml
[bash.allow]
mode = "replace"
commands = ["ls", "pwd"]  # Only these allowed, ignoring global config
```

Only valid for allow sections, not deny.

### Safe Browsing API

WebFetch URLs can be checked against Google Safe Browsing v4 for malware, social engineering, unwanted software, and potentially harmful applications.

```toml
[webfetch.safe_browsing]
enabled = true
api_key = "your-google-api-key"
```

Fails open (allows) on API errors. 5-second timeout per request.

### PostToolUse Session Scanning

The `scripts/postuse` hook runs after successful tool uses. `session_match.go` counts how many other session configs would also allow the same tool use. When matches are found, it injects a system reminder prompting Claude Code to generalize the rule to project-level config via `/allow-rules`.

### CWD Drift Detection

In hook mode, if the working directory differs from `$PROJECT_ROOT`, cc-allow injects a system reminder telling Claude Code to `cd` back. This prevents file operations from targeting wrong paths.

### Debug Config

```toml
[debug]
log_dir = "/tmp/cc-allow-debug"  # per-session JSONL debug logs
```

Also available via CLI: `cc-allow --debug`. Path supports `$HOME` and `$PROJECT_ROOT` variables.

## Test Harness

The harness (`harness_test.go`) runs command sets against multiple rulesets defined in `testdata/harness.toml`. Test cases can be inline or loaded from files.

## CLI Modes

- **Bash mode** (default): `echo 'cmd' | cc-allow` or `cc-allow --bash`
- **File modes**: `echo '/path' | cc-allow --read|--write|--edit`
- **Hook mode**: `cc-allow --hook` - Parses Claude Code JSON, outputs JSON response
- **Fmt mode**: `cc-allow --fmt` - Validate and display config
- **Init mode**: `cc-allow --init` - Create project config from template
- **Session mode**: `cc-allow --session <id>` - Load session-scoped config from `.config/cc-allow/sessions/<id>.toml`
- **Agent mode**: `cc-allow --agent <type>` - Load agent-specific config from `.config/cc-allow/<type>.toml`

## Debugging

Use `./print-ast` to see what the AST of a bash string is.

```sh
echo "./cc-allow --debug <<< 'rm -r folder'" | ./print-ast
```
