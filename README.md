# cc-allow

Permission control for Claude Code tools. Evaluates bash commands, file operations (Read/Write/Edit), search tools (Glob/Grep), and WebFetch URLs against configurable rules to allow, deny, or defer to Claude Code's permission system.

## Features

- **AST-based parsing** - Uses `mvdan.cc/sh/v3/syntax` for accurate bash parsing
- **Tool-centric configuration** - TOML config organized by tool type (`[bash]`, `[read]`, `[write]`, `[edit]`, `[glob]`, `[grep]`, `[webfetch]`)
- **Specificity-based matching** - More specific rules win, regardless of order
- **Layered configs** - Global defaults with project-level overrides
- **Pipe security** - Block dangerous patterns like `curl | bash`
- **Redirect control** - Prevent writes to sensitive paths
- **File rule integration** - Bash commands respect file access rules (e.g., `cat /etc/passwd` denied if `/etc/**` is in Read deny list)

## Disclaimer

**Bash is inherently dangerous.** This tool isn't a substitute for your human judgement. Whatever you let your LLM run is your responsibility.

## Installation

### As a Claude Code Plugin

1. Add the marketplace:
   ```
   /plugin marketplace add dannycoates/cc-allow
   ```

2. Install the plugin:
   ```
   /plugin install cc-allow@dannycoates-cc-allow
   ```

The plugin automatically downloads binaries on first session start.

### Manual Installation

Download from [releases](https://github.com/dannycoates/cc-allow/releases) or build from source:

```bash
go install github.com/dannycoates/cc-allow/cmd/cc-allow@latest
```

## Usage

```bash
# Evaluate a bash command (default)
echo 'rm -rf /' | cc-allow
# Exit code: 2 (deny)

# Evaluate file tool permissions
echo '/etc/passwd' | cc-allow --read
echo '/project/src/main.go' | cc-allow --write
echo '/home/user/.bashrc' | cc-allow --edit

# Evaluate search tool permissions
echo '/etc' | cc-allow --glob
echo '/home/user/project' | cc-allow --grep

# Evaluate WebFetch URL permissions
echo 'https://example.com' | cc-allow --fetch

# With explicit config
echo 'ls -la' | cc-allow --config ./my-rules.toml

# Hook mode for Claude Code (reads JSON from stdin)
cc-allow --hook

# Validate and inspect config
cc-allow --fmt
```

### Managing Rules with `/allow-rules`

The `/allow-rules` slash command provides a conversational interface for managing cc-allow rules. Tell it what you want in plain English and it figures out the right config changes.

#### Scope detection

The command determines where to write rules based on your phrasing:

| Scope | Keywords | Config file |
|-------|----------|-------------|
| **Session** (default) | "for now", "temporarily", or no scope mentioned | `.config/cc-allow/sessions/<id>.toml` |
| **Project** | "always", "permanently", "this project" | `.config/cc-allow.toml` |
| **Global** | "globally", "everywhere", "all projects" | `~/.config/cc-allow.toml` |

#### Examples

```
# Session-scoped (default) — allow docker for this session
/allow-rules allow docker

# Session-scoped — temporary override
/allow-rules let me use curl for now

# Project-scoped — permanent rule
/allow-rules always allow npm install in this project

# Global — applies everywhere
/allow-rules globally deny rm -rf

# Deny rules
/allow-rules block curl | bash

# File tool rules
/allow-rules allow reading /var/log/**

# Complex rules
/allow-rules allow git push but ask for --force
```

The command reads the appropriate config, makes the change, validates with `--fmt`, and tests with a matching command to confirm.

### Exit Codes

| Code | Action | Meaning |
|------|--------|---------|
| 0 | allow | Command explicitly allowed |
| 1 | ask | Defer to Claude Code's permission system |
| 2 | deny | Command explicitly denied |
| 3 | error | Configuration or parse error |

## Configuration

### Config Locations

Configs are loaded from multiple locations (loosest to strictest):

1. `~/.config/cc-allow.toml` - Global defaults
2. `<project>/.config/cc-allow.toml` - Project rules (in source control)
3. `<project>/.config/cc-allow.local.toml` - Local overrides (gitignored)
4. `<project>/.config/cc-allow/sessions/<id>.toml` - Session-scoped (auto-cleaned)
5. `--config <path>` - Explicit config

Rules are merged across configs: **deny always wins**, allow beats ask, ask means "no opinion."

### Quick Start

```toml
version = "2.0"

[bash]
default = "ask"
dynamic_commands = "deny"  # block $VAR or $(cmd) as command names

[bash.allow]
commands = ["ls", "cat", "grep", "git", "go", "npm"]

[bash.deny]
commands = ["sudo", "rm", "dd"]
message = "Dangerous command blocked"
```

### Rules with Specificity

More specific rules win regardless of order:

```toml
# Allow rm in general (specificity: 100)
[[bash.allow.rm]]

# But deny rm -r (specificity: 105)
[[bash.deny.rm]]
message = "Recursive rm not allowed"
args.any = ["flags:r", "--recursive"]
```

### Pipe Security

Block dangerous pipe patterns:

```toml
# Deny bash receiving piped input from download commands
[[bash.deny.bash]]
message = "Cannot pipe to bash from download commands"
pipe.from = ["curl", "wget"]
```

### Redirect Control

Prevent writes to sensitive paths:

```toml
[[bash.redirects.deny]]
message = "Cannot write to system directories"
paths = ["path:/etc/**", "path:/usr/**"]
```

### File Tool Permissions

Control Claude Code's Read, Write, and Edit file tools:

```toml
[read]
default = "ask"

[read.allow]
paths = ["path:$PROJECT_ROOT/**"]

[read.deny]
paths = ["path:$HOME/.ssh/**", "path:**/*.key"]

[write.deny]
paths = ["path:/etc/**", "path:$HOME/.bashrc"]
```

With this config:
- `cat ~/.ssh/id_rsa` → denied (Read command accessing denied path)
- `echo "x" > ~/.bashrc` → denied (redirect to denied Write path)

For commands like `cp` and `mv` where arguments have different access types, use positional file rules:

```toml
[[bash.allow.cp]]
args.position = { "0" = "ref:read.allow.paths", "1" = "ref:write.allow.paths" }
```

This checks the source against Read rules and destination against Write rules.

### Search Tool Permissions

Control Claude Code's Glob and Grep tools. These only have a search path — by default they delegate to Read rules:

```toml
[glob]
respect_file_rules = true

[grep]
respect_file_rules = true
```

With `respect_file_rules = true` (the default), the search path is checked against `[read]` rules. If Read allows a path, Glob/Grep allows it. If Read denies, searching is denied too.

### WebFetch URL Permissions

Control Claude Code's WebFetch tool with URL pattern matching:

```toml
[webfetch]
default = "allow"

[webfetch.deny]
paths = ["re:^https?://localhost", "re:^file://"]
message = "Blocked URL: {{.FilePath}}"

[webfetch.safe_browsing]
enabled = true
api_key = "AIza..."
```

See [docs/config.md](docs/config.md) for complete configuration reference.

### Session-Scoped Configs

Session configs let you temporarily adjust rules for the current Claude Code session. They live in `.config/cc-allow/sessions/<session-id>.toml` and are automatically cleaned up based on `session_max_age`.

```toml
# .config/cc-allow/sessions/<id>.toml
version = "2.0"

[bash.allow]
commands = ["docker", "curl"]
```

Session configs are loaded after project and local configs but before explicit `--config` paths. The standard merge rules apply: deny always wins, so a session can add new allows for commands that were previously "ask" but cannot override explicit deny rules from project configs.

Set cleanup in your global or project config:

```toml
[settings]
session_max_age = "30d"   # delete session configs older than 30 days
```

## CLI Reference

```bash
# Bash mode (default) - evaluate a bash command
echo 'some command' | cc-allow
echo 'some command' | cc-allow --bash

# File modes - evaluate file tool permissions (stdin is file path)
echo '/path/to/file' | cc-allow --read
echo '/path/to/file' | cc-allow --write
echo '/path/to/file' | cc-allow --edit

# Search modes - evaluate search tool permissions (stdin is search path)
echo '/path/to/search' | cc-allow --glob
echo '/path/to/search' | cc-allow --grep

# WebFetch mode - evaluate URL permissions (stdin is URL)
echo 'https://example.com' | cc-allow --fetch

# Hook mode - for Claude Code PreToolUse hooks (JSON input/output)
cc-allow --hook < tool_input.json

# Fmt mode - validate config and show rules by specificity
cc-allow --fmt
cc-allow --fmt --config ./my-rules.toml

# Session mode - use session-scoped config
echo 'docker ps' | cc-allow --session <session-id>

# Debug mode
cc-allow --debug
```

## How It Works

1. Tool request is identified (Bash, Read, Write, Edit, Glob, Grep, or WebFetch)
2. For Bash: input is parsed into an AST; commands, arguments, pipes, and redirects are extracted
3. For file/search/fetch tools: the path or URL is matched against tool-specific rules
4. Rules from all config layers are evaluated; most specific matching rule wins
5. For Bash and search tools: file rules may be checked (via `respect_file_rules`)
6. Results are merged across configs (deny > allow > ask)
7. Exit code indicates the final decision

## Example Global Config

See [cc-allow.global-example.toml](cc-allow.global-example.toml) for a comprehensive example covering common coreutils and development tools.

## License

MIT
