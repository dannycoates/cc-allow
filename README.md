# cc-allow

Bash command permission control for Claude Code. Parses bash commands into an AST and evaluates them against configurable rules to allow, deny, or defer to Claude Code's permission system.

## Features

- **AST-based parsing** - Uses `mvdan.cc/sh/v3/syntax` for accurate bash parsing
- **Tool-centric configuration** - TOML config organized by tool type (`[bash]`, `[read]`, `[write]`, `[edit]`)
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

# With explicit config
echo 'ls -la' | cc-allow --config ./my-rules.toml

# Hook mode for Claude Code (reads JSON from stdin)
cc-allow --hook

# Validate and inspect config
cc-allow --fmt
```

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
2. `<project>/.claude/cc-allow.toml` - Project rules (in source control)
3. `<project>/.claude/cc-allow.local.toml` - Local overrides (gitignored)
4. `--config <path>` - Explicit config

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

See [docs/config.md](docs/config.md) for complete configuration reference.

## CLI Reference

```bash
# Bash mode (default) - evaluate a bash command
echo 'some command' | cc-allow
echo 'some command' | cc-allow --bash

# File modes - evaluate file tool permissions (stdin is file path)
echo '/path/to/file' | cc-allow --read
echo '/path/to/file' | cc-allow --write
echo '/path/to/file' | cc-allow --edit

# Hook mode - for Claude Code PreToolUse hooks (JSON input/output)
cc-allow --hook < tool_input.json

# Fmt mode - validate config and show rules by specificity
cc-allow --fmt
cc-allow --fmt --config ./my-rules.toml

# Debug mode
cc-allow --debug
```

## How It Works

1. Bash input is parsed into an AST
2. Commands, arguments, pipes, and redirects are extracted from the AST
3. Rules from all config layers are evaluated
4. The most specific matching rule wins within each config
5. If file rules are configured, command arguments are checked against them
6. Results are merged across configs (deny > allow > ask)
7. Exit code indicates the final decision

## Example Global Config

See [cc-allow.global-example.toml](cc-allow.global-example.toml) for a comprehensive example covering common coreutils and development tools.

## License

MIT
