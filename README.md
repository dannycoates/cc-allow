# cc-allow

Bash command permission control for Claude Code. Parses bash commands into an AST and evaluates them against configurable rules to allow, deny, or defer to Claude Code's permission system.

## Features

- **AST-based parsing** - Uses `mvdan.cc/sh/v3/syntax` for accurate bash parsing
- **TOML configuration** - Simple, readable rule definitions
- **Specificity-based matching** - More specific rules win, regardless of order
- **Layered configs** - Global defaults with project-level overrides
- **Pipe security** - Block dangerous patterns like `curl | bash`
- **Redirect control** - Prevent writes to sensitive paths

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
# Evaluate a command
echo 'rm -rf /' | cc-allow
# Exit code: 2 (deny)

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
[policy]
default = "ask"
dynamic_commands = "deny"  # block $VAR or $(cmd) as command names

[commands.allow]
names = ["ls", "cat", "grep", "git", "go", "npm"]

[commands.deny]
names = ["sudo", "rm", "dd"]
message = "Dangerous command blocked"
```

### Rules with Specificity

More specific rules win regardless of order:

```toml
# Allow rm in general (specificity: 100)
[[rule]]
command = "rm"
action = "allow"

# But deny rm -r (specificity: 110)
[[rule]]
command = "rm"
action = "deny"
message = "Recursive rm not allowed"
[rule.args]
any_match = ["re:^-[a-zA-Z]*r[a-zA-Z]*$", "--recursive"]
```

### Pipe Security

Block dangerous pipe patterns:

```toml
# Deny bash receiving piped input from download commands
[[rule]]
command = "bash"
action = "deny"
message = "Cannot pipe to bash from download commands"
[rule.pipe]
from = ["curl", "wget"]
```

### Redirect Control

Prevent writes to sensitive paths:

```toml
[[redirect]]
action = "deny"
message = "Cannot write to system directories"
[redirect.to]
pattern = ["path:/etc/**", "path:/usr/**"]
```

See [docs/config.md](docs/config.md) for complete configuration reference.

## CLI Reference

```bash
# Pipe mode - evaluate a command
echo 'some command' | cc-allow

# Hook mode - for Claude Code PreToolUse hooks
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
5. Results are merged across configs (deny > allow > ask)
6. Exit code indicates the final decision

## Example Global Config

See [cc-allow.global-example.toml](cc-allow.global-example.toml) for a comprehensive example covering common coreutils and development tools.

## License

MIT
