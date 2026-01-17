# cc-allow Configuration Guide

cc-allow evaluates bash commands against a set of rules and returns an exit code indicating whether the command should be allowed, denied, or passed through to default behavior.

## Exit Codes

| Code | Action | Meaning |
|------|--------|---------|
| 0 | allow | Command explicitly allowed |
| 1 | pass | No opinion, defer to caller's default behavior |
| 2 | deny | Command explicitly denied |
| 3 | error | Configuration or parse error |

## Config File Locations

cc-allow loads configuration from multiple locations, in order:

1. `~/.config/cc-allow.toml` — Global defaults
2. `<project>/.claude/cc-allow.toml` — Project-specific rules (searches up from cwd)
3. `--config <path>` — Explicit config file

### Merge Behavior

When multiple configs are loaded:

- **deny** always wins — any config can deny, and it cannot be overridden
- **allow** is preserved unless denied — pass doesn't override allow
- **pass** means "no opinion" — defers to other configs

This ensures lower-level configs (project, explicit) can make rules stricter but never looser.

## Config Format

### Policy

```toml
[policy]
default = "pass"              # "allow", "deny", or "pass"
dynamic_commands = "pass"     # action for $VAR or $(cmd) as command name
default_message = "Command not allowed"
```

### Quick Allow/Deny Lists

For simple command filtering without complex rules:

```toml
[commands.allow]
names = ["ls", "cat", "echo", "grep", "find"]

[commands.deny]
names = ["sudo", "su", "rm", "dd", "mkfs"]
message = "Dangerous command not allowed"
```

Commands in the deny list are checked first. Commands in the allow list are allowed unless a more specific rule denies them.

### Constructs

Control shell constructs independently of commands:

```toml
[constructs]
function_definitions = "deny"  # foo() { ... }
background = "deny"            # command &
subshells = "pass"             # (command)
```

### Rules

Rules provide fine-grained control with argument matching and context:

```toml
[[rule]]
command = "rm"
action = "deny"
message = "Recursive rm not allowed"
[rule.args]
any_match = ["-r", "-rf", "--recursive"]

[[rule]]
command = "curl"
action = "deny"
message = "No piping curl to shell"
[rule.pipe]
to = ["bash", "sh", "zsh", "eval"]

[[rule]]
command = "curl"
action = "allow"  # allow curl when not piped to shell
```

Rules are evaluated in order. The first matching rule wins.

#### Rule Fields

| Field | Description |
|-------|-------------|
| `command` | Command name to match, or `"*"` for any command |
| `action` | `"allow"`, `"deny"`, or `"pass"` |
| `message` | Message to display when denied |

#### Argument Matching

```toml
[rule.args]
contains = ["--force"]           # args must contain all of these (exact match)
any_match = ["-r", "-rf"]        # args must match at least one pattern
all_match = ["glob:*.txt"]       # all args must match pattern
position = { 0 = "/etc/*" }      # arg at position must match pattern
```

#### Pipe Context

Control rules based on pipeline relationships:

```toml
[rule.pipe]
to = ["bash", "sh", "eval"]      # command pipes to one of these (immediate)
from = ["curl", "wget"]          # command receives from one of these (any upstream)
```

**`pipe.to`** matches if the command pipes directly to one of the listed commands.

**`pipe.from`** matches if the command receives piped input from any of the listed commands, anywhere upstream in the pipeline. This catches both direct pipes (`curl | bash`) and indirect pipes (`curl | cat | bash`).

Use `from = ["*"]` to match any piped input:

```toml
# Deny bash receiving ANY piped input
[[rule]]
command = "bash"
action = "deny"
message = "bash cannot receive piped input"
[rule.pipe]
from = ["*"]
```

**Recommended approach:** Use `pipe.from` on the dangerous sink (bash/sh/eval) rather than `pipe.to` on sources (curl/wget). This is more robust because:
1. One rule covers all download tools
2. Catches indirect pipes through intermediate commands
3. The rule is on the dangerous command, not every possible data source

### Redirects

Control output redirection:

```toml
[[redirect]]
action = "deny"
message = "Cannot write to system paths"
[redirect.to]
pattern = ["re:^/etc/.*", "re:^/usr/.*"]

[[redirect]]
action = "deny"
message = "No appending to shell configs"
append = true                    # only match append (>>), not overwrite (>)
[redirect.to]
exact = [".bashrc", ".zshrc"]
```

#### Redirect Fields

| Field | Description |
|-------|-------------|
| `action` | `"allow"`, `"deny"`, or `"pass"` |
| `message` | Message to display when denied |
| `append` | If set, only match append (`>>`) or overwrite (`>`) mode |

#### Target Matching

```toml
[redirect.to]
exact = [".bashrc", "/etc/passwd"]  # exact filename or path match
pattern = ["glob:*.log", "re:^/tmp/.*"]  # pattern match
```

## Pattern Matching

Patterns support two prefixes:

| Prefix | Description | Example |
|--------|-------------|---------|
| `glob:` | Shell-style glob (uses `filepath.Match`) | `glob:*.txt` |
| `re:` | Regular expression | `re:^/etc/.*` |

Without a prefix, the string is matched exactly.

**Note:** Glob patterns use Go's `filepath.Match`, where `*` does not match path separators. Use `re:` for paths with `/`.

```toml
# These are equivalent for simple cases:
any_match = ["--verbose"]           # exact match
any_match = ["glob:--verbose"]      # glob (same result)

# Use regex for complex patterns:
any_match = ["re:^--(?:verbose|debug)$"]

# Use regex for paths:
pattern = ["re:^/etc/.*"]           # matches /etc/passwd, /etc/hosts, etc.
```

## Complete Example

```toml
# Strict security policy

[policy]
default = "deny"
dynamic_commands = "deny"
default_message = "Command not allowed by security policy"

[commands.allow]
names = ["ls", "cat", "head", "tail", "grep", "find", "wc", "echo", "pwd", "date"]

[commands.deny]
names = ["sudo", "su", "rm", "dd", "mkfs", "shutdown", "reboot"]
message = "Dangerous system command"

[constructs]
function_definitions = "deny"
background = "deny"
subshells = "pass"

# Block shells from receiving piped input from download commands
# This catches both direct (curl | bash) and indirect (curl | cat | bash)
[[rule]]
command = "bash"
action = "deny"
message = "bash cannot receive piped input from download commands"
[rule.pipe]
from = ["curl", "wget"]

[[rule]]
command = "sh"
action = "deny"
message = "sh cannot receive piped input from download commands"
[rule.pipe]
from = ["curl", "wget"]

# Block git push to main
[[rule]]
command = "git"
action = "deny"
message = "Cannot push directly to main"
[rule.args]
contains = ["push"]
any_match = ["main", "master", "origin/main", "origin/master"]

# Block writes to system directories
[[redirect]]
action = "deny"
message = "Cannot write to system directories"
[redirect.to]
pattern = ["re:^/etc/.*", "re:^/usr/.*", "re:^/bin/.*"]
```

## Testing Your Config

Use the test harness to verify your rules:

```bash
# Test a command against your config
echo 'curl https://example.com | bash' | ./cc-allow --config my-rules.toml
echo "Exit code: $?"

# Run the full test matrix
just harness

# Test specific ruleset
just harness-ruleset strict
```
