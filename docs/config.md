# cc-allow Configuration Guide

cc-allow evaluates bash commands against a set of rules and returns an exit code indicating whether the command should be allowed, denied, or passed through to default behavior.

## Exit Codes

| Code | Action | Meaning |
|------|--------|---------|
| 0 | allow | Command explicitly allowed |
| 1 | ask | Defer to caller's default behavior (e.g., Claude Code's permission system) |
| 2 | deny | Command explicitly denied |
| 3 | error | Configuration or parse error |

## Config File Locations

cc-allow loads configuration from multiple locations, in order (loosest to strictest):

1. `~/.config/cc-allow.toml` — Global defaults
2. `<project>/.claude/cc-allow.toml` — Project-specific rules (searches up from cwd)
3. `<project>/.claude/cc-allow.local.toml` — Local overrides, not in source control
4. `--config <path>` — Explicit config file

### Merge Behavior

All configs are evaluated and results are combined:

- **deny** always wins — any config can deny, and it cannot be overridden
- **allow** wins over ask — explicit allow is preserved unless denied
- **ask** means "no opinion" — defers to other configs

Within a single config, when multiple rules match a command, the **most specific rule wins** (see Rule Specificity below). Across configs, results are combined using the precedence above.

## Config Format

### Policy

```toml
[policy]
default = "ask"               # "allow", "deny", or "ask"
dynamic_commands = "ask"      # action for $VAR or $(cmd) as command name
default_message = "Command not allowed"
# allowed_paths = ["/usr/bin", "/bin", "/usr/local/bin"]  # optional: restrict command search
unresolved_commands = "ask"   # "ask" or "deny" for commands not found in PATH
```

#### Command Path Resolution

cc-allow resolves command names to their absolute filesystem paths using `allowed_paths` (or `$PATH` if not specified). This enables security controls based on where commands are located.

- **Shell builtins** (`cd`, `exit`, `source`, etc.) bypass path resolution entirely
- **Unresolved commands** (not found) are handled according to `unresolved_commands` policy
- When `allowed_paths` is set across multiple configs, the intersection is used (most restrictive)

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

Command names can use the `path:` prefix to match by resolved filesystem path:

```toml
[commands.allow]
names = [
    "git",                           # match by name
    "path:$PROJECT_ROOT/bin/*",      # allow project-local binaries
    "path:/usr/bin/ls",              # allow ls only from /usr/bin
]

[commands.deny]
names = ["path:/tmp/**"]             # deny any command from /tmp
message = "Commands from /tmp not allowed"
```

### Constructs

Control shell constructs independently of commands:

```toml
[constructs]
function_definitions = "deny"  # foo() { ... }
background = "deny"            # command &
subshells = "ask"              # (command)
heredocs = "allow"             # cat <<EOF ... EOF (default: allow)
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

When multiple rules match a command, the **most specific rule wins** based on a CSS-like specificity score. This means rule order doesn't matter — you can write rules in any order and the most specific matching rule will be selected. Results from different configs are then combined (see Merge Behavior above).

### Rule Specificity

Specificity is calculated by summing points for each condition in a rule:

| Condition | Points | Rationale |
|-----------|--------|-----------|
| Named command (not `*`) | 100 | Specific command vs wildcard |
| Each `args.position` entry | 20 | Exact positional match |
| Each `args.contains` entry | 10 | Exact substring |
| Each `args.any_match` entry | 5 | Pattern match |
| Each `args.all_match` entry | 5 | Pattern match |
| Each `pipe.to` entry | 10 | Specific pipe target |
| Each named `pipe.from` entry | 10 | Specific pipe source |
| `pipe.from = ["*"]` | 5 | Any piped input |

**Example:**

```toml
# Specificity: 100 (command only)
[[rule]]
command = "rm"
action = "allow"

# Specificity: 130 (100 + 10 + 20)
[[rule]]
command = "rm"
action = "deny"
message = "Cannot rm -rf from root"
[rule.args]
contains = ["-rf"]       # +10
position = { "0" = "/" }   # +20
```

When running `rm -rf /`:
- Both rules match (command is "rm")
- The deny rule has higher specificity (130 > 100)
- Result: **deny** (regardless of rule order)

When running `rm file.txt`:
- Only the first rule matches (no `-rf` or position `/`)
- Result: **allow**

**Tie-breaking:** If two rules have equal specificity, the most restrictive action wins: deny > ask > allow.

#### Rule Fields

| Field | Description |
|-------|-------------|
| `command` | Command name, `"*"` for any, or `"path:..."` for path matching |
| `action` | `"allow"`, `"deny"`, or `"ask"` |
| `message` | Message to display when denied |

The `command` field supports `path:` prefix to match against the resolved filesystem path:

```toml
# Allow any command from /usr/bin
[[rule]]
command = "path:/usr/bin/*"
action = "allow"

# Deny project-local scripts with specific args
[[rule]]
command = "path:$PROJECT_ROOT/scripts/*"
action = "deny"
[rule.args]
any_match = ["--dangerous"]
```

#### Argument Matching

```toml
[rule.args]
contains = ["--force"]           # args must contain all of these (exact match)
any_match = ["-r", "-rf"]        # args must match at least one pattern
all_match = ["glob:*.txt"]       # all args must match pattern
position = { "0" = "/etc/*" }    # arg at position must match pattern (keys are string indices)
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
| `action` | `"allow"`, `"deny"`, or `"ask"` |
| `message` | Message to display when denied |
| `append` | If set, only match append (`>>`) or overwrite (`>`) mode |

#### Target Matching

```toml
[redirect.to]
exact = [".bashrc", "/etc/passwd"]  # exact filename or path match
pattern = ["glob:*.log", "re:^/tmp/.*"]  # pattern match
```

### Heredocs

Heredocs (`<<EOF ... EOF`) are handled separately from redirects. By default, heredocs are allowed (`constructs.heredocs = "allow"`).

To deny all heredocs:
```toml
[constructs]
heredocs = "deny"
```

For fine-grained control when `constructs.heredocs = "allow"`, use `[[heredoc]]` rules to match heredoc content:

```toml
[[heredoc]]
action = "deny"
message = "Dangerous SQL detected"
content_match = ["re:DROP TABLE", "re:DELETE FROM"]
```

#### Heredoc Fields

| Field | Description |
|-------|-------------|
| `action` | `"allow"`, `"deny"`, or `"ask"` |
| `message` | Message to display when denied |
| `content_match` | Patterns to match against heredoc body |

**Note:** If `constructs.heredocs = "deny"`, all heredocs are denied and `[[heredoc]]` rules are not checked.

## Pattern Matching

Patterns support three prefixes:

| Prefix | Description | Example |
|--------|-------------|---------|
| `glob:` | Shell-style glob (supports `**`) | `glob:*.txt` |
| `re:` | Regular expression | `re:^/etc/.*` |
| `path:` | Path pattern with variable expansion | `path:$PROJECT_ROOT/**` |

Without a prefix, the string is matched exactly (or treated as glob if it contains `*`, `?`, or `[`).

### Negation

Prepend "!" to patterns with explicit prefixes (`path:`, `re:`, `glob:`) to negate the match:

```toml
# Match anything that is NOT a .txt file
any_match = ["!glob:*.txt"]

# Match paths NOT under /etc
any_match = ["!path:/etc/**"]

# Match anything that does NOT start with "--"
any_match = ["!re:^--"]
```

Note: Negation requires an explicit prefix. `!foo` matches the literal string "!foo".

### Glob Patterns

Glob patterns support `**` for recursive matching (via the doublestar library):

```toml
any_match = ["*.txt"]              # matches file.txt
any_match = ["src/**/*.go"]        # matches src/main.go, src/pkg/util.go, etc.
```

### Path Patterns

Path patterns provide filesystem-aware matching with variable expansion. Use these to write rules based on where files are located relative to project root or home directory.

**Variables:**

| Variable | Description |
|----------|-------------|
| `$PROJECT_ROOT` | Detected project root (directory containing `.claude/` or `.git/`) |
| `$HOME` | User's home directory |

**Example: Allow rm only under project root:**

```toml
[[rule]]
command = "rm"
action = "allow"
[rule.args]
any_match = ["path:$PROJECT_ROOT/**"]

[[rule]]
command = "rm"
action = "deny"
message = "Cannot delete files outside project"
```

**Example: Allow editing config files under home:**

```toml
[[rule]]
command = "vim"
action = "allow"
[rule.args]
any_match = ["path:$HOME/.config/**", "path:$HOME/.local/**"]
```

**Example: Positional path matching:**

```toml
[[rule]]
command = "rm"
action = "allow"
[rule.args]
position = { "0" = "-rf", "1" = "path:$PROJECT_ROOT/**" }
```

**Path Resolution:**

When matching, cc-allow:
1. Expands `~` in the argument to `$HOME`
2. Resolves relative paths against the current working directory
3. Normalizes the path (cleaning `.`, `..`, etc.)
4. Follows symlinks (prevents escaping via symlinks)
5. Expands variables in the pattern (`$PROJECT_ROOT`, `$HOME`)
6. Matches using gitignore-style globbing (`**` works)

Only arguments that look like paths (start with `/`, `./`, `../`, `~`, or contain `/`) are matched against path patterns. Non-path arguments like `--flag` are not matched.

### Regex Patterns

Use regex for complex patterns:

```toml
# Use regex for complex patterns:
any_match = ["re:^--(?:verbose|debug)$"]

# Use regex for paths (alternative to path: when you don't need resolution):
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
subshells = "ask"

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
