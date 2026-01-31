# cc-allow Configuration Guide (v2)

cc-allow evaluates bash commands against a set of rules and returns an exit code indicating whether the command should be allowed, denied, or passed through to default behavior.

## Config Format Version

This documentation covers the v2 config format. The v2 format is **tool-centric** with top-level sections for each tool type: `[bash]`, `[read]`, `[write]`, `[edit]`.

```toml
version = "2.0"
```

Legacy v1 configs (with `[policy]`, `[[rule]]`, `[commands]`, etc.) are not supported. If cc-allow detects a v1 config, it returns exit code 3 with an error message.

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
2. `<project>/.config/cc-allow.toml` — Project-specific rules (searches up from cwd)
3. `<project>/.config/cc-allow.local.toml` — Local overrides, not in source control
4. `--config <path>` — Explicit config file

### Merge Behavior

All configs are evaluated and results are combined:

- **deny** always wins — any config can deny, and it cannot be overridden
- **allow** wins over ask — explicit allow is preserved unless denied
- **ask** means "no opinion" — defers to other configs
- **allow lists** are merged (unioned) by default — each config adds to the set

Within a single config, when multiple rules match a command, the **most specific rule wins** (see Rule Specificity below). Across configs, results are combined using the precedence above.

#### Allow Mode: merge vs replace

By default, `.allow` sections across configs are merged additively. A later config can set `mode = "replace"` to discard all allow entries from earlier configs and start fresh:

```toml
[bash.allow]
mode = "replace"       # clear parent allow commands and allow rules
commands = ["cat"]     # only "cat" is allowed
```

This is useful when a `--config` override needs to restrict permissions to a smaller set, rather than extend the parent config. Without `mode = "replace"`, you would need to deny every unwanted command individually.

- `mode = "merge"` (default) — union allow entries from all configs
- `mode = "replace"` — discard allow entries from earlier configs, use only this config's entries

**Note:** `mode` only applies to `.allow` sections. Deny lists are always unioned — a child config cannot remove a parent's denies.

---

## Bash Tool Configuration

### Basic Settings

```toml
[bash]
default = "ask"                    # "allow", "deny", or "ask" for unmatched commands
dynamic_commands = "deny"          # action for $VAR or $(cmd) as command name
unresolved_commands = "ask"        # "ask" or "deny" for commands not found in PATH
default_message = "Command requires approval"
respect_file_rules = true          # check file rules for command args (default: true)
```

### Shell Constructs

Control shell constructs independently of commands:

```toml
[bash.constructs]
function_definitions = "deny"      # foo() { ... }
background = "deny"                # command &
subshells = "ask"                  # (command)
heredocs = "allow"                 # <<EOF ... EOF (default: allow)
```

### Allow/Deny Command Lists

Simple lists of allowed or denied commands:

```toml
[bash.allow]
commands = ["ls", "cat", "head", "tail", "grep", "find", "echo", "pwd", "git"]

[bash.deny]
commands = ["sudo", "su", "dd", "mkfs", "shutdown", "reboot"]
message = "{{.Command}} blocked - dangerous system command"
```

To replace (rather than extend) the allow list from parent configs:

```toml
[bash.allow]
mode = "replace"
commands = ["cat"]
```

When `mode = "replace"` is set, all allow commands **and** allow rules (e.g., `[[bash.allow.cd]]`) from earlier configs are discarded. Deny lists are unaffected.

Command names can use the `path:` prefix to match by resolved filesystem path:

```toml
[bash.allow]
commands = [
    "git",                              # match by name
    "path:$PROJECT_ROOT/bin/*",         # allow project-local binaries
]

[bash.deny]
commands = ["path:/tmp/**"]             # deny any command from /tmp
message = "Commands from /tmp not allowed"
```

### Complex Rules with Argument Matching

For fine-grained control, use `[[bash.allow.X]]` or `[[bash.deny.X]]` sections:

```toml
# Block recursive rm
[[bash.deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"
args.any = ["flags:r", "--recursive"]

# Allow rm (base rule, lower specificity than above)
[[bash.allow.rm]]
```

#### Subcommand Nesting

Use nested paths for subcommand matching:

```toml
# git status - allowed
[[bash.allow.git.status]]

# git diff - allowed
[[bash.allow.git.diff]]

# git push --force - denied
[[bash.deny.git.push]]
message = "{{.ArgsStr}} - force push not allowed"
args.any = ["--force", "flags:f"]

# git push - allowed (base rule)
[[bash.allow.git.push]]

# docker compose up - allowed
[[bash.allow.docker.compose.up]]
```

This is equivalent to using `args.position`:
- `[[bash.deny.git.push]]` = command `git` with `position.0 = "push"`
- `[[bash.allow.docker.compose.up]]` = command `docker` with `position.0 = "compose"`, `position.1 = "up"`

#### Specificity with Nesting

Each nesting level adds +50 to specificity:
- `[[bash.allow.git]]` → specificity 100 (named command)
- `[[bash.allow.git.push]]` → specificity 150 (command + 1 subcommand)
- `[[bash.allow.docker.compose.up]]` → specificity 200 (command + 2 subcommands)

---

## Argument Matching

### Boolean Expression Arguments

Arguments use boolean operators for flexible matching:

| Operator | Description |
|----------|-------------|
| `args.any` | Matches if ANY pattern matches (OR) |
| `args.all` | Matches if ALL patterns match (AND) |
| `args.not` | Negates the result |
| `args.xor` | Exactly one must match |
| `args.position` | Absolute positional matching |

```toml
# Simple OR (most common)
[[bash.deny.rm]]
args.any = ["flags:r", "--recursive", "-rf"]

# Simple AND
[[bash.allow.openssl]]
args.all = [
    { any = ["-in", "--input"] },
    { any = ["-out", "--output"] }
]

# NOT
[[bash.deny.git]]
args.not = { any = ["status", "diff", "log", "branch"] }

# Nested expressions
[[bash.allow.tar]]
args.any = [
    { all = ["flags:c", "path:$PROJECT_ROOT/**"] },  # create in project
    { all = ["flags:t"] }                             # list anywhere
]
args.not = { any = ["flags:x"] }  # but never extract
```

### Position Matching

Position uses string keys for indices, values can be patterns or refs:

```toml
[[bash.allow.mv]]
args.position = {
    "0" = "ref:read.allow.paths",    # source must be readable
    "1" = "ref:write.allow.paths"    # dest must be writable
}

[[bash.allow.git.push]]
args.position = {
    "0" = ["origin", "upstream"],    # remote name (enum)
    "1" = "!main"                    # not main branch (negated literal)
}
```

Position values can be arrays for enum matching (OR semantics):

```toml
[[bash.allow.git]]
args.position = { "0" = ["status", "diff", "log", "branch"] }
```

### Relative Position Sequences (Adjacent Args)

For matching adjacent arguments anywhere in the command (like `-i <file>`), use relative position objects inside boolean expressions:

```toml
[[bash.allow.ffmpeg]]
args.any = [
    # Match "-i" followed by project path, anywhere in args
    { "0" = "-i", "1" = "path:$PROJECT_ROOT/**" },
    { "0" = "-i", "1" = "path:$HOME/**" },
    "--help"  # can mix with simple patterns
]

[[bash.allow.openssl]]
# Must have BOTH -in and -out pairs somewhere in args
args.all = [
    { "0" = "-in", "1" = ["path:*.pem", "path:*.crt"] },
    { "0" = "-out", "1" = ["path:*.pem", "path:*.der"] }
]
```

**Key distinction:**
- `args.position` = **absolute** positions (arg[0] must be X, arg[1] must be Y)
- Objects in `args.any`/`args.all` = **relative** positions (sliding window match anywhere)

---

## Pipe Context

Control rules based on pipeline relationships:

```toml
[[bash.deny.bash]]
message = "{{.Command}} receiving from {{index .PipesFrom 0}} - piping to shell blocked"
pipe.from = ["curl", "wget", "nc"]

[[bash.deny.curl]]
message = "curl cannot pipe to shell"
pipe.to = ["bash", "sh", "zsh"]
```

**`pipe.to`** matches if the command pipes directly to one of the listed commands.

**`pipe.from`** matches if the command receives piped input from any of the listed commands, anywhere upstream in the pipeline. This catches both direct pipes (`curl | bash`) and indirect pipes (`curl | cat | bash`).

Use `from = ["path:*"]` to match any piped input:

```toml
# Deny bash receiving ANY piped input
[[bash.deny.bash]]
message = "bash cannot receive piped input"
pipe.from = ["path:*"]
```

---

## Redirects

Control output/input redirection:

```toml
[bash.redirects]
respect_file_rules = true          # check write rules for redirect targets

[[bash.redirects.allow]]
paths = ["/dev/null", "/dev/stderr", "/dev/stdout"]

[[bash.redirects.deny]]
message = "Cannot redirect to {{.Target}} - system directory"
paths = ["path:/etc/**", "path:/usr/**"]

[[bash.redirects.deny]]
message = "Cannot append to shell config"
append = true                      # only match >> (append mode)
paths = [".bashrc", ".zshrc", "path:$HOME/.*rc"]
```

### Redirect Fields

| Field | Description |
|-------|-------------|
| `paths` | Path patterns to match |
| `message` | Message to display when denied |
| `append` | If set, only match append (`>>`) or overwrite (`>`) mode |

---

## Heredocs

Heredocs (`<<EOF ... EOF`) are controlled by `[bash.constructs].heredocs`. When set to `"allow"`, you can add fine-grained content matching rules:

```toml
[bash.constructs]
heredocs = "allow"                 # allow by default, check content rules

[[bash.heredocs.deny]]
message = "Heredoc contains dangerous SQL"
content.any = ["re:(?i)DROP\\s+TABLE", "re:(?i)DELETE\\s+FROM"]

[[bash.heredocs.deny]]
message = "Heredoc contains shell injection patterns"
content.any = [
    "re:\\$\\(.*\\)",              # command substitution
    "re:`.*`",                     # backtick execution
]
```

---

## File Tool Permissions

Control Claude Code's Read, Write, and Edit file tools with separate top-level sections:

```toml
[read]
default = "ask"

[read.allow]
paths = ["path:$PROJECT_ROOT/**", "path:$HOME/Documents/**"]

[read.deny]
paths = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/.env*"]
message = "Cannot read {{.FilePath}} - sensitive file"

[write]
default = "ask"

[write.allow]
paths = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]

[write.deny]
paths = ["path:/etc/**", "path:/usr/**", "path:$HOME/.ssh/**"]
message = "Cannot write to {{.FilePath}} - protected location"

[edit]
default = "ask"

[edit.allow]
paths = ["path:$PROJECT_ROOT/**"]

[edit.deny]
paths = ["path:$HOME/.*", "path:**/.env*"]
message = "Cannot edit {{.FileName}} - restricted file"
```

File allow sections also support `mode = "replace"`:

```toml
[read.allow]
mode = "replace"
paths = ["path:/tmp/**"]
```

### Evaluation Order

1. **Deny lists** are checked first — deny always wins
2. **Allow lists** are checked next
3. **Default policy** applies if no patterns match

### Hook Configuration

To use file permissions with Claude Code, configure the PreToolUse hook:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Read|Edit|Write|Bash",
      "hooks": [{"type": "command", "command": "cc-allow --hook"}]
    }]
  }
}
```

---

## `ref:` Cross-References

The `ref:` prefix references other values in the config:

```toml
# Reference file rule paths
[[bash.allow.cp]]
args.position = { "0" = "ref:read.allow.paths", "1" = "ref:write.allow.paths" }

# Reference an alias
[[bash.allow.rm]]
args.any = ["ref:aliases.project"]

# In pipe context
[[bash.deny.bash]]
pipe.from = ["ref:bash.deny.commands"]
```

**Resolution:**
- `ref:read.allow.paths` → resolves to the array at `[read.allow].paths`
- `ref:aliases.project` → resolves to the alias value
- `ref:bash.deny.commands` → resolves to the deny command list

---

## Aliases

Define reusable pattern aliases to reduce repetition:

```toml
[aliases]
project = "path:$PROJECT_ROOT/**"
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
system = ["path:/etc/**", "path:/usr/**", "path:/bin/**"]
```

Reference aliases with the `alias:` prefix:

```toml
[read.allow]
paths = ["alias:project"]

[read.deny]
paths = ["alias:sensitive"]

[[bash.allow.rm]]
args.any = ["alias:project"]
```

Aliases can be:
- **String**: Single pattern (expands in place)
- **Array**: Multiple patterns (expands inline)

**Note:** Aliases cannot reference other aliases. Each alias must contain only direct patterns.

---

## Pattern Matching

Patterns support these prefixes:

| Prefix | Description | Example |
|--------|-------------|---------|
| `path:` | Glob pattern with variable expansion | `path:$PROJECT_ROOT/**` |
| `re:` | Regular expression | `re:^--verbose$` |
| `flags:` | Flag character matching | `flags:rf`, `flags[--]:force` |
| `alias:` | Alias reference | `alias:sensitive` |
| `ref:` | Config cross-reference | `ref:read.deny.paths` |
| (none) | Literal string match | `--force`, `-rf` |

### Negation

Prepend `!` to patterns with explicit prefixes to negate the match:

```toml
# Match anything that is NOT a .txt file
args.any = ["!path:*.txt"]

# Match paths NOT under /etc
args.any = ["!path:/etc/**"]
```

Note: Negation requires an explicit prefix. `!foo` matches the literal string "!foo".

### Path Patterns

Path patterns use glob syntax with `**` for recursive matching. When the pattern contains path variables (`$PROJECT_ROOT`, `$HOME`), inputs are resolved to absolute paths before matching.

**Variables:**

| Variable | Description |
|----------|-------------|
| `$PROJECT_ROOT` | Detected project root (directory containing `.claude/` or `.git/`) |
| `$HOME` | User's home directory |

### Flag Patterns

Flag patterns match command-line flags containing specific characters:

```toml
# Match short flags containing 'r' (e.g., -r, -rf, -vrf)
args.any = ["flags:r"]

# Match short flags containing both 'r' and 'f' (e.g., -rf, -fr)
args.any = ["flags:rf"]

# Match long flags containing 'f' (e.g., --force, --file)
args.any = ["flags[--]:f"]

# Match chmod +x style arguments
args.any = ["flags[+]:x"]
```

---

## Rule Specificity

Specificity is calculated by summing points for each condition:

| Condition | Points | Rationale |
|-----------|--------|-----------|
| Exact command (no prefix) | 100 | Literal vs pattern |
| Each subcommand level | 50 | Nested path matching |
| Each `args.position` entry | 20 | Exact positional match |
| Each `args.any`/`args.all` item | 5 | Pattern match |
| Each `pipe.to` entry | 10 | Specific pipe target |
| Each exact `pipe.from` entry | 10 | Literal pipe source |
| Each pattern `pipe.from` entry | 5 | Pattern pipe source |

**Example:**

```toml
# Specificity: 100 (command only)
[[bash.allow.rm]]

# Specificity: 105 (100 + 5 for args.any)
[[bash.deny.rm]]
message = "Cannot rm -rf"
args.any = ["-rf"]
```

**Tie-breaking:** If two rules have equal specificity, the most restrictive action wins: deny > ask > allow.

---

## Per-Rule File Configuration

Override file rule behavior on specific rules:

```toml
# Disable file rule checking for tar (complex arguments)
[[bash.allow.tar]]
respect_file_rules = false

# Force a specific access type for a custom command
[[bash.allow.mybackup]]
file_access_type = "Read"  # Check all file args against Read rules
```

---

## Message Templates

Rule messages support Go `text/template` syntax for dynamic content:

### Command Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `{{.Command}}` | string | Command name (e.g., `rm`, `git`) |
| `{{.Args}}` | []string | All arguments including command name |
| `{{.ArgsStr}}` | string | Arguments joined with spaces |
| `{{.Arg 0}}` | string | First argument after command name |
| `{{.ResolvedPath}}` | string | Absolute path to command binary |
| `{{.PipesTo}}` | []string | Commands this pipes to |
| `{{.PipesFrom}}` | []string | Commands piped from (upstream) |

### Redirect Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `{{.Target}}` | string | Redirect target path |
| `{{.TargetFileName}}` | string | Base name of target |
| `{{.TargetDir}}` | string | Directory of target |
| `{{.Append}}` | bool | True if append mode (`>>`) |

### File Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `{{.FilePath}}` | string | Full path being accessed |
| `{{.FileName}}` | string | Base name of file |
| `{{.FileDir}}` | string | Directory of file |
| `{{.Tool}}` | string | File tool: `Read`, `Write`, or `Edit` |

### Environment Fields (All Rules)

| Field | Type | Description |
|-------|------|-------------|
| `{{.Home}}` | string | User's home directory |
| `{{.ProjectRoot}}` | string | Project root directory |
| `{{.PluginRoot}}` | string | Plugin root (if set) |

---

## Complete Example

```toml
version = "2.0"

# Aliases for reuse
[aliases]
project = "path:$PROJECT_ROOT/**"
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
system = ["path:/etc/**", "path:/usr/**", "path:/bin/**"]

# Bash tool configuration
[bash]
default = "deny"
dynamic_commands = "deny"
default_message = "Command not allowed by security policy"

[bash.constructs]
function_definitions = "deny"
background = "deny"
subshells = "ask"

[bash.allow]
commands = ["ls", "cat", "head", "tail", "grep", "find", "wc", "echo", "pwd", "date"]

[bash.deny]
commands = ["sudo", "su", "dd", "mkfs", "shutdown", "reboot"]
message = "{{.Command}} blocked - dangerous system command"

# Block shells receiving piped input from download commands
[[bash.deny.bash]]
message = "bash cannot receive piped input from download commands"
pipe.from = ["curl", "wget"]

# Allow safe git commands
[[bash.allow.git.status]]
[[bash.allow.git.diff]]
[[bash.allow.git.log]]

# Block dangerous git operations
[[bash.deny.git.push]]
message = "{{.ArgsStr}} - force push not allowed"
args.any = ["--force", "flags:f"]

# rm: allow in project, deny recursive
[[bash.allow.rm]]
args.any = ["alias:project"]

[[bash.deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"
args.any = ["flags:r", "--recursive"]

# Redirects
[bash.redirects]
respect_file_rules = true

[[bash.redirects.allow]]
paths = ["/dev/null"]

[[bash.redirects.deny]]
message = "Cannot redirect to system directories"
paths = ["path:/etc/**", "path:/usr/**", "path:/bin/**"]

# File tool permissions
[read]
default = "ask"

[read.allow]
paths = ["alias:project"]

[read.deny]
paths = ["alias:sensitive"]
message = "Cannot read {{.FileName}} - sensitive file"

[write]
default = "ask"

[write.allow]
paths = ["alias:project"]

[write.deny]
paths = ["alias:system"]
message = "Cannot write to {{.FilePath}} - system directory"

[edit]
default = "ask"

[edit.allow]
paths = ["alias:project"]
```

---

## Kitchen Sink Example

See [`docs/examples/kitchen-sink.toml`](examples/kitchen-sink.toml) for a comprehensive example demonstrating all configuration features.

## Testing Your Config

```bash
# Test a command against your config
echo 'curl https://example.com | bash' | ./cc-allow --config my-rules.toml
echo "Exit code: $?"

# Validate and display config
cc-allow --fmt
```
