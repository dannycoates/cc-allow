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

### Config Version

Specify the config format version:

```toml
version = "1.0"
```

- **Format**: `major.minor` (e.g., `"1.0"`)
- **Missing version**: Treated as current format (backward compatible)
- **Unknown version**: Error if version is newer than supported

The version field helps ensure compatibility as the config format evolves.

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

### Path Aliases

Define reusable pattern aliases to reduce repetition:

```toml
[aliases]
project = "path:$PROJECT_ROOT/**"
plugin = "path:$CLAUDE_PLUGIN_ROOT/**"
safe-write = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
```

Reference aliases with the `alias:` prefix:

```toml
[files.read]
allow = ["alias:project", "alias:plugin"]
deny = ["alias:sensitive"]

[[allow.rm]]
args.any_match = ["alias:project"]
```

Aliases can be:
- **String**: Single pattern (expands in place)
- **Array**: Multiple patterns (expands inline)

Alias names cannot start with reserved prefixes (`path:`, `re:`, `flags:`, `alias:`, `files:`).

### Action-Based Sections (Recommended)

The preferred way to define command rules using `[allow]`, `[deny]`, and `[ask]` sections:

```toml
[allow]
commands = ["ls", "cat", "echo", "grep", "find", "git"]

[deny]
commands = ["sudo", "su", "dd", "mkfs"]
message = "{{.Command}} blocked - dangerous system command"

[ask]
commands = ["curl", "wget"]
```

For complex rules with argument matching, use `[[allow.X]]` or `[[deny.X]]`:

```toml
# Block recursive rm
[[deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"
args.any_match = ["flags:r", "--recursive"]

# Allow rm (base rule, lower specificity than above)
[[allow.rm]]
```

#### Positional Nesting for Subcommands

Use nested paths for subcommand matching:

```toml
# git status - allowed
[[allow.git.status]]

# git diff - allowed
[[allow.git.diff]]

# git push --force - denied
[[deny.git.push]]
message = "{{.ArgsStr}} - force push not allowed"
args.any_match = ["--force", "flags:f"]

# git push - allowed (base rule)
[[allow.git.push]]

# docker compose up - allowed
[[allow.docker.compose.up]]
```

This is equivalent to using `args.position`:
- `[[deny.git.push]]` = command `git` with `position.0 = "push"`
- `[[allow.docker.compose.up]]` = command `docker` with `position.0 = "compose"`, `position.1 = "up"`

#### Specificity with Nesting

Each nesting level adds +20 to specificity:
- `[[allow.git]]` → specificity 100 (named command)
- `[[allow.git.push]]` → specificity 120 (command + 1 positional)
- `[[allow.docker.compose.up]]` → specificity 140 (command + 2 positional)

### Quick Allow/Deny Lists (Legacy Format)

The legacy format using `[commands.allow]` and `[commands.deny]` still works:

```toml
[commands.allow]
names = ["ls", "cat", "echo", "grep", "find"]

[commands.deny]
names = ["sudo", "su", "rm", "dd", "mkfs"]
message = "Dangerous command not allowed"
```

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

Rules provide fine-grained control with argument matching and context. The recommended format uses action-based sections (see above), but the legacy `[[rule]]` format also works:

**New format (recommended):**

```toml
[[deny.rm]]
message = "Recursive rm not allowed"
args.any_match = ["-r", "-rf", "--recursive"]

[[deny.curl]]
message = "No piping curl to shell"
pipe.to = ["bash", "sh", "zsh", "eval"]

[[allow.curl]]
# allow curl when not piped to shell
```

**Legacy format:**

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

Specificity is calculated by summing points for each condition in a files:

| Condition | Points | Rationale |
|-----------|--------|-----------|
| Exact command (no prefix) | 100 | Literal vs pattern |
| Each `args.position` entry | 20 | Exact positional match |
| Each `args.contains` entry | 10 | Exact substring |
| Each `args.any_match` entry | 5 | Pattern match |
| Each `args.all_match` entry | 5 | Pattern match |
| Each `pipe.to` entry | 10 | Specific pipe target |
| Each exact `pipe.from` entry | 10 | Literal pipe source |
| Each pattern `pipe.from` entry | 5 | Pattern pipe source |

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
| `command` | Command name, `"path:*"` for any, or `"path:..."` for path matching |
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
all_match = ["path:*.txt"]       # all args must match pattern
position = { "0" = "/etc/*" }    # arg at position must match pattern (keys are string indices)
```

#### Extended Argument Matching

Position values can be arrays for enum matching (OR semantics):

```toml
[[rule]]
command = "git"
action = "allow"
[rule.args]
# Allow any of these subcommands
position = { "0" = ["status", "diff", "log", "branch"] }

[[rule]]
command = "git"
action = "deny"
message = "Network operations need approval"
[rule.args]
# Deny any of these subcommands
position = { "0" = ["push", "pull", "fetch", "clone"] }
```

`any_match` and `all_match` can include sequence objects for adjacent argument matching:

```toml
[[rule]]
command = "ffmpeg"
action = "allow"
message = "ffmpeg with safe input"
[rule.args]
# Match "-i" followed by a path under $HOME (sliding window)
any_match = [
    { "0" = "-i", "1" = "path:$HOME/**" },
    { "0" = "-i", "1" = "path:$PROJECT_ROOT/**" },
    "re:^--help$"  # can mix strings and objects
]

[[rule]]
command = "openssl"
action = "allow"
[rule.args]
# Require BOTH -in and -out pairs to be present
all_match = [
    { "0" = "-in", "1" = ["path:*.pem", "path:*.crt"] },
    { "0" = "-out", "1" = ["path:*.pem", "path:*.der"] }
]
```

**Sequence matching behavior:**
- Keys in sequence objects are relative positions ("0", "1", "2", ...)
- Values can be strings or arrays (enum, OR semantics)
- Sequences use sliding window matching — they match anywhere in the args
- In `any_match`: any sequence or string matching succeeds (OR)
- In `all_match`: all sequences and strings must match (AND)

#### Pipe Context

Control rules based on pipeline relationships:

```toml
[rule.pipe]
to = ["bash", "sh", "eval"]      # command pipes to one of these (immediate)
from = ["curl", "wget"]          # command receives from one of these (any upstream)
```

**`pipe.to`** matches if the command pipes directly to one of the listed commands.

**`pipe.from`** matches if the command receives piped input from any of the listed commands, anywhere upstream in the pipeline. This catches both direct pipes (`curl | bash`) and indirect pipes (`curl | cat | bash`).

Use `from = ["path:*"]` to match any piped input:

```toml
# Deny bash receiving ANY piped input
[[rule]]
command = "bash"
action = "deny"
message = "bash cannot receive piped input"
[rule.pipe]
from = ["path:*"]
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
pattern = ["path:*.log", "re:^/tmp/.*"]  # pattern match
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

Patterns support these prefixes:

| Prefix | Description | Example |
|--------|-------------|---------|
| `path:` | Glob pattern with optional variable expansion | `path:*.txt`, `path:$PROJECT_ROOT/**` |
| `re:` | Regular expression | `re:^/etc/.*` |
| `flags:` | Flag pattern (chars must appear) | `flags:rf`, `flags[--]:rec` |
| `alias:` | Reference to alias defined in `[aliases]` | `alias:project`, `alias:sensitive` |
| `files:` | File rule marker for positional args | `files:read`, `files:write`, `files:edit` |

Without a prefix, the string is matched exactly as a literal.

**Note:** The `files:` prefix is special — it marks a positional argument for file rule checking rather than pattern matching. See "Positional File Rules" in the File Rule Integration section.

### Negation

Prepend "!" to patterns with explicit prefixes (`path:`, `re:`, `flags:`) to negate the match:

```toml
# Match anything that is NOT a .txt file
any_match = ["!path:*.txt"]

# Match paths NOT under /etc
any_match = ["!path:/etc/**"]

# Match anything that does NOT start with "--"
any_match = ["!re:^--"]
```

Note: Negation requires an explicit prefix. `!foo` matches the literal string "!foo".

### Path Patterns

Path patterns use glob syntax with `**` for recursive matching (via the doublestar library). When the pattern contains path variables (`$PROJECT_ROOT`, `$HOME`, `$CLAUDE_PLUGIN_ROOT`), inputs are resolved to absolute paths before matching.

```toml
# Simple glob matching (no path resolution)
any_match = ["path:*.txt"]              # matches file.txt
any_match = ["path:src/**/*.go"]        # matches src/main.go, src/pkg/util.go, etc.

# Path patterns with variables (full path resolution)
any_match = ["path:$PROJECT_ROOT/**"]   # matches files under project root
any_match = ["path:$HOME/.config/**"]   # matches files under ~/.config
```

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

### Flag Patterns

Flag patterns match command-line flags containing specific characters:

```toml
# Match short flags containing 'r' (e.g., -r, -rf, -vrf)
any_match = ["flags:r"]

# Match short flags containing both 'r' and 'f' (e.g., -rf, -fr)
any_match = ["flags:rf"]

# Match long flags containing 'f' (e.g., --force, --file)
any_match = ["flags[--]:f"]

# Match chmod +x style arguments
any_match = ["flags[+]:x"]

# Negated: match flags NOT containing 'r'
any_match = ["!flags:r"]
```

The delimiter defaults to `-` if not specified. Use `flags[delim]:` with any delimiter string (e.g., `flags[--]:` for long flags, `flags[+]:` for chmod). All specified characters must appear somewhere after the delimiter (in any order).

Note: When using `-` as delimiter, `--` prefixed arguments are excluded to avoid matching long flags.

## Complete Example

```toml
# Strict security policy

[aliases]
project = "path:$PROJECT_ROOT/**"
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
system = ["path:/etc/**", "path:/usr/**", "path:/bin/**"]

[policy]
default = "deny"
dynamic_commands = "deny"
default_message = "Command not allowed by security policy"

# Bulk allow/deny lists
[allow]
commands = ["ls", "cat", "head", "tail", "grep", "find", "wc", "echo", "pwd", "date"]

[deny]
commands = ["sudo", "su", "dd", "mkfs", "shutdown", "reboot"]
message = "{{.Command}} blocked - dangerous system command"

[constructs]
function_definitions = "deny"
background = "deny"
subshells = "ask"

# Block shells from receiving piped input from download commands
[[deny.bash]]
message = "bash cannot receive piped input from download commands"
pipe.from = ["curl", "wget"]

[[deny.sh]]
message = "sh cannot receive piped input from download commands"
pipe.from = ["curl", "wget"]

# Block dangerous git operations
[[deny.git.push]]
message = "{{.ArgsStr}} - force push not allowed"
args.any_match = ["--force", "flags:f"]

[[deny.git.push]]
message = "Cannot push directly to main"
args.any_match = ["main", "master", "origin/main", "origin/master"]

# Allow safe git commands
[[allow.git.status]]
[[allow.git.diff]]
[[allow.git.log]]

# rm: allow in project, deny recursive
[[allow.rm]]
args.any_match = ["alias:project"]

[[deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"
args.any_match = ["flags:r", "--recursive"]

# Block writes to system directories
[[redirect]]
action = "deny"
message = "Cannot write to system directories"
[redirect.to]
pattern = ["re:^/etc/.*", "re:^/usr/.*", "re:^/bin/.*"]

# File rules with aliases
[files.read]
allow = ["alias:project"]
deny = ["alias:sensitive"]

[files.write]
allow = ["alias:project"]
deny = ["alias:system"]
```

## File Tool Permissions

Control Claude Code's Read, Edit, and Write file tools. These are simpler than bash rules — just pattern arrays for allow/deny lists.

### Config Format

```toml
[files]
default = "ask"  # "allow", "deny", or "ask" when no rules match

[files.read]
allow = ["path:$PROJECT_ROOT/**", "path:$CLAUDE_PLUGIN_ROOT/**"]
deny = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
message = "Cannot read sensitive files"

[files.edit]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.*"]
message = "Cannot edit sensitive files"

[files.write]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.*", "path:/etc/**", "path:/usr/**"]
message = "Cannot write outside project directory"
```

### Evaluation Order

1. **Deny lists** are checked first — deny always wins
2. **Allow lists** are checked next
3. **Default policy** applies if no patterns match

### Pattern Types

File patterns support the same prefixes as command rules:

| Prefix | Example | Use case |
|--------|---------|----------|
| `path:` | `path:$PROJECT_ROOT/**`, `path:**/.env*` | Project-scoped or glob patterns |
| `re:` | `re:.*\.(key\|pem)$` | Complex extension matching |

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

### Config Merging

File rules merge the same way as command rules:
- Deny lists union across configs (anything denied anywhere stays denied)
- Allow lists union across configs
- Stricter default wins

## File Rule Integration with Bash Commands

When file rules are configured, bash commands can automatically have their file arguments checked against those rules. This provides unified security: if `/etc/**` is denied for the Read file tool, then `cat /etc/passwd` is also denied.

### Enabling File Rule Integration

File rule checking for bash commands is controlled by two settings:

```toml
[policy]
respect_file_rules = true  # Check file rules for command arguments (default: true)

[redirects]
respect_file_rules = true  # Check file rules for redirect targets (default: false)
```

**Important:** File rule checking only activates when file rules are actually configured. If there are no `[files.*]` sections with allow/deny patterns, commands are evaluated without file argument checking (backward compatible).

### How It Works

1. When a command is evaluated and would be **allowed**, file arguments are checked
2. Each path-like argument is resolved to an absolute path
3. The argument is checked against file rules based on the command's access type
4. If any argument is denied by file rules, the command is denied

### Default Access Types

Commands are automatically mapped to file access types:

| Access Type | Commands |
|-------------|----------|
| Read | `cat`, `less`, `more`, `head`, `tail`, `grep`, `egrep`, `fgrep`, `find`, `file`, `wc`, `diff`, `cmp`, `stat`, `od`, `xxd`, `hexdump`, `strings` |
| Write | `rm`, `rmdir`, `touch`, `mkdir`, `chmod`, `chown`, `chgrp`, `ln`, `unlink` |
| Edit | `sed` |

Commands not in this list skip file argument checking unless configured with `file_access_type`.

### Path Argument Detection

Only arguments that look like file paths are checked:
- Absolute paths (`/etc/passwd`)
- Relative paths with indicators (`./file`, `../parent/file`)
- Home directory paths (`~/documents`)
- Bare filenames with extensions (`README.md`, `file.txt`) — only if the file exists

Flags (`-rf`, `--verbose`) and non-path arguments are skipped.

### Per-Rule Configuration

Override file rule behavior on specific rules:

```toml
# Disable file rule checking for tar (has complex argument patterns)
[[rule]]
command = "tar"
action = "allow"
respect_file_rules = false

# Force a specific access type for a custom command
[[rule]]
command = "mybackup"
action = "allow"
file_access_type = "Read"  # Check all file args against Read rules
```

#### Rule Fields for File Integration

| Field | Description |
|-------|-------------|
| `respect_file_rules` | `true` or `false` — override policy default for this rule |
| `file_access_type` | `"Read"`, `"Write"`, or `"Edit"` — override inferred access type |

### Positional File Rules

For commands like `cp` and `mv` where different arguments have different access semantics, use the `files:` prefix in position patterns:

```toml
# cp: first arg is source (read), second arg is dest (write)
[[rule]]
command = "cp"
action = "allow"
[rule.args]
position = { "0" = "files:read", "1" = "files:write" }

# mv: same pattern as cp
[[rule]]
command = "mv"
action = "allow"
[rule.args]
position = { "0" = "files:read", "1" = "files:write" }

# install: source is read, dest is write
[[rule]]
command = "install"
action = "allow"
[rule.args]
position = { "0" = "files:read", "1" = "files:write" }
```

The `files:` prefix accepts three values:
- `files:read` — check this position against Read file rules
- `files:write` — check this position against Write file rules
- `files:edit` — check this position against Edit file rules

**Example behavior with file rules:**

```toml
[files.read]
deny = ["path:**/*.key", "path:$HOME/.ssh/**"]

[files.write]
deny = ["path:/etc/**", "path:/protected/**"]
```

- `cp ~/.ssh/id_rsa /tmp/key` → **denied** (source matches Read deny)
- `cp /tmp/file /etc/config` → **denied** (dest matches Write deny)
- `cp /project/file /tmp/backup` → **allowed** (both pass)

### Redirect File Rules

When `redirects.respect_file_rules = true`, redirect targets are checked against file rules:

- Output redirects (`>`, `>>`) are checked against **Write** file rules
- Input redirects (`<`) are checked against **Read** file rules

```toml
[redirects]
respect_file_rules = true

[files.write]
deny = ["path:/etc/**", "path:/protected/**"]

[files.read]
deny = ["path:**/*.key"]
```

With this configuration:
- `echo "data" > /etc/config` → **denied** (Write to /etc)
- `echo "data" >> /protected/log` → **denied** (Write to /protected)
- `cat < ~/.ssh/id_rsa.key` → **denied** (Read from *.key)

**Note:** Explicit `[[redirect]]` pattern rules take precedence over file rule checking. File rules are only checked when no redirect pattern matches.

### Complete Example

```toml
[policy]
default = "allow"
respect_file_rules = true

[redirects]
respect_file_rules = true

[commands.allow]
names = ["cat", "head", "tail", "grep", "rm", "touch", "cp", "mv", "echo"]

# File rules applied to both file tools AND bash command arguments
[files]
default = "allow"

[files.read]
allow = ["path:$PROJECT_ROOT/**", "path:$HOME/**", "/tmp/**"]
deny = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem", "path:**/.env*", "/etc/**", "/secrets/**"]

[files.write]
allow = ["path:$PROJECT_ROOT/**", "/tmp/**"]
deny = ["/etc/**", "/usr/**", "/bin/**", "/protected/**", "path:$HOME/.ssh/**"]

# Positional rules for cp/mv
[[rule]]
command = "cp"
action = "allow"
[rule.args]
position = { "0" = "files:read", "1" = "files:write" }

[[rule]]
command = "mv"
action = "allow"
[rule.args]
position = { "0" = "files:read", "1" = "files:write" }

# Disable file checking for tar (complex arguments)
[[rule]]
command = "tar"
action = "allow"
respect_file_rules = false
```

With this config:
- `cat /project/file.txt` → allowed (project path)
- `cat /etc/passwd` → denied (Read deny: /etc/**)
- `cat ~/.ssh/id_rsa` → denied (Read deny: .ssh/**)
- `rm /project/temp.txt` → allowed (Write allow: project)
- `rm /etc/hosts` → denied (Write deny: /etc/**)
- `cp /project/src.txt /project/dst.txt` → allowed (both paths pass)
- `cp ~/.ssh/key /tmp/key` → denied (source fails Read rules)
- `cp /tmp/file /etc/config` → denied (dest fails Write rules)
- `echo "x" > /etc/config` → denied (redirect to Write deny path)
- `tar -xf /etc/archive.tar` → allowed (file rules disabled for tar)

## Message Templates

Rule messages support Go `text/template` syntax for dynamic content. Templates are evaluated when a rule matches, allowing messages to include specific details about the command, file, or redirect that triggered the rule.

### Basic Usage

```toml
[[rule]]
command = "rm"
action = "deny"
message = "{{.ArgsStr}} - recursive deletion not allowed"
[rule.args]
any_match = ["flags:r"]

[[redirect]]
action = "deny"
message = "Cannot redirect to {{.Target}}"
[redirect.to]
pattern = ["path:/etc/**"]

[files.write]
deny = ["path:/etc/**"]
message = "Cannot write to {{.FilePath}} - system directory"
```

### Available Template Fields

Different fields are available depending on the rule type:

#### Command Rules

| Field | Type | Description |
|-------|------|-------------|
| `{{.Command}}` | string | Command name (e.g., `rm`, `git`) |
| `{{.Args}}` | []string | All arguments including command name |
| `{{.ArgsStr}}` | string | Arguments joined with spaces |
| `{{.Arg 0}}` | string | First argument after command name |
| `{{.Arg 1}}` | string | Second argument after command name |
| `{{.ResolvedPath}}` | string | Absolute path to command binary |
| `{{.Cwd}}` | string | Effective working directory |
| `{{.PipesTo}}` | []string | Commands this pipes to |
| `{{.PipesFrom}}` | []string | Commands piped from (upstream) |

#### Redirect Rules

| Field | Type | Description |
|-------|------|-------------|
| `{{.Target}}` | string | Redirect target path |
| `{{.TargetFileName}}` | string | Base name of target (e.g., `passwd` from `/etc/passwd`) |
| `{{.TargetDir}}` | string | Directory of target (e.g., `/etc` from `/etc/passwd`) |
| `{{.Append}}` | bool | True if append mode (`>>`) |

#### Heredoc Rules

| Field | Type | Description |
|-------|------|-------------|
| `{{.Delimiter}}` | string | Heredoc delimiter (e.g., `EOF`) |
| `{{.Body}}` | string | Heredoc content (truncated to 100 chars) |

#### File Rules

| Field | Type | Description |
|-------|------|-------------|
| `{{.FilePath}}` | string | Full path being accessed |
| `{{.FileName}}` | string | Base name of file |
| `{{.FileDir}}` | string | Directory of file |
| `{{.Tool}}` | string | File tool: `Read`, `Write`, or `Edit` |

#### Environment (All Rules)

| Field | Type | Description |
|-------|------|-------------|
| `{{.Home}}` | string | User's home directory |
| `{{.ProjectRoot}}` | string | Project root directory |
| `{{.PluginRoot}}` | string | Plugin root (if set) |

### Template Examples

```toml
# Show the full command that was blocked
[[rule]]
command = "git"
action = "deny"
message = "{{.ArgsStr}} - force push not allowed"
[rule.args]
contains = ["push"]
any_match = ["--force", "flags:f"]
# Output: "git push --force origin main - force push not allowed"

# Show which upstream command is piping to shell
[[rule]]
command = "bash"
action = "deny"
message = "{{.Command}} receiving from {{index .PipesFrom 0}} - piping to shell not allowed"
[rule.pipe]
from = ["curl", "wget"]
# Output: "bash receiving from curl - piping to shell not allowed"

# File tool message with path details
[files.write]
deny = ["path:/etc/**"]
message = "Cannot {{.Tool}} to {{.FileName}} in {{.FileDir}}"
# Output: "Cannot Write to passwd in /etc"

# Redirect with target info
[[redirect]]
action = "deny"
message = "Cannot write to {{.TargetFileName}} ({{.TargetDir}})"
[redirect.to]
pattern = ["path:/etc/**"]
# Output: "Cannot write to hosts (/etc)"

# Show specific argument
[[rule]]
command = "cd"
action = "deny"
message = "cd {{.Arg 0}} - only project directories allowed"
# Output: "cd /etc - only project directories allowed"
```

### Error Handling

If a template has syntax errors or references missing fields:
- The raw (unexpanded) message is used instead
- Errors are logged in debug mode (`--debug`)
- The rule evaluation continues normally

### Tips

- Use `{{.ArgsStr}}` to show the full command with all arguments
- Use `{{.Arg N}}` to reference specific positional arguments (0-indexed, excludes command name)
- Use `{{index .PipesFrom 0}}` to access the first element of an array
- Empty fields render as empty strings (no error)
- Templates only work in `message` and `message` fields

## Kitchen Sink Example

See [`docs/examples/kitchen-sink.toml`](examples/kitchen-sink.toml) for a comprehensive example demonstrating all configuration features.

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
