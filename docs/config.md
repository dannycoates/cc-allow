# cc-allow Configuration Guide (v2)

cc-allow evaluates bash commands, file tool requests (Read, Edit, Write), search tool requests (Glob, Grep), and WebFetch URL requests against a set of rules and returns an exit code indicating whether the command should be allowed, denied, or passed through to default behavior.

## Config Format Version

This documentation covers the v2 config format. The v2 format is **tool-centric** with top-level sections for each tool type: `[bash]`, `[read]`, `[write]`, `[edit]`, `[glob]`, `[grep]`, `[webfetch]`.

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

### Command File Access Classification

When `respect_file_rules` is enabled, cc-allow needs to know whether a command reads, writes, or edits files so it can check the appropriate file rules (`[read]`, `[write]`, or `[edit]`). Use `[bash.read]`, `[bash.write]`, and `[bash.edit]` sections to classify commands:

```toml
[bash.read]
commands = ["cat", "less", "grep", "head", "tail", "find"]

[bash.write]
commands = ["rm", "mkdir", "chmod", "touch"]

[bash.edit]
commands = ["sed", "awk"]
```

Classification is **orthogonal to permission** — it only affects which file rules are checked for a command's arguments, not whether the command is allowed or denied. A command can be classified as a read command and still be denied by a `[[bash.deny.X]]` rule.

**Built-in defaults:** When no `[bash.read]`, `[bash.write]`, or `[bash.edit]` sections exist anywhere in the config chain, cc-allow uses built-in defaults:

- **Read**: `cat`, `less`, `more`, `head`, `tail`, `grep`, `egrep`, `fgrep`, `rg`, `find`, `file`, `readlink`, `wc`, `diff`, `cmp`, `comm`, `stat`, `md5sum`, `sha256sum`, `sha1sum`, `od`, `xxd`, `hexdump`, `strings`, `sort`, `uniq`, `cut`, `tr`, `awk`, `sed`, `jq`, `yq`, `tee`, `xargs`
- **Write**: `rm`, `rmdir`, `touch`, `mkdir`, `mktemp`, `chmod`, `chown`, `chgrp`, `unlink`
- **Positional** (source=Read, dest=Write): `cp`, `mv`, `ln`, `install`, `rsync`, `scp`

Once any config in the chain defines a classification section, the built-in defaults are replaced entirely — you must explicitly list all commands you want classified.

**Config chain merging:** Later configs can override the classification of individual commands. If a command appears in `[bash.read]` in the project config and `[bash.write]` in a local override, the later config wins for that command. A command appearing in multiple sections within the same file is a validation error.

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

#### Per-Position IO Types

By default, file arguments in `args.position` are checked against the command's classified access type (see Command File Access Classification above). Use the `"N.type"` key format to override the access type for a specific position:

```toml
# cp: first arg is read, second arg is write
[[bash.allow.cp]]
args.position = { "0.read" = "path:**", "1.write" = "path:**" }

# install: source is read, destination is write
[[bash.allow.install]]
args.position = { "0.read" = "path:$PROJECT_ROOT/**", "1.write" = "path:/usr/local/bin/*" }
```

The `.type` suffix can be `read`, `write`, `edit`, `pattern`, or `skip`. When `read`/`write`/`edit`, the matched argument is checked against the corresponding file rules instead of the command's default classification. When `pattern` or `skip`, the argument is excluded from file rule checking entirely — useful for marking non-file arguments like search patterns or expressions.

```toml
# Mark args after -e as patterns (not file paths)
[[bash.allow.mygrep]]
args.any = [
    { "0" = "-e", "1.pattern" = "path:**" },
]
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

The `"N.type"` key format also works in relative position sequences to specify per-position IO types:

```toml
[[bash.allow.ffmpeg]]
args.any = [
    { "0" = "-i", "1.read" = "path:$PROJECT_ROOT/**" },   # -i <input file> checked as read
    { "0" = "-o", "1.write" = "path:$PROJECT_ROOT/**" },   # -o <output file> checked as write
]

# Mark flag values as non-file arguments
[[bash.allow.mycommand]]
args.any = [
    { "0" = "--pattern", "1.pattern" = "path:**" },   # --pattern <value> is never a file
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

## Search Tool Permissions (Glob/Grep)

Control Claude Code's Glob (file pattern matching) and Grep (content search) tools. These tools only have a search `path` parameter — there is no command to evaluate, so permissions are path-based.

```toml
[glob]
respect_file_rules = true

[grep]
respect_file_rules = true
```

### `respect_file_rules`

When `respect_file_rules = true` (the default), the search path is checked against `[read]` rules. This means Glob/Grep inherit the same path permissions as the Read tool — if Read denies a path, searching it is also denied.

The default action for Glob/Grep is `"allow"`, so with `respect_file_rules = true` the Read rules are the sole authority over which paths can be searched.

### Tool-Specific Rules

You can also add Glob/Grep-specific allow/deny rules, which work the same as file tool path patterns:

```toml
[glob]
respect_file_rules = true

[glob.deny]
paths = ["path:/var/log/**"]
message = "Cannot search {{.FilePath}} - log directory"
```

Tool-specific deny rules are checked first. If the tool doesn't deny, and `respect_file_rules = true`, the Read rules are checked. The most restrictive result wins.

### Disabling Read Rule Inheritance

Set `respect_file_rules = false` to evaluate only tool-specific rules, ignoring Read rules:

```toml
[glob]
respect_file_rules = false

[glob.allow]
paths = ["path:/**"]
```

### Hook Configuration

Include `Glob` and `Grep` in the hook matcher:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Read|Edit|Write|Bash|WebFetch|Glob|Grep",
      "hooks": [{"type": "command", "command": "cc-allow --hook"}]
    }]
  }
}
```

### CLI Testing

```bash
# Test glob path
echo '/etc' | ./cc-allow --glob

# Test grep path
echo '/home/user/project' | ./cc-allow --grep

# Test in hook mode
echo '{"tool_name":"Glob","tool_input":{"pattern":"**/*.go","path":"/etc"}}' | ./cc-allow --hook
```

---

## WebFetch Tool Permissions

Control Claude Code's WebFetch tool with URL pattern matching and optional Google Safe Browsing integration:

```toml
[webfetch]
default = "ask"
default_message = "URL fetch requires approval: {{.FilePath}}"

[webfetch.allow]
paths = [
    "re:^https://github\\.com/",
    "re:^https://api\\.github\\.com/",
    "re:^https://pkg\\.go\\.dev/",
    "re:^https://docs\\.",
]

[webfetch.deny]
paths = [
    "re:^https?://localhost",
    "re:^https?://127\\.0\\.0\\.1",
    "re:^https?://\\[::1\\]",
    "re:^file://",
]
message = "Blocked URL: {{.FilePath}}"
```

**Important:** URL patterns must use the `re:` prefix. The `path:` prefix is designed for filesystem paths and will not work correctly for URLs.

### Evaluation Order

1. **Deny patterns** are checked first — deny always wins
2. **Allow patterns** are checked next
3. **Safe Browsing API** is checked if enabled and no local pattern matched
4. **Default policy** applies if nothing matched

### Google Safe Browsing Integration

Enable automatic URL threat detection using Google's Safe Browsing v4 API:

```toml
[webfetch.safe_browsing]
enabled = true
api_key = "AIza..."
```

When enabled and an API key is configured, URLs that don't match any local allow/deny pattern are checked against Google Safe Browsing. URLs flagged as malware, social engineering, unwanted software, or potentially harmful applications are automatically denied.

**Merge behavior:** Safe Browsing uses strictest-wins semantics. Once enabled by any config in the chain, it cannot be disabled by a later config. The API key uses last-config-wins (a later config can override the key).

**Error handling:** On API errors (network failure, invalid key, etc.), Safe Browsing returns "ask" — the URL is deferred to Claude Code's permission system rather than silently allowed or blocked.

The API key is free but required. Get one from the [Google Cloud Console](https://console.cloud.google.com/apis/credentials) with the Safe Browsing API enabled.

### WebFetch Allow Mode

Like file tools, WebFetch supports `mode = "replace"` to discard allow patterns from earlier configs:

```toml
[webfetch.allow]
mode = "replace"
paths = ["re:^https://github\\.com/"]
```

### Hook Configuration

To use WebFetch permissions with Claude Code, include `WebFetch` in the hook matcher:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Read|Edit|Write|Bash|WebFetch|Glob|Grep",
      "hooks": [{"type": "command", "command": "cc-allow --hook"}]
    }]
  }
}
```

### Template Variables

WebFetch uses the same template variables as file tools. The URL is available as `{{.FilePath}}`:

| Field | Description |
|-------|-------------|
| `{{.FilePath}}` | The URL being fetched |
| `{{.Tool}}` | Always `WebFetch` |

---

## File Tool Permissions

Control Claude Code's Read, Write, and Edit file tools with separate top-level sections:

```toml
[read]
default = "ask"
default_message = "File read requires approval: {{.FilePath}}"

[read.allow]
paths = ["path:$PROJECT_ROOT/**", "path:$HOME/Documents/**"]

[read.deny]
paths = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/.env*"]
message = "Cannot read {{.FilePath}} - sensitive file"

[write]
default = "ask"
default_message = "File write requires approval: {{.FilePath}}"

[write.allow]
paths = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]

[write.deny]
paths = ["path:/etc/**", "path:/usr/**", "path:$HOME/.ssh/**"]
message = "Cannot write to {{.FilePath}} - protected location"

[edit]
default = "ask"
default_message = "File edit requires approval: {{.FilePath}}"

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

### Default Message

Use `default_message` to customize the message shown when no patterns match and the default action is triggered:

```toml
[read]
default = "ask"
default_message = "File read requires approval: {{.FilePath}}"
```

Available template variables: `{{.FilePath}}`, `{{.FileName}}`, `{{.FileDir}}`, `{{.Tool}}`, `{{.Home}}`, `{{.ProjectRoot}}`.

### Hook Configuration

To use file permissions with Claude Code, configure the PreToolUse hook:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Read|Edit|Write|Bash|WebFetch|Glob|Grep",
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
- `ref:glob.deny.paths` → resolves to `[glob.deny].paths`
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

The `file_access_type` field overrides the command's bulk classification (from `[bash.read]`/`[bash.write]`/`[bash.edit]`) for all file arguments matched by this rule. This is useful for commands that behave differently depending on their arguments:

```toml
# sed is classified as edit by default, but sed -i is specifically an edit
# while sed without -i is just a read (output goes to stdout)
[[bash.ask.sed]]
args.any = ["flags:i"]
file_access_type = "Edit"
```

**Precedence:** Per-position IO types (`"N.type"`) override `file_access_type`, which overrides bulk classification.

### File Argument Detection

When checking file rules for bash command arguments, cc-allow uses heuristics to determine which arguments are file paths. This avoids false positives from pattern arguments like `grep '/etc/passwd' file.txt` where `/etc/passwd` is a search string, not a file being read.

**Pattern-first commands:** For commands where the first non-flag argument is always a pattern or expression (not a file path), that argument is automatically skipped:

- `grep`, `egrep`, `fgrep`, `rg` — first non-flag arg is the search pattern
- `sed` — first non-flag arg is the sed expression
- `awk`, `gawk`, `mawk` — first non-flag arg is the awk program
- `jq`, `yq` — first non-flag arg is the query expression

**Pattern-consuming flags:** Some flags consume the next argument as a pattern. These are handled automatically:

- `grep -e <pattern>`, `grep --regexp <pattern>`, `grep -f <file>`
- `sed -e <expression>`, `sed --expression <expression>`, `sed -f <file>`
- `rg -e <pattern>`, `rg --regexp <pattern>`

Multiple pattern flags work correctly: `grep -e 'pat1' -e 'pat2' file.txt` skips both patterns.

**Filesystem validation:** Arguments containing `/` that aren't recognized by the above heuristics are validated against the filesystem (stat check). If the path doesn't exist as a file or directory, it's not treated as a file argument. This catches remaining edge cases like `sed -e 's/a/b/' -e 's/c/d/' file` where the second expression passes through pattern-first skipping.

**Custom pattern positions:** Use `"N.pattern"` or `"N.skip"` IO types in `args.position` or sequence objects to explicitly mark argument positions as non-file for commands not covered by the built-in lists.

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
| `{{.Tool}}` | string | Tool name: `Read`, `Write`, `Edit`, `Glob`, or `Grep` |

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
default_message = "File read requires approval: {{.FilePath}}"

[read.allow]
paths = ["alias:project"]

[read.deny]
paths = ["alias:sensitive"]
message = "Cannot read {{.FileName}} - sensitive file"

[write]
default = "ask"
default_message = "File write requires approval: {{.FilePath}}"

[write.allow]
paths = ["alias:project"]

[write.deny]
paths = ["alias:system"]
message = "Cannot write to {{.FilePath}} - system directory"

[edit]
default = "ask"
default_message = "File edit requires approval: {{.FilePath}}"

[edit.allow]
paths = ["alias:project"]

# Search tools — delegate to read rules
[glob]
respect_file_rules = true

[grep]
respect_file_rules = true

# WebFetch tool configuration
[webfetch]
default = "ask"
default_message = "URL fetch requires approval: {{.FilePath}}"

[webfetch.allow]
paths = [
    "re:^https://github\\.com/",
    "re:^https://pkg\\.go\\.dev/",
    "re:^https://docs\\.",
]

[webfetch.deny]
paths = [
    "re:^https?://localhost",
    "re:^https?://127\\.0\\.0\\.1",
    "re:^file://",
]
message = "Blocked URL: {{.FilePath}}"

[webfetch.safe_browsing]
enabled = true
# api_key = "AIza..."
```

---

## Kitchen Sink Example

See [`docs/examples/kitchen-sink.toml`](examples/kitchen-sink.toml) for a comprehensive example demonstrating all configuration features.

## Testing Your Config

```bash
# Test a bash command against your config
echo 'curl https://example.com | bash' | ./cc-allow --config my-rules.toml
echo "Exit code: $?"

# Test file tools
echo '/etc/passwd' | ./cc-allow --read
echo '$HOME/.bashrc' | ./cc-allow --write

# Test search tools
echo '/etc' | ./cc-allow --glob
echo '/home/user/project' | ./cc-allow --grep

# Test WebFetch URLs
echo 'https://github.com/user/repo' | ./cc-allow --fetch
echo "Exit code: $?"

# Test in hook mode (JSON input/output)
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://github.com/user/repo"}}' | ./cc-allow --hook

# Validate and display config
cc-allow --fmt
```
