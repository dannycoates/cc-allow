---
name: allow-rules
description: Manages cc-allow.toml configuration files for bash command permission control. Use when the user wants to add, modify, or remove allow/deny rules, redirect rules, or pipe rules for Claude Code bash commands.
context: fork
---

# Managing cc-allow Rules (v2 Config Format)

cc-allow evaluates bash commands and file tool requests (Read, Edit, Write) and returns exit codes: 0=allow, 1=ask (defer), 2=deny, 3=error.

## Config Format Version

```toml
version = "2.0"
```

The v2 format is **tool-centric** with top-level sections: `[bash]`, `[read]`, `[write]`, `[edit]`.

## Config Locations

1. `~/.config/cc-allow.toml` — Global defaults
2. `<project>/.config/cc-allow.toml` — Project-specific (searches up from cwd)

**Merge behavior**: All configs are evaluated and combined. deny > allow > ask. Within a config, most specific matching rule wins.

## Config Structure

### Bash Tool Configuration

```toml
[bash]
default = "ask"                    # "allow", "deny", or "ask"
dynamic_commands = "deny"          # action for $VAR or $(cmd) as command name
default_message = "Command not allowed"
unresolved_commands = "ask"        # "ask" or "deny" for commands not found
respect_file_rules = true          # check file rules for command args
```

### Shell Constructs

```toml
[bash.constructs]
function_definitions = "deny"      # foo() { ... }
background = "deny"                # command &
subshells = "ask"                  # (command)
heredocs = "allow"                 # <<EOF ... EOF (default: allow)
```

### Aliases

Define reusable pattern aliases:

```toml
[aliases]
project = "path:$PROJECT_ROOT/**"
plugin = "path:$CLAUDE_PLUGIN_ROOT/**"
safe-write = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
```

Reference with `alias:` prefix (aliases cannot reference other aliases):

```toml
[read.allow]
paths = ["alias:project", "alias:plugin"]

[read.deny]
paths = ["alias:sensitive"]

[[bash.allow.rm]]
args.any = ["alias:project"]
```

### Allow/Deny Command Lists

```toml
[bash.allow]
commands = ["ls", "cat", "git", "go"]

[bash.deny]
commands = ["sudo", "rm", "dd"]
message = "{{.Command}} blocked - dangerous command"
```

### Complex Rules with Argument Matching

For fine-grained control, use `[[bash.allow.X]]` or `[[bash.deny.X]]`:

```toml
[[bash.deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"
args.any = ["flags:r", "--recursive"]

[[bash.allow.rm]]
# base allow (lower specificity)
```

### Subcommand Nesting

```toml
[[bash.allow.git.status]]
[[bash.allow.git.diff]]

[[bash.deny.git.push]]
message = "{{.ArgsStr}} - force push not allowed"
args.any = ["--force", "flags:f"]

[[bash.allow.git.push]]
# base allow for git push

[[bash.allow.docker.compose.up]]
# matches: docker compose up
```

This is equivalent to `args.position`:
- `[[bash.deny.git.push]]` = command `git` with `position.0 = "push"`
- `[[bash.allow.docker.compose.up]]` = command `docker` with `position.0 = "compose"`, `position.1 = "up"`

**Specificity with nesting**: +50 per nesting level
- `[[bash.allow.git]]` → 100
- `[[bash.allow.git.push]]` → 150
- `[[bash.allow.docker.compose.up]]` → 200

### Rule Specificity

When multiple rules match, **most specific rule wins**. Rule order doesn't matter.

**Specificity points**: Named command (+100), each subcommand (+50), each position arg (+20), each pattern in args.any/all (+5), each pipe target (+10), pipe from wildcard (+5). Tie-break: deny > ask > allow.

### Argument Matching

Boolean expression operators:

```toml
args.any = ["-r", "-rf"]              # at least one must match (OR)
args.all = ["path:*.txt"]             # all args must match (AND)
args.not = { any = ["--dry-run"] }    # negate the result
args.position = { "0" = "/etc/*" }    # absolute positional match
```

#### Position with Enum Values

Position values can be arrays (OR semantics):

```toml
[[bash.allow.git]]
args.position = { "0" = ["status", "diff", "log", "branch"] }

[[bash.deny.git]]
args.position = { "0" = ["push", "pull", "fetch", "clone"] }
```

#### Relative Position Sequences

`args.any` and `args.all` support sequence objects for adjacent arg matching:

```toml
[[bash.allow.ffmpeg]]
args.any = [
    { "0" = "-i", "1" = "path:$HOME/**" },
    "re:^--help$"
]

[[bash.allow.openssl]]
args.all = [
    { "0" = "-in", "1" = ["path:*.pem", "path:*.crt"] },
    { "0" = "-out", "1" = ["path:*.pem", "path:*.der"] }
]
```

**Key distinction:**
- `args.position` = **absolute** positions (arg[0] must be X)
- Objects in `args.any`/`args.all` = **relative** positions (sliding window)

### Pipe Context

```toml
pipe.to = ["bash", "sh"]              # pipes directly to one of these
pipe.from = ["curl", "wget"]          # receives from any upstream
```

Use `from = ["path:*"]` to match any piped input.

### Redirects

```toml
[bash.redirects]
respect_file_rules = true

[[bash.redirects.allow]]
paths = ["/dev/null"]

[[bash.redirects.deny]]
message = "Cannot write to system paths"
paths = ["path:/etc/**", "path:/usr/**"]

[[bash.redirects.deny]]
message = "Cannot append to shell config"
append = true                          # only match >> (omit for both > and >>)
paths = [".bashrc", ".zshrc"]
```

### Heredocs

```toml
# Deny all heredocs
[bash.constructs]
heredocs = "deny"

# Or use fine-grained rules (only checked if constructs.heredocs = "allow")
[[bash.heredocs.deny]]
message = "Dangerous content"
content.any = ["re:DROP TABLE", "re:DELETE FROM"]
```

## Pattern Matching

| Prefix | Description | Example |
|--------|-------------|---------|
| `path:` | Glob pattern with variable expansion | `path:*.txt`, `path:$PROJECT_ROOT/**` |
| `re:` | Regular expression | `re:^/etc/.*` |
| `flags:` | Flag pattern (chars must appear) | `flags:rf`, `flags[--]:rec` |
| `alias:` | Reference to path alias | `alias:project`, `alias:sensitive` |
| `ref:` | Config cross-reference | `ref:read.allow.paths` |
| (none) | Exact literal match | `--verbose` |

### Negation

Prepend "!" to patterns with explicit prefixes:

```toml
args.any = ["!path:/etc/**"]         # NOT under /etc
args.any = ["!path:*.txt"]           # NOT .txt files
```

Note: Negation requires an explicit prefix. `!foo` matches the literal string "!foo".

### Path Variables

| Variable | Description |
|----------|-------------|
| `$PROJECT_ROOT` | Directory containing `.claude/` or `.git/` |
| `$HOME` | User's home directory |
| `$CLAUDE_PLUGIN_ROOT` | Plugin root directory |

## File Tool Permissions

Separate top-level sections for each file tool:

```toml
[read]
default = "ask"

[read.allow]
paths = ["alias:project", "alias:plugin"]

[read.deny]
paths = ["alias:sensitive"]
message = "Cannot read sensitive files"

[edit]
default = "ask"

[edit.allow]
paths = ["alias:project"]

[edit.deny]
paths = ["path:$HOME/.*"]

[write]
default = "ask"

[write.allow]
paths = ["alias:project", "path:/tmp/**"]

[write.deny]
paths = ["path:$HOME/.*", "path:/etc/**", "path:/usr/**"]
message = "Cannot write outside project"
```

**Evaluation order**: deny → allow → default (deny always wins)

## ref: Cross-References

Use `ref:` to reference other config values:

```toml
# Reference file rule paths for cp/mv
[[bash.allow.cp]]
args.position = { "0" = "ref:read.allow.paths", "1" = "ref:write.allow.paths" }

# Reference an alias
[[bash.allow.rm]]
args.any = ["ref:aliases.project"]
```

**Resolution:**
- `ref:read.allow.paths` → resolves to `[read.allow].paths`
- `ref:aliases.project` → resolves to the alias value

## Per-Rule File Configuration

```toml
[[bash.allow.tar]]
respect_file_rules = false          # disable file checking for complex args

[[bash.allow.mycommand]]
file_access_type = "Write"          # force specific access type
```

## Message Templates

```toml
[[bash.deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"

[write.deny]
message = "Cannot write to {{.FilePath}} - system directory"
```

| Field | Description | Available For |
|-------|-------------|---------------|
| `{{.Command}}` | Command name | Command rules |
| `{{.ArgsStr}}` | Arguments as string | Command rules |
| `{{.Arg 0}}` | First argument | Command rules |
| `{{.PipesFrom}}` | Upstream commands | Command rules |
| `{{.Target}}` | Redirect target | Redirect rules |
| `{{.FilePath}}` | File path | File rules |
| `{{.FileName}}` | File base name | File rules |
| `{{.Tool}}` | File tool name | File rules |

## Common Tasks

**Allow a command**: Add to `[bash.allow].commands` or create `[[bash.allow.X]]`

**Block a command**: Add to `[bash.deny].commands` or create `[[bash.deny.X]]`

**Block with specific args**: Use `[[bash.deny.X]]` with `args.any` or `args.all`

**Block subcommand**: Use nested path like `[[bash.deny.git.push]]`

**Restrict to project**: Use `alias:project` or `path:$PROJECT_ROOT/**`

**Block piping to shell**: Use `[[bash.deny.bash]]` with `pipe.from = ["curl", "wget"]`

**Allow file reading**: Add to `[read.allow].paths`

**Block file writing**: Add to `[write.deny].paths`

## Workflow

0. If no project config exists, initialize one:
   ```bash
   ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --init
   ```
1. Read the existing config at `.config/cc-allow.toml`
2. Determine what change is needed
3. Add new rules
4. Write the updated config
5. Validate with `--fmt` to check syntax and view rules by specificity:
   ```bash
   ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --fmt
   ```
6. Test the new rule with a matching command:
   ```bash
   # Test bash command
   echo 'git push --force' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow
   echo $?  # 0=allow, 1=ask, 2=deny

   # Test file tools
   echo '/etc/passwd' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --read
   echo '$HOME/.bashrc' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --write
   ```
7. Use `--debug` for detailed evaluation trace:
   ```bash
   echo 'git push --force' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --debug
   ```
