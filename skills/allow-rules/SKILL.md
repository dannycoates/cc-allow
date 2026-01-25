---
name: allow-rules
description: Manages cc-allow.toml configuration files for bash command permission control. Use when the user wants to add, modify, or remove allow/deny rules, redirect rules, or pipe rules for Claude Code bash commands.
context: fork
---

# Managing cc-allow Rules

cc-allow evaluates bash commands and file tool requests (Read, Edit, Write) and returns exit codes: 0=allow, 1=ask (defer), 2=deny, 3=error.

## Config Locations

1. `~/.config/cc-allow.toml` — Global defaults
2. `<project>/.claude/cc-allow.toml` — Project-specific (searches up from cwd)

**Merge behavior**: All configs are evaluated and combined. deny > allow > ask. Within a config, most specific matching rule wins.

## Config Structure

### Policy

```toml
[policy]
default = "ask"               # "allow", "deny", or "ask"
dynamic_commands = "ask"      # action for $VAR or $(cmd) as command name
default_message = "Command not allowed"
# allowed_paths = ["/usr/bin", "/bin"]  # optional: restrict command search paths
unresolved_commands = "ask"   # "ask" or "deny" for commands not found
```

### Path Aliases

Define reusable path patterns:

```toml
[paths]
project = "path:$PROJECT_ROOT/**"
plugin = "path:$CLAUDE_PLUGIN_ROOT/**"
safe-write = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]
```

Reference with `alias:` prefix:

```toml
[files.read]
allow = ["alias:project", "alias:plugin"]
deny = ["alias:sensitive"]

[[allow.rm]]
args.any_match = ["alias:project"]
```

### Action-Based Sections (Recommended)

Use `[allow]`, `[deny]`, `[ask]` sections for bulk command lists:

```toml
[allow]
commands = ["ls", "cat", "git", "go"]

[deny]
commands = ["sudo", "rm", "dd"]
message = "{{.Command}} blocked - dangerous command"

[ask]
commands = ["curl", "wget"]
```

For complex rules with arguments, use `[[allow.X]]` or `[[deny.X]]`:

```toml
[[deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"
args.any_match = ["flags:r", "--recursive"]

[[allow.rm]]
# base allow (lower specificity)
```

#### Positional Nesting for Subcommands

```toml
[[allow.git.status]]
[[allow.git.diff]]

[[deny.git.push]]
message = "{{.ArgsStr}} - force push not allowed"
args.any_match = ["--force", "flags:f"]

[[allow.git.push]]
# base allow for git push

[[allow.docker.compose.up]]
# matches: docker compose up
```

This is equivalent to `args.position`:
- `[[deny.git.push]]` = command `git` with `position.0 = "push"`
- `[[allow.docker.compose.up]]` = command `docker` with `position.0 = "compose"`, `position.1 = "up"`

**Specificity with nesting**: +20 per nesting level
- `[[allow.git]]` → 100
- `[[allow.git.push]]` → 120
- `[[allow.docker.compose.up]]` → 140

### Legacy Quick Allow/Deny Lists

The legacy format still works:

```toml
[commands.allow]
names = ["ls", "cat", "git", "go"]

[commands.deny]
names = ["sudo", "rm", "dd"]
message = "Dangerous command blocked"
```

### Constructs

```toml
[constructs]
function_definitions = "deny"  # foo() { ... }
background = "deny"            # command &
subshells = "ask"              # (command)
heredocs = "allow"             # <<EOF ... EOF (default: allow)
```

### Rules (Fine-grained Control)

When multiple rules match, **most specific rule wins**. Rule order doesn't matter.

**Specificity points**: Named command (+100), each position arg (+20), each contains (+10), each pattern (+5), each pipe target (+10), pipe from wildcard (+5). Tie-break: deny > ask > allow.

**New format (recommended):**

```toml
[[deny.git]]
message = "Force push not allowed"
args.any_match = ["--force", "-f"]
args.contains = ["push"]

[[deny.curl]]
message = "No piping curl to shell"
pipe.to = ["bash", "sh"]

[[allow."path:$PROJECT_ROOT/scripts/*"]]
# allow project scripts
```

**Legacy format:**

```toml
[[rule]]
command = "git"
action = "deny"
message = "Force push not allowed"
[rule.args]
any_match = ["--force", "-f"]
contains = ["push"]
```

#### Argument Matching

```toml
args.contains = ["--force"]           # must contain all (exact match)
args.any_match = ["-r", "-rf"]        # must match at least one
args.all_match = ["path:*.txt"]       # all args must match
args.position = { "0" = "/etc/*" }    # arg at position must match
```

#### Extended Argument Matching

Position values can be arrays (enum matching with OR semantics):

```toml
[[allow.git]]
args.position = { "0" = ["status", "diff", "log", "branch"] }

[[deny.git]]
args.position = { "0" = ["push", "pull", "fetch", "clone"] }
```

`any_match` and `all_match` support sequence objects for adjacent arg matching:

```toml
[[allow.ffmpeg]]
args.any_match = [
    { "0" = "-i", "1" = "path:$HOME/**" },
    "re:^--help$"
]

[[allow.openssl]]
args.all_match = [
    { "0" = "-in", "1" = ["path:*.pem", "path:*.crt"] },
    { "0" = "-out", "1" = ["path:*.pem", "path:*.der"] }
]
```

#### Pipe Context

```toml
pipe.to = ["bash", "sh"]              # pipes directly to one of these
pipe.from = ["curl", "wget"]          # receives from any upstream
```

Use `from = ["*"]` to match any piped input.

### Redirects

```toml
[[redirect]]
action = "allow"
[redirect.to]
exact = ["/dev/null"]

[[redirect]]
action = "deny"
message = "Cannot write to system paths"
append = true                    # only match >> (omit for both > and >>)
[redirect.to]
pattern = ["re:^/etc/.*", "re:^/usr/.*"]
exact = [".bashrc", ".zshrc"]
```

### Heredocs

```toml
# Deny all heredocs
[constructs]
heredocs = "deny"

# Or use fine-grained rules (only checked if constructs.heredocs = "allow")
[[heredoc]]
action = "deny"
message = "Dangerous content"
content_match = ["re:DROP TABLE", "re:DELETE FROM"]
```

## Pattern Matching

| Prefix | Description | Example |
|--------|-------------|---------|
| `path:` | Glob pattern with variable expansion | `path:*.txt`, `path:$PROJECT_ROOT/**` |
| `re:` | Regular expression | `re:^/etc/.*` |
| `flags:` | Flag pattern (chars must appear) | `flags:rf`, `flags[--]:rec` |
| `alias:` | Reference to path alias | `alias:project`, `alias:sensitive` |
| `rule:` | File rule marker for positional args | `rule:read`, `rule:write`, `rule:edit` |
| (none) | Exact literal match | `--verbose` |

### Negation

Prepend "!" to patterns with explicit prefixes:

```toml
args.any_match = ["!path:/etc/**"]   # NOT under /etc
args.any_match = ["!path:*.txt"]     # NOT .txt files
args.any_match = ["!re:^--"]         # NOT starting with --
```

Note: Negation requires an explicit prefix. `!foo` matches the literal string "!foo".

### Path Patterns

| Variable | Description |
|----------|-------------|
| `$PROJECT_ROOT` | Directory containing `.claude/` or `.git/` |
| `$HOME` | User's home directory |
| `$CLAUDE_PLUGIN_ROOT` | Plugin root directory |

```toml
[[allow.rm]]
args.any_match = ["alias:project"]

[[deny.rm]]
message = "Cannot delete files outside project"
```

## File Tool Permissions

```toml
[files]
default = "ask"

[files.read]
allow = ["alias:project", "alias:plugin"]
deny = ["alias:sensitive"]
deny_message = "Cannot read sensitive files"

[files.edit]
allow = ["alias:project"]
deny = ["path:$HOME/.*"]

[files.write]
allow = ["alias:project", "path:/tmp/**"]
deny = ["path:$HOME/.*", "path:/etc/**", "path:/usr/**"]
deny_message = "Cannot write outside project"
```

**Evaluation order**: deny → allow → default (deny always wins)

## File Rule Integration with Bash Commands

```toml
[policy]
respect_file_rules = true  # default: true (only active when file rules exist)

[redirects]
respect_file_rules = true  # check file rules for redirect targets
```

### Known Command Access Types

| Access Type | Commands |
|-------------|----------|
| Read | `cat`, `less`, `head`, `tail`, `grep`, `find`, `file`, `wc`, `diff`, `stat` |
| Write | `rm`, `rmdir`, `touch`, `mkdir`, `chmod`, `chown`, `ln` |
| Edit | `sed` (with `-i`) |

### Per-Rule Configuration

```toml
[[allow.tar]]
respect_file_rules = false  # disable file checking for complex args

[[allow.mycommand]]
file_access_type = "Write"  # force specific access type
```

### Positional File Rules (cp, mv)

```toml
[[allow.cp]]
args.position = { "0" = "rule:read", "1" = "rule:write" }

[[allow.mv]]
args.position = { "0" = "rule:read", "1" = "rule:write" }
```

## Message Templates

```toml
[[deny.rm]]
message = "{{.ArgsStr}} - recursive deletion not allowed"

[files.write]
deny_message = "Cannot write to {{.FilePath}} - system directory"
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

**Allow a command**: Add to `[allow].commands` or create `[[allow.X]]`

**Block a command**: Add to `[deny].commands` or create `[[deny.X]]`

**Block with specific args**: Use `[[deny.X]]` with `args.any_match` or `args.contains`

**Block subcommand**: Use nested path like `[[deny.git.push]]`

**Restrict to project**: Use `alias:project` or `path:$PROJECT_ROOT/**`

**Block piping to shell**: Use `[[deny.bash]]` with `pipe.from = ["curl", "wget"]`

**Allow file reading**: Add to `[files.read].allow`

**Block file writing**: Add to `[files.write].deny`

## Workflow

0. If no project config exists, initialize one:
   ```bash
   ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --init
   ```
1. Read the existing config at `.claude/cc-allow.toml`
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
