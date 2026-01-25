# Migrating from v1 to v2 Config Format

This guide explains how to migrate cc-allow configuration files from the v1 format to the v2 format.

## Overview

The v2 config format is **tool-centric** with top-level sections for each tool type: `[bash]`, `[read]`, `[write]`, `[edit]`. This replaces the v1 format's flatter structure with `[policy]`, `[commands]`, `[constructs]`, `[[rule]]`, and `[files]`.

## Version Declaration

Add the version declaration at the top of your config:

```toml
version = "2.0"
```

## Quick Reference

| v1 | v2 |
|----|-----|
| `[policy]` | `[bash]` |
| `[commands.allow].names` | `[bash.allow].commands` |
| `[commands.deny].names` | `[bash.deny].commands` |
| `[commands.deny].message` | `[bash.deny].message` |
| `[constructs]` | `[bash.constructs]` |
| `[[rule]]` with `command`, `action` | `[[bash.allow.X]]` or `[[bash.deny.X]]` |
| `[rule.args]` | `args` (inline) |
| `[rule.pipe]` | `pipe` (inline) |
| `args.any_match` | `args.any` |
| `args.all_match` | `args.all` |
| `[files]` | Removed (separate sections) |
| `[files.read].allow/deny` | `[read.allow].paths` / `[read.deny].paths` |
| `[files.read].deny_message` | `[read.deny].message` |
| `[files.write]` | `[write]` (top-level) |
| `[files.edit]` | `[edit]` (top-level) |
| `[redirects]` | `[bash.redirects]` |
| `[[redirect]]` + `[redirect.to]` | `[[bash.redirects.allow]]` / `[[bash.redirects.deny]]` with `paths` |
| `[[heredoc]]` + `content_match` | `[[bash.heredocs.allow]]` / `[[bash.heredocs.deny]]` with `content.any` |
| `files:read` | `ref:read.allow.paths` |
| `files:write` | `ref:write.allow.paths` |
| `files:edit` | `ref:edit.allow.paths` |

## Detailed Migration Steps

### 1. Policy → Bash

**v1:**
```toml
[policy]
default = "ask"
dynamic_commands = "deny"
default_message = "Command not allowed"
unresolved_commands = "ask"
```

**v2:**
```toml
[bash]
default = "ask"
dynamic_commands = "deny"
default_message = "Command not allowed"
unresolved_commands = "ask"
```

### 2. Commands Allow/Deny Lists

**v1:**
```toml
[commands.allow]
names = ["ls", "cat", "git"]

[commands.deny]
names = ["sudo", "rm", "dd"]
message = "Dangerous command"
```

**v2:**
```toml
[bash.allow]
commands = ["ls", "cat", "git"]

[bash.deny]
commands = ["sudo", "rm", "dd"]
message = "Dangerous command"
```

### 3. Shell Constructs

**v1:**
```toml
[constructs]
function_definitions = "deny"
background = "ask"
subshells = "ask"
heredocs = "allow"
```

**v2:**
```toml
[bash.constructs]
function_definitions = "deny"
background = "ask"
subshells = "ask"
heredocs = "allow"
```

### 4. Rules → Typed Rule Arrays

Rules are the biggest change. The v1 `[[rule]]` syntax with `command` and `action` fields becomes typed arrays: `[[bash.allow.X]]` or `[[bash.deny.X]]`.

**v1:**
```toml
[[rule]]
command = "rm"
action = "deny"
message = "Recursive rm not allowed"
[rule.args]
any_match = ["-r", "-rf", "--recursive"]

[[rule]]
command = "rm"
action = "allow"
```

**v2:**
```toml
[[bash.deny.rm]]
message = "Recursive rm not allowed"
args.any = ["-r", "-rf", "--recursive"]

[[bash.allow.rm]]
# base allow (lower specificity than the deny rule above)
```

Note:
- `command = "rm"` + `action = "deny"` becomes `[[bash.deny.rm]]`
- `command = "rm"` + `action = "allow"` becomes `[[bash.allow.rm]]`
- `[rule.args]` becomes inline `args.` notation
- `any_match` becomes `any`
- `all_match` becomes `all`

### 5. Subcommand Rules

v1 used `args.position` or `args.contains` to match subcommands. v2 supports nested command paths for cleaner subcommand rules.

**v1:**
```toml
[[rule]]
command = "git"
action = "deny"
message = "Force push not allowed"
[rule.args]
contains = ["push"]
any_match = ["--force", "flags:f"]
```

**v2:**
```toml
[[bash.deny.git.push]]
message = "Force push not allowed"
args.any = ["--force", "flags:f"]
```

The nested path `git.push` is equivalent to `command = "git"` with `args.position = {"0" = "push"}` but more readable and with higher specificity (+50 per nesting level).

**More examples:**

```toml
# v1
[[rule]]
command = "systemctl"
action = "allow"
[rule.args]
position = { "0" = "status" }

# v2
[[bash.allow.systemctl.status]]
```

```toml
# v1
[[rule]]
command = "docker"
action = "allow"
[rule.args]
position = { "0" = "compose", "1" = "up" }

# v2
[[bash.allow.docker.compose.up]]
```

### 6. Pipe Rules

**v1:**
```toml
[[rule]]
command = "bash"
action = "deny"
message = "Piping to shell not allowed"
[rule.pipe]
from = ["curl", "wget"]
```

**v2:**
```toml
[[bash.deny.bash]]
message = "Piping to shell not allowed"
pipe.from = ["curl", "wget"]
```

### 7. File Tool Permissions

File permissions move from nested `[files.X]` to top-level `[read]`, `[write]`, `[edit]` sections.

**v1:**
```toml
[files]
default = "ask"

[files.read]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.ssh/**", "glob:**/*.key"]
deny_message = "Cannot read sensitive file"

[files.write]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:/etc/**"]
deny_message = "Cannot write to system directory"

[files.edit]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.*"]
deny_message = "Cannot edit dotfiles"
```

**v2:**
```toml
[read]
default = "ask"

[read.allow]
paths = ["path:$PROJECT_ROOT/**"]

[read.deny]
paths = ["path:$HOME/.ssh/**", "path:**/*.key"]
message = "Cannot read sensitive file"

[write]
default = "ask"

[write.allow]
paths = ["path:$PROJECT_ROOT/**"]

[write.deny]
paths = ["path:/etc/**"]
message = "Cannot write to system directory"

[edit]
default = "ask"

[edit.allow]
paths = ["path:$PROJECT_ROOT/**"]

[edit.deny]
paths = ["path:$HOME/.*"]
message = "Cannot edit dotfiles"
```

Note:
- `allow = [...]` becomes `[X.allow].paths = [...]`
- `deny = [...]` becomes `[X.deny].paths = [...]`
- `deny_message` becomes `message` under `[X.deny]`
- `glob:` prefix is now just `path:` (glob patterns work with `path:`)

### 8. Redirects

**v1:**
```toml
[redirects]
respect_file_rules = true

[[redirect]]
action = "allow"
[redirect.to]
exact = ["/dev/null"]

[[redirect]]
action = "deny"
message = "Cannot redirect to system paths"
[redirect.to]
glob = ["/etc/**", "/usr/**"]
```

**v2:**
```toml
[bash.redirects]
respect_file_rules = true

[[bash.redirects.allow]]
paths = ["/dev/null"]

[[bash.redirects.deny]]
message = "Cannot redirect to system paths"
paths = ["path:/etc/**", "path:/usr/**"]
```

Note:
- `[[redirect]]` with `action = "allow/deny"` becomes `[[bash.redirects.allow]]` or `[[bash.redirects.deny]]`
- `[redirect.to].exact` and `[redirect.to].glob` merge into a single `paths` array
- Exact paths don't need a prefix, glob patterns use `path:` prefix

### 9. Heredocs

**v1:**
```toml
[[heredoc]]
action = "deny"
message = "Dangerous SQL in heredoc"
content_match = ["re:(?i)DROP\\s+TABLE", "re:(?i)DELETE\\s+FROM"]
```

**v2:**
```toml
[[bash.heredocs.deny]]
message = "Dangerous SQL in heredoc"
content.any = ["re:(?i)DROP\\s+TABLE", "re:(?i)DELETE\\s+FROM"]
```

### 10. Cross-References (files: → ref:)

The `files:` prefix for referencing file rules is replaced with the more general `ref:` prefix.

**v1:**
```toml
[[rule]]
command = "cp"
action = "allow"
[rule.args]
position = { "0" = "files:read", "1" = "files:write" }
```

**v2:**
```toml
[[bash.allow.cp]]
args.position = { "0" = "ref:read.allow.paths", "1" = "ref:write.allow.paths" }
```

### 11. Aliases (New in v2)

v2 introduces aliases for reusable patterns:

```toml
[aliases]
project = "path:$PROJECT_ROOT/**"
plugin = "path:$CLAUDE_PLUGIN_ROOT/**"
sensitive = ["path:$HOME/.ssh/**", "path:**/*.key", "path:**/*.pem"]

[read.allow]
paths = ["alias:project", "alias:plugin"]

[read.deny]
paths = ["alias:sensitive"]
```

## Complete Migration Example

**v1 config:**
```toml
[policy]
default = "ask"
dynamic_commands = "deny"

[commands.allow]
names = ["ls", "cat", "git"]

[commands.deny]
names = ["sudo", "dd"]
message = "Dangerous command"

[constructs]
function_definitions = "deny"
background = "ask"

[files.read]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.ssh/**"]
deny_message = "Cannot read SSH keys"

[files.write]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:/etc/**"]

[redirects]
respect_file_rules = true

[[redirect]]
action = "allow"
[redirect.to]
exact = ["/dev/null"]

[[rule]]
command = "rm"
action = "deny"
message = "Recursive rm blocked"
[rule.args]
any_match = ["flags:r", "--recursive"]

[[rule]]
command = "rm"
action = "allow"

[[rule]]
command = "git"
action = "deny"
message = "Force push blocked"
[rule.args]
contains = ["push"]
any_match = ["--force", "flags:f"]

[[rule]]
command = "bash"
action = "deny"
message = "Piping to shell blocked"
[rule.pipe]
from = ["curl", "wget"]
```

**v2 config:**
```toml
version = "2.0"

[aliases]
project = "path:$PROJECT_ROOT/**"
sensitive = ["path:$HOME/.ssh/**"]

[bash]
default = "ask"
dynamic_commands = "deny"

[bash.constructs]
function_definitions = "deny"
background = "ask"

[bash.allow]
commands = ["ls", "cat", "git"]

[bash.deny]
commands = ["sudo", "dd"]
message = "Dangerous command"

[[bash.deny.rm]]
message = "Recursive rm blocked"
args.any = ["flags:r", "--recursive"]

[[bash.allow.rm]]

[[bash.deny.git.push]]
message = "Force push blocked"
args.any = ["--force", "flags:f"]

[[bash.deny.bash]]
message = "Piping to shell blocked"
pipe.from = ["curl", "wget"]

[bash.redirects]
respect_file_rules = true

[[bash.redirects.allow]]
paths = ["/dev/null"]

[read]
default = "ask"

[read.allow]
paths = ["alias:project"]

[read.deny]
paths = ["alias:sensitive"]
message = "Cannot read SSH keys"

[write]
default = "ask"

[write.allow]
paths = ["alias:project"]

[write.deny]
paths = ["path:/etc/**"]
```

## Validation

After migrating, validate your config:

```bash
cc-allow --fmt
```

This will parse the config, report any errors, and display rules organized by specificity.

## Testing

Test specific commands against your migrated config:

```bash
# Test bash commands
echo 'rm -rf /' | cc-allow
echo $?  # 0=allow, 1=ask, 2=deny

# Test file tools
echo '/etc/passwd' | cc-allow --read
echo '/home/user/.ssh/id_rsa' | cc-allow --write

# Debug mode for detailed evaluation trace
echo 'git push --force' | cc-allow --debug
```
