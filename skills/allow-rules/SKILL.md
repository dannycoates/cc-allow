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

**Command Path Resolution**: Commands are resolved to absolute paths. Shell builtins bypass resolution. Use `allowed_paths` to restrict where commands can be found.

### Quick Allow/Deny Lists

```toml
[commands.allow]
names = ["ls", "cat", "git", "go"]
# Can also use path: prefix for path-based matching:
# names = ["git", "path:$PROJECT_ROOT/bin/*", "path:/usr/bin/ls"]

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

When multiple rules match, the **most specific rule wins** based on specificity scoring. Rule order doesn't matter. Across configs, results are combined.

**Specificity points**: Named command (+100), each position arg (+20), each contains (+10), each pattern (+5), each pipe target (+10), pipe from wildcard (+5). Tie-break: deny > ask > allow.

The `command` field can be a name, `"*"` for any, or `"path:..."` for resolved path matching:

```toml
[[rule]]
command = "git"
action = "deny"
message = "Force push not allowed"
[rule.args]
any_match = ["--force", "-f"]
contains = ["push"]

[[rule]]
command = "curl"
action = "deny"
message = "No piping curl to shell"
[rule.pipe]
to = ["bash", "sh"]

# Match by resolved path
[[rule]]
command = "path:$PROJECT_ROOT/scripts/*"
action = "allow"
```

#### Argument Matching

```toml
[rule.args]
contains = ["--force"]           # must contain all (exact match)
any_match = ["-r", "-rf"]        # must match at least one
all_match = ["glob:*.txt"]       # all args must match
position = { "0" = "/etc/*" }      # arg at position must match (indices are strings)
```

#### Pipe Context

```toml
[rule.pipe]
to = ["bash", "sh"]              # pipes directly to one of these
from = ["curl", "wget"]          # receives from any upstream (use for dangerous sinks)
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

Heredocs are separate from redirects (default: `constructs.heredocs = "allow"`).

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
| `glob:` | Shell glob (supports `**`) | `glob:*.txt`, `src/**/*.go` |
| `re:` | Regular expression | `re:^/etc/.*` |
| `path:` | Path pattern with variable expansion | `path:$PROJECT_ROOT/**` |
| `flags:` | Flag pattern (chars must appear) | `flags:rf`, `flags[--]:rec` |
| `rule:` | File rule marker for positional args | `rule:read`, `rule:write`, `rule:edit` |
| (none) | Exact match (or glob if contains `*?[`) | `--verbose` |

### Negation

Prepend "!" to patterns with explicit prefixes (`path:`, `re:`, `glob:`, `flags:`) to negate the match:

```toml
# Allow rm only for paths NOT under /etc
[[rule]]
command = "rm"
action = "allow"
[rule.args]
any_match = ["!path:/etc/**"]

# Match files that are NOT .txt
any_match = ["!glob:*.txt"]

# Match args that do NOT start with "--"
any_match = ["!re:^--"]
```

Note: Negation requires an explicit prefix. `!foo` matches the literal string "!foo".

### Path Patterns

Path patterns resolve arguments to absolute paths and expand variables:

| Variable | Description |
|----------|-------------|
| `$PROJECT_ROOT` | Directory containing `.claude/` or `.git/` |
| `$HOME` | User's home directory |

```toml
# Allow rm only under project root
[[rule]]
command = "rm"
action = "allow"
[rule.args]
any_match = ["path:$PROJECT_ROOT/**"]

# Block rm outside project
[[rule]]
command = "rm"
action = "deny"
message = "Cannot delete files outside project"
```

Path matching:
- Expands `~` to `$HOME`
- Resolves relative paths against cwd
- Follows symlinks (security)
- Uses gitignore-style `**` for recursive matching
- Only matches path-like arguments (starts with `/`, `./`, `../`, `~`, or contains `/`)

## File Tool Permissions

Control Read, Edit, and Write file tools with pattern arrays:

```toml
[files]
default = "ask"  # when no rules match

[files.read]
allow = ["path:$PROJECT_ROOT/**", "path:$CLAUDE_PLUGIN_ROOT/**"]
deny = ["path:$HOME/.ssh/**", "glob:**/*.key", "glob:**/*.pem"]
deny_message = "Cannot read sensitive files"

[files.edit]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.*"]
deny_message = "Cannot edit sensitive files"

[files.write]
allow = ["path:$PROJECT_ROOT/**"]
deny = ["path:$HOME/.*", "path:/etc/**", "path:/usr/**"]
deny_message = "Cannot write outside project directory"
```

**Evaluation order**: deny → allow → default (deny always wins)

**Pattern types**: Same as command rules — `path:`, `glob:`, `re:`

## File Rule Integration with Bash Commands

Bash commands can automatically respect file rules based on their arguments. When enabled, commands like `cat /etc/passwd` will be denied if `/etc/**` is in the Read deny list.

### Enabling File Rule Checking

```toml
[policy]
respect_file_rules = true  # default: true (only active when file rules exist)

[redirects]
respect_file_rules = true  # check file rules for redirect targets (default: false)
```

File rule checking is automatically enabled when file rules are configured. If no `[files.*]` rules exist, commands are evaluated without file arg checking.

### Known Command Access Types

Commands are mapped to file access types:

| Access Type | Commands |
|-------------|----------|
| Read | `cat`, `less`, `head`, `tail`, `grep`, `find`, `file`, `wc`, `diff`, `stat` |
| Write | `rm`, `rmdir`, `touch`, `mkdir`, `chmod`, `chown`, `ln` |
| Edit | `sed` (with `-i`) |

Unknown commands skip file arg checking unless configured with `file_access_type`.

### Per-Rule Configuration

Override file rule behavior on specific rules:

```toml
# Disable file rule checking for tar (complex arguments)
[[rule]]
command = "tar"
action = "allow"
respect_file_rules = false

# Force Write access type for custom command
[[rule]]
command = "mycommand"
action = "allow"
file_access_type = "Write"
```

### Positional File Rules (cp, mv)

Use `rule:read`, `rule:write`, or `rule:edit` in position patterns to check specific arguments against file rules:

```toml
# cp: source checked with Read rules, dest checked with Write rules
[[rule]]
command = "cp"
action = "allow"
[rule.args]
position = { "0" = "rule:read", "1" = "rule:write" }

# mv: same pattern
[[rule]]
command = "mv"
action = "allow"
[rule.args]
position = { "0" = "rule:read", "1" = "rule:write" }
```

This ensures `cp secret.key /tmp/` is denied if `*.key` is in Read deny list, and `cp file.txt /etc/` is denied if `/etc/**` is in Write deny list.

### Redirect File Rules

When `redirects.respect_file_rules = true`, redirect targets are checked:

- Output redirects (`>`, `>>`) → checked against Write file rules
- Input redirects (`<`) → checked against Read file rules

```toml
[redirects]
respect_file_rules = true

[files.write]
deny = ["/etc/**", "/protected/**"]

# Now "echo x > /etc/config" is denied
```

## Message Templates

Rule messages support Go `text/template` syntax for dynamic content:

```toml
[[rule]]
command = "rm"
action = "deny"
message = "{{.ArgsStr}} - recursive deletion not allowed"

[files.write]
deny = ["path:/etc/**"]
deny_message = "Cannot write to {{.FilePath}} - system directory"
```

### Available Fields

| Field | Description | Available For |
|-------|-------------|---------------|
| `{{.Command}}` | Command name | Command rules |
| `{{.Args}}` | All arguments (array) | Command rules |
| `{{.ArgsStr}}` | Arguments as space-separated string | Command rules |
| `{{.Arg 0}}` | First argument (after command) | Command rules |
| `{{.ResolvedPath}}` | Absolute path to command | Command rules |
| `{{.Cwd}}` | Effective working directory | Command rules |
| `{{.PipesTo}}` | Commands piped to (array) | Command rules |
| `{{.PipesFrom}}` | Commands piped from (array) | Command rules |
| `{{.Target}}` | Redirect target path | Redirect rules |
| `{{.TargetFileName}}` | Base name of redirect target | Redirect rules |
| `{{.TargetDir}}` | Directory of redirect target | Redirect rules |
| `{{.Append}}` | True if append mode (>>) | Redirect rules |
| `{{.Delimiter}}` | Heredoc delimiter | Heredoc rules |
| `{{.Body}}` | Heredoc content (truncated) | Heredoc rules |
| `{{.FilePath}}` | File being accessed | File rules |
| `{{.FileName}}` | Base name of file | File rules |
| `{{.FileDir}}` | Directory of file | File rules |
| `{{.Tool}}` | File tool (Read/Write/Edit) | File rules |
| `{{.Home}}` | $HOME directory | All rules |
| `{{.ProjectRoot}}` | Project root | All rules |

### Template Examples

```toml
# Show full command in denial message
message = "{{.ArgsStr}} - force push not allowed"
# Output: "git push --force origin main - force push not allowed"

# Show pipe source in message
message = "{{.Command}} receiving from {{index .PipesFrom 0}} - piping to shell not allowed"
# Output: "bash receiving from curl - piping to shell not allowed"

# File tool message with path info
deny_message = "Cannot {{.Tool}} {{.FileName}} in {{.FileDir}}"
# Output: "Cannot Write config.txt in /etc"

# Redirect message with target info
message = "Cannot redirect to {{.TargetFileName}}"
# Output: "Cannot redirect to passwd"
```

## Common Tasks

**Allow a command**: Add to `[commands.allow].names`

**Block a command**: Add to `[commands.deny].names`

**Block with specific args**: Add `[[rule]]` with `[rule.args]`

**Restrict to project directory**: Use `path:$PROJECT_ROOT/**` in `[rule.args].any_match`

**Allow redirect target**: Add `[[redirect]]` with `action = "allow"` (redirect rules still use first-match)

**Block piping to shell**: Add rule on the sink command with `[rule.pipe].from`

**Allow file reading**: Add pattern to `[files.read].allow`

**Block file writing**: Add pattern to `[files.write].deny`

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
   # Test bash command (default, or use --bash)
   echo 'git push --force' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow
   echo $?  # 0=allow, 1=ask, 2=deny

   # Test file tools (stdin is the file path)
   echo '/etc/passwd' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --read
   echo '$HOME/.bashrc' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --write
   echo '/project/src/main.go' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --edit
   ```
7. Use `--debug` for detailed evaluation trace:
   ```bash
   echo 'git push --force' | ${CLAUDE_PLUGIN_ROOT}/bin/cc-allow --debug
   ```
