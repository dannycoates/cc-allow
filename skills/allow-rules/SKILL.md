---
name: allow-rules
description: Manages cc-allow.toml configuration files for bash command permission control. Use when the user wants to add, modify, or remove allow/deny rules, redirect rules, or pipe rules for Claude Code bash commands.
context: fork
---

# Managing cc-allow Rules

cc-allow evaluates bash commands and returns exit codes: 0=allow, 1=ask (defer), 2=deny, 3=error.

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
```

### Quick Allow/Deny Lists

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

When multiple rules match, the **most specific rule wins** based on specificity scoring. Rule order doesn't matter. Across configs, results are combined.

**Specificity points**: Named command (+100), each position arg (+20), each contains (+10), each pattern (+5), each pipe target (+10), pipe from wildcard (+5). Tie-break: deny > ask > allow.

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
```

#### Argument Matching

```toml
[rule.args]
contains = ["--force"]           # must contain all (exact match)
any_match = ["-r", "-rf"]        # must match at least one
all_match = ["glob:*.txt"]       # all args must match
position = { 0 = "/etc/*" }      # arg at position must match
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
| `glob:` | Shell glob (`*` doesn't match `/`) | `glob:*.txt` |
| `re:` | Regular expression | `re:^/etc/.*` |
| (none) | Exact match | `--verbose` |

## Common Tasks

**Allow a command**: Add to `[commands.allow].names`

**Block a command**: Add to `[commands.deny].names`

**Block with specific args**: Add `[[rule]]` with `[rule.args]`

**Allow redirect target**: Add `[[redirect]]` with `action = "allow"` (redirect rules still use first-match)

**Block piping to shell**: Add rule on the sink command with `[rule.pipe].from`

## Workflow

0. If no project config exists, initialize one:
   ```bash
   cc-allow --init
   ```
1. Read the existing config at `.claude/cc-allow.toml`
2. Determine what change is needed
3. Add new rules
4. Write the updated config
5. Validate with `--fmt` to check syntax and view rules by specificity:
   ```bash
   ./cc-allow --fmt
   ```
6. Test the new rule with a matching command:
   ```bash
   echo 'git push --force' | ./cc-allow
   echo $?  # 0=allow, 1=ask, 2=deny
   ```
7. Use `--debug` for detailed evaluation trace:
   ```bash
   echo 'git push --force' | ./cc-allow --debug
   ```
