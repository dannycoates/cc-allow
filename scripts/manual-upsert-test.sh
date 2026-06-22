#!/usr/bin/env bash
# Manual verification for "migrate Claude Code Always-allow approvals into cc-allow rules".
#
# Builds the CURRENT checkout (this PR) and `main`, then for each supported Always-allow
# UPSERT replays SUBSEQUENT actions through `cc-allow --hook` in a throwaway project. Runs
# with an empty HOME and a forced project dir so NEITHER your ~/.config/cc-allow.toml NOR any
# project .config/cc-allow.toml is consulted — the migrated .local.toml is the only policy.
# Prints, per upsert, the cc-allow rule it becomes and each subsequent action's verdict on
# main (no migration) vs this branch (migrated). Exits non-zero if any row deviates.
#
# Tags: intended = the blessed invocation; related (unsafe) = dangerous neighbour that must
# stay gated; related (safe) = harmless neighbour that also stays gated (grant is scoped).
#
# Usage: from this commit, `./scripts/manual-upsert-test.sh`   (needs go + jq)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
WORK=$(mktemp -d)
trap 'git worktree remove --force "$WORK/main-src" 2>/dev/null || true; rm -rf "$WORK"' EXIT
EMPTY="$WORK/home"; mkdir -p "$EMPTY"
unset CC_ALLOW_CONFIG 2>/dev/null || true

echo "Building this revision…"
go build -o "$WORK/cc.branch" ./cmd/cc-allow
base=$(git rev-parse --verify -q main || git rev-parse --verify -q origin/main || true)
[ -n "$base" ] || { echo "need a local 'main' or 'origin/main' ref"; exit 1; }
echo "Building main ($base)…"
git worktree add -q "$WORK/main-src" "$base"
( cd "$WORK/main-src" && go build -o "$WORK/cc.main" ./cmd/cc-allow )

fixture() { # $1 = project dir; fresh settings.local.json, one entry per upsert
  rm -rf "$1"; mkdir -p "$1/.claude"; git -C "$1" init -q
  cat > "$1/.claude/settings.local.json" <<'JSON'
{ "permissions": { "allow": [
  "Bash(jq:*)", "Bash(git push:*)", "Bash(npm run build)",
  "Read(/docs/**)", "Read(//tmp/abs/**)", "Read(~/.config/foo/**)",
  "Edit(src/**)", "Write(/build/**)", "Glob(lib/**)", "Grep(lib/**)",
  "WebFetch(domain:example.com)", "WebFetch(domain:*.example.com)",
  "mcp__server__tool", "Skill(foo)", "WebSearch", "Edit"
], "deny": [] } }
JSON
}
run_hook() { # $1 bin, $2 proj — fire migration
  printf '{"tool_name":"Read","tool_input":{"file_path":"%s/x"},"session_id":"t"}' "$2" \
    | CC_PROJECT_DIR="$2" HOME="$EMPTY" "$1" --hook >/dev/null 2>&1 || true
}
decide() { # $1 bin, $2 proj, $3 flag, $4 stdin -> allow|ask|deny
  # cc-allow exits 1=ask / 2=deny, so the pipeline "fails" under pipefail; the trailing
  # `|| true` keeps that from tripping `set -e` (the decision word is already on stdout).
  printf '%s' "$4" | CC_PROJECT_DIR="$2" HOME="$EMPTY" "$1" "$3" --debug 2>&1 \
    | grep -oE 'decision: (allow|ask|deny)' | tail -1 | awk '{print $2}' || true
}

PM="$WORK/p-main"; PB="$WORK/p-branch"
fixture "$PM"; run_hook "$WORK/cc.main"   "$PM"
fixture "$PB"; run_hook "$WORK/cc.branch" "$PB"

echo
echo "main   migrated a local.toml? $([ -f "$PM/.config/cc-allow.local.toml" ] && echo YES || echo NO)"
echo "branch migrated a local.toml? $([ -f "$PB/.config/cc-allow.local.toml" ] && echo YES || echo NO)"
echo; echo "branch .config/cc-allow.local.toml:"; sed 's/^/    /' "$PB/.config/cc-allow.local.toml"
echo; echo "branch settings.local.json leftovers (non-migratable kept):"
echo "    $(jq -c '.permissions.allow' "$PB/.claude/settings.local.json")"

fail=0
group() { printf '\nupsert  %-30s ->  %s\n' "$1" "$2"; }
row() { # $1 tag, $2 flag, $3 real-input, $4 display, $5 want_main, $6 want_branch
  local gm gb ok="ok"
  gm=$(decide "$WORK/cc.main"   "$PM" "$2" "$3")
  gb=$(decide "$WORK/cc.branch" "$PB" "$2" "$3")
  [ "$gm" = "$5" ] && [ "$gb" = "$6" ] || { ok="FAIL"; fail=1; }
  printf '    [%-4s] subsequent action: %-38s main=%-4s branch=%-5s %s\n' "$ok" "$4" "$gm" "$gb" "$1"
}

cat <<'LEGEND'

Legend: main = cc-allow verdict BEFORE (upsert unmigrated)   branch = AFTER (migrated)
        intended = blessed invocation   related (unsafe) = dangerous neighbour, must stay gated
        related (safe) = harmless neighbour, also gated (the grant is scoped, not broad)
LEGEND

group 'Bash(git push:*)' '[[bash.allow.git.push]]'
row 'intended'         -bash 'git push --force-with-lease' 'git push --force-with-lease' ask allow
row 'related (unsafe)' -bash 'git reset --hard'            'git reset --hard'            ask ask
row 'related (safe)'   -bash 'git status'                  'git status'                  ask ask

group 'Bash(npm run build)' '[[bash.allow.npm.run.build]]'
row 'intended'         -bash 'npm run build --silent'      'npm run build --silent'      ask allow
row 'related (unsafe)' -bash 'npm publish'                 'npm publish'                 ask ask
row 'related (safe)'   -bash 'npm run test'                'npm run test'                ask ask

group 'Bash(jq:*)' 'bash.allow commands=["jq"]'
row 'intended'         -bash 'jq .'                        'jq .'                        ask allow
row 'intended'         -bash "jq -n '{}'"                  "jq -n '{}' (bare cmd -> whole command)" ask allow

group 'Edit(src/**)' 'edit  path:$PROJECT_ROOT/src/**'
row 'intended'         -edit "$PB/src/app.ts"   'edit <proj>/src/app.ts'   ask allow
row 'related (unsafe)' -edit "$PB/.git/config"  'edit <proj>/.git/config'  ask ask
row 'related (safe)'   -edit "$PB/package.json" 'edit <proj>/package.json' ask ask

group 'Read(/docs/**)' 'read  path:$PROJECT_ROOT/docs/**'
row 'intended'         -read "$PB/docs/api.md"  'read <proj>/docs/api.md'  ask allow
row 'related (unsafe)' -read "$PB/.env"         'read <proj>/.env'         ask ask
row 'related (safe)'   -read "$PB/README.md"    'read <proj>/README.md'    ask ask

group 'Read(//tmp/abs/**)' 'read  path:/tmp/abs/**'
row 'intended'         -read '/tmp/abs/scratch' 'read /tmp/abs/scratch'    ask allow
row 'related (unsafe)' -read '/etc/passwd'      'read /etc/passwd'         ask ask
row 'related (safe)'   -read '/tmp/other/x'     'read /tmp/other/x'        ask ask

group 'Read(~/.config/foo/**)' 'read  path:$HOME/.config/foo/**'
row 'intended'         -read "$EMPTY/.config/foo/cfg" 'read <home>/.config/foo/cfg' ask allow
row 'related (unsafe)' -read "$EMPTY/.ssh/id_rsa"     'read <home>/.ssh/id_rsa'     ask ask
row 'related (safe)'   -read "$EMPTY/.config/bar/cfg" 'read <home>/.config/bar/cfg' ask ask

group 'Write(/build/**)' 'write path:$PROJECT_ROOT/build/**'
row 'intended'         -write "$PB/build/out.js" 'write <proj>/build/out.js' ask allow
row 'related (unsafe)' -write "$PB/.env"          'write <proj>/.env'         ask ask

group 'Glob(lib/**), Grep(lib/**)' 'read  path:$PROJECT_ROOT/lib/**'
row 'intended'         -read "$PB/lib/index.js" 'read <proj>/lib/index.js (routed to read)' ask allow
row 'related (safe)'   -read "$PB/secret.txt"   'read <proj>/secret.txt'                    ask ask

group 'WebFetch(domain:example.com)' 'webfetch re:^https?://example\.com(/|$)'
row 'intended'         -fetch 'https://example.com/x'         'fetch https://example.com/x'         ask allow
row 'related (unsafe)' -fetch 'https://example.com.evil.com/' 'fetch https://example.com.evil.com/' ask ask
row 'related (safe)'   -fetch 'https://example.org/'          'fetch https://example.org/'          ask ask

group 'WebFetch(domain:*.example.com)' 'webfetch re:^https?://([^/.]+\.)+example\.com(/|$)'
row 'intended'         -fetch 'https://api.example.com/x'     'fetch https://api.example.com/x'     ask allow
row 'intended'         -fetch 'https://a.b.example.com/x'     'fetch https://a.b.example.com/x'     ask allow
row 'related (unsafe)' -fetch 'https://evil.com/'             'fetch https://evil.com/'             ask ask

echo
[ "$fail" = 0 ] && echo "ALL EXPECTATIONS MET" || echo "SOME ROWS DEVIATED (see FAIL)"
exit "$fail"
