# mvdan/sh Syntax Package - AST Node Atlas

This document provides a comprehensive reference for all AST (Abstract Syntax Tree) node types in the [mvdan/sh](https://github.com/mvdan/sh) syntax package. Each node type includes a description and example bash strings that produce that node type.

---

## Top-Level Nodes

### File

The root node representing a complete shell script or source file. Contains a list of statements and trailing comments.

```bash
echo hello
echo world
```

### Stmt

A single statement (command) with optional attributes like negation, background execution, and redirections.

```bash
echo hello
```

**With negation (`Negated: true`):**
```bash
! cmd
```

**With background (`Background: true`):**
```bash
cmd &
```

### Comment

A single-line comment. Comments are attached to statements or appear in the `Last` field of container nodes.

```bash
# this is a comment
echo hello
```

---

## Command Types

### CallExpr

A simple command - the most common command type. Represents command execution or function calls with optional environment variable assignments.

```bash
echo hello world
```

**With assignment prefix:**
```bash
VAR=value cmd
```

### BinaryCmd

A binary expression connecting two statements with an operator (`&&`, `||`, `|`, `|&`).

**Logical AND:**
```bash
echo hello && echo world
```

**Logical OR:**
```bash
echo hello || echo fallback
```

**Pipeline:**
```bash
echo hello | grep h
```

**Pipeline with stderr (`|&`):**
```bash
echo |& cat
```

### IfClause

Conditional if/elif/else statement. The `Else` field contains another `IfClause` for elif/else branches.

```bash
if true; then echo yes; else echo no; fi
```

### WhileClause

While or until loop. The `Until` field is `true` for until loops.

**While loop:**
```bash
while true; do echo loop; done
```

**Until loop (`Until: true`):**
```bash
until false; do echo loop; done
```

### ForClause

For or select loop. Uses `WordIter` for word iteration or `CStyleLoop` for C-style loops. The `Select` field is `true` for select statements.

**For loop with word iteration:**
```bash
for i in a b c; do echo $i; done
```

**Select statement (`Select: true`):**
```bash
select opt in a b c; do echo $opt; done
```

**C-style for loop:**
```bash
for ((i=0; i<10; i++)); do echo $i; done
```

### CaseClause

Case (switch) statement with pattern matching.

```bash
case $x in a) echo a;; b) echo b;; esac
```

### CaseItem

A single case item within a CaseClause. Contains patterns and statements.

```bash
case $x in
  a) echo a;;   # This is one CaseItem
  b) echo b;;   # This is another CaseItem
esac
```

### Block

A group of commands in curly braces `{ }`. Creates a command group in the current shell.

```bash
{ echo hello; echo world; }
```

### Subshell

Commands executed in a subshell (parentheses). Creates a new shell process.

```bash
(echo hello; echo world)
```

### FuncDecl

Function declaration. The `RsrvWord` field is `true` when using the `function` keyword.

```bash
foo() { echo bar; }
```

### ArithmCmd

Arithmetic command using `(( ))` syntax.

```bash
((x++))
```

### TestClause

Bash extended test clause using `[[ ]]` syntax.

```bash
[[ -f file ]]
```

### DeclClause

Bash declare/local/export/readonly/typeset clause.

```bash
declare -a arr
```

### TimeClause

Bash time clause for timing command execution.

```bash
time sleep 1
```

### CoprocClause

Bash coprocess clause for running commands as coprocesses.

```bash
coproc cmd
```

### LetClause

Bash let clause for arithmetic evaluation.

```bash
let x=1+2
```

---

## Loop Constructs

### WordIter

For loop iteration over a list of words.

```bash
for i in a b c; do echo $i; done
```

### CStyleLoop

C-style for loop with init, condition, and post expressions.

```bash
for ((i=0; i<10; i++)); do echo $i; done
```

---

## Word and Literal Types

### Word

A shell word consisting of one or more word parts. Words can contain literals, quotes, expansions, etc.

```bash
echo hello
```

### Lit

A literal string that doesn't require special processing.

```bash
echo hello
```

### SglQuoted

Single-quoted string. The `Dollar` field is `true` for `$'...'` syntax.

**Regular single quotes:**
```bash
echo 'single quoted'
```

**Dollar single quotes (`Dollar: true`):**
```bash
echo $'hello\nworld'
```

### DblQuoted

Double-quoted string with nested word parts. The `Dollar` field is `true` for `$"..."` syntax.

```bash
echo "double $var quoted"
```

---

## Parameter Expansion

### ParamExp

Parameter/variable expansion. Has many optional fields for different expansion types.

**Simple expansion (`Short: true`):**
```bash
echo $var
```

**Braced expansion:**
```bash
echo ${var}
```

**With default value (`Exp` field with `:-` operator):**
```bash
echo ${var:-default}
```

**Length prefix (`Length: true`):**
```bash
echo ${#var}
```

**Substring/Slice (`Slice` field):**
```bash
echo ${var:0:5}
```

**Search and replace (`Repl` field):**
```bash
echo ${var/foo/bar}
```

**Array index (`Index` field):**
```bash
echo ${arr[0]}
```

### Expansion

Represents parameter expansion operations like `:-`, `:=`, `:+`, `:?`, `#`, `##`, `%`, `%%`.

```bash
echo ${var:-default}
```

### Slice

Character slicing in parameter expansion with offset and optional length.

```bash
echo ${var:0:5}
```

### Replace

Search and replace operation in parameter expansion. The `All` field is `true` for global replacement (`//`).

```bash
echo ${var/foo/bar}
```

---

## Command and Arithmetic Expansion

### CmdSubst

Command substitution using `$(...)` or backticks.

```bash
echo $(cmd)
```

### ArithmExp

Arithmetic expansion using `$((...))` syntax.

```bash
echo $((1+2))
```

---

## Arithmetic Expressions

### BinaryArithm

Binary arithmetic operation with an operator and two operands.

```bash
echo $((1+2))
```

```bash
echo $((a*b))
```

### UnaryArithm

Unary arithmetic operation. The `Post` field indicates postfix operators.

**Postfix increment (`Post: true`):**
```bash
((x++))
```

**Prefix increment:**
```bash
((++x))
```

### ParenArithm

Parenthesized arithmetic expression for grouping.

```bash
echo $(( (1+2)*3 ))
```

---

## Test Expressions

### BinaryTest

Binary test operation within `[[ ]]`.

```bash
[[ $a == $b ]]
```

### UnaryTest

Unary test operation within `[[ ]]`.

```bash
[[ -f file ]]
```

### ParenTest

Parenthesized test expression for grouping.

```bash
[[ ( -f x ) ]]
```

---

## Redirections

### Redirect

Input/output redirection. The `Op` field specifies the redirect type, and `N` is the optional file descriptor number.

**Output redirect:**
```bash
echo > file.txt
```

**Append redirect:**
```bash
cmd >> file
```

**Input redirect:**
```bash
cmd < input
```

**File descriptor redirect:**
```bash
cmd 2>&1
```

**Heredoc:**
```bash
cat <<EOF
hello
EOF
```

---

## Arrays

### ArrayExpr

Bash array expression for array literal syntax.

```bash
arr=(one two three)
```

### ArrayElem

Individual element within an array expression. Can include an index for associative arrays.

```bash
arr=(one two three)
```

---

## Assignment

### Assign

Variable assignment. Can appear in `CallExpr.Assigns` or `DeclClause.Args`.

**Simple assignment:**
```bash
VAR=value
```

**Assignment with command:**
```bash
VAR=value cmd
```

**Append assignment (`Append: true`):**
```bash
VAR+=more
```

**Array assignment:**
```bash
arr=(one two three)
```

---

## Process Substitution

### ProcSubst

Bash process substitution using `<(...)` or `>(...)` syntax.

```bash
diff <(cat a) <(cat b)
```

---

## Extended Globbing

### ExtGlob

Bash extended globbing patterns like `+(...)`, `*(...)`, `?(...)`, `@(...)`, `!(...)`.

```bash
echo +(foo|bar)
```

---

## Node Relationships

The AST has a hierarchical structure:

```
File
  |-- Stmts: []*Stmt
        |-- Cmd: Command (CallExpr, BinaryCmd, IfClause, etc.)
        |-- Redirs: []*Redirect
        |-- Comments: []Comment

CallExpr
  |-- Assigns: []*Assign
  |-- Args: []*Word
        |-- Parts: []WordPart (Lit, ParamExp, CmdSubst, etc.)
```

Most command types contain nested `Stmt` nodes, allowing for arbitrary nesting of shell constructs.

---

## Testing Examples

You can verify node types by running:

```bash
echo 'your bash here' | go run .
```

This will print the AST structure showing all node types produced by the input.
