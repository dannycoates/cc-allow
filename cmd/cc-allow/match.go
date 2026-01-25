package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"cc-allow/pkg/pathutil"
)

// PatternType indicates what kind of pattern this is.
type PatternType int

const (
	PatternRegex PatternType = iota
	PatternLiteral
	PatternPath     // path pattern with variable expansion and symlink resolution (also used for glob-like matching)
	PatternFlag     // flag pattern matching characters in flags (e.g., flags:rf matches -rf, -fr)
	PatternFileRule // file rule marker (e.g., rule:read, rule:write, rule:edit)
)

// MatchContext provides context needed for path pattern matching.
type MatchContext struct {
	PathVars *pathutil.PathVars
}

// Pattern represents a parsed pattern with its type.
type Pattern struct {
	Type          PatternType
	Raw           string
	Regex         *regexp.Regexp // compiled regex (for regex patterns)
	PathPattern   string         // unexpanded path pattern (for path patterns)
	Negated       bool           // if true, match result is inverted
	FlagDelimiter string         // flag delimiter ("-" or "--") for flag patterns
	FlagChars     string         // characters that must all be present (for flag patterns)
	FileRuleType  string         // for PatternFileRule: "Read", "Write", or "Edit"
}

// ParsePattern parses a pattern string and determines its type.
// Supported prefixes:
//   - "re:" for regex patterns
//   - "path:" for path patterns with variable expansion ($PROJECT_ROOT, $HOME) and glob-style matching
//   - "flags:" for flag patterns (e.g., "flags:rf" matches -rf, -fr, -vrf)
//   - "flags[delim]:" for flag patterns with explicit delimiter (e.g., "flags[--]:rec")
//   - "rule:" for file rule markers (e.g., "rule:read", "rule:write", "rule:edit")
//   - No prefix defaults to literal match
//
// Patterns with explicit prefixes can be negated by prepending "!"
// (e.g., "!path:/foo", "!re:test", "!flags:r")
// Note: "rule:" patterns cannot be negated and are markers, not matchers.
func ParsePattern(s string) (*Pattern, error) {
	p := &Pattern{Raw: s}

	// Check for negation prefix (only for explicit pattern types)
	if strings.HasPrefix(s, "!") {
		rest := s[1:]
		if strings.HasPrefix(rest, "re:") ||
			strings.HasPrefix(rest, "path:") ||
			strings.HasPrefix(rest, "flags:") ||
			strings.HasPrefix(rest, "flags[") {
			p.Negated = true
			s = rest
			p.Raw = s // Update Raw to stripped version for matching
		}
	}

	switch {
	case strings.HasPrefix(s, "rule:"):
		p.Type = PatternFileRule
		ruleType := strings.TrimPrefix(s, "rule:")
		switch ruleType {
		case "read":
			p.FileRuleType = "Read"
		case "write":
			p.FileRuleType = "Write"
		case "edit":
			p.FileRuleType = "Edit"
		default:
			return nil, fmt.Errorf("invalid file rule type %q (must be read, write, or edit)", ruleType)
		}
		return p, nil
	case strings.HasPrefix(s, "re:"):
		p.Type = PatternRegex
		re, err := regexp.Compile(strings.TrimPrefix(s, "re:"))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidPattern, s, err)
		}
		p.Regex = re
	case strings.HasPrefix(s, "path:"):
		p.Type = PatternPath
		p.PathPattern = strings.TrimPrefix(s, "path:")
	case strings.HasPrefix(s, "flags:"), strings.HasPrefix(s, "flags["):
		p.Type = PatternFlag
		delimiter, chars, err := parseFlagPattern(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidPattern, s, err)
		}
		p.FlagDelimiter = delimiter
		p.FlagChars = chars
	default:
		// No prefix means literal match
		p.Type = PatternLiteral
	}
	return p, nil
}

// parseFlagPattern parses "flags:chars" or "flags[delim]:chars" and returns
// (delimiter, chars, error). Default delimiter is "-".
func parseFlagPattern(s string) (string, string, error) {
	// Handle "flags[delim]:chars" format
	if strings.HasPrefix(s, "flags[") {
		closeBracket := strings.Index(s, "]:")
		if closeBracket == -1 {
			return "", "", fmt.Errorf("invalid flag pattern: missing ']:'")
		}
		delimiter := s[6:closeBracket] // extract content between [ and ]
		if delimiter == "" {
			return "", "", fmt.Errorf("flag delimiter cannot be empty")
		}
		chars := s[closeBracket+2:]
		if chars == "" {
			return "", "", fmt.Errorf("flag pattern requires at least one character")
		}
		if !isValidFlagChars(chars) {
			return "", "", fmt.Errorf("flag chars must be alphanumeric, got %q", chars)
		}
		return delimiter, chars, nil
	}

	// Handle "flags:chars" format (default delimiter is "-")
	if strings.HasPrefix(s, "flags:") {
		chars := strings.TrimPrefix(s, "flags:")
		if chars == "" {
			return "", "", fmt.Errorf("flag pattern requires at least one character")
		}
		if !isValidFlagChars(chars) {
			return "", "", fmt.Errorf("flag chars must be alphanumeric, got %q", chars)
		}
		return "-", chars, nil
	}

	return "", "", fmt.Errorf("invalid flag pattern syntax")
}

// isValidFlagChars checks that all characters are alphanumeric.
func isValidFlagChars(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// Match checks if the given string matches the pattern.
// For path patterns, use MatchWithContext instead.
func (p *Pattern) Match(s string) bool {
	return p.MatchWithContext(s, nil)
}

// MatchWithContext checks if the given string matches the pattern.
// Context is required for path patterns to expand variables and resolve paths.
func (p *Pattern) MatchWithContext(s string, ctx *MatchContext) bool {
	var matched bool
	switch p.Type {
	case PatternRegex:
		matched = p.Regex.MatchString(s)
	case PatternLiteral:
		matched = s == p.Raw
	case PatternPath:
		matched = p.matchPath(s, ctx)
	case PatternFlag:
		matched = p.matchFlag(s)
	case PatternFileRule:
		// File rule patterns are markers, not matchers.
		// They signal that file rules should be checked for this position.
		// Return true to indicate the position "matches" (will be checked by file rules).
		return true
	}
	if p.Negated {
		return !matched
	}
	return matched
}

// IsFileRulePattern returns true if this is a file rule marker pattern.
func (p *Pattern) IsFileRulePattern() bool {
	return p.Type == PatternFileRule
}

// matchPath handles path pattern matching with variable expansion and path resolution.
// If the pattern contains path variables ($PROJECT_ROOT, $HOME, $CLAUDE_PLUGIN_ROOT) and
// the input is path-like, does full variable expansion and path resolution.
// Otherwise, does raw doublestar glob matching.
func (p *Pattern) matchPath(s string, ctx *MatchContext) bool {
	// Only do full path resolution if:
	// 1. The pattern contains path variables that need expansion
	// 2. The input looks like a path
	// 3. We have context for resolution
	if pathutil.HasPathVars(p.PathPattern) && pathutil.IsPathLike(s) && ctx != nil && ctx.PathVars != nil {
		// Expand variables in the pattern
		expandedPattern := ctx.PathVars.ExpandPattern(p.PathPattern)

		// Resolve the argument to an absolute path
		resolved := pathutil.ResolvePath(s, ctx.PathVars.Cwd, ctx.PathVars.Home)

		// Use doublestar for gitignore-style matching
		matched, _ := doublestar.Match(expandedPattern, resolved)
		return matched
	}

	// For patterns without path variables or non-path strings, do raw doublestar matching
	matched, _ := doublestar.Match(p.PathPattern, s)
	return matched
}

// matchFlag checks if the string matches the flag pattern.
// For delimiter "-": matches strings like "-rf", "-fr", "-vrf" if chars="rf"
// For delimiter "--": matches strings like "--recursive" if chars="rec"
func (p *Pattern) matchFlag(s string) bool {
	// Must start with the delimiter
	if !strings.HasPrefix(s, p.FlagDelimiter) {
		return false
	}

	// For single-dash delimiter, make sure it's not a double-dash flag
	if p.FlagDelimiter == "-" && strings.HasPrefix(s, "--") {
		return false
	}

	// Get the part after the delimiter
	rest := s[len(p.FlagDelimiter):]
	if rest == "" {
		return false
	}

	// All required characters must be present in the rest
	for _, c := range p.FlagChars {
		if !strings.ContainsRune(rest, c) {
			return false
		}
	}

	return true
}

// MatchAny checks if any of the given strings match the pattern.
func (p *Pattern) MatchAny(ss []string) bool {
	return p.MatchAnyWithContext(ss, nil)
}

// MatchAnyWithContext checks if any of the given strings match the pattern.
func (p *Pattern) MatchAnyWithContext(ss []string, ctx *MatchContext) bool {
	for _, s := range ss {
		if p.MatchWithContext(s, ctx) {
			return true
		}
	}
	return false
}

// Matcher provides convenient pattern matching operations.
type Matcher struct {
	patterns []*Pattern
}

// NewMatcher creates a matcher from pattern strings.
func NewMatcher(patterns []string) (*Matcher, error) {
	m := &Matcher{patterns: make([]*Pattern, 0, len(patterns))}
	for _, ps := range patterns {
		p, err := ParsePattern(ps)
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, p)
	}
	return m, nil
}

// AnyMatch returns true if any pattern matches any of the given strings.
func (m *Matcher) AnyMatch(ss []string) bool {
	return m.AnyMatchWithContext(ss, nil)
}

// AnyMatchWithContext returns true if any pattern matches any of the given strings.
func (m *Matcher) AnyMatchWithContext(ss []string, ctx *MatchContext) bool {
	for _, p := range m.patterns {
		if p.MatchAnyWithContext(ss, ctx) {
			return true
		}
	}
	return false
}

// AllMatch returns true if all patterns match at least one string.
func (m *Matcher) AllMatch(ss []string) bool {
	return m.AllMatchWithContext(ss, nil)
}

// AllMatchWithContext returns true if all patterns match at least one string.
func (m *Matcher) AllMatchWithContext(ss []string, ctx *MatchContext) bool {
	for _, p := range m.patterns {
		if !p.MatchAnyWithContext(ss, ctx) {
			return false
		}
	}
	return true
}

// Contains checks if any string contains any of the substrings.
func Contains(ss []string, substrings []string) bool {
	for _, s := range ss {
		for _, sub := range substrings {
			if strings.Contains(s, sub) {
				return true
			}
		}
	}
	return false
}

// ContainsExact checks if any string exactly equals any of the targets.
func ContainsExact(ss []string, targets []string) bool {
	for _, s := range ss {
		for _, t := range targets {
			if s == t {
				return true
			}
		}
	}
	return false
}

// MatchPosition checks if the string at a specific position matches the pattern.
func MatchPosition(args []string, pos int, pattern string) bool {
	return MatchPositionWithContext(args, pos, pattern, nil)
}

// MatchPositionWithContext checks if the string at a specific position matches the pattern.
func MatchPositionWithContext(args []string, pos int, pattern string, ctx *MatchContext) bool {
	if pos < 0 || pos >= len(args) {
		return false
	}
	p, err := ParsePattern(pattern)
	if err != nil {
		return false
	}
	return p.MatchWithContext(args[pos], ctx)
}
