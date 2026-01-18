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
	PatternGlob PatternType = iota
	PatternRegex
	PatternLiteral
	PatternPath // path pattern with variable expansion and symlink resolution
)

// MatchContext provides context needed for path pattern matching.
type MatchContext struct {
	PathVars *pathutil.PathVars
}

// Pattern represents a parsed pattern with its type.
type Pattern struct {
	Type        PatternType
	Raw         string
	Regex       *regexp.Regexp // compiled regex (for regex patterns)
	PathPattern string         // unexpanded path pattern (for path patterns)
}

// ParsePattern parses a pattern string and determines its type.
// Supported prefixes:
//   - "re:" for regex patterns
//   - "glob:" for explicit glob patterns
//   - "path:" for path patterns with variable expansion ($PROJECT_ROOT, $HOME)
//   - No prefix defaults to glob
func ParsePattern(s string) (*Pattern, error) {
	p := &Pattern{Raw: s}

	switch {
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
	case strings.HasPrefix(s, "glob:"):
		p.Type = PatternGlob
		p.Raw = strings.TrimPrefix(s, "glob:")
	default:
		// Default to glob if the pattern contains glob metacharacters
		if containsGlobMeta(s) {
			p.Type = PatternGlob
		} else {
			p.Type = PatternLiteral
		}
	}
	return p, nil
}

// containsGlobMeta checks if a string contains glob metacharacters.
func containsGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// Match checks if the given string matches the pattern.
// For path patterns, use MatchWithContext instead.
func (p *Pattern) Match(s string) bool {
	return p.MatchWithContext(s, nil)
}

// MatchWithContext checks if the given string matches the pattern.
// Context is required for path patterns to expand variables and resolve paths.
func (p *Pattern) MatchWithContext(s string, ctx *MatchContext) bool {
	switch p.Type {
	case PatternRegex:
		return p.Regex.MatchString(s)
	case PatternGlob:
		matched, _ := doublestar.Match(p.Raw, s)
		return matched
	case PatternLiteral:
		return s == p.Raw
	case PatternPath:
		return p.matchPath(s, ctx)
	}
	return false
}

// matchPath handles path pattern matching with variable expansion and path resolution.
func (p *Pattern) matchPath(s string, ctx *MatchContext) bool {
	if ctx == nil || ctx.PathVars == nil {
		return false
	}

	// Only match path-like arguments
	if !pathutil.IsPathLike(s) {
		return false
	}

	// Expand variables in the pattern
	expandedPattern := ctx.PathVars.ExpandPattern(p.PathPattern)

	// Resolve the argument to an absolute path
	resolved := pathutil.ResolvePath(s, ctx.PathVars.Cwd, ctx.PathVars.Home)

	// Use doublestar for gitignore-style matching
	matched, _ := doublestar.Match(expandedPattern, resolved)
	return matched
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
