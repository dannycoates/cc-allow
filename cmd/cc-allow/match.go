package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// PatternType indicates what kind of pattern this is.
type PatternType int

const (
	PatternGlob PatternType = iota
	PatternRegex
	PatternLiteral
)

// Pattern represents a parsed pattern with its type.
type Pattern struct {
	Type    PatternType
	Raw     string
	Regex   *regexp.Regexp // compiled regex (for regex patterns)
}

// ParsePattern parses a pattern string and determines its type.
// Supported prefixes:
//   - "re:" for regex patterns
//   - "glob:" for explicit glob patterns
//   - No prefix defaults to glob
func ParsePattern(s string) (*Pattern, error) {
	p := &Pattern{Raw: s}

	switch {
	case strings.HasPrefix(s, "re:"):
		p.Type = PatternRegex
		re, err := regexp.Compile(strings.TrimPrefix(s, "re:"))
		if err != nil {
			return nil, err
		}
		p.Regex = re
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
func (p *Pattern) Match(s string) bool {
	switch p.Type {
	case PatternRegex:
		return p.Regex.MatchString(s)
	case PatternGlob:
		matched, _ := filepath.Match(p.Raw, s)
		return matched
	case PatternLiteral:
		return s == p.Raw
	}
	return false
}

// MatchAny checks if any of the given strings match the pattern.
func (p *Pattern) MatchAny(ss []string) bool {
	for _, s := range ss {
		if p.Match(s) {
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
	for _, p := range m.patterns {
		if p.MatchAny(ss) {
			return true
		}
	}
	return false
}

// AllMatch returns true if all patterns match at least one string.
func (m *Matcher) AllMatch(ss []string) bool {
	for _, p := range m.patterns {
		if !p.MatchAny(ss) {
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
	if pos < 0 || pos >= len(args) {
		return false
	}
	p, err := ParsePattern(pattern)
	if err != nil {
		return false
	}
	return p.Match(args[pos])
}
