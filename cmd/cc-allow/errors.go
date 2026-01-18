package main

import "errors"

// Sentinel errors for cc-allow.
// Use errors.Is() to check for these error types.
var (
	// ErrInvalidPattern indicates a pattern string could not be compiled.
	// This typically means an invalid regex syntax in a "re:" prefixed pattern.
	ErrInvalidPattern = errors.New("invalid pattern")

	// ErrInvalidConfig indicates the configuration file has validation errors.
	// The wrapped error contains details about which rule/pattern failed.
	ErrInvalidConfig = errors.New("invalid configuration")
)
