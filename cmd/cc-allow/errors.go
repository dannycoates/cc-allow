package main

import "errors"

// Sentinel errors for cc-allow.
// Use errors.Is() to check for these error types.
var (
	// ErrConfigNotFound indicates a config file does not exist at the expected path.
	// This is distinct from ErrConfigRead (I/O error) and ErrInvalidConfig (parse/validation error).
	ErrConfigNotFound = errors.New("config file not found")

	// ErrConfigRead indicates an I/O error when reading a config file.
	// The file exists but could not be read (permissions, etc.).
	ErrConfigRead = errors.New("failed to read config file")

	// ErrConfigParse indicates a TOML syntax error in the config file.
	// The file was read but could not be parsed as valid TOML.
	ErrConfigParse = errors.New("config parse error")

	// ErrInvalidConfig indicates the configuration has validation errors.
	// The TOML parsed successfully but contains invalid values (bad patterns, invalid keys, etc.).
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrInvalidPattern indicates a pattern string could not be compiled.
	// This typically means an invalid regex syntax in a "re:" prefixed pattern.
	ErrInvalidPattern = errors.New("invalid pattern")
)
