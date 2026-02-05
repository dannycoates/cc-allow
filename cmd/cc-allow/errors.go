package main

import (
	"errors"
	"fmt"
	"strings"
)

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

// ConfigError wraps a config-related error with context about which config file
// and what location within the config caused the error.
type ConfigError struct {
	Path     string // config file path (may be empty if unknown)
	Location string // location within the config (e.g., "bash.allow.commands[0]")
	Value    string // the invalid value (if applicable)
	Err      error  // underlying error
}

func (e *ConfigError) Error() string {
	var sb strings.Builder

	if e.Path != "" {
		sb.WriteString(e.Path)
		sb.WriteString(": ")
	}

	if e.Err != nil {
		sb.WriteString(e.Err.Error())
	}

	if e.Location != "" {
		sb.WriteString("\n  at: ")
		sb.WriteString(e.Location)
	}

	if e.Value != "" {
		sb.WriteString("\n  value: ")
		sb.WriteString(e.Value)
	}

	return sb.String()
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// NewConfigError creates a ConfigError with the given path and underlying error.
func NewConfigError(path string, err error) *ConfigError {
	return &ConfigError{Path: path, Err: err}
}

// WithLocation adds location context to a ConfigError.
func (e *ConfigError) WithLocation(location string) *ConfigError {
	e.Location = location
	return e
}

// WithValue adds the invalid value to a ConfigError.
func (e *ConfigError) WithValue(value string) *ConfigError {
	e.Value = value
	return e
}

// WrapConfigError wraps an error with config context. If the error is already
// a ConfigError, it updates the path if not already set. Otherwise, it creates
// a new ConfigError.
func WrapConfigError(path string, err error) error {
	if err == nil {
		return nil
	}

	var cfgErr *ConfigError
	if errors.As(err, &cfgErr) {
		// Already a ConfigError - update path if not set
		if cfgErr.Path == "" {
			cfgErr.Path = path
		}
		return cfgErr
	}

	return NewConfigError(path, err)
}

// ConfigValidationError represents a validation error with location and value context.
// This is used during config validation to provide detailed error information.
// It wraps ErrInvalidConfig so errors.Is(err, ErrInvalidConfig) returns true.
// It can also wrap an underlying cause error (e.g., ErrInvalidPattern).
type ConfigValidationError struct {
	Location string // path within config (e.g., "bash.allow.commands[0]")
	Value    string // the invalid value
	Message  string // human-readable error description
	Cause    error  // underlying error (e.g., from pattern parsing)
}

func (e *ConfigValidationError) Error() string {
	var sb strings.Builder
	sb.WriteString("invalid configuration: ")
	sb.WriteString(e.Location)
	sb.WriteString(": ")
	if e.Cause != nil {
		// When there's a cause, use it directly (it already has the message)
		sb.WriteString(e.Cause.Error())
	} else {
		sb.WriteString(e.Message)
	}
	if e.Value != "" {
		sb.WriteString(" (value: ")
		sb.WriteString(fmt.Sprintf("%q", e.Value))
		sb.WriteString(")")
	}
	return sb.String()
}

// Unwrap returns the error chain: ConfigValidationError wraps both ErrInvalidConfig
// and any underlying cause. This uses the []error form for multi-error unwrapping.
func (e *ConfigValidationError) Unwrap() []error {
	if e.Cause != nil {
		return []error{ErrInvalidConfig, e.Cause}
	}
	return []error{ErrInvalidConfig}
}

// NewValidationError creates a validation error for the given location and message.
func NewValidationError(location, message string) *ConfigValidationError {
	return &ConfigValidationError{Location: location, Message: message}
}

// WithValue adds the problematic value to the validation error.
func (e *ConfigValidationError) WithValue(value string) *ConfigValidationError {
	e.Value = value
	return e
}

// WithCause adds an underlying cause error to the validation error.
func (e *ConfigValidationError) WithCause(cause error) *ConfigValidationError {
	e.Cause = cause
	return e
}
