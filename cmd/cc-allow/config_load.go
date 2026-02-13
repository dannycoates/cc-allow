package main

import (
	"errors"
	"fmt"
	"os"
)

// loadConfig reads and parses a TOML configuration file without applying defaults.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigRead, path, err)
	}
	cfg, err := parseConfig(string(data))
	if err != nil {
		return nil, WrapConfigError(path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// parseConfig parses a TOML configuration string without applying defaults.
func parseConfig(data string) (*Config, error) {
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadConfigWithDefaults reads and parses a TOML configuration file with defaults applied.
func LoadConfigWithDefaults(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigRead, path, err)
	}
	cfg, err := ParseConfigWithDefaults(string(data))
	if err != nil {
		return nil, WrapConfigError(path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// ParseConfigWithDefaults parses a TOML configuration string with defaults applied.
func ParseConfigWithDefaults(data string) (*Config, error) {
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
	}
	if cfg.Path == "" {
		cfg.Path = "(inline)"
	}
	applyDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadConfigChain loads configs from standard locations plus an optional explicit path.
func LoadConfigChain(explicitPath string, sessionID string) (*ConfigChain, error) {
	chain := &ConfigChain{}
	chain.SessionID = sessionID

	// Cache project root once for all config discovery
	chain.ProjectRoot = findProjectRoot()

	// 1. Load global config
	if globalPath := findGlobalConfig(); globalPath != "" {
		cfg, err := loadConfig(globalPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 2. Load project configs
	discovery := findProjectConfigsWithRoot(chain.ProjectRoot)
	if discovery.ProjectConfig != "" {
		cfg, err := loadConfig(discovery.ProjectConfig)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}
	if discovery.LocalConfig != "" {
		cfg, err := loadConfig(discovery.LocalConfig)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// Propagate migration hints for legacy .claude/ paths
	chain.MigrationHints = discovery.LegacyPaths

	// 3. Load session config
	if sessionPath := findSessionConfig(sessionID, chain.ProjectRoot); sessionPath != "" {
		cfg, err := loadConfig(sessionPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 4. Load explicit config
	if explicitPath != "" {
		cfg, err := loadConfig(explicitPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// If no configs found, use default
	if len(chain.Configs) == 0 {
		chain.Configs = append(chain.Configs, DefaultConfig())
	}

	// Merge all configs
	chain.Merged = MergeConfigs(chain.Configs)

	return chain, nil
}
