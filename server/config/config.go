package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads the configuration from the specified YAML file
func LoadConfig(configPath string) (*Config, error) {
	// Ensure the config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file does not exist: %s", configPath)
	}

	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Parse the YAML
	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	// Validate and set defaults
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("config validation error: %v", err)
	}

	return config, nil
}

func validateConfig(config *Config) error {
	if config.Storage.Path == "" {
		config.Storage.Path = "data/microc2.db"
	}
	if configuredPath := os.Getenv("MICROC2_STORAGE_PATH"); configuredPath != "" {
		config.Storage.Path = configuredPath
	}
	if strings.TrimSpace(config.Server.StaticDir) == "" {
		return fmt.Errorf("server static directory is required")
	}
	if strings.TrimSpace(config.Storage.Path) == "" {
		return fmt.Errorf("storage path is required")
	}

	// Ensure required directories exist or can be created
	dirs := []string{config.Server.UploadDir, config.Server.StaticDir}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	storagePath, err := canonicalPathThroughExisting(config.Storage.Path)
	if err != nil {
		return fmt.Errorf("resolve storage path: %v", err)
	}
	staticPath, err := canonicalPathThroughExisting(config.Server.StaticDir)
	if err != nil {
		return fmt.Errorf("resolve static directory: %v", err)
	}
	withinStatic, err := pathWithinDirectory(staticPath, storagePath)
	if err != nil {
		return fmt.Errorf("compare storage and static paths: %v", err)
	}
	if withinStatic {
		return fmt.Errorf("storage path must be outside the web-served static directory")
	}

	// Validate protocol selection
	switch config.Communication.Protocol {
	case "http", "socks5":
		// Valid protocols
	default:
		return fmt.Errorf("unsupported protocol: %s", config.Communication.Protocol)
	}

	// Set defaults if not specified
	if config.Server.Port == "" {
		config.Server.Port = "8080"
	}

	if config.Communication.HTTPPolling.HeartbeatInterval == 0 {
		config.Communication.HTTPPolling.HeartbeatInterval = 60
	}

	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}

	// The operator token can also come from the environment so it does not
	// have to be stored in the config file.
	if config.Security.OperatorToken == "" {
		config.Security.OperatorToken = os.Getenv("MICROC2_OPERATOR_TOKEN")
	}

	return nil
}

// canonicalPathThroughExisting resolves every symlink in the existing prefix
// while preserving any suffix that has not been created yet.
func canonicalPathThroughExisting(path string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}

	current := absolute
	suffix := make([]string, 0)
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathWithinDirectory(directory, candidate string) (bool, error) {
	return pathWithinDirectoryWithCaseFolding(
		directory,
		candidate,
		runtime.GOOS == "darwin" || runtime.GOOS == "windows",
	)
}

func pathWithinDirectoryWithCaseFolding(
	directory string,
	candidate string,
	caseFold bool,
) (bool, error) {
	within, err := lexicallyWithinDirectory(directory, candidate)
	if err != nil {
		return false, err
	}
	if within {
		return true, nil
	}
	if caseFold {
		within, err = lexicallyWithinDirectory(
			strings.ToLower(directory),
			strings.ToLower(candidate),
		)
		if err != nil {
			return false, err
		}
		if within {
			return true, nil
		}
	}

	// SameFile catches aliases that the filesystem considers identical even
	// when EvalSymlinks preserves a caller-provided case spelling.
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		return false, err
	}
	current := candidate
	for {
		info, statErr := os.Stat(current)
		switch {
		case statErr == nil && os.SameFile(directoryInfo, info):
			return true, nil
		case statErr != nil && !errors.Is(statErr, os.ErrNotExist):
			return false, statErr
		}

		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		current = parent
	}
}

func lexicallyWithinDirectory(directory, candidate string) (bool, error) {
	// filepath.Rel cannot compare paths on different Windows volumes. Distinct
	// volumes are definitively not contained, so treat that as a normal
	// negative result rather than failing configuration validation.
	if !strings.EqualFold(
		filepath.VolumeName(directory),
		filepath.VolumeName(candidate),
	) {
		return false, nil
	}
	relative, err := filepath.Rel(directory, candidate)
	if err != nil {
		return false, err
	}
	return relative == "." ||
		(relative != ".." &&
			!filepath.IsAbs(relative) &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}
