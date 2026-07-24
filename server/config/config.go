package config

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"microc2/server/internal/common"

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

	// Parse exactly one YAML document and reject unknown fields. Silently
	// accepting misspelled or retired settings would make the file look
	// authoritative while the runtime ignores it.
	config := &Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}
	var trailingDocument any
	if err := decoder.Decode(&trailingDocument); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("error parsing config file: %w", err)
		}
		return nil, errors.New("error parsing config file: multiple YAML documents are not supported")
	}

	applyDefaults(config)
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("config validation error: %w", err)
	}
	if err := prepareDirectories(config); err != nil {
		return nil, fmt.Errorf("config preparation error: %w", err)
	}

	return config, nil
}

func applyDefaults(config *Config) {
	if config.Storage.Path == "" {
		config.Storage.Path = "data/microc2.db"
	}
	if configuredPath := os.Getenv("MICROC2_STORAGE_PATH"); configuredPath != "" {
		config.Storage.Path = configuredPath
	}
	if config.Server.Port == "" {
		config.Server.Port = "8443"
	}
	if config.Logging.File == "" {
		config.Logging.File = "server.log"
	}
	if config.Security.OperatorToken == "" {
		config.Security.OperatorToken = os.Getenv("MICROC2_OPERATOR_TOKEN")
	}
}

func validateConfig(config *Config) error {
	if config == nil {
		return errors.New("configuration is required")
	}
	if strings.TrimSpace(config.Server.StaticDir) == "" {
		return fmt.Errorf("server static directory is required")
	}
	if strings.TrimSpace(config.Server.UploadDir) == "" {
		return fmt.Errorf("server upload directory is required")
	}
	if strings.TrimSpace(config.Storage.Path) == "" {
		return fmt.Errorf("storage path is required")
	}
	if strings.TrimSpace(config.Logging.File) == "" {
		return fmt.Errorf("logging file is required")
	}
	if strings.TrimSpace(config.Server.TLS.CertFile) == "" ||
		strings.TrimSpace(config.Server.TLS.KeyFile) == "" {
		return fmt.Errorf("server TLS certificate and key files are required")
	}

	operatorPort, err := validatePort("server.port", config.Server.Port)
	if err != nil {
		return err
	}
	if config.Server.Redirect.Enabled {
		redirectPort, err := validatePort(
			"server.redirect.httpPort",
			config.Server.Redirect.HTTPPort,
		)
		if err != nil {
			return err
		}
		if redirectPort == operatorPort {
			return fmt.Errorf(
				"server.redirect.httpPort must differ from server.port",
			)
		}
	} else if strings.TrimSpace(config.Server.Redirect.HTTPPort) != "" {
		return fmt.Errorf(
			"server.redirect.httpPort must be empty when redirects are disabled",
		)
	}
	if err := validateOrigins(
		"security.corsOrigins",
		config.Security.CORSOrigins,
	); err != nil {
		return err
	}
	if err := validateOrigins(
		"security.operatorAllowedOrigins",
		config.Security.OperatorAllowedOrigins,
	); err != nil {
		return err
	}

	if _, err := tls.LoadX509KeyPair(
		config.Server.TLS.CertFile,
		config.Server.TLS.KeyFile,
	); err != nil {
		return fmt.Errorf("load server TLS certificate and key: %w", err)
	}

	staticPath, err := canonicalPathThroughExisting(config.Server.StaticDir)
	if err != nil {
		return fmt.Errorf("resolve static directory: %v", err)
	}
	privatePaths := []struct {
		name  string
		value string
	}{
		{name: "storage path", value: config.Storage.Path},
		{name: "server upload directory", value: config.Server.UploadDir},
		{name: "logging file", value: config.Logging.File},
		{name: "server TLS certificate", value: config.Server.TLS.CertFile},
		{name: "server TLS private key", value: config.Server.TLS.KeyFile},
	}
	for _, privatePath := range privatePaths {
		candidate, err := canonicalPathThroughExisting(privatePath.value)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", privatePath.name, err)
		}
		withinStatic, err := pathWithinDirectory(staticPath, candidate)
		if err != nil {
			return fmt.Errorf(
				"compare %s and static paths: %w",
				privatePath.name,
				err,
			)
		}
		if withinStatic {
			return fmt.Errorf(
				"%s must be outside the web-served static directory",
				privatePath.name,
			)
		}
	}

	return nil
}

func validatePort(field, value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return 0, fmt.Errorf("%s must not contain surrounding whitespace", field)
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be an integer between 1 and 65535", field)
	}
	return port, nil
}

func validateOrigins(field string, values []string) error {
	for index, value := range values {
		if value == "*" {
			if len(values) != 1 {
				return fmt.Errorf(
					"%s[%d] wildcard must be the only configured origin",
					field,
					index,
				)
			}
			continue
		}
		if err := common.ValidateHTTPOrigin(value); err != nil {
			return fmt.Errorf("%s[%d] %w", field, index, err)
		}
	}
	return nil
}

func prepareDirectories(config *Config) error {
	for _, dir := range []string{
		config.Server.UploadDir,
		config.Server.StaticDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
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
	// filepath.Rel cannot compare paths on different Windows volumes. Distinct
	// volumes are definitively not contained, so avoid both Rel and filesystem
	// identity checks in that case.
	if !strings.EqualFold(
		filepath.VolumeName(directory),
		filepath.VolumeName(candidate),
	) {
		return false, nil
	}

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
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
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
	relative, err := filepath.Rel(directory, candidate)
	if err != nil {
		return false, err
	}
	return relative == "." ||
		(relative != ".." &&
			!filepath.IsAbs(relative) &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator))), nil
}
