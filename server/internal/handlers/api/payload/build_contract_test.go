package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValidateAndResolvePayloadConfigSupportedProfiles(t *testing.T) {
	testCases := []struct {
		name       string
		agentType  string
		format     string
		wantTarget string
		wantOS     string
		wantFile   string
		wantBuild  string
	}{
		{
			name:       "Linux release ELF",
			agentType:  "agent",
			format:     "linux_elf",
			wantTarget: "x86_64-unknown-linux-gnu",
			wantOS:     "linux",
			wantFile:   "agent",
			wantBuild:  "release",
		},
		{
			name:       "Windows debug executable",
			agentType:  "debugAgent",
			format:     "windows_exe",
			wantTarget: "x86_64-pc-windows-gnu",
			wantOS:     "windows",
			wantFile:   "agent.exe",
			wantBuild:  "debug",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := validPayloadBuildConfig()
			config.AgentType = testCase.agentType
			config.Format = testCase.format
			plan, err := validateAndResolvePayloadConfig(config)
			if err != nil {
				t.Fatalf("resolve supported profile: %v", err)
			}
			if plan.profile.targetTriple != testCase.wantTarget ||
				plan.profile.targetOS != testCase.wantOS ||
				plan.profile.filename != testCase.wantFile ||
				plan.buildType != testCase.wantBuild {
				t.Fatalf("resolved profile = %#v, want target=%q os=%q file=%q build=%q",
					plan,
					testCase.wantTarget,
					testCase.wantOS,
					testCase.wantFile,
					testCase.wantBuild,
				)
			}
			if plan.config.Socks5Host != "127.0.0.1" ||
				plan.config.Socks5Port != 9050 ||
				plan.config.SleepTechnique != "standard" {
				t.Fatalf("resolved defaults are incomplete: %#v", plan.config)
			}
		})
	}
}

func TestValidateAndResolvePayloadConfigRejectsUnsupportedOptions(
	t *testing.T,
) {
	testCases := []struct {
		name   string
		field  string
		mutate func(*PayloadConfig)
	}{
		{
			name:  "unknown agent type",
			field: "agentType",
			mutate: func(config *PayloadConfig) {
				config.AgentType = "stealth"
			},
		},
		{
			name:  "x86 architecture",
			field: "architecture/format",
			mutate: func(config *PayloadConfig) {
				config.Architecture = "x86"
			},
		},
		{
			name:  "ARM64 architecture",
			field: "architecture/format",
			mutate: func(config *PayloadConfig) {
				config.Architecture = "arm64"
			},
		},
		{
			name:  "DLL format",
			field: "architecture/format",
			mutate: func(config *PayloadConfig) {
				config.Format = "windows_dll"
			},
		},
		{
			name:  "service format",
			field: "architecture/format",
			mutate: func(config *PayloadConfig) {
				config.Format = "windows_service"
			},
		},
		{
			name:  "shellcode format",
			field: "architecture/format",
			mutate: func(config *PayloadConfig) {
				config.Format = "windows_shellcode"
			},
		},
		{
			name:  "indirect syscalls",
			field: "indirectSyscall",
			mutate: func(config *PayloadConfig) {
				config.IndirectSyscall = true
			},
		},
		{
			name:  "custom sleep",
			field: "sleepTechnique",
			mutate: func(config *PayloadConfig) {
				config.SleepTechnique = "modified"
			},
		},
		{
			name:  "DLL sideloading",
			field: "dllSideloading",
			mutate: func(config *PayloadConfig) {
				config.DllSideloading = true
			},
		},
		{
			name:  "ignored exit threshold",
			field: "OPSEC exit thresholds",
			mutate: func(config *PayloadConfig) {
				config.BaseThresholdExitFullOpsec = 30
			},
		},
		{
			name:  "zero sleep",
			field: "sleep",
			mutate: func(config *PayloadConfig) {
				config.Sleep = 0
			},
		},
		{
			name:  "reduced activity threshold reaches full OPSEC threshold",
			field: "base_threshold_enter_reduced_activity",
			mutate: func(config *PayloadConfig) {
				config.BaseThresholdEnterReducedActivity =
					config.BaseThresholdEnterFullOpsec
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := validPayloadBuildConfig()
			testCase.mutate(&config)
			_, err := validateAndResolvePayloadConfig(config)
			var validationError *payloadConfigValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("validation error = %v, want typed validation error", err)
			}
			if validationError.field != testCase.field {
				t.Fatalf(
					"validation field = %q, want %q",
					validationError.field,
					testCase.field,
				)
			}
		})
	}
}

func TestValidateAndResolvePayloadConfigRejectsValuesOutsideAgentTypes(
	t *testing.T,
) {
	testCases := []struct {
		name   string
		field  string
		mutate func(*PayloadConfig)
	}{
		{
			name:  "increase factor exceeds f32",
			field: "c2_failure_threshold_increase_factor",
			mutate: func(config *PayloadConfig) {
				config.C2FailureThresholdIncreaseFactor = math.MaxFloat64
			},
		},
		{
			name:  "max multiplier exceeds f32",
			field: "c2_dynamic_threshold_max_multiplier",
			mutate: func(config *PayloadConfig) {
				config.C2DynamicThresholdMaxMultiplier = math.MaxFloat64
			},
		},
		{
			name:  "positive factor underflows f32",
			field: "c2_failure_threshold_decrease_factor",
			mutate: func(config *PayloadConfig) {
				config.C2FailureThresholdDecreaseFactor = math.SmallestNonzeroFloat64
			},
		},
	}
	if strconv.IntSize == 64 {
		testCases = append(testCases, struct {
			name   string
			field  string
			mutate func(*PayloadConfig)
		}{
			name:  "failure counter exceeds u32",
			field: "base_max_consecutive_c2_failures",
			mutate: func(config *PayloadConfig) {
				config.BaseMaxConsecutiveC2Failures = int(maxRustU32 + 1)
			},
		})
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := validPayloadBuildConfig()
			testCase.mutate(&config)
			_, err := validateAndResolvePayloadConfig(config)
			var validationError *payloadConfigValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("validation error = %v, want typed validation error", err)
			}
			if validationError.field != testCase.field {
				t.Fatalf(
					"validation field = %q, want %q",
					validationError.field,
					testCase.field,
				)
			}
		})
	}
}

func TestValidateAndResolvePayloadConfigNormalizesLosslesslyForRustF32(
	t *testing.T,
) {
	config := validPayloadBuildConfig()
	config.BaseThresholdEnterFullOpsec = 63.125
	config.BaseThresholdEnterReducedActivity = 17.75
	config.C2FailureThresholdIncreaseFactor = 1.234
	config.C2FailureThresholdDecreaseFactor = 0.876
	config.C2DynamicThresholdMaxMultiplier = 2.345

	plan, err := validateAndResolvePayloadConfig(config)
	if err != nil {
		t.Fatalf("validate payload config: %v", err)
	}
	testCases := []struct {
		name  string
		got   float64
		input float64
	}{
		{"full score", plan.config.BaseThresholdEnterFullOpsec, 63.125},
		{"reduced score", plan.config.BaseThresholdEnterReducedActivity, 17.75},
		{"increase", plan.config.C2FailureThresholdIncreaseFactor, 1.234},
		{"decrease", plan.config.C2FailureThresholdDecreaseFactor, 0.876},
		{"maximum", plan.config.C2DynamicThresholdMaxMultiplier, 2.345},
	}
	for _, testCase := range testCases {
		want := float64(float32(testCase.input))
		if testCase.got != want {
			t.Fatalf("%s normalized value = %v, want %v", testCase.name, testCase.got, want)
		}
		formatted := formatRustF32(testCase.got)
		parsed, err := strconv.ParseFloat(formatted, 32)
		if err != nil {
			t.Fatalf("parse formatted %s value %q: %v", testCase.name, formatted, err)
		}
		if float32(parsed) != float32(testCase.input) {
			t.Fatalf(
				"%s formatted value %q does not round-trip to %v",
				testCase.name,
				formatted,
				float32(testCase.input),
			)
		}
	}
	if got := formatRustF32(plan.config.C2FailureThresholdIncreaseFactor); got != "1.234" {
		t.Fatalf("increase factor was silently rounded: got %q, want 1.234", got)
	}
}

func TestPayloadGenerateRejectsUnsupportedProfileBeforeBuild(t *testing.T) {
	handler := NewPayloadHandlerForIsolatedLab(t.TempDir(), t.TempDir())
	buildCalls := 0
	handler.runBuild = func(*exec.Cmd) ([]byte, error) {
		buildCalls++
		return nil, nil
	}
	config := validPayloadBuildConfig()
	config.Format = "windows_shellcode"
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal payload config: %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/payload/generate",
		bytes.NewReader(body),
	)
	response := httptest.NewRecorder()
	handler.HandleGeneratePayload(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"unsupported profile status = %d, want 400: %s",
			response.Code,
			response.Body.String(),
		)
	}
	if !strings.Contains(response.Body.String(), "architecture/format") {
		t.Fatalf("validation response is not actionable: %q", response.Body.String())
	}
	if buildCalls != 0 {
		t.Fatalf("invalid profile invoked build %d times", buildCalls)
	}
}

func TestManifestUsesExactCredentialFreeConfigExportedByBuild(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	handler, err := newPayloadHandler(
		filepath.Join(tempDir, "payloads"),
		agentDir,
		testListenerLookup(),
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("create payload handler: %v", err)
	}
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		values := make(map[string]string)
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found {
				values[name] = value
			}
		}
		outputDir := ""
		for index := 0; index+1 < len(command.Args); index++ {
			if command.Args[index] == "--output" {
				outputDir = command.Args[index+1]
				break
			}
		}
		if outputDir == "" {
			return nil, errors.New("build command omitted --output")
		}
		if err := os.WriteFile(
			filepath.Join(outputDir, "agent"),
			[]byte("fake agent"),
			0o600,
		); err != nil {
			return nil, err
		}
		effectivePath := values["EFFECTIVE_CONFIG_PATH"]
		if !filepath.IsAbs(effectivePath) {
			effectivePath = filepath.Join(command.Dir, effectivePath)
		}
		increaseFactor, err := strconv.ParseFloat(
			values["C2_THRESH_INC_FACTOR"],
			32,
		)
		if err != nil {
			return nil, fmt.Errorf("parse C2 threshold increase factor: %w", err)
		}
		effective := map[string]interface{}{
			"server_url":                           values["SERVER_URL"],
			"payload_id":                           values["PAYLOAD_ID"],
			"agent_id":                             "",
			"listener_id":                          values["LISTENER_ID"],
			"mutation_seed":                        values["MUTATION_SEED"],
			"protocol":                             values["PROTOCOL"],
			"socks5_enabled":                       true,
			"user_agent":                           "seed-selected-user-agent",
			"allow_invalid_certs":                  false,
			"allow_insecure_isolated_lab":          true,
			"c2_failure_threshold_increase_factor": float32(increaseFactor),
		}
		data, err := json.Marshal(effective)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(effectivePath, data, 0o600); err != nil {
			return nil, err
		}
		return []byte("hook build complete"), nil
	}

	config := testPayloadConfig()
	config.Socks5Enabled = true
	config.C2FailureThresholdIncreaseFactor = 1.234
	result, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate payload: %v", err)
	}
	if result.Manifest == nil {
		t.Fatal("generation result omitted its build manifest")
	}
	var effective map[string]interface{}
	if err := json.Unmarshal(result.Manifest.EffectiveConfig, &effective); err != nil {
		t.Fatalf("decode effective config: %v", err)
	}
	if effective["protocol"] != "http" ||
		effective["socks5_enabled"] != true ||
		effective["user_agent"] != "seed-selected-user-agent" ||
		effective["c2_failure_threshold_increase_factor"] != 1.234 {
		t.Fatalf("manifest did not preserve exact build export: %#v", effective)
	}
	publishedConfig, err := os.ReadFile(
		filepath.Join(filepath.Dir(result.Path), "config.json"),
	)
	if err != nil {
		t.Fatalf("read published effective config: %v", err)
	}
	if !bytes.Equal(publishedConfig, result.Manifest.EffectiveConfig) {
		t.Fatalf(
			"published config differs from manifest: %s != %s",
			publishedConfig,
			result.Manifest.EffectiveConfig,
		)
	}
	sidecar, err := os.ReadFile(
		filepath.Join(filepath.Dir(result.Path), "provenance.json"),
	)
	if err != nil {
		t.Fatalf("read manifest sidecar: %v", err)
	}
	if _, err := decodePayloadBuildManifest(sidecar); err != nil {
		t.Fatalf("manifest sidecar failed its decoder: %v", err)
	}
}

func TestReadEffectiveBuildConfigRejectsCredentialMaterial(t *testing.T) {
	const (
		payloadID    = "payload-test"
		listenerID   = "listener-test"
		mutationSeed = "0123456789abcdef"
		relativePath = "effective-config.json"
	)
	// Base64url for a synthetic 32-byte all-zero credential.
	credential := strings.Repeat("A", 43)
	const credentialError = "effective build config contains enrollment credential material"

	testCases := []struct {
		name    string
		config  map[string]interface{}
		wantErr string
	}{
		{
			name: "credential-free identity-matching control",
			config: map[string]interface{}{
				"payload_id":    payloadID,
				"listener_id":   listenerID,
				"mutation_seed": mutationSeed,
				"protocol":      "https",
			},
		},
		{
			name: "enrollment credential field",
			config: map[string]interface{}{
				"payload_id":            payloadID,
				"listener_id":           listenerID,
				"mutation_seed":         mutationSeed,
				"protocol":              "https",
				"enrollment_credential": "not-the-test-credential",
			},
			wantErr: credentialError,
		},
		{
			name: "credential bytes elsewhere",
			config: map[string]interface{}{
				"payload_id":    payloadID,
				"listener_id":   listenerID,
				"mutation_seed": mutationSeed,
				"protocol":      "https",
				"note":          credential,
			},
			wantErr: credentialError,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			buildRoot := t.TempDir()
			configJSON, err := json.Marshal(testCase.config)
			if err != nil {
				t.Fatalf("marshal effective config: %v", err)
			}
			if err := os.WriteFile(
				filepath.Join(buildRoot, relativePath),
				configJSON,
				0o600,
			); err != nil {
				t.Fatalf("write effective config: %v", err)
			}

			_, err = readEffectiveBuildConfig(
				buildRoot,
				relativePath,
				payloadID,
				listenerID,
				mutationSeed,
				credential,
			)
			if testCase.wantErr == "" {
				if err != nil {
					t.Fatalf("read credential-free effective config: %v", err)
				}
				return
			}
			if err == nil || err.Error() != testCase.wantErr {
				t.Fatalf(
					"read effective config error = %v, want %q",
					err,
					testCase.wantErr,
				)
			}
		})
	}
}

func validPayloadBuildConfig() PayloadConfig {
	config := defaultPayloadRequestConfig()
	config.ListenerID = "listener-one"
	config.AgentType = "debugAgent"
	config.Architecture = "x64"
	config.Format = "linux_elf"
	config.Sleep = 5
	return config
}
