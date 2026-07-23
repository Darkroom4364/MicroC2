package payload

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestGeneratePayloadCreatesBuildIDsDistinctFromListenerID(t *testing.T) {
	tempDir := withTempWorkingDir(t)
	agentDir := filepath.Join(tempDir, "agent")
	writeFakeBuildScript(t, agentDir)
	writeListenerConfig(t, ListenerConfig{
		ID:       "listener-one",
		Name:     "lab-listener",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     9001,
	})

	handler := NewPayloadHandler(filepath.Join(tempDir, "static", "payloads"), agentDir)
	config := PayloadConfig{
		ListenerID: "listener-one",
		AgentType:  "debugAgent",
		Format:     "linux_elf",
		Sleep:      5,
	}

	first, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate first payload: %v", err)
	}
	second, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate second payload: %v", err)
	}

	if first.ID == "listener-one" || second.ID == "listener-one" {
		t.Fatalf("payload ID must not reuse listener ID: first=%q second=%q", first.ID, second.ID)
	}
	if first.ID == second.ID {
		t.Fatalf("payload builds from one listener should get distinct IDs: %q", first.ID)
	}
	if filepath.Dir(first.Path) == filepath.Dir(second.Path) {
		t.Fatalf("payload builds should use distinct output dirs: %q", filepath.Dir(first.Path))
	}
	if first.PayloadID != first.ID || second.PayloadID != second.ID {
		t.Fatalf("payload result should expose payload ID consistently: first=%+v second=%+v", first, second)
	}
	if first.ListenerID != "listener-one" || second.ListenerID != "listener-one" {
		t.Fatalf("payload result should retain listener traceability: first=%+v second=%+v", first, second)
	}

	configPath := filepath.Join(filepath.Dir(first.Path), "config.json")
	configData := readJSONFile(t, configPath)
	if configData["payload_id"] == "listener-one" {
		t.Fatalf("generated config reused listener ID as payload ID: %#v", configData)
	}
	if configData["payload_id"] != first.ID {
		t.Fatalf("generated config payload_id = %#v, want %q", configData["payload_id"], first.ID)
	}
	if configData["listener_id"] != "listener-one" {
		t.Fatalf("generated config listener_id = %#v, want listener-one", configData["listener_id"])
	}
	if configData["agent_id"] != "" {
		t.Fatalf("generated config should leave runtime agent_id empty, got %#v", configData["agent_id"])
	}
}

func TestGeneratePayloadGeneratesSeedAndWritesProvenance(t *testing.T) {
	tempDir := withTempWorkingDir(t)
	agentDir := filepath.Join(tempDir, "agent")
	writeFakeBuildScript(t, agentDir)
	writeListenerConfig(t, ListenerConfig{
		ID:       "listener-one",
		Name:     "lab-listener",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     9001,
	})

	handler := NewPayloadHandler(filepath.Join(tempDir, "static", "payloads"), agentDir)
	config := PayloadConfig{
		ListenerID: "listener-one",
		AgentType:  "debugAgent",
		Format:     "linux_elf",
		Sleep:      5,
	}

	seedPattern := regexp.MustCompile(`^[0-9a-f]{16}$`)

	first, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate first payload: %v", err)
	}
	if !seedPattern.MatchString(first.MutationSeed) {
		t.Fatalf("generated mutation seed %q does not match 16 lowercase hex chars", first.MutationSeed)
	}

	// The build script must receive the seed through its environment.
	envSeed, err := os.ReadFile(filepath.Join(filepath.Dir(first.Path), "mutation_seed.env"))
	if err != nil {
		t.Fatalf("read recorded build env seed: %v", err)
	}
	if string(envSeed) != first.MutationSeed {
		t.Fatalf("build script received MUTATION_SEED=%q, want %q", envSeed, first.MutationSeed)
	}

	provenance := readJSONFile(t, filepath.Join(filepath.Dir(first.Path), "provenance.json"))
	if provenance["mutation_seed"] != first.MutationSeed {
		t.Fatalf("provenance mutation_seed = %#v, want %q", provenance["mutation_seed"], first.MutationSeed)
	}
	if provenance["seed_generated_by_server"] != true {
		t.Fatalf("provenance should mark the seed as server-generated: %#v", provenance["seed_generated_by_server"])
	}
	if provenance["git_revision"] == nil || provenance["git_revision"] == "" {
		t.Fatalf("provenance should record a git revision (or \"unknown\"): %#v", provenance["git_revision"])
	}
	if provenance["target"] != "x86_64-unknown-linux-gnu" {
		t.Fatalf("provenance target = %#v, want x86_64-unknown-linux-gnu", provenance["target"])
	}
	if provenance["config_sha256"] == nil || provenance["config_sha256"] == "" {
		t.Fatalf("provenance should record the resolved config hash: %#v", provenance["config_sha256"])
	}
	if provenance["built_at"] == nil || provenance["built_at"] == "" {
		t.Fatalf("provenance should record a build timestamp: %#v", provenance["built_at"])
	}
	flags, ok := provenance["mutation_flags"].([]interface{})
	if !ok || len(flags) == 0 {
		t.Fatalf("provenance should list mutation flags: %#v", provenance["mutation_flags"])
	}

	second, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate second payload: %v", err)
	}
	if second.MutationSeed == first.MutationSeed {
		t.Fatalf("distinct payloads should get distinct random seeds: %q", first.MutationSeed)
	}
}

func TestGeneratePayloadHonoursSuppliedMutationSeed(t *testing.T) {
	tempDir := withTempWorkingDir(t)
	agentDir := filepath.Join(tempDir, "agent")
	writeFakeBuildScript(t, agentDir)
	writeListenerConfig(t, ListenerConfig{
		ID:       "listener-one",
		Name:     "lab-listener",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     9001,
	})

	handler := NewPayloadHandler(filepath.Join(tempDir, "static", "payloads"), agentDir)
	config := PayloadConfig{
		ListenerID:   "listener-one",
		AgentType:    "debugAgent",
		Format:       "linux_elf",
		Sleep:        5,
		MutationSeed: "0123456789abcdef",
	}

	result, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate payload with supplied seed: %v", err)
	}
	if result.MutationSeed != "0123456789abcdef" {
		t.Fatalf("supplied mutation seed should be used verbatim, got %q", result.MutationSeed)
	}

	provenance := readJSONFile(t, filepath.Join(filepath.Dir(result.Path), "provenance.json"))
	if provenance["seed_generated_by_server"] != false {
		t.Fatalf("provenance should mark the seed as caller-supplied: %#v", provenance["seed_generated_by_server"])
	}

	config.MutationSeed = "0xABCD"
	shortSeed, err := handler.GeneratePayload(config)
	if err != nil {
		t.Fatalf("generate payload with short prefixed seed: %v", err)
	}
	if shortSeed.MutationSeed != "000000000000abcd" {
		t.Fatalf("short seed should be normalized to 16 hex chars, got %q", shortSeed.MutationSeed)
	}

	config.MutationSeed = "not-hex"
	if _, err := handler.GeneratePayload(config); err == nil {
		t.Fatalf("invalid mutation seed should be rejected")
	}
}

func withTempWorkingDir(t *testing.T) string {
	t.Helper()

	tempDir := t.TempDir()
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("switch to temp cwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldCwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	return tempDir
}

func writeListenerConfig(t *testing.T, config ListenerConfig) {
	t.Helper()

	listenerDir := filepath.Join("static", "listeners", config.Name)
	if err := os.MkdirAll(listenerDir, 0755); err != nil {
		t.Fatalf("create listener dir: %v", err)
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal listener config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(listenerDir, "config.json"), configBytes, 0644); err != nil {
		t.Fatalf("write listener config: %v", err)
	}
}

func writeFakeBuildScript(t *testing.T, agentDir string) {
	t.Helper()

	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("create fake agent dir: %v", err)
	}
	script := `#!/bin/bash
set -e
output=""
format="linux_elf"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --format)
      format="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
case "$format" in
  windows_exe)
    artifact="agent.exe"
    ;;
  windows_dll)
    artifact="agent.dll"
    ;;
  windows_service)
    artifact="agent_service.exe"
    ;;
  windows_shellcode)
    artifact="shellcode.bin"
    ;;
  *)
    artifact="agent"
    ;;
esac
mkdir -p "$output"
printf 'fake agent' > "$output/$artifact"
printf '%s' "${MUTATION_SEED:-}" > "$output/mutation_seed.env"
`
	if err := os.WriteFile(filepath.Join(agentDir, "build.sh"), []byte(script), 0644); err != nil {
		t.Fatalf("write fake build script: %v", err)
	}
}

func readJSONFile(t *testing.T, path string) map[string]interface{} {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json file %s: %v", path, err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		t.Fatalf("decode json file %s: %v", path, err)
	}
	return data
}
