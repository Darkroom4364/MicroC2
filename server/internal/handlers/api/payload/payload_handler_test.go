package payload

import (
	"encoding/json"
	"os"
	"path/filepath"
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
