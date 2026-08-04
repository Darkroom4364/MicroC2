package modules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultRegistryRejectsDuplicateTopLevelProperties(t *testing.T) {
	registry := DefaultRegistry()
	if err := registry.ValidateInput(
		"agent.capability_inventory.v1",
		json.RawMessage(`{"ignored":true,"ignored":false}`),
	); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate module input error = %v", err)
	}
	if err := registry.ValidateOutput(
		"agent.capability_inventory.v1",
		json.RawMessage(`{"operating_system":"linux","operating_system":"darwin","architecture":"arm64","logical_cpu_count":8,"total_memory_bytes":1}`),
	); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate module output error = %v", err)
	}
}
