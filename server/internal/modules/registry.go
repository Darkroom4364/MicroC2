// Package modules defines the server-owned catalog of typed agent modules.
// Modules are compile-time registered: the operator cannot submit arbitrary
// code, and each module has a closed input/output contract.
package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion  = 1
	MaxInputBytes  = 64 << 10
	MaxOutputBytes = 64 << 10
)

var ErrUnknownModule = errors.New("unknown module")

// Safety declares the execution constraints that an operator must review
// before creating a module task.
type Safety struct {
	RiskLevel                       string `json:"risk_level"`
	TargetScope                     string `json:"target_scope"`
	RequiresOperatorAcknowledgement bool   `json:"requires_operator_acknowledgement"`
	EvidenceRequired                bool   `json:"evidence_required"`
}

// Descriptor is the non-executable, operator-visible definition of a module.
type Descriptor struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Version      int    `json:"version"`
	Description  string `json:"description"`
	InputSchema  string `json:"input_schema"`
	OutputSchema string `json:"output_schema"`
	Safety       Safety `json:"safety"`
}

// Catalog is the bounded operator API response.
type Catalog struct {
	SchemaVersion int          `json:"schema_version"`
	Modules       []Descriptor `json:"modules"`
}

type definition struct {
	descriptor     Descriptor
	validateInput  func(json.RawMessage) error
	validateOutput func(json.RawMessage) error
}

// Registry holds immutable module definitions.
type Registry struct {
	definitions map[string]definition
	catalog     []Descriptor
}

var defaultRegistry = newRegistry([]definition{
	{
		descriptor: Descriptor{
			ID:           "agent.capability_inventory.v1",
			Name:         "Agent capability inventory",
			Version:      1,
			Description:  "Collects bounded local hardware and operating-system capabilities without network or process actions.",
			InputSchema:  "module-capability-inventory-input-v1.schema.json",
			OutputSchema: "module-capability-inventory-output-v1.schema.json",
			Safety: Safety{
				RiskLevel:                       "read_only",
				TargetScope:                     "self",
				RequiresOperatorAcknowledgement: false,
				EvidenceRequired:                true,
			},
		},
		validateInput:  validateEmptyObject,
		validateOutput: validateCapabilityInventoryOutput,
	},
})

// DefaultRegistry returns the process-wide immutable catalog.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

func newRegistry(definitions []definition) *Registry {
	registry := &Registry{
		definitions: make(map[string]definition, len(definitions)),
		catalog:     make([]Descriptor, 0, len(definitions)),
	}
	for _, definition := range definitions {
		registry.definitions[definition.descriptor.ID] = definition
		registry.catalog = append(registry.catalog, definition.descriptor)
	}
	return registry
}

// Catalog returns a detached module catalog suitable for JSON encoding.
func (r *Registry) Catalog() Catalog {
	if r == nil {
		return Catalog{SchemaVersion: SchemaVersion, Modules: []Descriptor{}}
	}
	modules := make([]Descriptor, len(r.catalog))
	copy(modules, r.catalog)
	return Catalog{SchemaVersion: SchemaVersion, Modules: modules}
}

func (r *Registry) Descriptor(moduleID string) (Descriptor, bool) {
	if r == nil {
		return Descriptor{}, false
	}
	definition, ok := r.definitions[moduleID]
	return definition.descriptor, ok
}

func (r *Registry) ValidateInput(moduleID string, input json.RawMessage) error {
	definition, ok := r.definition(moduleID)
	if !ok {
		return ErrUnknownModule
	}
	if len(input) > MaxInputBytes {
		return fmt.Errorf("input exceeds %d bytes", MaxInputBytes)
	}
	return definition.validateInput(input)
}

func (r *Registry) ValidateOutput(moduleID string, output json.RawMessage) error {
	definition, ok := r.definition(moduleID)
	if !ok {
		return ErrUnknownModule
	}
	if len(output) > MaxOutputBytes {
		return fmt.Errorf("output exceeds %d bytes", MaxOutputBytes)
	}
	return definition.validateOutput(output)
}

func (r *Registry) RequiresAcknowledgement(moduleID string) (bool, error) {
	descriptor, ok := r.Descriptor(moduleID)
	if !ok {
		return false, ErrUnknownModule
	}
	return descriptor.Safety.RequiresOperatorAcknowledgement, nil
}

func (r *Registry) definition(moduleID string) (definition, bool) {
	if r == nil {
		return definition{}, false
	}
	definition, ok := r.definitions[moduleID]
	return definition, ok
}

func validateEmptyObject(input json.RawMessage) error {
	object, err := decodeObject(input)
	if err != nil {
		return fmt.Errorf("input %w", err)
	}
	if len(object) != 0 {
		return errors.New("input must not contain properties")
	}
	return nil
}

func validateCapabilityInventoryOutput(output json.RawMessage) error {
	object, err := decodeObject(output)
	if err != nil {
		return fmt.Errorf("output %w", err)
	}
	if len(object) != 4 {
		return errors.New("output must contain exactly four properties")
	}

	if err := validateBoundedString(object, "operating_system"); err != nil {
		return err
	}
	if err := validateBoundedString(object, "architecture"); err != nil {
		return err
	}
	if err := validatePositiveInt(object, "logical_cpu_count"); err != nil {
		return err
	}
	if err := validateUnsignedInt(object, "total_memory_bytes"); err != nil {
		return err
	}
	return nil
}

func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, errors.New("must be valid JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("must be an object")
	}
	return object, nil
}

func validateBoundedString(object map[string]json.RawMessage, name string) error {
	raw, ok := object[name]
	if !ok {
		return fmt.Errorf("output.%s is required", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" ||
		utf8.RuneCountInString(value) > 128 {
		return fmt.Errorf("output.%s must be a nonblank string of at most 128 characters", name)
	}
	return nil
}

func validatePositiveInt(object map[string]json.RawMessage, name string) error {
	raw, ok := object[name]
	if !ok {
		return fmt.Errorf("output.%s is required", name)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value < 1 {
		return fmt.Errorf("output.%s must be a positive integer", name)
	}
	return nil
}

func validateUnsignedInt(object map[string]json.RawMessage, name string) error {
	raw, ok := object[name]
	if !ok {
		return fmt.Errorf("output.%s is required", name)
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("output.%s must be an unsigned integer", name)
	}
	return nil
}
