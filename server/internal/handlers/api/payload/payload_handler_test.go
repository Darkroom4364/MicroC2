package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
)

func TestGeneratePayloadCreatesBuildIDsDistinctFromListenerID(t *testing.T) {
	tempDir := withTempWorkingDir(t)
	agentDir := filepath.Join(tempDir, "agent")
	writeFakeBuildScript(t, agentDir)
	writeListenerConfig(t, listeners.ListenerConfig{
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
	writeListenerConfig(t, listeners.ListenerConfig{
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
	writeListenerConfig(t, listeners.ListenerConfig{
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

func TestPayloadMetadataAndDownloadSurviveRestartWithCustomRoot(t *testing.T) {
	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "nonstandard", "artifact-root")
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	lookup := staticListenerLookup{
		"listener-one": {
			ID:       "listener-one",
			Name:     "lab-listener",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     9001,
		},
	}
	databasePath := filepath.Join(tempDir, "state", "microc2.db")
	firstDatabase, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("open first persistence database: %v", err)
	}
	firstHandler, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		agentDir,
		lookup,
		firstDatabase,
	)
	if err != nil {
		firstDatabase.Close()
		t.Fatalf("create first persistent handler: %v", err)
	}
	installSuccessfulBuildHook(t, firstHandler, firstDatabase, payloadsDir)
	generated := generatePayloadOverHTTP(t, firstHandler)

	var relativePath, state, artifactHash, createdAt string
	var provenanceJSON []byte
	var recordCount int
	if err := firstDatabase.SQL().QueryRow(
		`SELECT relative_path, state, sha256, created_at, provenance_json
		 FROM payload_builds WHERE id = ?`,
		generated.ID,
	).Scan(
		&relativePath,
		&state,
		&artifactHash,
		&createdAt,
		&provenanceJSON,
	); err != nil {
		firstDatabase.Close()
		t.Fatalf("read stored payload metadata: %v", err)
	}
	if filepath.IsAbs(relativePath) ||
		strings.Contains(relativePath, payloadsDir) ||
		relativePath == "" {
		firstDatabase.Close()
		t.Fatalf("stored artifact path must be root-relative, got %q", relativePath)
	}
	if state != payloadStateCompleted {
		firstDatabase.Close()
		t.Fatalf("stored payload state = %q, want %q", state, payloadStateCompleted)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(artifactHash) {
		firstDatabase.Close()
		t.Fatalf("stored artifact hash is invalid: %q", artifactHash)
	}
	if createdAt != generated.Created {
		firstDatabase.Close()
		t.Fatalf("stored completion timestamp = %q, want %q", createdAt, generated.Created)
	}
	var provenance map[string]interface{}
	if err := json.Unmarshal(provenanceJSON, &provenance); err != nil {
		firstDatabase.Close()
		t.Fatalf("decode stored provenance: %v", err)
	}
	if provenance["built_at"] != generated.Created {
		firstDatabase.Close()
		t.Fatalf(
			"stored provenance built_at = %#v, want %q",
			provenance["built_at"],
			generated.Created,
		)
	}
	if err := firstDatabase.SQL().QueryRow(
		`SELECT COUNT(*) FROM payload_builds WHERE id = ?`,
		generated.ID,
	).Scan(&recordCount); err != nil {
		firstDatabase.Close()
		t.Fatalf("count stored payload metadata: %v", err)
	}
	if recordCount != 1 {
		firstDatabase.Close()
		t.Fatalf("stored payload metadata count = %d, want 1", recordCount)
	}
	if err := firstDatabase.Close(); err != nil {
		t.Fatalf("close first persistence database: %v", err)
	}

	secondDatabase, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("reopen persistence database: %v", err)
	}
	t.Cleanup(func() {
		if err := secondDatabase.Close(); err != nil {
			t.Errorf("close second persistence database: %v", err)
		}
	})
	secondHandler, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		agentDir,
		lookup,
		secondDatabase,
	)
	if err != nil {
		t.Fatalf("create restarted persistent handler: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/payload/download/"+generated.ID,
		nil,
	)
	secondHandler.HandleDownloadPayload(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("download after restart: status %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != "fake agent" {
		t.Fatalf("downloaded payload = %q, want fake agent", recorder.Body.String())
	}
	if recorder.Header().Get("Content-Length") != "10" {
		t.Fatalf("download content length = %q, want 10", recorder.Header().Get("Content-Length"))
	}
	if !strings.Contains(recorder.Header().Get("Content-Disposition"), "filename=agent") {
		t.Fatalf(
			"download content disposition = %q",
			recorder.Header().Get("Content-Disposition"),
		)
	}
}

func TestPayloadRestartRetainsMissingAndCorruptMetadata(t *testing.T) {
	testCases := []struct {
		name      string
		mutate    func(*testing.T, string)
		wantState string
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove payload artifact: %v", err)
				}
			},
			wantState: payloadStateMissing,
		},
		{
			name: "hash mismatch with unchanged size",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("evil agent"), 0644); err != nil {
					t.Fatalf("replace payload artifact: %v", err)
				}
			},
			wantState: payloadStateCorrupt,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tempDir := t.TempDir()
			payloadsDir := filepath.Join(tempDir, "payload-root")
			agentDir := filepath.Join(tempDir, "agent")
			writePlaceholderBuildScript(t, agentDir)
			lookup := staticListenerLookup{
				"listener-one": {
					ID:       "listener-one",
					Name:     "lab-listener",
					Protocol: "http",
					BindHost: "127.0.0.1",
					Port:     9001,
				},
			}
			databasePath := filepath.Join(tempDir, "state.db")
			firstDatabase, err := persistence.Open(databasePath)
			if err != nil {
				t.Fatalf("open first persistence database: %v", err)
			}
			firstHandler, err := NewPayloadHandlerWithPersistence(
				payloadsDir,
				agentDir,
				lookup,
				firstDatabase,
			)
			if err != nil {
				firstDatabase.Close()
				t.Fatalf("create first persistent handler: %v", err)
			}
			installSuccessfulBuildHook(t, firstHandler, firstDatabase, payloadsDir)
			generated := generatePayloadOverHTTP(t, firstHandler)
			if err := firstDatabase.Close(); err != nil {
				t.Fatalf("close first persistence database: %v", err)
			}

			testCase.mutate(t, generated.Path)

			secondDatabase, err := persistence.Open(databasePath)
			if err != nil {
				t.Fatalf("reopen persistence database: %v", err)
			}
			t.Cleanup(func() {
				if err := secondDatabase.Close(); err != nil {
					t.Errorf("close second persistence database: %v", err)
				}
			})
			secondHandler, err := NewPayloadHandlerWithPersistence(
				payloadsDir,
				agentDir,
				lookup,
				secondDatabase,
			)
			if err != nil {
				t.Fatalf("create restarted persistent handler: %v", err)
			}

			var state string
			var count int
			if err := secondDatabase.SQL().QueryRow(
				`SELECT state FROM payload_builds WHERE id = ?`,
				generated.ID,
			).Scan(&state); err != nil {
				t.Fatalf("read reconciled payload state: %v", err)
			}
			if state != testCase.wantState {
				t.Fatalf("reconciled state = %q, want %q", state, testCase.wantState)
			}
			if err := secondDatabase.SQL().QueryRow(
				`SELECT COUNT(*) FROM payload_builds WHERE id = ?`,
				generated.ID,
			).Scan(&count); err != nil {
				t.Fatalf("count retained payload metadata: %v", err)
			}
			if count != 1 {
				t.Fatalf("retained payload metadata count = %d, want 1", count)
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/payload/download/"+generated.ID,
				nil,
			)
			secondHandler.HandleDownloadPayload(recorder, request)
			if recorder.Code != http.StatusGone {
				t.Fatalf(
					"unavailable download: status %d, want %d: %s",
					recorder.Code,
					http.StatusGone,
					recorder.Body.String(),
				)
			}
		})
	}
}

func TestPayloadDownloadRevalidatesArtifactAfterStartup(t *testing.T) {
	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "payload-root")
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	lookup := staticListenerLookup{
		"listener-one": {
			ID:       "listener-one",
			Name:     "lab-listener",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     9001,
		},
	}
	database, err := persistence.Open(filepath.Join(tempDir, "state.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close persistence database: %v", err)
		}
	})
	handler, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		agentDir,
		lookup,
		database,
	)
	if err != nil {
		t.Fatalf("create persistent handler: %v", err)
	}
	installSuccessfulBuildHook(t, handler, database, payloadsDir)
	generated := generatePayloadOverHTTP(t, handler)
	if err := os.WriteFile(generated.Path, []byte("evil agent"), 0644); err != nil {
		t.Fatalf("replace payload artifact after startup: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/payload/download/"+generated.ID,
		nil,
	)
	handler.HandleDownloadPayload(recorder, request)
	if recorder.Code != http.StatusGone {
		t.Fatalf(
			"download-time revalidation: status %d, want %d: %s",
			recorder.Code,
			http.StatusGone,
			recorder.Body.String(),
		)
	}
	var state string
	if err := database.SQL().QueryRow(
		`SELECT state FROM payload_builds WHERE id = ?`,
		generated.ID,
	).Scan(&state); err != nil {
		t.Fatalf("read download-time payload state: %v", err)
	}
	if state != payloadStateCorrupt {
		t.Fatalf("download-time payload state = %q, want %q", state, payloadStateCorrupt)
	}
}

func TestPersistentBuildFailureRecordsBoundedFailedState(t *testing.T) {
	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "payload-root")
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	database, err := persistence.Open(filepath.Join(tempDir, "state.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close persistence database: %v", err)
		}
	})
	handler, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent handler: %v", err)
	}

	handler.runBuild = func(_ *exec.Cmd) ([]byte, error) {
		var state string
		if err := database.SQL().QueryRow(
			`SELECT state FROM payload_builds ORDER BY created_at DESC LIMIT 1`,
		).Scan(&state); err != nil {
			t.Fatalf("read state before failed build: %v", err)
		}
		if state != payloadStateBuilding {
			t.Fatalf("state before failed build = %q, want %q", state, payloadStateBuilding)
		}
		return []byte(strings.Repeat("sensitive-command-output", 512)),
			errors.New("hooked build failure")
	}

	_, err = handler.GeneratePayload(testPayloadConfig())
	if err == nil {
		t.Fatal("failed build unexpectedly succeeded")
	}

	var state, detail string
	var recordCount int
	if err := database.SQL().QueryRow(
		`SELECT state, state_detail FROM payload_builds`,
	).Scan(&state, &detail); err != nil {
		t.Fatalf("read failed payload state: %v", err)
	}
	if state != payloadStateFailed {
		t.Fatalf("failed payload state = %q, want %q", state, payloadStateFailed)
	}
	if detail != payloadFailedDetail {
		t.Fatalf("failed payload detail = %q, want %q", detail, payloadFailedDetail)
	}
	if strings.Contains(detail, "sensitive") ||
		strings.Contains(detail, "hooked build failure") ||
		len(detail) > 128 {
		t.Fatalf("failed payload detail contains unbounded or sensitive output: %q", detail)
	}
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM payload_builds`,
	).Scan(&recordCount); err != nil {
		t.Fatalf("count failed payload metadata: %v", err)
	}
	if recordCount != 1 {
		t.Fatalf("failed payload metadata count = %d, want 1", recordCount)
	}
}

func TestBuildingPayloadBecomesInterruptedExactlyOnceOnRestart(t *testing.T) {
	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "payload-root")
	database, err := persistence.Open(filepath.Join(tempDir, "state.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close persistence database: %v", err)
		}
	})
	const payloadID = "interrupted-build"
	if _, err := database.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		payloadID,
		payloadID,
		"listener-one",
		"0123456789abcdef",
		"agent",
		"release/interrupted-build/agent",
		0,
		"",
		"2026-07-23T00:00:00Z",
		payloadStateBuilding,
		"",
		[]byte("{}"),
	); err != nil {
		t.Fatalf("insert building payload metadata: %v", err)
	}

	if _, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		filepath.Join(tempDir, "agent"),
		testListenerLookup(),
		database,
	); err != nil {
		t.Fatalf("reconcile first restart: %v", err)
	}
	var state, detail string
	if err := database.SQL().QueryRow(
		`SELECT state, state_detail FROM payload_builds WHERE id = ?`,
		payloadID,
	).Scan(&state, &detail); err != nil {
		t.Fatalf("read interrupted payload state: %v", err)
	}
	if state != payloadStateInterrupted || detail != payloadInterruptedDetail {
		t.Fatalf(
			"first restart state/detail = %q/%q, want %q/%q",
			state,
			detail,
			payloadStateInterrupted,
			payloadInterruptedDetail,
		)
	}

	const sentinelDetail = "already reconciled"
	if _, err := database.SQL().Exec(
		`UPDATE payload_builds SET state_detail = ? WHERE id = ?`,
		sentinelDetail,
		payloadID,
	); err != nil {
		t.Fatalf("set interrupted sentinel detail: %v", err)
	}
	if _, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		filepath.Join(tempDir, "agent"),
		testListenerLookup(),
		database,
	); err != nil {
		t.Fatalf("reconcile second restart: %v", err)
	}
	if err := database.SQL().QueryRow(
		`SELECT state, state_detail FROM payload_builds WHERE id = ?`,
		payloadID,
	).Scan(&state, &detail); err != nil {
		t.Fatalf("read twice-reconciled payload state: %v", err)
	}
	if state != payloadStateInterrupted || detail != sentinelDetail {
		t.Fatalf(
			"second restart changed terminal state/detail to %q/%q",
			state,
			detail,
		)
	}
}

func TestDownloadStreamsVerifiedHandleAcrossPathSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX rename semantics for an open file")
	}

	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "payload-root")
	const payloadID = "path-swap-build"
	relativePath := filepath.ToSlash(
		filepath.Join("release", payloadID, "agent"),
	)
	artifactPath := filepath.Join(payloadsDir, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0755); err != nil {
		t.Fatalf("create artifact directory: %v", err)
	}
	trustedContent := []byte("trusted!")
	swappedContent := []byte("swapped!")
	if err := os.WriteFile(artifactPath, trustedContent, 0644); err != nil {
		t.Fatalf("write trusted artifact: %v", err)
	}
	artifactHash, err := hashArtifact(artifactPath)
	if err != nil {
		t.Fatalf("hash trusted artifact: %v", err)
	}

	database, err := persistence.Open(filepath.Join(tempDir, "state.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close persistence database: %v", err)
		}
	})
	if _, err := database.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		payloadID,
		payloadID,
		"listener-one",
		"0123456789abcdef",
		"agent",
		relativePath,
		len(trustedContent),
		artifactHash,
		"2026-07-23T00:00:00Z",
		payloadStateCompleted,
		"",
		[]byte("{}"),
	); err != nil {
		t.Fatalf("insert completed payload metadata: %v", err)
	}
	handler, err := NewPayloadHandlerWithPersistence(
		payloadsDir,
		filepath.Join(tempDir, "agent"),
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent handler: %v", err)
	}

	swapCount := 0
	handler.afterVerified = func() {
		swapCount++
		if err := os.Rename(artifactPath, artifactPath+".verified"); err != nil {
			t.Fatalf("rename verified artifact: %v", err)
		}
		if err := os.WriteFile(artifactPath, swappedContent, 0644); err != nil {
			t.Fatalf("write swapped artifact: %v", err)
		}
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/payload/download/"+payloadID,
		nil,
	)
	handler.HandleDownloadPayload(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("download after path swap: status %d: %s", recorder.Code, recorder.Body.String())
	}
	if swapCount != 1 {
		t.Fatalf("post-verification swap hook count = %d, want 1", swapCount)
	}
	if !bytes.Equal(recorder.Body.Bytes(), trustedContent) {
		t.Fatalf(
			"download streamed %q after path swap, want verified content %q",
			recorder.Body.Bytes(),
			trustedContent,
		)
	}
	replacement, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read replacement artifact: %v", err)
	}
	if !bytes.Equal(replacement, swappedContent) {
		t.Fatalf("artifact path contains %q, want swapped content %q", replacement, swappedContent)
	}
}

func generatePayloadOverHTTP(t *testing.T, handler *PayloadHandler) PayloadResult {
	t.Helper()
	body, err := json.Marshal(PayloadConfig{
		ListenerID:   "listener-one",
		AgentType:    "debugAgent",
		Format:       "linux_elf",
		Sleep:        5,
		MutationSeed: "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("marshal payload request: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/payload/generate",
		bytes.NewReader(body),
	)
	handler.HandleGeneratePayload(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("generate payload: status %d: %s", recorder.Code, recorder.Body.String())
	}
	var result PayloadResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode generated payload response: %v", err)
	}
	if result.ID == "" || result.Path == "" {
		t.Fatalf("generated payload response is incomplete: %#v", result)
	}
	if filepath.IsAbs(result.Path) ||
		strings.Contains(result.Path, handler.payloadsDir) {
		t.Fatalf("generated payload response disclosed its filesystem root: %q", result.Path)
	}
	result.Path = filepath.Join(
		handler.payloadsDir,
		filepath.FromSlash(result.Path),
	)
	return result
}

func testPayloadConfig() PayloadConfig {
	return PayloadConfig{
		ListenerID:   "listener-one",
		AgentType:    "debugAgent",
		Format:       "linux_elf",
		Sleep:        5,
		MutationSeed: "0123456789abcdef",
	}
}

func testListenerLookup() staticListenerLookup {
	return staticListenerLookup{
		"listener-one": {
			ID:       "listener-one",
			Name:     "lab-listener",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     9001,
		},
	}
}

type staticListenerLookup map[string]listeners.ListenerConfig

func (lookup staticListenerLookup) LookupListener(
	listenerID string,
) (listeners.ListenerConfig, error) {
	config, ok := lookup[listenerID]
	if !ok {
		return listeners.ListenerConfig{}, fmt.Errorf("listener %s not found", listenerID)
	}
	return config, nil
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

func writeListenerConfig(t *testing.T, config listeners.ListenerConfig) {
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
	if runtime.GOOS == "windows" {
		t.Skip("requires Bash")
	}

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

func writePlaceholderBuildScript(t *testing.T, agentDir string) {
	t.Helper()
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		t.Fatalf("create placeholder agent dir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(agentDir, "build.sh"),
		[]byte("build execution is replaced by a test hook"),
		0644,
	); err != nil {
		t.Fatalf("write placeholder build script: %v", err)
	}
}

func installSuccessfulBuildHook(
	t *testing.T,
	handler *PayloadHandler,
	database *persistence.Database,
	payloadsDir string,
) {
	t.Helper()
	handler.runBuild = func(_ *exec.Cmd) ([]byte, error) {
		var relativePath, state, artifactHash string
		var size int64
		var provenanceJSON []byte
		if err := database.SQL().QueryRow(
			`SELECT relative_path, state, size, sha256, provenance_json
			 FROM payload_builds
			 WHERE state = ?
			 ORDER BY created_at DESC
			 LIMIT 1`,
			payloadStateBuilding,
		).Scan(
			&relativePath,
			&state,
			&size,
			&artifactHash,
			&provenanceJSON,
		); err != nil {
			t.Fatalf("read building payload metadata from hook: %v", err)
		}
		if state != payloadStateBuilding ||
			size != 0 ||
			artifactHash != "" ||
			string(provenanceJSON) != "{}" {
			t.Fatalf(
				"initial payload metadata = state %q, size %d, hash %q, provenance %q",
				state,
				size,
				artifactHash,
				provenanceJSON,
			)
		}
		artifactPath := filepath.Join(
			payloadsDir,
			filepath.FromSlash(relativePath),
		)
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0755); err != nil {
			t.Fatalf("create hooked artifact directory: %v", err)
		}
		if err := os.WriteFile(artifactPath, []byte("fake agent"), 0644); err != nil {
			t.Fatalf("write hooked payload artifact: %v", err)
		}
		return []byte("hook build complete"), nil
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
