package payload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"microc2/server/internal/audit"
	"microc2/server/internal/common"
	"microc2/server/internal/enrollment"
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

	handler := NewPayloadHandlerForIsolatedLab(filepath.Join(tempDir, "static", "payloads"), agentDir)
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

	handler := NewPayloadHandlerForIsolatedLab(filepath.Join(tempDir, "static", "payloads"), agentDir)
	var receivedSeeds []string
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found && name == "MUTATION_SEED" {
				receivedSeeds = append(receivedSeeds, value)
				break
			}
		}
		return command.CombinedOutput()
	}
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

	if len(receivedSeeds) != 1 || receivedSeeds[0] != first.MutationSeed {
		t.Fatalf(
			"build script received MUTATION_SEED=%q, want %q",
			receivedSeeds,
			first.MutationSeed,
		)
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
	if provenance["enrollment_credential_source"] !=
		"server-generated-ephemeral" {
		t.Fatalf(
			"provenance enrollment source = %#v, want non-secret mode",
			provenance["enrollment_credential_source"],
		)
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

func TestAdvertisedListenerEndpointValidatesAndBracketsHosts(t *testing.T) {
	testCases := []struct {
		name       string
		listener   listeners.ListenerConfig
		wantHost   string
		wantScheme string
		wantURL    string
		wantError  bool
	}{
		{
			name: "dns name",
			listener: listeners.ListenerConfig{
				Protocol: "HTTPS",
				BindHost: "127.0.0.1",
				Hosts:    []string{"c2.example.test"},
				Port:     8443,
			},
			wantHost:   "c2.example.test",
			wantScheme: "https",
			wantURL:    "https://c2.example.test:8443",
		},
		{
			name: "unbracketed IPv6",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "2001:db8::1",
				Port:     443,
			},
			wantHost:   "2001:db8::1",
			wantScheme: "https",
			wantURL:    "https://[2001:db8::1]:443",
		},
		{
			name: "bracketed IPv6",
			listener: listeners.ListenerConfig{
				Protocol: "http",
				BindHost: "[::1]",
				Port:     8081,
			},
			wantHost:   "::1",
			wantScheme: "http",
			wantURL:    "http://[::1]:8081",
		},
		{
			name: "userinfo rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "operator@c2.example",
				Port:     443,
			},
			wantError: true,
		},
		{
			name: "path rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "c2.example/agent",
				Port:     443,
			},
			wantError: true,
		},
		{
			name: "quote rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: `c2.example"`,
				Port:     443,
			},
			wantError: true,
		},
		{
			name: "control rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "c2.example\ninjected",
				Port:     443,
			},
			wantError: true,
		},
		{
			name: "scheme rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "https://c2.example",
				Port:     443,
			},
			wantError: true,
		},
		{
			name: "embedded port rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "c2.example:443",
				Port:     443,
			},
			wantError: true,
		},
		{
			name: "unspecified bind address rejected",
			listener: listeners.ListenerConfig{
				Protocol: "https",
				BindHost: "0.0.0.0",
				Port:     443,
			},
			wantError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			host, protocol, serverURL, err := advertisedListenerEndpoint(
				testCase.listener,
			)
			if testCase.wantError {
				if err == nil {
					t.Fatalf(
						"advertised endpoint unexpectedly accepted as %s",
						serverURL,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate advertised endpoint: %v", err)
			}
			if host != testCase.wantHost ||
				protocol != testCase.wantScheme ||
				serverURL != testCase.wantURL {
				t.Fatalf(
					"advertised endpoint = (%q, %q, %q), want (%q, %q, %q)",
					host,
					protocol,
					serverURL,
					testCase.wantHost,
					testCase.wantScheme,
					testCase.wantURL,
				)
			}
		})
	}
}

func TestPayloadBuildReceivesCanonicalIPv6ServerURL(t *testing.T) {
	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	handler, err := newPayloadHandler(
		filepath.Join(tempDir, "payloads"),
		agentDir,
		staticListenerLookup{
			"listener-one": {
				ID:       "listener-one",
				Name:     "ipv6-listener",
				Protocol: "https",
				BindHost: "::",
				Hosts:    []string{"2001:db8::1"},
				Port:     8443,
			},
		},
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("create payload handler: %v", err)
	}

	var serverURL, listenerHost string
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if !found {
				continue
			}
			switch name {
			case "SERVER_URL":
				serverURL = value
			case "LISTENER_HOST":
				listenerHost = value
			}
		}
		for index := 0; index+1 < len(command.Args); index++ {
			if command.Args[index] != "--output" {
				continue
			}
			return []byte("hook build complete"), os.WriteFile(
				filepath.Join(command.Args[index+1], "agent"),
				[]byte("fake agent"),
				0o600,
			)
		}
		return nil, errors.New("build command omitted --output")
	}

	result, err := handler.GeneratePayload(testPayloadConfig())
	if err != nil {
		t.Fatalf("generate IPv6 payload: %v", err)
	}
	if serverURL != "https://[2001:db8::1]:8443" {
		t.Fatalf("SERVER_URL = %q, want canonical IPv6 URL", serverURL)
	}
	if listenerHost != "2001:db8::1" {
		t.Fatalf("LISTENER_HOST = %q, want unbracketed IPv6 host", listenerHost)
	}
	projected := readJSONFile(
		t,
		filepath.Join(filepath.Dir(result.Path), "config.json"),
	)
	if projected["server_url"] != serverURL {
		t.Fatalf(
			"projected server_url = %#v, want %q",
			projected["server_url"],
			serverURL,
		)
	}
}

func TestPersistentPayloadEnrollmentCredentialIsHashOnlyAndNotProjected(
	t *testing.T,
) {
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}

	var (
		bootstrapCredential string
		labOverride         string
		buildOutput         []byte
		logOutput           bytes.Buffer
	)
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if !found {
				continue
			}
			switch name {
			case "ENROLLMENT_CREDENTIAL":
				bootstrapCredential = value
			case "ALLOW_INSECURE_ISOLATED_LAB":
				labOverride = value
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
			t.Fatal("build command omitted --output")
		}
		if err := os.WriteFile(
			filepath.Join(outputDir, "agent"),
			[]byte("fake agent"),
			0o600,
		); err != nil {
			t.Fatalf("write hooked payload artifact: %v", err)
		}
		buildOutput = []byte(
			"hook build complete; credential=" + bootstrapCredential,
		)
		return buildOutput, nil
	}

	previousLogWriter := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() {
		log.SetOutput(previousLogWriter)
	})
	result, err := handler.GeneratePayload(testPayloadConfig())
	log.SetOutput(previousLogWriter)
	if err != nil {
		t.Fatalf("generate authenticated payload: %v", err)
	}
	decodedBootstrap, err := base64.RawURLEncoding.DecodeString(
		bootstrapCredential,
	)
	if err != nil {
		t.Fatalf("decode generated bootstrap credential: %v", err)
	}
	if len(decodedBootstrap) != 32 {
		t.Fatalf("bootstrap entropy bytes = %d, want 32", len(decodedBootstrap))
	}
	if !bytes.Contains(buildOutput, []byte(bootstrapCredential)) {
		t.Fatal("test build output did not exercise credential redaction")
	}
	if labOverride != "true" {
		t.Fatalf("HTTP lab build override = %q, want true", labOverride)
	}

	var storedHash []byte
	var maxSessions int
	if err := database.SQL().QueryRow(
		`SELECT bootstrap_sha256, max_sessions
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = ?`,
		result.ID,
	).Scan(&storedHash, &maxSessions); err != nil {
		t.Fatalf("read stored payload enrollment credential: %v", err)
	}
	wantHash := sha256.Sum256(decodedBootstrap)
	if !bytes.Equal(storedHash, wantHash[:]) {
		t.Fatal("stored bootstrap hash does not match the generated credential")
	}
	if maxSessions != defaultPayloadMaxSessions {
		t.Fatalf(
			"stored max_sessions = %d, want %d",
			maxSessions,
			defaultPayloadMaxSessions,
		)
	}

	configBytes, err := os.ReadFile(
		filepath.Join(filepath.Dir(result.Path), "config.json"),
	)
	if err != nil {
		t.Fatalf("read projected payload config: %v", err)
	}
	provenanceBytes, err := os.ReadFile(
		filepath.Join(filepath.Dir(result.Path), "provenance.json"),
	)
	if err != nil {
		t.Fatalf("read payload provenance: %v", err)
	}
	responseBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal payload response: %v", err)
	}
	for name, content := range map[string][]byte{
		"config projection": configBytes,
		"provenance":        provenanceBytes,
		"operator response": responseBytes,
		"server logs":       logOutput.Bytes(),
	} {
		if bytes.Contains(content, []byte(bootstrapCredential)) {
			t.Fatalf("%s exposed the bootstrap credential", name)
		}
	}
	if bytes.Contains(logOutput.Bytes(), []byte("hook build complete")) {
		t.Fatal("server logs exposed untrusted child build output")
	}
	if bytes.Contains(configBytes, []byte("enrollment_credential")) {
		t.Fatal("ordinary payload config contains an enrollment credential field")
	}
}

func TestPayloadBuildFailureRedactsEnrollmentCredentialFromLogsAndResponse(
	t *testing.T,
) {
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}

	var bootstrapCredential string
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found && name == "ENROLLMENT_CREDENTIAL" {
				bootstrapCredential = value
				break
			}
		}
		return []byte("child output leaked " + bootstrapCredential),
			errors.New("compiler error leaked " + bootstrapCredential)
	}

	requestBody, err := json.Marshal(testPayloadConfig())
	if err != nil {
		t.Fatalf("marshal payload request: %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/payload/generate",
		bytes.NewReader(requestBody),
	)
	response := httptest.NewRecorder()
	var logOutput bytes.Buffer
	previousLogWriter := log.Writer()
	log.SetOutput(&logOutput)
	t.Cleanup(func() {
		log.SetOutput(previousLogWriter)
	})
	handler.HandleGeneratePayload(response, request)
	log.SetOutput(previousLogWriter)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"payload failure status = %d, want %d: %s",
			response.Code,
			http.StatusInternalServerError,
			response.Body.String(),
		)
	}
	if bootstrapCredential == "" {
		t.Fatal("test build did not receive an enrollment credential")
	}
	for name, content := range map[string]string{
		"server logs":       logOutput.String(),
		"operator response": response.Body.String(),
	} {
		if strings.Contains(content, bootstrapCredential) {
			t.Fatalf("%s exposed the bootstrap credential", name)
		}
		for _, forbidden := range []string{
			"child output leaked",
			"compiler error leaked",
		} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s exposed untrusted build diagnostic %q", name, forbidden)
			}
		}
	}
	if !strings.Contains(response.Body.String(), "Payload generation failed") {
		t.Fatalf("operator response omitted generic build failure: %q", response.Body.String())
	}

	page, err := handler.audit.Page(
		context.Background(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page failed-build audit events: %v", err)
	}
	if page.Total != 2 || len(page.Events) != 2 {
		t.Fatalf(
			"failed-build audit event count = %d/%d, want 2/2: %#v",
			page.Total,
			len(page.Events),
			page.Events,
		)
	}
	failed := page.Events[0]
	requested := page.Events[1]
	if requested.Action != "payload.build.requested" ||
		requested.CausationSequence != nil ||
		failed.Action != "payload.build.failed" ||
		failed.Outcome != audit.OutcomeFailed ||
		failed.ReasonCode != "build_failed" ||
		failed.CausationSequence == nil ||
		*failed.CausationSequence != requested.Sequence ||
		failed.PayloadBuildID != requested.PayloadBuildID {
		t.Fatalf(
			"failed payload audit chain is not causal: requested=%#v failed=%#v",
			requested,
			failed,
		)
	}
	serialized, err := json.Marshal(page.Events)
	if err != nil {
		t.Fatalf("marshal failed-build audit events: %v", err)
	}
	for name, forbidden := range map[string]string{
		"bootstrap credential": bootstrapCredential,
		"child build output":   "child output leaked",
		"child build error":    "compiler error leaked",
	} {
		if bytes.Contains(serialized, []byte(forbidden)) {
			t.Fatalf("failed-build audit events exposed %s: %s", name, serialized)
		}
	}
}

func TestConcurrentPayloadBuildsSerializeSharedAgentWorkspace(t *testing.T) {
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}

	sharedArtifact := filepath.Join(agentDir, "target", "shared-agent")
	if err := os.MkdirAll(filepath.Dir(sharedArtifact), 0o755); err != nil {
		t.Fatalf("create simulated shared Cargo target: %v", err)
	}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseFirst)
		})
	}
	t.Cleanup(release)

	var stateMutex sync.Mutex
	invocations := 0
	expectedByPayloadID := make(map[string]string)
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		var credential, outputDir, payloadID string
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found && name == "ENROLLMENT_CREDENTIAL" {
				credential = value
			}
		}
		for index := 0; index+1 < len(command.Args); index++ {
			switch command.Args[index] {
			case "--output":
				outputDir = command.Args[index+1]
			case "--payload-id":
				payloadID = command.Args[index+1]
			}
		}
		if credential == "" || outputDir == "" || payloadID == "" {
			return nil, errors.New("build hook is missing credential or output")
		}

		stateMutex.Lock()
		invocations++
		invocation := invocations
		expectedByPayloadID[payloadID] = credential
		stateMutex.Unlock()

		if err := os.WriteFile(
			sharedArtifact,
			[]byte(credential),
			0o600,
		); err != nil {
			return nil, fmt.Errorf("write simulated shared artifact: %w", err)
		}
		if invocation == 1 {
			close(firstEntered)
			<-releaseFirst
		}
		artifact, err := os.ReadFile(sharedArtifact)
		if err != nil {
			return nil, fmt.Errorf("read simulated shared artifact: %w", err)
		}
		if err := os.WriteFile(
			filepath.Join(outputDir, "agent"),
			artifact,
			0o600,
		); err != nil {
			return nil, fmt.Errorf("copy simulated shared artifact: %w", err)
		}
		return []byte("hook build complete"), nil
	}

	type buildResponse struct {
		result PayloadResult
		err    error
	}
	responses := make(chan buildResponse, 2)
	startBuild := func() {
		result, err := handler.GeneratePayload(testPayloadConfig())
		responses <- buildResponse{result: result, err: err}
	}
	go startBuild()
	select {
	case <-firstEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first payload build did not enter the build hook")
	}
	go startBuild()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var building int
		if err := database.SQL().QueryRow(
			`SELECT COUNT(*) FROM payload_builds WHERE state = ?`,
			payloadStateBuilding,
		).Scan(&building); err != nil {
			release()
			t.Fatalf("count concurrent building payloads: %v", err)
		}
		if building == 2 {
			break
		}
		if time.Now().After(deadline) {
			release()
			t.Fatalf(
				"second payload did not reach serialized build boundary; building=%d",
				building,
			)
		}
		runtime.Gosched()
	}

	if handler.buildMutex.TryLock() {
		handler.buildMutex.Unlock()
		release()
		t.Fatal("shared build mutex was not held for the full child build")
	}
	stateMutex.Lock()
	enteredBeforeRelease := invocations
	stateMutex.Unlock()
	if enteredBeforeRelease != 1 {
		release()
		t.Fatalf(
			"concurrent build hook entries before release = %d, want 1",
			enteredBeforeRelease,
		)
	}
	release()

	results := make([]PayloadResult, 0, 2)
	for range 2 {
		select {
		case response := <-responses:
			if response.err != nil {
				t.Fatalf("generate concurrent payload: %v", response.err)
			}
			results = append(results, response.result)
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent payload build did not complete")
		}
	}

	for _, result := range results {
		stateMutex.Lock()
		expectedCredential := expectedByPayloadID[result.ID]
		stateMutex.Unlock()
		if expectedCredential == "" {
			t.Fatalf("no credential recorded for build %s", result.ID)
		}
		artifact, err := os.ReadFile(result.Path)
		if err != nil {
			t.Fatalf("read generated artifact %s: %v", result.Path, err)
		}
		if string(artifact) != expectedCredential {
			t.Fatalf(
				"artifact %s was copied from another build's shared output",
				result.ID,
			)
		}
		decodedCredential, err := base64.RawURLEncoding.DecodeString(
			expectedCredential,
		)
		if err != nil {
			t.Fatalf("decode credential for build %s: %v", result.ID, err)
		}
		wantHash := sha256.Sum256(decodedCredential)
		var storedHash []byte
		if err := database.SQL().QueryRow(
			`SELECT bootstrap_sha256
			 FROM payload_bootstrap_credentials
			 WHERE payload_build_id = ?`,
			result.ID,
		).Scan(&storedHash); err != nil {
			t.Fatalf("read credential hash for build %s: %v", result.ID, err)
		}
		if !bytes.Equal(storedHash, wantHash[:]) {
			t.Fatalf(
				"artifact and durable credential disagree for build %s",
				result.ID,
			)
		}
	}
}

func TestPayloadArtifactsRemainDownloadableWithPrivatePermissions(t *testing.T) {
	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "payload-root")
	if err := os.MkdirAll(payloadsDir, 0o755); err != nil {
		t.Fatalf("create permissive payload root: %v", err)
	}
	if err := os.Chmod(payloadsDir, 0o755); err != nil {
		t.Fatalf("make payload root permissive: %v", err)
	}
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}
	var (
		cargoTargetDir  string
		cargoTargetPath string
		cargoTargetMode os.FileMode
	)
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found && name == "CARGO_TARGET_DIR" {
				cargoTargetDir = value
				break
			}
		}
		if cargoTargetDir == "" {
			return nil, errors.New("build command omitted CARGO_TARGET_DIR")
		}
		cargoTargetPath = filepath.Join(command.Dir, cargoTargetDir)
		targetInfo, err := os.Stat(cargoTargetPath)
		if err != nil {
			return nil, fmt.Errorf("stat private Cargo target: %w", err)
		}
		cargoTargetMode = targetInfo.Mode().Perm()
		if err := os.MkdirAll(cargoTargetPath, 0o755); err != nil {
			return nil, fmt.Errorf("create simulated Cargo target: %w", err)
		}
		if err := os.WriteFile(
			filepath.Join(cargoTargetPath, "credential-bearing-object"),
			[]byte("simulated build intermediate"),
			0o644,
		); err != nil {
			return nil, fmt.Errorf("write simulated Cargo intermediate: %w", err)
		}
		for index := 0; index+1 < len(command.Args); index++ {
			if command.Args[index] != "--output" {
				continue
			}
			return []byte("hook build complete"), os.WriteFile(
				filepath.Join(command.Args[index+1], "agent"),
				[]byte("private agent"),
				0o644,
			)
		}
		return nil, errors.New("build command omitted --output")
	}

	result, err := handler.GeneratePayload(testPayloadConfig())
	if err != nil {
		t.Fatalf("generate private payload: %v", err)
	}
	wantCargoTargetDir := filepath.Join(
		privateCargoBuildRoot,
		result.ID,
		"target",
	)
	if cargoTargetDir != wantCargoTargetDir {
		t.Fatalf(
			"CARGO_TARGET_DIR = %q, want relative private per-build path %q",
			cargoTargetDir,
			wantCargoTargetDir,
		)
	}
	if filepath.IsAbs(cargoTargetDir) {
		t.Fatalf("CARGO_TARGET_DIR = %q, want a Cross-visible relative path", cargoTargetDir)
	}
	wantCargoTargetPath := filepath.Join(agentDir, wantCargoTargetDir)
	if cargoTargetPath != wantCargoTargetPath {
		t.Fatalf(
			"resolved Cargo target = %q, want %q inside agent source",
			cargoTargetPath,
			wantCargoTargetPath,
		)
	}
	wantCargoBuildDir := filepath.Join(
		agentDir,
		privateCargoBuildRoot,
		result.ID,
	)
	if _, err := os.Stat(wantCargoBuildDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"private Cargo intermediates remained after build: %v",
			err,
		)
	}
	if _, err := os.Stat(filepath.Join(agentDir, "target")); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("server build used shared agent target directory: %v", err)
	}
	if runtime.GOOS != "windows" {
		if cargoTargetMode != 0o700 {
			t.Fatalf(
				"private Cargo target permissions = %04o, want 0700",
				cargoTargetMode,
			)
		}
		for _, path := range []string{
			payloadsDir,
			filepath.Join(payloadsDir, "debug"),
			filepath.Join(payloadsDir, "release"),
			filepath.Join(agentDir, privateCargoBuildRoot),
			filepath.Dir(result.Path),
			result.Path,
		} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat private payload path %s: %v", path, err)
			}
			if info.Mode().Perm() != 0o700 {
				t.Fatalf(
					"payload path %s permissions = %04o, want 0700",
					path,
					info.Mode().Perm(),
				)
			}
		}
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/payload/download/"+result.ID,
		nil,
	)
	response := httptest.NewRecorder()
	handler.HandleDownloadPayload(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf(
			"download private payload status = %d, want 200: %s",
			response.Code,
			response.Body.String(),
		)
	}
	if response.Body.String() != "private agent" {
		t.Fatalf("downloaded private payload = %q", response.Body.String())
	}
}

func TestPrivateCargoBuildPathsRejectSymlinkRedirection(t *testing.T) {
	t.Run("setup", func(t *testing.T) {
		agentDir := t.TempDir()
		outsideDir := t.TempDir()
		sentinel := filepath.Join(outsideDir, "sentinel")
		if err := os.WriteFile(sentinel, []byte("outside"), 0o600); err != nil {
			t.Fatalf("write outside sentinel: %v", err)
		}
		buildRoot := filepath.Join(agentDir, privateCargoBuildRoot)
		if err := os.Symlink(outsideDir, buildRoot); err != nil {
			t.Skipf("filesystem does not permit symlink test: %v", err)
		}

		err := ensurePrivateCargoBuildDirectories(
			buildRoot,
			filepath.Join(buildRoot, "build-one"),
			filepath.Join(buildRoot, "build-one", "target"),
		)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("symlinked private build root error = %v", err)
		}
		if contents, err := os.ReadFile(sentinel); err != nil {
			t.Fatalf("symlink refusal removed outside sentinel: %v", err)
		} else if string(contents) != "outside" {
			t.Fatalf("outside sentinel changed to %q", contents)
		}
	})

	t.Run("cleanup", func(t *testing.T) {
		agentDir := t.TempDir()
		outsideDir := t.TempDir()
		sentinel := filepath.Join(outsideDir, "sentinel")
		if err := os.WriteFile(sentinel, []byte("outside"), 0o600); err != nil {
			t.Fatalf("write outside sentinel: %v", err)
		}
		buildRoot := filepath.Join(agentDir, privateCargoBuildRoot)
		buildDir := filepath.Join(buildRoot, "build-one")
		targetDir := filepath.Join(buildDir, "target")
		if err := ensurePrivateCargoBuildDirectories(
			buildRoot,
			buildDir,
			targetDir,
		); err != nil {
			t.Fatalf("create private Cargo build paths: %v", err)
		}
		if err := os.RemoveAll(buildRoot); err != nil {
			t.Fatalf("remove private Cargo root before swap: %v", err)
		}
		if err := os.Symlink(outsideDir, buildRoot); err != nil {
			t.Skipf("filesystem does not permit symlink test: %v", err)
		}

		err := removePrivateCargoBuildDirectory(
			buildRoot,
			buildDir,
			targetDir,
		)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("symlinked cleanup root error = %v", err)
		}
		if contents, err := os.ReadFile(sentinel); err != nil {
			t.Fatalf("symlink-safe cleanup removed outside sentinel: %v", err)
		} else if string(contents) != "outside" {
			t.Fatalf("outside sentinel changed to %q", contents)
		}
	})
}

func TestPayloadGenerateRequestRequiresOneBoundedStrictJSONValue(
	t *testing.T,
) {
	handler := NewPayloadHandlerForIsolatedLab(t.TempDir(), t.TempDir())
	testCases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "unknown field",
			body:       `{"listener":"listener-one","unexpected":true}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "trailing value",
			body:       `{"listener":"listener-one"} {}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "oversized",
			body: `{"listener":"` +
				strings.Repeat("a", maxPayloadRequestBytes) +
				`"}`,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/payload/generate",
				strings.NewReader(testCase.body),
			)
			response := httptest.NewRecorder()
			handler.HandleGeneratePayload(response, request)
			if response.Code != testCase.wantStatus {
				t.Fatalf(
					"payload request status = %d, want %d: %s",
					response.Code,
					testCase.wantStatus,
					response.Body.String(),
				)
			}
		})
	}
}

func TestPayloadEnrollmentRevokeOperatorRoute(t *testing.T) {
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}

	var bootstrapCredential string
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found && name == "ENROLLMENT_CREDENTIAL" {
				bootstrapCredential = value
			}
		}
		for index := 0; index+1 < len(command.Args); index++ {
			if command.Args[index] != "--output" {
				continue
			}
			return []byte("hook build complete"), os.WriteFile(
				filepath.Join(command.Args[index+1], "agent"),
				[]byte("fake agent"),
				0o600,
			)
		}
		return nil, errors.New("build command omitted --output")
	}
	result, err := handler.GeneratePayload(testPayloadConfig())
	if err != nil {
		t.Fatalf("generate revocable payload: %v", err)
	}
	if bootstrapCredential == "" {
		t.Fatal("payload build omitted its bootstrap credential")
	}
	enrolled, err := handler.enrollment.Enroll(
		context.Background(),
		enrollment.EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: result.ID,
			Bootstrap:      bootstrapCredential,
		},
	)
	if err != nil {
		t.Fatalf("enroll existing session: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	revokePath := "/api/payload/" + result.ID + "/enrollment/revoke"
	operator := audit.Actor{
		Kind: audit.ActorOperator,
		ID:   "payload-revocation-test",
	}
	serve := func(
		t *testing.T,
		method string,
		path string,
		body string,
	) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request = request.WithContext(
			audit.WithActor(request.Context(), operator),
		)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf(
				"%s %s Cache-Control = %q, want no-store",
				method,
				path,
				response.Header().Get("Cache-Control"),
			)
		}
		if strings.Contains(response.Body.String(), bootstrapCredential) {
			t.Fatalf("%s %s exposed the bootstrap credential", method, path)
		}
		return response
	}

	testCases := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "method",
			method:     http.MethodGet,
			path:       revokePath,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "query",
			method:     http.MethodPost,
			path:       revokePath + "?force=true",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "nonempty body",
			method:     http.MethodPost,
			path:       revokePath,
			body:       "x",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "oversized body",
			method:     http.MethodPost,
			path:       revokePath,
			body:       "xx",
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "invalid payload ID",
			method:     http.MethodPost,
			path:       "/api/payload/bad$id/enrollment/revoke",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "trailing slash",
			method:     http.MethodPost,
			path:       revokePath + "/",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "unknown payload",
			method:     http.MethodPost,
			path:       "/api/payload/unknown-build/enrollment/revoke",
			wantStatus: http.StatusNotFound,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			response := serve(
				t,
				testCase.method,
				testCase.path,
				testCase.body,
			)
			if response.Code != testCase.wantStatus {
				t.Fatalf(
					"status = %d, want %d: %s",
					response.Code,
					testCase.wantStatus,
					response.Body.String(),
				)
			}
			if testCase.name == "method" &&
				response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf(
					"Allow = %q, want POST",
					response.Header().Get("Allow"),
				)
			}
		})
	}
	var rejectedBeforeMutation int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM audit_events
		 WHERE action = 'payload.enrollment.revoke.rejected'`,
	).Scan(&rejectedBeforeMutation); err != nil {
		t.Fatalf("count rejected payload revocation events: %v", err)
	}
	if rejectedBeforeMutation != 6 {
		t.Fatalf(
			"rejected payload revocation event count = %d, want 6",
			rejectedBeforeMutation,
		)
	}

	if _, err := database.SQL().Exec(
		`CREATE TRIGGER reject_payload_enrollment_revoke_audit
		 BEFORE INSERT ON audit_events
		 WHEN NEW.action = 'payload.enrollment.revoke'
		 BEGIN
		     SELECT RAISE(ABORT, 'injected payload revocation audit failure');
		 END`,
	); err != nil {
		t.Fatalf("create payload revocation audit failure trigger: %v", err)
	}
	response := serve(t, http.MethodPost, revokePath, "")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"audit-failed revocation status = %d, want 500: %s",
			response.Code,
			response.Body.String(),
		)
	}
	var revokedCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = ? AND revoked_at IS NOT NULL`,
		result.ID,
	).Scan(&revokedCount); err != nil {
		t.Fatalf("inspect rolled-back payload revocation: %v", err)
	}
	if revokedCount != 0 {
		t.Fatal("payload credential revocation survived failed audit append")
	}
	var rejectedAfterAuditFailure int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM audit_events
		 WHERE action = 'payload.enrollment.revoke.rejected'`,
	).Scan(&rejectedAfterAuditFailure); err != nil {
		t.Fatalf("count audit-failed payload revocation event: %v", err)
	}
	if rejectedAfterAuditFailure != 7 {
		t.Fatalf(
			"rejected payload revocation event count after audit failure = %d, want 7",
			rejectedAfterAuditFailure,
		)
	}
	if _, err := database.SQL().Exec(
		`DROP TRIGGER reject_payload_enrollment_revoke_audit`,
	); err != nil {
		t.Fatalf("drop payload revocation audit failure trigger: %v", err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		response := serve(t, http.MethodPost, revokePath, "")
		if response.Code != http.StatusNoContent {
			t.Fatalf(
				"revocation attempt %d status = %d, want 204: %s",
				attempt+1,
				response.Code,
				response.Body.String(),
			)
		}
		if response.Body.Len() != 0 {
			t.Fatalf(
				"revocation attempt %d returned a body: %q",
				attempt+1,
				response.Body.String(),
			)
		}
	}

	var rootSequence int64
	if err := database.SQL().QueryRow(
		`SELECT created_audit_event_seq
		 FROM payload_builds
		 WHERE id = ?`,
		result.ID,
	).Scan(&rootSequence); err != nil {
		t.Fatalf("read revoked payload audit root: %v", err)
	}
	rows, err := database.SQL().Query(
		`SELECT
		     actor_kind, actor_id, outcome, causation_sequence,
		     listener_id, payload_build_id
		 FROM audit_events
		 WHERE action = 'payload.enrollment.revoke'
		 ORDER BY seq`,
	)
	if err != nil {
		t.Fatalf("query payload revocation audit events: %v", err)
	}
	defer rows.Close()
	revocationEvents := 0
	for rows.Next() {
		var actorKind, actorID, outcome, listenerID, payloadBuildID string
		var causation int64
		if err := rows.Scan(
			&actorKind,
			&actorID,
			&outcome,
			&causation,
			&listenerID,
			&payloadBuildID,
		); err != nil {
			t.Fatalf("scan payload revocation audit event: %v", err)
		}
		revocationEvents++
		if actorKind != string(operator.Kind) ||
			actorID != operator.ID ||
			outcome != string(audit.OutcomeSucceeded) ||
			causation != rootSequence ||
			listenerID != "listener-one" ||
			payloadBuildID != result.ID {
			t.Fatalf(
				"unexpected payload revocation audit event: actor=%s/%s outcome=%s cause=%d listener=%s payload=%s",
				actorKind,
				actorID,
				outcome,
				causation,
				listenerID,
				payloadBuildID,
			)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate payload revocation audit events: %v", err)
	}
	if revocationEvents != 2 {
		t.Fatalf(
			"payload revocation audit event count = %d, want 2",
			revocationEvents,
		)
	}

	for _, agentID := range []string{"agent-one", "agent-two"} {
		_, err := handler.enrollment.Enroll(
			context.Background(),
			enrollment.EnrollRequest{
				ListenerID:     "listener-one",
				AgentID:        agentID,
				PayloadBuildID: result.ID,
				Bootstrap:      bootstrapCredential,
			},
		)
		if !errors.Is(err, enrollment.ErrUnauthorized) {
			t.Fatalf(
				"bootstrap after retirement for %s error = %v, want unauthorized",
				agentID,
				err,
			)
		}
	}
	if _, err := handler.enrollment.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	); err != nil {
		t.Fatalf("existing session after build retirement: %v", err)
	}
}

func TestPayloadGenerationRejectsInvalidSessionAllowance(t *testing.T) {
	handler := NewPayloadHandlerForIsolatedLab(t.TempDir(), t.TempDir())
	body, err := json.Marshal(PayloadConfig{
		ListenerID:  "listener-one",
		MaxSessions: 65,
	})
	if err != nil {
		t.Fatalf("marshal invalid payload request: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/payload/generate",
		bytes.NewReader(body),
	)
	handler.HandleGeneratePayload(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"invalid max_sessions status = %d, want 400: %s",
			recorder.Code,
			recorder.Body.String(),
		)
	}
}

func TestPayloadHandlerRequiresExplicitLabOverrideForHTTP(t *testing.T) {
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
	handler := NewPayloadHandler(
		filepath.Join(tempDir, "static", "payloads"),
		agentDir,
	)
	_, err := handler.GeneratePayload(testPayloadConfig())
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("HTTP payload error = %v, want explicit-lab rejection", err)
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

	handler := NewPayloadHandlerForIsolatedLab(filepath.Join(tempDir, "static", "payloads"), agentDir)
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

func TestPayloadBuildAuditRootPrecedesBuildFilesystemSideEffects(t *testing.T) {
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}
	if _, err := database.SQL().Exec(
		`CREATE TRIGGER reject_payload_build_requested_audit
		 BEFORE INSERT ON audit_events
		 WHEN NEW.action = 'payload.build.requested'
		 BEGIN
		     SELECT RAISE(ABORT, 'injected requested audit failure');
		 END`,
	); err != nil {
		t.Fatalf("create requested audit failure trigger: %v", err)
	}
	buildInvoked := false
	handler.runBuild = func(*exec.Cmd) ([]byte, error) {
		buildInvoked = true
		return nil, errors.New("build must not run")
	}

	if _, err := handler.GeneratePayload(testPayloadConfig()); err == nil {
		t.Fatal("payload generation succeeded despite rejected audit root")
	}
	if buildInvoked {
		t.Fatal("payload build ran before its durable audit root")
	}
	var buildCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM payload_builds`,
	).Scan(&buildCount); err != nil {
		t.Fatalf("count payload builds: %v", err)
	}
	if buildCount != 0 {
		t.Fatalf("rejected audit root retained %d payload build rows", buildCount)
	}
	entries, err := os.ReadDir(filepath.Join(payloadsDir, "debug"))
	if err != nil {
		t.Fatalf("read debug payload root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected audit root created build filesystem entries: %v", entries)
	}
}

func TestPayloadCompletionAuditFailureRollsBackCredentialActivation(t *testing.T) {
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		database,
	)
	if err != nil {
		t.Fatalf("create persistent payload handler: %v", err)
	}
	if _, err := database.SQL().Exec(
		`CREATE TRIGGER reject_payload_build_completed_audit
		 BEFORE INSERT ON audit_events
		 WHEN NEW.action = 'payload.build.completed'
		 BEGIN
		     SELECT RAISE(ABORT, 'injected completed audit failure');
		 END`,
	); err != nil {
		t.Fatalf("create completed audit failure trigger: %v", err)
	}
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		for index := 0; index+1 < len(command.Args); index++ {
			if command.Args[index] != "--output" {
				continue
			}
			return []byte("untrusted compiler output"), os.WriteFile(
				filepath.Join(command.Args[index+1], "agent"),
				[]byte("fake agent"),
				0o600,
			)
		}
		return nil, errors.New("build command omitted --output")
	}

	if _, err := handler.GeneratePayload(testPayloadConfig()); err == nil {
		t.Fatal("payload generation succeeded despite rejected completion audit")
	}
	var buildID, state string
	if err := database.SQL().QueryRow(
		`SELECT id, state
		 FROM payload_builds
		 ORDER BY rowid DESC
		 LIMIT 1`,
	).Scan(&buildID, &state); err != nil {
		t.Fatalf("read failed payload build: %v", err)
	}
	if state != payloadStateFailed {
		t.Fatalf("payload state = %q, want %q", state, payloadStateFailed)
	}
	var credentialCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = ?`,
		buildID,
	).Scan(&credentialCount); err != nil {
		t.Fatalf("count payload credentials: %v", err)
	}
	if credentialCount != 0 {
		t.Fatalf(
			"failed completion retained %d activated payload credentials",
			credentialCount,
		)
	}
	page, err := handler.audit.Page(
		context.Background(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page completion failure audit: %v", err)
	}
	if page.Total != 2 ||
		page.Events[0].Action != "payload.build.failed" ||
		page.Events[1].Action != "payload.build.requested" ||
		page.Events[0].CausationSequence == nil ||
		*page.Events[0].CausationSequence != page.Events[1].Sequence {
		t.Fatalf("unexpected completion failure audit chain: %#v", page.Events)
	}
}

func TestPayloadBuildAuditRootCompletionAndRedactionSurviveRestart(
	t *testing.T,
) {
	tempDir := t.TempDir()
	payloadsDir := filepath.Join(tempDir, "payload-root")
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	databasePath := filepath.Join(tempDir, "state.db")
	firstDatabase, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("open first persistence database: %v", err)
	}
	firstHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		firstDatabase,
	)
	if err != nil {
		_ = firstDatabase.Close()
		t.Fatalf("create first persistent handler: %v", err)
	}

	const buildOutputMarker = "sensitive-build-output-marker"
	var bootstrapCredential string
	var buildOutput []byte
	firstHandler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		outputDir := ""
		for _, entry := range command.Env {
			name, value, found := strings.Cut(entry, "=")
			if found && name == "ENROLLMENT_CREDENTIAL" {
				bootstrapCredential = value
			}
		}
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
			return nil, fmt.Errorf("write hooked payload artifact: %w", err)
		}
		buildOutput = []byte(
			buildOutputMarker + "; credential=" + bootstrapCredential,
		)
		return buildOutput, nil
	}

	operator := audit.Actor{
		Kind: audit.ActorOperator,
		ID:   "payload-audit-test-operator",
	}
	result, err := firstHandler.GeneratePayloadWithContext(
		audit.WithActor(context.Background(), operator),
		testPayloadConfig(),
	)
	if err != nil {
		_ = firstDatabase.Close()
		t.Fatalf("generate persistent payload: %v", err)
	}
	if bootstrapCredential == "" ||
		!bytes.Contains(buildOutput, []byte(bootstrapCredential)) {
		_ = firstDatabase.Close()
		t.Fatal("test build did not exercise secret-bearing build output")
	}

	var rootSequence int64
	if err := firstDatabase.SQL().QueryRow(
		`SELECT created_audit_event_seq
		 FROM payload_builds
		 WHERE id = ?`,
		result.ID,
	).Scan(&rootSequence); err != nil {
		_ = firstDatabase.Close()
		t.Fatalf("read payload audit root: %v", err)
	}
	if rootSequence <= 0 {
		_ = firstDatabase.Close()
		t.Fatalf("payload audit root sequence = %d, want positive", rootSequence)
	}

	assertLifecycle := func(t *testing.T, store *audit.Store) {
		t.Helper()
		page, err := store.Page(
			context.Background(),
			audit.PageOptions{Limit: 10},
		)
		if err != nil {
			t.Fatalf("page payload audit events: %v", err)
		}
		if page.Total != 2 || len(page.Events) != 2 {
			t.Fatalf(
				"payload audit event count = %d/%d, want 2/2: %#v",
				page.Total,
				len(page.Events),
				page.Events,
			)
		}
		completed := page.Events[0]
		requested := page.Events[1]
		wantTarget := audit.Target{Kind: "payload_build", ID: result.ID}
		if requested.Sequence != rootSequence ||
			requested.Actor != operator ||
			requested.Action != "payload.build.requested" ||
			requested.Route != "POST /api/payload/generate" ||
			requested.Target != wantTarget ||
			requested.Outcome != audit.OutcomeSucceeded ||
			requested.CausationSequence != nil ||
			requested.ListenerID != "listener-one" ||
			requested.PayloadBuildID != result.ID {
			t.Fatalf("unexpected requested payload audit root: %#v", requested)
		}
		if completed.Sequence <= requested.Sequence ||
			completed.Actor != operator ||
			completed.Action != "payload.build.completed" ||
			completed.Route != "POST /api/payload/generate" ||
			completed.Target != wantTarget ||
			completed.Outcome != audit.OutcomeSucceeded ||
			completed.CausationSequence == nil ||
			*completed.CausationSequence != rootSequence ||
			completed.ListenerID != "listener-one" ||
			completed.PayloadBuildID != result.ID {
			t.Fatalf("unexpected completed payload audit event: %#v", completed)
		}

		serialized, err := json.Marshal(page.Events)
		if err != nil {
			t.Fatalf("marshal payload audit events: %v", err)
		}
		for name, forbidden := range map[string]string{
			"build output":         buildOutputMarker,
			"bootstrap credential": bootstrapCredential,
		} {
			if bytes.Contains(serialized, []byte(forbidden)) {
				t.Fatalf("payload audit events exposed %s: %s", name, serialized)
			}
		}
	}
	assertLifecycle(t, firstHandler.audit)

	if err := firstDatabase.Close(); err != nil {
		t.Fatalf("close first persistence database: %v", err)
	}
	secondDatabase, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("reopen persistence database: %v", err)
	}
	t.Cleanup(func() {
		if err := secondDatabase.Close(); err != nil {
			t.Errorf("close restarted persistence database: %v", err)
		}
	})
	secondHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		agentDir,
		testListenerLookup(),
		secondDatabase,
	)
	if err != nil {
		t.Fatalf("create restarted persistent handler: %v", err)
	}
	assertLifecycle(t, secondHandler.audit)
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
	firstHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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
	secondHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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
			firstHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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
			secondHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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

	firstRestartHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		filepath.Join(tempDir, "agent"),
		testListenerLookup(),
		database,
	)
	if err != nil {
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
	var rootSequence int64
	if err := database.SQL().QueryRow(
		`SELECT created_audit_event_seq
		 FROM payload_builds
		 WHERE id = ?`,
		payloadID,
	).Scan(&rootSequence); err != nil {
		t.Fatalf("read recovered payload audit root: %v", err)
	}
	firstPage, err := firstRestartHandler.audit.Page(
		context.Background(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page first-restart payload audit events: %v", err)
	}
	if firstPage.Total != 2 || len(firstPage.Events) != 2 {
		t.Fatalf(
			"first-restart audit event count = %d/%d, want 2/2: %#v",
			firstPage.Total,
			len(firstPage.Events),
			firstPage.Events,
		)
	}
	interrupted := firstPage.Events[0]
	recovered := firstPage.Events[1]
	systemActor := audit.DefaultSystemActor()
	wantTarget := audit.Target{Kind: "payload_build", ID: payloadID}
	if rootSequence <= 0 ||
		recovered.Sequence != rootSequence ||
		recovered.Actor != systemActor ||
		recovered.Action != "payload.build.recovered" ||
		recovered.Route != "internal:payload_recovery" ||
		recovered.Target != wantTarget ||
		recovered.Outcome != audit.OutcomeSucceeded ||
		recovered.ReasonCode != "missing_audit_root" ||
		recovered.CausationSequence != nil ||
		recovered.ListenerID != "listener-one" ||
		recovered.PayloadBuildID != payloadID {
		t.Fatalf("unexpected recovered payload audit root: %#v", recovered)
	}
	if interrupted.Sequence <= recovered.Sequence ||
		interrupted.Actor != systemActor ||
		interrupted.Action != "payload.build.interrupted" ||
		interrupted.Route != "internal:payload_recovery" ||
		interrupted.Target != wantTarget ||
		interrupted.Outcome != audit.OutcomeFailed ||
		interrupted.ReasonCode != "server_restart" ||
		interrupted.CausationSequence == nil ||
		*interrupted.CausationSequence != rootSequence ||
		interrupted.ListenerID != "listener-one" ||
		interrupted.PayloadBuildID != payloadID {
		t.Fatalf("unexpected interrupted payload audit event: %#v", interrupted)
	}

	const sentinelDetail = "already reconciled"
	if _, err := database.SQL().Exec(
		`UPDATE payload_builds SET state_detail = ? WHERE id = ?`,
		sentinelDetail,
		payloadID,
	); err != nil {
		t.Fatalf("set interrupted sentinel detail: %v", err)
	}
	secondRestartHandler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
		payloadsDir,
		filepath.Join(tempDir, "agent"),
		testListenerLookup(),
		database,
	)
	if err != nil {
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
	secondPage, err := secondRestartHandler.audit.Page(
		context.Background(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page second-restart payload audit events: %v", err)
	}
	if secondPage.Total != 2 ||
		len(secondPage.Events) != 2 ||
		secondPage.Events[0].Sequence != interrupted.Sequence ||
		secondPage.Events[1].Sequence != recovered.Sequence {
		t.Fatalf(
			"second restart duplicated or changed payload audit events: %#v",
			secondPage,
		)
	}
}

func TestPayloadArtifactOperationsRejectSymlinkEscapes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on Windows")
	}

	for _, test := range []struct {
		name  string
		setup func(t *testing.T, payloadRoot, outsideDir string)
	}{
		{
			name: "parent component",
			setup: func(t *testing.T, payloadRoot, outsideDir string) {
				t.Helper()
				if err := os.Symlink(
					outsideDir,
					filepath.Join(payloadRoot, "release", "build"),
				); err != nil {
					t.Fatalf("create parent symlink: %v", err)
				}
			},
		},
		{
			name: "final components",
			setup: func(t *testing.T, payloadRoot, outsideDir string) {
				t.Helper()
				buildDir := filepath.Join(payloadRoot, "release", "build")
				if err := os.Mkdir(buildDir, 0700); err != nil {
					t.Fatalf("create payload build directory: %v", err)
				}
				for _, filename := range []string{"agent", "provenance.json"} {
					if err := os.Symlink(
						filepath.Join(outsideDir, filename),
						filepath.Join(buildDir, filename),
					); err != nil {
						t.Fatalf("create %s symlink: %v", filename, err)
					}
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			payloadRoot := filepath.Join(tempDir, "payload-root")
			outsideDir := filepath.Join(tempDir, "outside")
			stagingRoot := filepath.Join(tempDir, "staging")
			if err := os.MkdirAll(
				filepath.Join(payloadRoot, "release"),
				0700,
			); err != nil {
				t.Fatalf("create payload root: %v", err)
			}
			if err := os.Mkdir(outsideDir, 0700); err != nil {
				t.Fatalf("create outside directory: %v", err)
			}
			if err := os.MkdirAll(
				filepath.Join(stagingRoot, "output"),
				0700,
			); err != nil {
				t.Fatalf("create staging directory: %v", err)
			}
			if err := os.WriteFile(
				filepath.Join(stagingRoot, "output", "agent"),
				[]byte("trusted staged artifact"),
				0600,
			); err != nil {
				t.Fatalf("write staged artifact: %v", err)
			}

			artifactSentinel := []byte("outside artifact sentinel")
			provenanceSentinel := []byte("outside provenance sentinel")
			artifactPath := filepath.Join(outsideDir, "agent")
			provenancePath := filepath.Join(outsideDir, "provenance.json")
			if err := os.WriteFile(artifactPath, artifactSentinel, 0644); err != nil {
				t.Fatalf("write outside artifact sentinel: %v", err)
			}
			if err := os.WriteFile(
				provenancePath,
				provenanceSentinel,
				0644,
			); err != nil {
				t.Fatalf("write outside provenance sentinel: %v", err)
			}
			originalInfo, err := os.Stat(artifactPath)
			if err != nil {
				t.Fatalf("stat outside artifact sentinel: %v", err)
			}

			test.setup(t, payloadRoot, outsideDir)
			handler := &PayloadHandler{payloadsDir: payloadRoot}
			relativeArtifact := filepath.ToSlash(
				filepath.Join("release", "build", "agent"),
			)
			if _, _, err := handler.publishGeneratedArtifact(
				stagingRoot,
				filepath.Join("output", "agent"),
				relativeArtifact,
			); err == nil {
				t.Fatal("symlinked artifact publication unexpectedly succeeded")
			}
			file, state, _, _ := handler.openVerifiedPayload(
				payloadBuildRecord{
					Filename:       "agent",
					RelativePath:   relativeArtifact,
					Size:           int64(len(artifactSentinel)),
					ProvenanceJSON: []byte("{}"),
				},
			)
			if file != nil {
				_ = file.Close()
				t.Fatal("symlinked artifact verification unexpectedly succeeded")
			}
			if state == payloadStateCompleted {
				t.Fatal("symlinked artifact was marked completed")
			}
			if err := writeProvenance(
				payloadRoot,
				relativeArtifact,
				map[string]interface{}{"source": "attacker-controlled"},
			); err == nil {
				t.Fatal("symlinked provenance write unexpectedly succeeded")
			}

			gotArtifact, err := os.ReadFile(artifactPath)
			if err != nil {
				t.Fatalf("read outside artifact sentinel: %v", err)
			}
			if !bytes.Equal(gotArtifact, artifactSentinel) {
				t.Fatalf(
					"outside artifact changed to %q",
					gotArtifact,
				)
			}
			gotProvenance, err := os.ReadFile(provenancePath)
			if err != nil {
				t.Fatalf("read outside provenance sentinel: %v", err)
			}
			if !bytes.Equal(gotProvenance, provenanceSentinel) {
				t.Fatalf(
					"outside provenance changed to %q",
					gotProvenance,
				)
			}
			infoAfter, err := os.Stat(artifactPath)
			if err != nil {
				t.Fatalf("restat outside artifact sentinel: %v", err)
			}
			if infoAfter.Mode().Perm() != originalInfo.Mode().Perm() {
				t.Fatalf(
					"outside artifact mode changed from %o to %o",
					originalInfo.Mode().Perm(),
					infoAfter.Mode().Perm(),
				)
			}
		})
	}
}

func TestPayloadDirectoryCreationRejectsSymlinkClass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on Windows")
	}

	tempDir := t.TempDir()
	payloadRoot := filepath.Join(tempDir, "payload-root")
	outsideDir := filepath.Join(tempDir, "outside")
	if err := os.Mkdir(payloadRoot, 0700); err != nil {
		t.Fatalf("create payload root: %v", err)
	}
	if err := os.Mkdir(outsideDir, 0700); err != nil {
		t.Fatalf("create outside directory: %v", err)
	}
	if err := os.Symlink(
		outsideDir,
		filepath.Join(payloadRoot, "release"),
	); err != nil {
		t.Fatalf("create payload class symlink: %v", err)
	}

	if err := createPayloadBuildDirectory(
		payloadRoot,
		"release",
		"build",
	); err == nil {
		t.Fatal("created a build directory through a symlinked class")
	}
	if _, err := os.Stat(
		filepath.Join(outsideDir, "build"),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside build directory was created: %v", err)
	}
}

func TestPayloadArtifactParentSwapNeverEscapesRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires privileges on Windows")
	}

	tempDir := t.TempDir()
	payloadRoot := filepath.Join(tempDir, "payload-root")
	releaseDir := filepath.Join(payloadRoot, "release")
	buildDir := filepath.Join(releaseDir, "build")
	parkedBuildDir := filepath.Join(releaseDir, "build.real")
	outsideDir := filepath.Join(tempDir, "outside")
	stagingRoot := filepath.Join(tempDir, "staging")
	if err := os.MkdirAll(buildDir, 0700); err != nil {
		t.Fatalf("create payload build directory: %v", err)
	}
	if err := os.Mkdir(outsideDir, 0700); err != nil {
		t.Fatalf("create outside directory: %v", err)
	}
	if err := os.MkdirAll(
		filepath.Join(stagingRoot, "output"),
		0700,
	); err != nil {
		t.Fatalf("create staging directory: %v", err)
	}

	trustedArtifact := []byte("trusted artifact")
	outsideArtifact := []byte("outside artifact sentinel")
	outsideProvenance := []byte("outside provenance sentinel")
	if err := os.WriteFile(
		filepath.Join(buildDir, "agent"),
		trustedArtifact,
		0600,
	); err != nil {
		t.Fatalf("write trusted artifact: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(outsideDir, "agent"),
		outsideArtifact,
		0644,
	); err != nil {
		t.Fatalf("write outside artifact sentinel: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(outsideDir, "provenance.json"),
		outsideProvenance,
		0644,
	); err != nil {
		t.Fatalf("write outside provenance sentinel: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(stagingRoot, "output", "agent"),
		trustedArtifact,
		0600,
	); err != nil {
		t.Fatalf("write staged artifact: %v", err)
	}

	stop := make(chan struct{})
	swapResult := make(chan error, 1)
	var stopOnce sync.Once
	stopSwap := func() {
		stopOnce.Do(func() {
			close(stop)
		})
	}
	t.Cleanup(stopSwap)
	go func() {
		for {
			if err := os.Rename(buildDir, parkedBuildDir); err != nil {
				swapResult <- fmt.Errorf("park build directory: %w", err)
				return
			}
			if err := os.Symlink(outsideDir, buildDir); err != nil {
				swapResult <- fmt.Errorf("install parent symlink: %w", err)
				return
			}
			runtime.Gosched()
			if err := os.Remove(buildDir); err != nil {
				swapResult <- fmt.Errorf("remove parent symlink: %w", err)
				return
			}
			if err := os.Rename(parkedBuildDir, buildDir); err != nil {
				swapResult <- fmt.Errorf("restore build directory: %w", err)
				return
			}
			runtime.Gosched()
			select {
			case <-stop:
				swapResult <- nil
				return
			default:
			}
		}
	}()

	relativeArtifact := filepath.ToSlash(
		filepath.Join("release", "build", "agent"),
	)
	handler := &PayloadHandler{payloadsDir: payloadRoot}
	successfulOpens, successfulPublications := 0, 0
	for iteration := range 500 {
		file, err := openPayloadArtifactBeneath(
			payloadRoot,
			relativeArtifact,
		)
		if err == nil {
			content, readErr := io.ReadAll(file)
			closeErr := file.Close()
			if readErr != nil {
				t.Fatalf("read safely opened artifact: %v", readErr)
			}
			if closeErr != nil {
				t.Fatalf("close safely opened artifact: %v", closeErr)
			}
			if !bytes.Equal(content, trustedArtifact) {
				t.Fatalf("safely opened artifact contained %q", content)
			}
			successfulOpens++
		}
		if _, _, err := handler.publishGeneratedArtifact(
			stagingRoot,
			filepath.Join("output", "agent"),
			filepath.ToSlash(filepath.Join(
				"release",
				"build",
				fmt.Sprintf("published-%d", iteration),
			)),
		); err == nil {
			successfulPublications++
		}
		_ = writeProvenance(
			payloadRoot,
			relativeArtifact,
			map[string]interface{}{"source": "trusted"},
		)
	}
	stopSwap()
	if err := <-swapResult; err != nil {
		t.Fatal(err)
	}
	if successfulOpens == 0 {
		t.Fatal("swap test never opened the legitimate artifact")
	}
	if successfulPublications == 0 {
		t.Fatal("swap test never published into the legitimate directory")
	}

	gotOutsideArtifact, err := os.ReadFile(
		filepath.Join(outsideDir, "agent"),
	)
	if err != nil {
		t.Fatalf("read outside artifact sentinel: %v", err)
	}
	if !bytes.Equal(gotOutsideArtifact, outsideArtifact) {
		t.Fatalf("outside artifact changed to %q", gotOutsideArtifact)
	}
	gotOutsideProvenance, err := os.ReadFile(
		filepath.Join(outsideDir, "provenance.json"),
	)
	if err != nil {
		t.Fatalf("read outside provenance sentinel: %v", err)
	}
	if !bytes.Equal(gotOutsideProvenance, outsideProvenance) {
		t.Fatalf("outside provenance changed to %q", gotOutsideProvenance)
	}
	outsideEntries, err := os.ReadDir(outsideDir)
	if err != nil {
		t.Fatalf("list outside directory: %v", err)
	}
	if len(outsideEntries) != 2 {
		t.Fatalf("outside directory gained entries: %#v", outsideEntries)
	}
}

func TestGeneratePayloadDoesNotUseLegacyFallbackArtifact(t *testing.T) {
	tempDir := t.TempDir()
	payloadRoot := filepath.Join(tempDir, "payload-root")
	agentDir := filepath.Join(tempDir, "agent")
	writePlaceholderBuildScript(t, agentDir)
	handler, err := newPayloadHandler(
		payloadRoot,
		agentDir,
		testListenerLookup(),
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("create payload handler: %v", err)
	}

	var legacyArtifactPath string
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		var buildType, format, payloadID string
		for index := 0; index+1 < len(command.Args); index++ {
			switch command.Args[index] {
			case "--build-type":
				buildType = command.Args[index+1]
			case "--format":
				format = command.Args[index+1]
			case "--payload-id":
				payloadID = command.Args[index+1]
			}
		}
		legacyArtifactPath = filepath.Join(
			agentDir,
			"static",
			"payloads",
			buildType,
			payloadID,
			payloadFilename(format),
		)
		if err := os.MkdirAll(
			filepath.Dir(legacyArtifactPath),
			0700,
		); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(
			legacyArtifactPath,
			[]byte("legacy fallback artifact"),
			0600,
		)
	}

	if _, err := handler.GeneratePayload(testPayloadConfig()); err == nil {
		t.Fatal("generation accepted an artifact outside the build contract")
	}
	if legacyArtifactPath == "" {
		t.Fatal("build hook did not create the legacy artifact")
	}
	info, err := os.Stat(legacyArtifactPath)
	if err != nil {
		t.Fatalf("stat legacy artifact: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf(
			"legacy artifact mode changed to %o",
			info.Mode().Perm(),
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
	artifactFile, err := os.Open(artifactPath)
	if err != nil {
		t.Fatalf("open trusted artifact: %v", err)
	}
	artifactHash, err := hashOpenArtifact(artifactFile)
	if closeErr := artifactFile.Close(); err == nil {
		err = closeErr
	}
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
	handler, err := NewPayloadHandlerWithPersistenceForIsolatedLab(
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
	_ string,
) {
	t.Helper()
	handler.runBuild = func(command *exec.Cmd) ([]byte, error) {
		var relativePath, filename, state, artifactHash string
		var size int64
		var provenanceJSON []byte
		if err := database.SQL().QueryRow(
			`SELECT relative_path, filename, state, size, sha256, provenance_json
			 FROM payload_builds
			 WHERE state = ?
			 ORDER BY created_at DESC
			 LIMIT 1`,
			payloadStateBuilding,
		).Scan(
			&relativePath,
			&filename,
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
		outputDir := ""
		for index := 0; index+1 < len(command.Args); index++ {
			if command.Args[index] == "--output" {
				outputDir = command.Args[index+1]
				break
			}
		}
		if outputDir == "" {
			t.Fatal("build command omitted --output")
		}
		if err := os.WriteFile(
			filepath.Join(outputDir, filename),
			[]byte("fake agent"),
			0644,
		); err != nil {
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
