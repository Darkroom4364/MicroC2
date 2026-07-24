package listeners

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"microc2/server/internal/audit"
	"microc2/server/internal/common"
	"microc2/server/internal/persistence"
)

func TestDurableHTTPListenerRestartRequiresExplicitLabOverride(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	labManager, err := NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		listenersDir,
		database,
	)
	if err != nil {
		t.Fatalf("create isolated-lab listener manager: %v", err)
	}
	listener, err := labManager.CreateListener(ListenerConfig{
		Name:     "durable-http",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err != nil {
		t.Fatalf("create durable HTTP listener: %v", err)
	}
	if err := listener.Stop(); err != nil {
		t.Fatalf("stop runtime before simulated restart: %v", err)
	}

	_, err = NewListenerManagerWithPersistence(
		nil,
		listenersDir,
		database,
	)
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("default secure restart error = %v, want insecure transport rejection", err)
	}

	_, err = NewProductionListenerManager(
		nil,
		listenersDir,
		database,
		common.AgentTransportPolicy{},
	)
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("secure restart error = %v, want insecure transport rejection", err)
	}

	restarted, err := NewProductionListenerManager(
		nil,
		listenersDir,
		database,
		common.AgentTransportPolicy{AllowInsecureIsolatedLab: true},
	)
	if err != nil {
		t.Fatalf("restart with explicit isolated-lab override: %v", err)
	}
	reloaded, err := restarted.GetListener(listener.Config.ID)
	if err != nil {
		t.Fatalf("get reloaded HTTP listener: %v", err)
	}
	if got := reloaded.GetStatus(); got != StatusStopped {
		t.Fatalf("reloaded HTTP listener status = %s, want %s", got, StatusStopped)
	}
}

func TestListenerLifecycleEventsSurviveRestartAndRecoverStopped(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "custom-static", "listeners")
	databasePath := filepath.Join(root, "state", "microc2.db")

	database, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("create durable listener manager: %v", err)
	}
	listener, err := manager.CreateListenerWithContext(
		audit.WithActor(context.Background(), audit.Actor{
			Kind: audit.ActorOperator,
			ID:   "shared-token",
		}),
		ListenerConfig{
			Name:     "durable-listener",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     freeTCPPort(t),
		},
	)
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	listenerID := listener.Config.ID

	events, err := manager.ListListenerEvents(listenerID)
	if err != nil {
		t.Fatalf("list initial listener events: %v", err)
	}
	assertListenerEventTypes(t, events, "created", "started")
	assertListenerAuditLinks(
		t,
		database,
		listenerID,
		[]string{"listener.create", "listener.start"},
		[]string{"shared-token", "shared-token"},
	)

	// Model a process exit: the socket is closed, but the database retains the
	// last committed ACTIVE state because no graceful manager stop occurred.
	if err := listener.Stop(); err != nil {
		t.Fatalf("close listener socket before simulated restart: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	database, err = persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("reopen persistence database: %v", err)
	}
	defer database.Close()
	restarted, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("reload durable listener manager: %v", err)
	}
	reloaded, err := restarted.GetListener(listenerID)
	if err != nil {
		t.Fatalf("get reloaded listener: %v", err)
	}
	if got := reloaded.GetStatus(); got != StatusStopped {
		t.Fatalf("reloaded status = %s, want %s", got, StatusStopped)
	}
	events, err = restarted.ListListenerEvents(listenerID)
	if err != nil {
		t.Fatalf("list recovered listener events: %v", err)
	}
	assertListenerEventTypes(t, events, "created", "started", "recovered_stopped")
	assertListenerAuditLinks(
		t,
		database,
		listenerID,
		[]string{"listener.create", "listener.start", "listener.recover"},
		[]string{"shared-token", "shared-token", "microc2-server"},
	)

	// Reconciliation is idempotent: a second reload does not append another
	// recovery transition.
	reloadedAgain, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("reload listener manager twice: %v", err)
	}
	events, err = reloadedAgain.ListListenerEvents(listenerID)
	if err != nil {
		t.Fatalf("list idempotently recovered events: %v", err)
	}
	assertListenerEventTypes(t, events, "created", "started", "recovered_stopped")
}

func TestDeletedListenerIsNotResurrectedByStaleConfig(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	databasePath := filepath.Join(root, "state", "microc2.db")
	database, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("create durable listener manager: %v", err)
	}
	listener, err := manager.CreateListener(ListenerConfig{
		Name:     "deleted-listener",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	config := listener.Config
	if err := manager.DeleteListener(config.ID); err != nil {
		t.Fatalf("delete listener: %v", err)
	}

	// Simulate a stale compatibility projection left behind by an interrupted
	// filesystem cleanup.
	configDir := filepath.Join(listenersDir, config.Name)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("recreate stale config directory: %v", err)
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal stale config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configJSON, 0o644); err != nil {
		t.Fatalf("write stale config: %v", err)
	}

	restarted, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("reload listener manager: %v", err)
	}
	if got := restarted.ListListeners(); len(got) != 0 {
		t.Fatalf("tombstoned listener was resurrected: %#v", got)
	}
	events, err := restarted.ListListenerEvents(config.ID)
	if err != nil {
		t.Fatalf("list deleted listener events: %v", err)
	}
	assertListenerEventTypes(t, events, "created", "started", "stopped", "deleted")
}

func TestFailedDurableCreateIsTombstonedBeforeSameNameRetry(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	heldPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold listener port: %v", err)
	}
	port := heldPort.Addr().(*net.TCPAddr).Port

	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("create durable listener manager: %v", err)
	}
	config := ListenerConfig{
		Name:     "retry-after-failure",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     port,
	}
	if _, err := manager.CreateListener(config); err == nil {
		t.Fatal("listener unexpectedly bound a held port")
	}
	if got := manager.ListListeners(); len(got) != 0 {
		t.Fatalf("failed listener remained registered after tombstone: %#v", got)
	}

	var failedID string
	if err := database.SQL().QueryRow(
		`SELECT id
		 FROM listeners
		 WHERE name = ? AND deleted_at IS NOT NULL`,
		config.Name,
	).Scan(&failedID); err != nil {
		t.Fatalf("query tombstoned failed listener: %v", err)
	}
	var nondeleted int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM listeners
		 WHERE name = ? AND deleted_at IS NULL`,
		config.Name,
	).Scan(&nondeleted); err != nil {
		t.Fatalf("count nondeleted failed listeners: %v", err)
	}
	if nondeleted != 0 {
		t.Fatalf("failed create left %d nondeleted durable rows", nondeleted)
	}
	failedEvents, err := manager.ListListenerEvents(failedID)
	if err != nil {
		t.Fatalf("list failed creation events: %v", err)
	}
	assertListenerEventTypes(t, failedEvents, "created", "creation_failed")

	if err := heldPort.Close(); err != nil {
		t.Fatalf("release held listener port: %v", err)
	}
	retried, err := manager.CreateListener(config)
	if err != nil {
		t.Fatalf("retry listener after releasing port: %v", err)
	}
	if retried.Config.ID == failedID {
		t.Fatal("retry reused the tombstoned listener ID")
	}
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM listeners
		 WHERE name = ? AND deleted_at IS NULL`,
		config.Name,
	).Scan(&nondeleted); err != nil {
		t.Fatalf("count retried durable listeners: %v", err)
	}
	if nondeleted != 1 {
		t.Fatalf("same-name retry left %d nondeleted rows, want 1", nondeleted)
	}

	// Simulate a crash after the successful retry. Startup must ignore the
	// failed tombstone and recover only the successful listener.
	if err := retried.Stop(); err != nil {
		t.Fatalf("close retried listener socket: %v", err)
	}
	restarted, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("restart after same-name retry: %v", err)
	}
	if got := restarted.ListListeners(); len(got) != 1 {
		t.Fatalf("restarted listener count = %d, want 1", len(got))
	}
	if _, err := restarted.GetListener(failedID); err == nil {
		t.Fatal("tombstoned failed listener reappeared after restart")
	}
	if _, err := restarted.GetListener(retried.Config.ID); err != nil {
		t.Fatalf("successful retry missing after restart: %v", err)
	}
}

func TestDurableStoreRejectsDuplicateLiveListenerNames(t *testing.T) {
	root := t.TempDir()
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	first := ListenerConfig{
		ID:       "first-live-name",
		Name:     "SharedName",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41501,
	}
	second := ListenerConfig{
		ID:       "second-live-name",
		Name:     "sharedname",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41502,
	}
	insertDurableListenerForTest(t, database, first, StatusStopped, "")

	configJSON, checksum, err := encodedListenerConfig(second)
	if err != nil {
		t.Fatalf("encode duplicate listener config: %v", err)
	}
	const timestamp = "2026-07-24T12:00:00Z"
	insertSecond := func() error {
		_, err := database.SQL().Exec(
			`INSERT INTO listeners (
				id, name, config_json, config_sha256, status, last_error,
				created_at, updated_at, deleted_at
			) VALUES (?, ?, ?, ?, ?, '', ?, ?, NULL)`,
			second.ID,
			second.Name,
			configJSON,
			checksum,
			string(StatusStopped),
			timestamp,
			timestamp,
		)
		return err
	}
	if err := insertSecond(); err == nil {
		t.Fatal("database accepted duplicate case-insensitive live listener names")
	}
	if _, err := database.SQL().Exec(
		`UPDATE listeners
		 SET deleted_at = ?, updated_at = ?
		 WHERE id = ?`,
		timestamp,
		timestamp,
		first.ID,
	); err != nil {
		t.Fatalf("tombstone first listener: %v", err)
	}
	if err := insertSecond(); err != nil {
		t.Fatalf("reuse tombstoned listener name: %v", err)
	}
}

func TestDurableCreateRejectsSymlinkedListenerDirectory(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	if err := os.MkdirAll(listenersDir, 0o700); err != nil {
		t.Fatalf("create listeners directory: %v", err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("create outside directory: %v", err)
	}
	listenerDir := filepath.Join(listenersDir, "escape")
	if err := os.Symlink(outside, listenerDir); err != nil {
		t.Skipf("create listener directory symlink: %v", err)
	}

	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()
	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("create durable listener manager: %v", err)
	}

	if _, err := manager.CreateListener(ListenerConfig{
		Name:     "escape",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41401,
	}); err == nil {
		t.Fatal("listener creation followed a symlinked listener directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("read outside directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("listener creation wrote outside listeners root: %#v", entries)
	}
	var rowCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM listeners`,
	).Scan(&rowCount); err != nil {
		t.Fatalf("count durable listeners: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("symlinked listener creation persisted %d rows", rowCount)
	}
}

func TestDurableStartupRejectsNonPortableListenerNames(t *testing.T) {
	for _, name := range []string{"é", "e\u0301", "CON", "com1", "LPT9"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			database, err := persistence.Open(
				filepath.Join(root, "state", "microc2.db"),
			)
			if err != nil {
				t.Fatalf("open persistence database: %v", err)
			}
			defer database.Close()

			insertDurableListenerForTest(t, database, ListenerConfig{
				ID:       "invalid-name-listener",
				Name:     name,
				Protocol: "http",
				BindHost: "127.0.0.1",
				Port:     41601,
			}, StatusStopped, "")
			listenersDir := filepath.Join(root, "static", "listeners")
			if _, err := NewListenerManagerWithPersistenceForIsolatedLab(
				nil,
				listenersDir,
				database,
			); err == nil {
				t.Fatalf("durable startup accepted nonportable name %q", name)
			}
			entries, err := os.ReadDir(listenersDir)
			if err != nil {
				t.Fatalf("read listeners directory: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf(
					"invalid durable name %q created projections: %#v",
					name,
					entries,
				)
			}
		})
	}
}

func TestDurableStartupFailsExplicitlyForUnsafeDiskOnlyName(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	config := ListenerConfig{
		ID:       "unsafe-disk-name",
		Name:     "é",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41602,
	}
	writeProjectionForTest(t, listenersDir, config)

	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()
	if _, err := NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		listenersDir,
		database,
	); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe disk listener did not fail startup explicitly: %v", err)
	}
	var rowCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM listeners`,
	).Scan(&rowCount); err != nil {
		t.Fatalf("count durable listeners: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("unsafe disk listener imported %d durable rows", rowCount)
	}
}

func TestDurableListenersLoadWithoutConfigDirectoryAndRecoverGlobally(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "missing-static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	configs := []ListenerConfig{
		{
			ID:       "active-listener",
			Name:     "active",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     41001,
		},
		{
			ID:       "error-listener",
			Name:     "errored",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     41002,
		},
		{
			ID:       "stopped-listener",
			Name:     "stopped",
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     41003,
		},
	}
	insertDurableListenerForTest(t, database, configs[0], StatusActive, "")
	insertDurableListenerForTest(t, database, configs[1], StatusError, "listen failed")
	insertDurableListenerForTest(t, database, configs[2], StatusStopped, "")

	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("load database-only listeners: %v", err)
	}
	if got := len(manager.ListListeners()); got != len(configs) {
		t.Fatalf("loaded listener count = %d, want %d", got, len(configs))
	}
	for _, config := range configs {
		listener, err := manager.GetListener(config.ID)
		if err != nil {
			t.Fatalf("get recovered listener %s: %v", config.ID, err)
		}
		if got := listener.GetStatus(); got != StatusStopped {
			t.Fatalf("listener %s status = %s, want %s", config.ID, got, StatusStopped)
		}

		var status, lastError string
		if err := database.SQL().QueryRow(
			`SELECT status, last_error FROM listeners WHERE id = ?`,
			config.ID,
		).Scan(&status, &lastError); err != nil {
			t.Fatalf("query recovered listener %s: %v", config.ID, err)
		}
		if status != string(StatusStopped) || lastError != "" {
			t.Fatalf(
				"listener %s durable state = (%q, %q), want (%q, empty)",
				config.ID,
				status,
				lastError,
				StatusStopped,
			)
		}

		projection := readProjectedConfigForTest(
			t,
			filepath.Join(listenersDir, config.Name, "config.json"),
		)
		if projection.ID != config.ID {
			t.Fatalf("projection ID = %q, want %q", projection.ID, config.ID)
		}
	}

	assertPrivateListenerProjectionModes(t, listenersDir, configs)

	activeEvents, err := manager.ListListenerEvents(configs[0].ID)
	if err != nil {
		t.Fatalf("list active listener events: %v", err)
	}
	assertListenerEventTypes(t, activeEvents, "recovered_stopped")
	errorEvents, err := manager.ListListenerEvents(configs[1].ID)
	if err != nil {
		t.Fatalf("list errored listener events: %v", err)
	}
	assertListenerEventTypes(t, errorEvents, "recovered_stopped")
	stoppedEvents, err := manager.ListListenerEvents(configs[2].ID)
	if err != nil {
		t.Fatalf("list stopped listener events: %v", err)
	}
	assertListenerEventTypes(t, stoppedEvents)

	restarted, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("reload recovered listeners: %v", err)
	}
	activeEvents, err = restarted.ListListenerEvents(configs[0].ID)
	if err != nil {
		t.Fatalf("list idempotently recovered events: %v", err)
	}
	assertListenerEventTypes(t, activeEvents, "recovered_stopped")
	errorEvents, err = restarted.ListListenerEvents(configs[1].ID)
	if err != nil {
		t.Fatalf("list idempotently recovered error events: %v", err)
	}
	assertListenerEventTypes(t, errorEvents, "recovered_stopped")
}

func TestDurableListenerRecoveryRollsBackAsOneUnit(t *testing.T) {
	root := t.TempDir()
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	valid := ListenerConfig{
		ID:       "a-valid-listener",
		Name:     "valid",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41101,
	}
	corrupt := ListenerConfig{
		ID:       "z-corrupt-listener",
		Name:     "corrupt",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41102,
	}
	insertDurableListenerForTest(t, database, valid, StatusActive, "")
	insertDurableListenerForTest(t, database, corrupt, StatusError, "broken")
	if _, err := database.SQL().Exec(
		`UPDATE listeners SET config_sha256 = ? WHERE id = ?`,
		strings.Repeat("0", 64),
		corrupt.ID,
	); err != nil {
		t.Fatalf("corrupt durable listener checksum: %v", err)
	}

	if _, err := NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		filepath.Join(root, "static", "listeners"),
		database,
	); err == nil {
		t.Fatal("startup accepted a corrupt durable listener")
	}

	var status string
	if err := database.SQL().QueryRow(
		`SELECT status FROM listeners WHERE id = ?`,
		valid.ID,
	).Scan(&status); err != nil {
		t.Fatalf("query valid durable listener: %v", err)
	}
	if status != string(StatusActive) {
		t.Fatalf("valid listener status = %q, want rollback to %q", status, StatusActive)
	}
	events, err := (&ListenerManager{database: database}).ListListenerEvents(valid.ID)
	if err != nil {
		t.Fatalf("list valid listener events: %v", err)
	}
	assertListenerEventTypes(t, events)
}

func TestDurableListenerConfigOverridesStaleProjection(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	authoritative := ListenerConfig{
		ID:       "authoritative-listener",
		Name:     "authoritative",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41201,
		Hosts:    []string{"durable.example"},
	}
	insertDurableListenerForTest(t, database, authoritative, StatusStopped, "")

	stale := authoritative
	stale.Port = 49999
	stale.Hosts = []string{"stale.invalid"}
	writeProjectionForTest(t, listenersDir, stale)

	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("load authoritative durable listener: %v", err)
	}
	listener, err := manager.GetListener(authoritative.ID)
	if err != nil {
		t.Fatalf("get authoritative listener: %v", err)
	}
	if listener.Config.Port != authoritative.Port ||
		len(listener.Config.Hosts) != 1 ||
		listener.Config.Hosts[0] != "durable.example" {
		t.Fatalf("runtime used stale projection: %#v", listener.Config)
	}

	projected := readProjectedConfigForTest(
		t,
		filepath.Join(listenersDir, authoritative.Name, "config.json"),
	)
	if projected.Port != authoritative.Port ||
		len(projected.Hosts) != 1 ||
		projected.Hosts[0] != "durable.example" {
		t.Fatalf("projection was not replaced with durable state: %#v", projected)
	}

	var durableJSON []byte
	if err := database.SQL().QueryRow(
		`SELECT config_json FROM listeners WHERE id = ?`,
		authoritative.ID,
	).Scan(&durableJSON); err != nil {
		t.Fatalf("read authoritative durable config: %v", err)
	}
	var durable ListenerConfig
	if err := json.Unmarshal(durableJSON, &durable); err != nil {
		t.Fatalf("decode authoritative durable config: %v", err)
	}
	if durable.Port != authoritative.Port ||
		len(durable.Hosts) != 1 ||
		durable.Hosts[0] != "durable.example" {
		t.Fatalf("durable config was overwritten by stale projection: %#v", durable)
	}
	assertPrivateListenerProjectionModes(t, listenersDir, []ListenerConfig{authoritative})
}

func TestDiskOnlySupportedListenerIsImported(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	config := ListenerConfig{
		ID:       "disk-only-listener",
		Name:     "disk-only",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41301,
		Hosts:    []string{"disk-only.example"},
	}
	writeProjectionForTest(t, listenersDir, config)

	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("import disk-only listener: %v", err)
	}
	listener, err := manager.GetListener(config.ID)
	if err != nil {
		t.Fatalf("get imported listener: %v", err)
	}
	if len(listener.Config.Hosts) != 1 ||
		listener.Config.Hosts[0] != "disk-only.example" {
		t.Fatalf("imported runtime lost advertised host: %#v", listener.Config)
	}

	var durableJSON []byte
	if err := database.SQL().QueryRow(
		`SELECT config_json FROM listeners WHERE id = ?`,
		config.ID,
	).Scan(&durableJSON); err != nil {
		t.Fatalf("read imported durable config: %v", err)
	}
	var durable ListenerConfig
	if err := json.Unmarshal(durableJSON, &durable); err != nil {
		t.Fatalf("decode imported durable config: %v", err)
	}
	if len(durable.Hosts) != 1 || durable.Hosts[0] != "disk-only.example" {
		t.Fatalf("durable import lost advertised host: %#v", durable)
	}
	projected := readProjectedConfigForTest(
		t,
		filepath.Join(listenersDir, config.Name, "config.json"),
	)
	if len(projected.Hosts) != 1 || projected.Hosts[0] != "disk-only.example" {
		t.Fatalf("imported projection lost advertised host: %#v", projected)
	}
	events, err := manager.ListListenerEvents(config.ID)
	if err != nil {
		t.Fatalf("list imported listener events: %v", err)
	}
	assertListenerEventTypes(t, events, "imported")
	assertPrivateListenerProjectionModes(t, listenersDir, []ListenerConfig{config})
}

func TestLegacyListenerProjectionStillRedactsProxyPasswords(t *testing.T) {
	listenersDir := filepath.Join(t.TempDir(), "static", "listeners")
	config := ListenerConfig{
		ID:       "legacy-proxy-listener",
		Name:     "legacy-proxy",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41302,
		Proxy: &ProxyConfig{
			Type:     "http",
			Host:     "proxy.example",
			Port:     8080,
			Username: "operator",
			Password: "legacy-secret",
		},
	}
	if err := writeListenerConfigProjection(listenersDir, config, true); err != nil {
		t.Fatalf("write redacted legacy projection: %v", err)
	}
	projected := readProjectedConfigForTest(
		t,
		filepath.Join(listenersDir, config.Name, "config.json"),
	)
	if projected.Proxy == nil ||
		projected.Proxy.Username != config.Proxy.Username ||
		projected.Proxy.Password != "" {
		t.Fatalf(
			"legacy proxy projection was not safely redacted: %#v",
			projected.Proxy,
		)
	}
}

func TestDurableListenerWithUnsupportedSettingsFailsStartup(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	config := ListenerConfig{
		ID:       "unsupported-proxy-listener",
		Name:     "unsupported-proxy",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41303,
		Proxy: &ProxyConfig{
			Type: "http",
			Host: "proxy.example",
			Port: 8080,
		},
	}
	insertDurableListenerForTest(t, database, config, StatusStopped, "")

	_, err = NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		listenersDir,
		database,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"listener proxy configuration is not implemented",
	) {
		t.Fatalf("unsupported durable listener error = %v", err)
	}
}

func TestInvalidHTTPSKeyPairIsRejectedBeforePersistence(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()
	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		listenersDir,
		database,
	)
	if err != nil {
		t.Fatalf("create listener manager: %v", err)
	}

	certFile, _ := writeTestTLSCertificate(t)
	invalidKeyFile := filepath.Join(t.TempDir(), "invalid.key")
	if err := os.WriteFile(
		invalidKeyFile,
		[]byte("not a private key"),
		0o600,
	); err != nil {
		t.Fatalf("write invalid TLS key: %v", err)
	}
	_, err = manager.CreateListener(ListenerConfig{
		Name:     "invalid-tls",
		Protocol: "https",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
		TLSConfig: &TLSConfig{
			CertFile: certFile,
			KeyFile:  invalidKeyFile,
		},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "certificate and key") {
		t.Fatalf("invalid HTTPS key pair error = %v", err)
	}
	assertRejectedListenerHasNoDurableSideEffects(
		t,
		manager,
		database,
		filepath.Join(listenersDir, "invalid-tls"),
	)
}

func TestHTTPSKeyMaterialInsideStaticRootIsRejectedBeforePersistence(
	t *testing.T,
) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()
	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		listenersDir,
		database,
	)
	if err != nil {
		t.Fatalf("create listener manager: %v", err)
	}

	sourceCert, sourceKey := writeTestTLSCertificate(t)
	staticCert := filepath.Join(root, "static", "listener.crt")
	staticKey := filepath.Join(root, "static", "listener.key")
	for source, destination := range map[string]string{
		sourceCert: staticCert,
		sourceKey:  staticKey,
	} {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read TLS test material: %v", err)
		}
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatalf("write TLS test material under static root: %v", err)
		}
	}

	_, err = manager.CreateListener(ListenerConfig{
		Name:     "static-tls",
		Protocol: "https",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
		TLSConfig: &TLSConfig{
			CertFile: staticCert,
			KeyFile:  staticKey,
		},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "outside the static directory") {
		t.Fatalf("static-root HTTPS material error = %v", err)
	}
	assertRejectedListenerHasNoDurableSideEffects(
		t,
		manager,
		database,
		filepath.Join(listenersDir, "static-tls"),
	)
}

func assertRejectedListenerHasNoDurableSideEffects(
	t *testing.T,
	manager *ListenerManager,
	database *persistence.Database,
	listenerDir string,
) {
	t.Helper()
	if len(manager.ListListeners()) != 0 {
		t.Fatal("rejected listener was registered")
	}
	if _, err := os.Stat(listenerDir); !os.IsNotExist(err) {
		t.Fatalf("rejected listener created a directory: %v", err)
	}
	var rowCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM listeners`,
	).Scan(&rowCount); err != nil {
		t.Fatalf("count durable listeners: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("rejected listener persisted %d row(s)", rowCount)
	}
}

func TestLegacySpacedListenerNameImportsAndRestarts(t *testing.T) {
	root := t.TempDir()
	listenersDir := filepath.Join(root, "static", "listeners")
	database, err := persistence.Open(filepath.Join(root, "state", "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	config := ListenerConfig{
		ID:       "legacy-spaced-listener",
		Name:     "base - http",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     41701,
	}
	writeProjectionForTest(t, listenersDir, config)

	manager, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("import legacy spaced listener: %v", err)
	}
	if _, err := manager.GetListener(config.ID); err != nil {
		t.Fatalf("get imported legacy listener: %v", err)
	}
	events, err := manager.ListListenerEvents(config.ID)
	if err != nil {
		t.Fatalf("list imported legacy listener events: %v", err)
	}
	assertListenerEventTypes(t, events, "imported")

	restarted, err := NewListenerManagerWithPersistenceForIsolatedLab(nil, listenersDir, database)
	if err != nil {
		t.Fatalf("restart with legacy spaced listener: %v", err)
	}
	reloaded, err := restarted.GetListener(config.ID)
	if err != nil {
		t.Fatalf("get restarted legacy listener: %v", err)
	}
	if reloaded.Config.Name != config.Name {
		t.Fatalf(
			"restarted legacy name = %q, want %q",
			reloaded.Config.Name,
			config.Name,
		)
	}
}

func assertListenerEventTypes(t *testing.T, events []ListenerEvent, want ...string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("event count = %d, want %d: %#v", len(events), len(want), events)
	}
	for index, eventType := range want {
		if events[index].Type != eventType {
			t.Fatalf(
				"event %d type = %q, want %q: %#v",
				index,
				events[index].Type,
				eventType,
				events,
			)
		}
		if events[index].Sequence <= 0 || events[index].ListenerID == "" ||
			events[index].OccurredAt.IsZero() {
			t.Fatalf("event %d is incomplete: %#v", index, events[index])
		}
	}
}

func assertListenerAuditLinks(
	t *testing.T,
	database *persistence.Database,
	listenerID string,
	wantActions []string,
	wantActorIDs []string,
) {
	t.Helper()
	rows, err := database.SQL().Query(
		`SELECT audit.action, audit.actor_id
		 FROM listener_events AS lifecycle
		 JOIN audit_events AS audit
		   ON audit.seq = lifecycle.audit_event_seq
		 WHERE lifecycle.listener_id = ?
		 ORDER BY lifecycle.seq`,
		listenerID,
	)
	if err != nil {
		t.Fatalf("query linked listener audits: %v", err)
	}
	defer rows.Close()
	var actions, actorIDs []string
	for rows.Next() {
		var action, actorID string
		if err := rows.Scan(&action, &actorID); err != nil {
			t.Fatalf("scan linked listener audit: %v", err)
		}
		actions = append(actions, action)
		actorIDs = append(actorIDs, actorID)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate linked listener audits: %v", err)
	}
	if strings.Join(actions, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("listener audit actions = %#v, want %#v", actions, wantActions)
	}
	if strings.Join(actorIDs, ",") != strings.Join(wantActorIDs, ",") {
		t.Fatalf("listener audit actors = %#v, want %#v", actorIDs, wantActorIDs)
	}
}

func insertDurableListenerForTest(
	t *testing.T,
	database *persistence.Database,
	config ListenerConfig,
	status ListenerStatus,
	lastError string,
) {
	t.Helper()
	configJSON, checksum, err := encodedListenerConfig(config)
	if err != nil {
		t.Fatalf("encode durable listener config: %v", err)
	}
	const timestamp = "2026-07-23T12:00:00Z"
	if _, err := database.SQL().Exec(
		`INSERT INTO listeners (
			id, name, config_json, config_sha256, status, last_error,
			created_at, updated_at, deleted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		config.ID,
		config.Name,
		configJSON,
		checksum,
		string(status),
		lastError,
		timestamp,
		timestamp,
	); err != nil {
		t.Fatalf("insert durable listener %s: %v", config.ID, err)
	}
}

func writeProjectionForTest(
	t *testing.T,
	listenersDir string,
	config ListenerConfig,
) {
	t.Helper()
	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal listener projection: %v", err)
	}
	configDir := filepath.Join(listenersDir, config.Name)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("create listener projection directory: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(configDir, "config.json"),
		configJSON,
		0o644,
	); err != nil {
		t.Fatalf("write listener projection: %v", err)
	}
}

func readProjectedConfigForTest(t *testing.T, path string) ListenerConfig {
	t.Helper()
	configJSON, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read listener projection: %v", err)
	}
	var config ListenerConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		t.Fatalf("decode listener projection: %v", err)
	}
	return config
}

func assertPrivateListenerProjectionModes(
	t *testing.T,
	listenersDir string,
	configs []ListenerConfig,
) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	rootInfo, err := os.Stat(listenersDir)
	if err != nil {
		t.Fatalf("stat listeners directory: %v", err)
	}
	if got := rootInfo.Mode().Perm(); got != listenerDirectoryMode {
		t.Fatalf(
			"listeners directory mode = %#o, want %#o",
			got,
			listenerDirectoryMode,
		)
	}
	for _, config := range configs {
		directoryInfo, err := os.Stat(filepath.Join(listenersDir, config.Name))
		if err != nil {
			t.Fatalf("stat listener directory: %v", err)
		}
		if got := directoryInfo.Mode().Perm(); got != listenerDirectoryMode {
			t.Fatalf(
				"listener %s directory mode = %#o, want %#o",
				config.ID,
				got,
				listenerDirectoryMode,
			)
		}
		configInfo, err := os.Stat(
			filepath.Join(listenersDir, config.Name, "config.json"),
		)
		if err != nil {
			t.Fatalf("stat listener config: %v", err)
		}
		if got := configInfo.Mode().Perm(); got != listenerConfigMode {
			t.Fatalf(
				"listener %s config mode = %#o, want %#o",
				config.ID,
				got,
				listenerConfigMode,
			)
		}
	}
}
