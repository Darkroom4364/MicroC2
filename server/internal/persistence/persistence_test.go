package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestOpenBootstrapsAndReopensFileDatabase(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "private", "microc2.db")

	database, err := Open(databasePath)
	if err != nil {
		t.Fatalf("open new database: %v", err)
	}
	absolutePath, err := filepath.Abs(databasePath)
	if err != nil {
		t.Fatalf("resolve expected path: %v", err)
	}
	if database.Path() != absolutePath {
		t.Fatalf("database path = %q, want %q", database.Path(), absolutePath)
	}

	requiredTables := []string{
		"schema_migrations",
		"listeners",
		"listener_events",
		"agents",
		"tasks",
		"module_task_policies",
		"task_results",
		"legacy_results",
		"payload_builds",
		"enrollment_server_keys",
		"payload_bootstrap_credentials",
		"agent_enrollment_sessions",
		"payload_enrollment_allocations",
		"audit_events",
	}
	for _, table := range requiredTables {
		var count int
		if err := database.SQL().QueryRow(
			`SELECT COUNT(*) FROM sqlite_master
			 WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&count); err != nil {
			t.Fatalf("look up table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("table %s count = %d, want 1", table, count)
		}
	}

	var migrationCount int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&migrationCount); err != nil {
		t.Fatalf("read migration ledger: %v", err)
	}
	var migrationName, checksum string
	if err := database.SQL().QueryRow(
		`SELECT name, checksum_sha256
		 FROM schema_migrations
		 WHERE version = 6`,
	).Scan(&migrationName, &checksum); err != nil {
		t.Fatalf("read latest migration ledger entry: %v", err)
	}
	if migrationCount != 6 ||
		migrationName != "0006_module_task_policies.sql" ||
		len(checksum) != 64 {
		t.Fatalf(
			"unexpected migration ledger: count=%d name=%q checksum=%q",
			migrationCount,
			migrationName,
			checksum,
		)
	}

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err := database.SQL().Exec(
		`INSERT INTO listeners (
			id, name, config_json, config_sha256, status, last_error,
			created_at, updated_at, deleted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		"listener-one",
		"listener",
		[]byte(`{"protocol":"http"}`),
		strings.Repeat("a", 64),
		"STOPPED",
		"",
		now,
		now,
	); err != nil {
		t.Fatalf("insert durable row: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	reopened, err := Open(databasePath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer reopened.Close()

	var listenerName string
	if err := reopened.SQL().QueryRow(
		`SELECT name FROM listeners WHERE id = ?`,
		"listener-one",
	).Scan(&listenerName); err != nil {
		t.Fatalf("read durable row after reopen: %v", err)
	}
	if listenerName != "listener" {
		t.Fatalf("listener name = %q, want listener", listenerName)
	}

	if runtime.GOOS != "windows" {
		assertPermissions(t, filepath.Dir(databasePath), databaseDirectoryMode)
		assertPermissions(t, databasePath, databaseFileMode)
	}
}

func TestAuditMigrationBackfillsExistingDurableObjectsAndLinks(t *testing.T) {
	migrations, err := loadMigrations(embeddedMigrations)
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if len(migrations) < 4 {
		t.Fatalf("loaded %d migrations, want at least 4", len(migrations))
	}

	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	legacy, err := open(databasePath, migrations[:3])
	if err != nil {
		t.Fatalf("open version-3 database: %v", err)
	}
	now := "2026-07-24T12:00:00Z"
	if _, err := legacy.SQL().Exec(
		`INSERT INTO listeners (
			id, name, config_json, config_sha256, status, last_error,
			created_at, updated_at, deleted_at
		) VALUES (?, ?, ?, ?, ?, '', ?, ?, NULL)`,
		"listener-one",
		"listener",
		[]byte(`{"id":"listener-one","name":"listener"}`),
		strings.Repeat("a", 64),
		"STOPPED",
		now,
		now,
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("insert version-3 listener: %v", err)
	}
	if _, err := legacy.SQL().Exec(
		`INSERT INTO listener_events (
			listener_id, event_type, status, message, occurred_at
		) VALUES (?, ?, ?, '', ?)`,
		"listener-one",
		"created",
		"STOPPED",
		now,
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("insert version-3 listener event: %v", err)
	}
	if _, err := legacy.SQL().Exec(
		`INSERT INTO tasks (
			listener_id, task_id, agent_id, schema_version, task_type,
			command, timeout_seconds, status, created_at, queued_at,
			expires_at, legacy_origin
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"listener-one",
		"task-one",
		"agent-one",
		1,
		"shell",
		"whoami",
		30,
		"queued",
		now,
		now,
		"2026-07-24T12:05:00Z",
		0,
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("insert version-3 task: %v", err)
	}
	if _, err := legacy.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?)`,
		"payload-one",
		"payload-one",
		"listener-one",
		"0000000000000001",
		"agent.bin",
		"release/payload-one/agent.bin",
		7,
		strings.Repeat("b", 64),
		now,
		"completed",
		[]byte(`{}`),
	); err != nil {
		_ = legacy.Close()
		t.Fatalf("insert version-3 payload: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close version-3 database: %v", err)
	}

	upgraded, err := Open(databasePath)
	if err != nil {
		t.Fatalf("upgrade database through audit migration: %v", err)
	}
	defer upgraded.Close()

	for table, column := range map[string]string{
		"tasks":           "created_audit_event_seq",
		"payload_builds":  "created_audit_event_seq",
		"listener_events": "audit_event_seq",
	} {
		if !tableHasColumn(t, upgraded.SQL(), table, column) {
			t.Fatalf("table %s is missing audit-link column %s", table, column)
		}
	}

	type expectedLink struct {
		query      string
		action     string
		targetKind string
		targetID   string
	}
	for name, expected := range map[string]expectedLink{
		"task": {
			query: `SELECT
					event.action, event.target_kind, event.target_id,
					event.actor_kind, event.actor_id, event.outcome,
					event.reason_code
				FROM tasks AS object
				JOIN audit_events AS event
				  ON event.seq = object.created_audit_event_seq
				WHERE object.listener_id = 'listener-one'
				  AND object.task_id = 'task-one'`,
			action:     "task.migrated",
			targetKind: "task",
			targetID:   "task-one",
		},
		"payload": {
			query: `SELECT
					event.action, event.target_kind, event.target_id,
					event.actor_kind, event.actor_id, event.outcome,
					event.reason_code
				FROM payload_builds AS object
				JOIN audit_events AS event
				  ON event.seq = object.created_audit_event_seq
				WHERE object.id = 'payload-one'`,
			action:     "payload_build.migrated",
			targetKind: "payload_build",
			targetID:   "payload-one",
		},
		"listener event": {
			query: `SELECT
					event.action, event.target_kind, event.target_id,
					event.actor_kind, event.actor_id, event.outcome,
					event.reason_code
				FROM listener_events AS object
				JOIN audit_events AS event
				  ON event.seq = object.audit_event_seq
				WHERE object.listener_id = 'listener-one'`,
			action:     "listener_event.migrated",
			targetKind: "listener_event",
			targetID:   "1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var action, targetKind, targetID string
			var actorKind, actorID, outcome, reasonCode string
			if err := upgraded.SQL().QueryRow(expected.query).Scan(
				&action,
				&targetKind,
				&targetID,
				&actorKind,
				&actorID,
				&outcome,
				&reasonCode,
			); err != nil {
				t.Fatalf("read backfilled audit link: %v", err)
			}
			if action != expected.action ||
				targetKind != expected.targetKind ||
				targetID != expected.targetID ||
				actorKind != "system" ||
				actorID != "migration:0004" ||
				outcome != "succeeded" ||
				reasonCode != "pre_audit_state" {
				t.Fatalf(
					"backfilled event = (%q, %q, %q, %q, %q, %q, %q)",
					action,
					targetKind,
					targetID,
					actorKind,
					actorID,
					outcome,
					reasonCode,
				)
			}
		})
	}

	var auditCount int
	if err := upgraded.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events`,
	).Scan(&auditCount); err != nil {
		t.Fatalf("count backfilled events: %v", err)
	}
	if auditCount != 3 {
		t.Fatalf("backfilled audit event count = %d, want 3", auditCount)
	}
}

func TestOpenConfiguresRequiredSQLitePragmas(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer database.Close()

	var journalMode string
	if err := database.SQL().QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "delete") {
		t.Fatalf("journal_mode = %q, want delete", journalMode)
	}

	for _, testCase := range []struct {
		pragma string
		want   int
	}{
		{pragma: "foreign_keys", want: 1},
		{pragma: "synchronous", want: 2},
		{pragma: "busy_timeout", want: sqliteBusyTimeoutMS},
	} {
		var got int
		if err := database.SQL().QueryRow(
			"PRAGMA " + testCase.pragma,
		).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", testCase.pragma, err)
		}
		if got != testCase.want {
			t.Fatalf("%s = %d, want %d", testCase.pragma, got, testCase.want)
		}
	}
	if got := database.SQL().Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}

	_, err = database.SQL().Exec(
		`INSERT INTO task_results (
			listener_id, task_id, schema_version, agent_id, outcome,
			agent_started_at, agent_completed_at, exit_code,
			stdout, stderr, error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"listener-one",
		"missing-task",
		1,
		"agent-one",
		"completed",
		"2026-07-23T12:00:00Z",
		"2026-07-23T12:00:01Z",
		0,
		"",
		"",
		"",
	)
	if err == nil {
		t.Fatal("foreign key violation unexpectedly succeeded")
	}
}

func TestOpenDoesNotChangeExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix directory permission bits")
	}
	parent := filepath.Join(t.TempDir(), "shared-parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("create existing parent: %v", err)
	}
	database, err := Open(filepath.Join(parent, "microc2.db"))
	if err != nil {
		t.Fatalf("open database under existing parent: %v", err)
	}
	defer database.Close()

	assertPermissions(t, parent, 0o755)
	assertPermissions(t, database.Path(), databaseFileMode)
}

func TestOpenRefusesMigrationChecksumMismatch(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	database, err := Open(databasePath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	tamperDatabase(t, databasePath, func(db *sql.DB) error {
		_, err := db.Exec(
			`UPDATE schema_migrations
			 SET checksum_sha256 = ?
			 WHERE version = 1`,
			strings.Repeat("0", 64),
		)
		return err
	})

	reopened, err := Open(databasePath)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrMigrationMismatch) {
		t.Fatalf("Open error = %v, want ErrMigrationMismatch", err)
	}
}

func TestOpenRefusesFutureMigrationVersion(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	database, err := Open(databasePath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	tamperDatabase(t, databasePath, func(db *sql.DB) error {
		_, err := db.Exec(
			`INSERT INTO schema_migrations
				(version, name, checksum_sha256, applied_at)
			 VALUES (?, ?, ?, ?)`,
			9999,
			"9999_future.sql",
			strings.Repeat("f", 64),
			"2026-07-23T12:00:00Z",
		)
		return err
	})

	reopened, err := Open(databasePath)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrFutureSchema) {
		t.Fatalf("Open error = %v, want ErrFutureSchema", err)
	}
}

func TestApplyMigrationsRollsBackEntireBatch(t *testing.T) {
	databasePath, err := prepareDatabasePath(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("prepare database: %v", err)
	}
	sqlDB, err := sql.Open("sqlite", sqliteDataSourceName(databasePath))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer sqlDB.Close()
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping database: %v", err)
	}

	testMigrations := []migration{
		newTestMigration(1, "0001_first.sql", "CREATE TABLE first_table (id INTEGER);"),
		newTestMigration(2, "0002_broken.sql", "THIS IS NOT VALID SQL;"),
	}
	if err := applyMigrations(context.Background(), sqlDB, testMigrations); err == nil {
		t.Fatal("broken migration batch unexpectedly succeeded")
	}

	for _, table := range []string{"schema_migrations", "first_table"} {
		var count int
		if err := sqlDB.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master
			 WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&count); err != nil {
			t.Fatalf("look up table %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("table %s survived rolled-back migration batch", table)
		}
	}
}

func TestLoadMigrationsRejectsGapsAndInvalidNames(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
	}{
		{
			name: "gap",
			fsys: fstest.MapFS{
				"migrations/0001_first.sql": {Data: []byte("SELECT 1;")},
				"migrations/0003_third.sql": {Data: []byte("SELECT 3;")},
			},
		},
		{
			name: "invalid name",
			fsys: fstest.MapFS{
				"migrations/1-invalid.sql": {Data: []byte("SELECT 1;")},
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := loadMigrations(testCase.fsys); err == nil {
				t.Fatal("invalid migration set unexpectedly loaded")
			}
		})
	}
}

func tamperDatabase(t *testing.T, path string, operation func(*sql.DB) error) {
	t.Helper()
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve database path: %v", err)
	}
	sqlDB, err := sql.Open("sqlite", sqliteDataSourceName(absolutePath))
	if err != nil {
		t.Fatalf("open database for test mutation: %v", err)
	}
	defer sqlDB.Close()
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping database for test mutation: %v", err)
	}
	if err := operation(sqlDB); err != nil {
		t.Fatalf("mutate database for test: %v", err)
	}
}

func newTestMigration(version int, name, statement string) migration {
	checksum := fmt.Sprintf("%x", sha256ForTest(statement))
	return migration{
		version:  version,
		name:     name,
		sql:      statement,
		checksum: checksum,
	}
}

func sha256ForTest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func tableHasColumn(
	t *testing.T,
	database *sql.DB,
	table string,
	column string,
) bool {
	t.Helper()
	rows, err := database.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("inspect table %s: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			columnID     int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(
			&columnID,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			t.Fatalf("scan table %s metadata: %v", table, err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table %s metadata: %v", table, err)
	}
	return false
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, want)
	}
}
