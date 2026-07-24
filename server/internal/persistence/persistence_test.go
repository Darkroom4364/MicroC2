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
		"task_results",
		"legacy_results",
		"payload_builds",
		"enrollment_server_keys",
		"payload_bootstrap_credentials",
		"agent_enrollment_sessions",
		"payload_enrollment_allocations",
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
		 WHERE version = 3`,
	).Scan(&migrationName, &checksum); err != nil {
		t.Fatalf("read latest migration ledger entry: %v", err)
	}
	if migrationCount != 3 ||
		migrationName != "0003_payload_enrollment_allocations.sql" ||
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
