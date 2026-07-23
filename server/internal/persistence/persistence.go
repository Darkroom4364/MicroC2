package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	databaseDirectoryMode = 0o700
	databaseFileMode      = 0o600
	sqliteBusyTimeoutMS   = 5000
)

var (
	// ErrFutureSchema is returned when a database was migrated by a newer
	// MicroC2 binary than the one attempting to open it.
	ErrFutureSchema = errors.New("database schema is newer than this binary")

	// ErrMigrationMismatch is returned when the applied migration ledger is
	// not an exact prefix of the migrations embedded in this binary.
	ErrMigrationMismatch = errors.New("database migration ledger mismatch")

	migrationNamePattern = regexp.MustCompile(`^([0-9]{4})_[a-z0-9_]+\.sql$`)

	//go:embed migrations/*.sql
	embeddedMigrations embed.FS
)

// Database owns the process-wide SQLite connection pool.
type Database struct {
	sql  *sql.DB
	path string
}

// Open creates or opens a file-backed MicroC2 database, applies all pending
// embedded migrations transactionally, and verifies the required SQLite
// durability and integrity settings.
func Open(path string) (*Database, error) {
	migrations, err := loadMigrations(embeddedMigrations)
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}
	return open(path, migrations)
}

// SQL exposes the configured database/sql handle to persistence repositories.
// Callers must not change connection-pool limits or durability PRAGMAs.
func (d *Database) SQL() *sql.DB {
	if d == nil {
		return nil
	}
	return d.sql
}

// Path returns the absolute path of the SQLite database file.
func (d *Database) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Close releases the database connection pool.
func (d *Database) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

type appliedMigration struct {
	version  int
	name     string
	checksum string
}

func open(path string, migrations []migration) (_ *Database, returnErr error) {
	absolutePath, err := prepareDatabasePath(path)
	if err != nil {
		return nil, err
	}

	sqlDB, err := sql.Open("sqlite", sqliteDataSourceName(absolutePath))
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = sqlDB.Close()
		}
	}()

	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	ctx := context.Background()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connect to SQLite database: %w", err)
	}
	if err := applyMigrations(ctx, sqlDB, migrations); err != nil {
		return nil, err
	}
	if err := verifyPragmas(ctx, sqlDB); err != nil {
		return nil, err
	}
	if err := enforceDatabasePermissions(absolutePath); err != nil {
		return nil, err
	}

	return &Database{sql: sqlDB, path: absolutePath}, nil
}

func prepareDatabasePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("database path is required")
	}
	if path == ":memory:" || strings.HasPrefix(path, "file:") {
		return "", errors.New("database path must be a local filesystem path")
	}

	absolutePath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve database path: %w", err)
	}
	parent := filepath.Dir(absolutePath)
	parentInfo, err := os.Stat(parent)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(parent, databaseDirectoryMode); err != nil {
			return "", fmt.Errorf("create database directory: %w", err)
		}
		// MkdirAll is subject to the process umask. Tighten only a directory
		// created for this database; never chmod a pre-existing parent such as
		// /tmp or /var/lib.
		if err := os.Chmod(parent, databaseDirectoryMode); err != nil {
			return "", fmt.Errorf("restrict database directory permissions: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("inspect database directory: %w", err)
	case !parentInfo.IsDir():
		return "", fmt.Errorf("database parent is not a directory: %s", parent)
	}

	info, err := os.Lstat(absolutePath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("database path is not a regular file: %s", absolutePath)
		}
		if err := os.Chmod(absolutePath, databaseFileMode); err != nil {
			return "", fmt.Errorf("restrict database file permissions: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
		file, createErr := os.OpenFile(
			absolutePath,
			os.O_CREATE|os.O_EXCL|os.O_RDWR,
			databaseFileMode,
		)
		if createErr != nil {
			return "", fmt.Errorf("create database file: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return "", fmt.Errorf("close new database file: %w", closeErr)
		}
	default:
		return "", fmt.Errorf("inspect database path: %w", err)
	}

	return absolutePath, nil
}

func enforceDatabasePermissions(path string) error {
	if err := os.Chmod(path, databaseFileMode); err != nil {
		return fmt.Errorf("restrict database file permissions: %w", err)
	}
	return nil
}

func sqliteDataSourceName(path string) string {
	slashPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	databaseURL := url.URL{Scheme: "file", Path: slashPath}
	query := url.Values{}
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", sqliteBusyTimeoutMS))
	query.Add("_pragma", "journal_mode(DELETE)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	databaseURL.RawQuery = query.Encode()
	return databaseURL.String()
}

func loadMigrations(migrationFS fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}

	migrations := make([]migration, 0, len(entries))
	seenVersions := make(map[int]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		match := migrationNamePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(match[1])
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid migration version in %q", entry.Name())
		}
		if previous, exists := seenVersions[version]; exists {
			return nil, fmt.Errorf(
				"duplicate migration version %04d in %q and %q",
				version,
				previous,
				entry.Name(),
			)
		}

		data, err := fs.ReadFile(migrationFS, filepath.ToSlash(filepath.Join("migrations", entry.Name())))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(data)
		migrations = append(migrations, migration{
			version:  version,
			name:     entry.Name(),
			sql:      string(data),
			checksum: fmt.Sprintf("%x", sum),
		})
		seenVersions[version] = entry.Name()
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	if len(migrations) == 0 {
		return nil, errors.New("no migrations found")
	}
	for index, migration := range migrations {
		expectedVersion := index + 1
		if migration.version != expectedVersion {
			return nil, fmt.Errorf(
				"migration versions must be contiguous: got %04d, expected %04d",
				migration.version,
				expectedVersion,
			)
		}
	}
	return migrations, nil
}

func applyMigrations(ctx context.Context, db *sql.DB, migrations []migration) error {
	if len(migrations) == 0 {
		return errors.New("at least one migration is required")
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY CHECK (version > 0),
			name TEXT NOT NULL CHECK (length(name) > 0),
			checksum_sha256 TEXT NOT NULL
				CHECK (
					length(checksum_sha256) = 64
					AND checksum_sha256 NOT GLOB '*[^0-9a-f]*'
				),
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("bootstrap migration ledger: %w", err)
	}

	applied, err := readAppliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	latestVersion := migrations[len(migrations)-1].version
	if len(applied) > 0 && applied[len(applied)-1].version > latestVersion {
		return fmt.Errorf(
			"%w: database version %d, binary version %d",
			ErrFutureSchema,
			applied[len(applied)-1].version,
			latestVersion,
		)
	}
	if err := verifyAppliedMigrations(applied, migrations); err != nil {
		return err
	}

	for _, migration := range migrations[len(applied):] {
		if _, err := tx.ExecContext(ctx, migration.sql); err != nil {
			return fmt.Errorf("apply migration %q: %w", migration.name, err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations
				(version, name, checksum_sha256, applied_at)
			 VALUES (?, ?, ?, ?)`,
			migration.version,
			migration.name,
			migration.checksum,
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			return fmt.Errorf("record migration %q: %w", migration.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func readAppliedMigrations(ctx context.Context, tx *sql.Tx) ([]appliedMigration, error) {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT version, name, checksum_sha256
		 FROM schema_migrations
		 ORDER BY version`,
	)
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()

	var applied []appliedMigration
	for rows.Next() {
		var migration appliedMigration
		if err := rows.Scan(&migration.version, &migration.name, &migration.checksum); err != nil {
			return nil, fmt.Errorf("scan migration ledger: %w", err)
		}
		applied = append(applied, migration)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration ledger: %w", err)
	}
	return applied, nil
}

func verifyAppliedMigrations(applied []appliedMigration, migrations []migration) error {
	for index, actual := range applied {
		expectedVersion := index + 1
		if actual.version != expectedVersion {
			return fmt.Errorf(
				"%w: applied versions are not contiguous at version %d",
				ErrMigrationMismatch,
				actual.version,
			)
		}
		if index >= len(migrations) {
			return fmt.Errorf(
				"%w: database version %d, binary version %d",
				ErrFutureSchema,
				actual.version,
				len(migrations),
			)
		}
		expected := migrations[index]
		if actual.name != expected.name || actual.checksum != expected.checksum {
			return fmt.Errorf(
				"%w: version %04d does not match embedded migration %q",
				ErrMigrationMismatch,
				actual.version,
				expected.name,
			)
		}
	}
	return nil
}

func verifyPragmas(ctx context.Context, db *sql.DB) error {
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("read SQLite journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "delete") {
		return fmt.Errorf("SQLite journal mode is %q, expected DELETE", journalMode)
	}

	checks := []struct {
		pragma string
		want   int
	}{
		{pragma: "foreign_keys", want: 1},
		{pragma: "synchronous", want: 2},
		{pragma: "busy_timeout", want: sqliteBusyTimeoutMS},
	}
	for _, check := range checks {
		var got int
		if err := db.QueryRowContext(
			ctx,
			"PRAGMA "+check.pragma,
		).Scan(&got); err != nil {
			return fmt.Errorf("read SQLite %s pragma: %w", check.pragma, err)
		}
		if got != check.want {
			return fmt.Errorf(
				"SQLite %s pragma is %d, expected %d",
				check.pragma,
				got,
				check.want,
			)
		}
	}
	return nil
}
