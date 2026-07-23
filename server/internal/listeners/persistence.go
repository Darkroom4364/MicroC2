package listeners

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ListenerEvent is an append-only record of a listener lifecycle transition.
// Operator identity and causal audit metadata are intentionally deferred to
// issue #100.
type ListenerEvent struct {
	Sequence   int64          `json:"sequence"`
	ListenerID string         `json:"listener_id"`
	Type       string         `json:"type"`
	Status     ListenerStatus `json:"status"`
	Message    string         `json:"message,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
}

func (m *ListenerManager) recordListenerCreated(config ListenerConfig) error {
	return m.insertDurableListener(
		config,
		"created",
		"",
	)
}

func (m *ListenerManager) recordListenerImported(config ListenerConfig) error {
	return m.insertDurableListener(
		config,
		"imported",
		"imported saved listener configuration",
	)
}

func (m *ListenerManager) insertDurableListener(
	config ListenerConfig,
	eventType string,
	message string,
) error {
	if m.database == nil {
		return nil
	}
	configJSON, digest, err := encodedListenerConfig(config)
	if err != nil {
		return err
	}
	now := m.timestamp()
	tx, err := m.database.SQL().BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO listeners (
			id, name, config_json, config_sha256, status, last_error,
			created_at, updated_at, deleted_at
		) VALUES (?, ?, ?, ?, ?, '', ?, ?, NULL)`,
		config.ID,
		config.Name,
		configJSON,
		digest,
		string(StatusStopped),
		now,
		now,
	); err != nil {
		return err
	}
	if err := insertListenerEvent(
		tx,
		config.ID,
		eventType,
		StatusStopped,
		message,
		now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

type durableListenerRecord struct {
	id         string
	name       string
	configJSON []byte
	checksum   string
	status     ListenerStatus
	deletedAt  sql.NullString
	config     ListenerConfig
}

// loadAndRecoverDurableListeners makes SQLite authoritative for every listener
// that has not been tombstoned. ACTIVE and ERROR rows are recovered to STOPPED
// together in one transaction, so a restart can never record only a prefix of
// the required recovery events.
func (m *ListenerManager) loadAndRecoverDurableListeners() (
	[]ListenerConfig,
	map[string]struct{},
	map[string]struct{},
	error,
) {
	tombstonedIDs := make(map[string]struct{})
	tombstonedNames := make(map[string]struct{})
	if m.database == nil {
		return nil, tombstonedIDs, tombstonedNames, nil
	}

	tx, err := m.database.SQL().BeginTx(context.Background(), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, name, config_json, config_sha256, status, deleted_at
		 FROM listeners
		 ORDER BY id`,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	records := make([]durableListenerRecord, 0)
	for rows.Next() {
		var record durableListenerRecord
		var status string
		if err := rows.Scan(
			&record.id,
			&record.name,
			&record.configJSON,
			&record.checksum,
			&status,
			&record.deletedAt,
		); err != nil {
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf("scan durable listener: %w", err)
		}
		record.status = ListenerStatus(status)
		if record.deletedAt.Valid {
			tombstonedIDs[record.id] = struct{}{}
			if record.name != "" {
				tombstonedNames[strings.ToLower(record.name)] = struct{}{}
			}
			continue
		}

		actualChecksum := sha256.Sum256(record.configJSON)
		if hex.EncodeToString(actualChecksum[:]) != record.checksum {
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf(
				"durable listener %s config checksum does not match config_json",
				record.id,
			)
		}
		if err := json.Unmarshal(record.configJSON, &record.config); err != nil {
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf(
				"decode durable listener %s config: %w",
				record.id,
				err,
			)
		}
		record.config.Protocol = strings.ToLower(record.config.Protocol)
		if record.config.ID != record.id || record.config.Name != record.name {
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf(
				"durable listener %s identity does not match config_json",
				record.id,
			)
		}
		if err := m.validateListenerConfig(record.config); err != nil {
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf(
				"validate durable listener %s config: %w",
				record.id,
				err,
			)
		}
		switch record.status {
		case StatusActive, StatusStopped, StatusError:
		default:
			_ = rows.Close()
			return nil, nil, nil, fmt.Errorf(
				"durable listener %s has unsupported status %q",
				record.id,
				record.status,
			)
		}
		for _, existing := range records {
			if strings.EqualFold(existing.name, record.name) {
				_ = rows.Close()
				return nil, nil, nil, fmt.Errorf(
					"durable listeners %s and %s share name %q",
					existing.id,
					record.id,
					record.name,
				)
			}
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, nil, fmt.Errorf("iterate durable listeners: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, nil, fmt.Errorf("close durable listener rows: %w", err)
	}

	now := m.timestamp()
	for index := range records {
		record := &records[index]
		if record.status != StatusActive && record.status != StatusError {
			continue
		}
		result, err := tx.Exec(
			`UPDATE listeners
			 SET status = ?, last_error = '', updated_at = ?
			 WHERE id = ? AND deleted_at IS NULL AND status IN (?, ?)`,
			string(StatusStopped),
			now,
			record.id,
			string(StatusActive),
			string(StatusError),
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"recover durable listener %s: %w",
				record.id,
				err,
			)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"inspect durable listener %s recovery: %w",
				record.id,
				err,
			)
		}
		if affected != 1 {
			return nil, nil, nil, fmt.Errorf(
				"durable listener %s changed during recovery",
				record.id,
			)
		}
		if err := insertListenerEvent(
			tx,
			record.id,
			"recovered_stopped",
			StatusStopped,
			"listener recovered as stopped after server restart",
			now,
		); err != nil {
			return nil, nil, nil, fmt.Errorf(
				"record durable listener %s recovery: %w",
				record.id,
				err,
			)
		}
		record.status = StatusStopped
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}

	configs := make([]ListenerConfig, 0, len(records))
	for _, record := range records {
		configs = append(configs, record.config)
	}
	return configs, tombstonedIDs, tombstonedNames, nil
}

func (m *ListenerManager) recordListenerState(
	listenerID string,
	status ListenerStatus,
	eventType string,
	message string,
	deleted bool,
) error {
	if m.database == nil {
		return nil
	}
	now := m.timestamp()
	tx, err := m.database.SQL().BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var result sql.Result
	if deleted {
		result, err = tx.Exec(
			`UPDATE listeners
			 SET status = ?, last_error = ?, updated_at = ?, deleted_at = ?
			 WHERE id = ?`,
			string(status),
			message,
			now,
			now,
			listenerID,
		)
	} else {
		result, err = tx.Exec(
			`UPDATE listeners
			 SET status = ?, last_error = ?, updated_at = ?
			 WHERE id = ? AND deleted_at IS NULL`,
			string(status),
			message,
			now,
			listenerID,
		)
	}
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("listener %s has no durable record", listenerID)
	}
	if err := insertListenerEvent(
		tx,
		listenerID,
		eventType,
		status,
		message,
		now,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *ListenerManager) timestamp() string {
	return m.now().UTC().Round(0).Format(time.RFC3339Nano)
}

func (m *ListenerManager) cleanupListenerConfig(name string) {
	listenerDir := filepath.Join(m.listenersDir, name)
	if err := os.RemoveAll(listenerDir); err != nil {
		log.Printf(
			"[WARNING] Failed to cleanup listener directory %s: %v",
			listenerDir,
			err,
		)
	}
}

// ListListenerEvents returns durable lifecycle history, including history for
// listeners that are no longer present in the runtime registry.
func (m *ListenerManager) ListListenerEvents(listenerID string) ([]ListenerEvent, error) {
	if m.database == nil {
		return []ListenerEvent{}, nil
	}
	rows, err := m.database.SQL().Query(
		`SELECT seq, listener_id, event_type, status, message, occurred_at
		 FROM listener_events
		 WHERE listener_id = ?
		 ORDER BY seq`,
		listenerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]ListenerEvent, 0)
	for rows.Next() {
		var (
			event      ListenerEvent
			status     string
			occurredAt string
		)
		if err := rows.Scan(
			&event.Sequence,
			&event.ListenerID,
			&event.Type,
			&status,
			&event.Message,
			&occurredAt,
		); err != nil {
			return nil, err
		}
		event.Status = ListenerStatus(status)
		parsed, err := time.Parse(time.RFC3339Nano, occurredAt)
		if err != nil {
			return nil, fmt.Errorf(
				"parse listener event %d timestamp: %w",
				event.Sequence,
				err,
			)
		}
		event.OccurredAt = parsed
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func encodedListenerConfig(config ListenerConfig) ([]byte, string, error) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(configJSON)
	return configJSON, hex.EncodeToString(sum[:]), nil
}

type listenerEventInserter interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func insertListenerEvent(
	executor listenerEventInserter,
	listenerID string,
	eventType string,
	status ListenerStatus,
	message string,
	occurredAt string,
) error {
	_, err := executor.Exec(
		`INSERT INTO listener_events (
			listener_id, event_type, status, message, occurred_at
		) VALUES (?, ?, ?, ?, ?)`,
		listenerID,
		eventType,
		string(status),
		message,
		occurredAt,
	)
	return err
}
