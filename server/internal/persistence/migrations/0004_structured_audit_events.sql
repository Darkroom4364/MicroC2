CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version INTEGER NOT NULL
        CHECK (schema_version = 1),
    occurred_at TEXT NOT NULL
        CHECK (length(occurred_at) > 0),
    actor_kind TEXT NOT NULL
        CHECK (actor_kind IN ('operator', 'agent', 'system')),
    actor_id TEXT NOT NULL
        CHECK (length(actor_id) >= 1 AND length(actor_id) <= 128),
    action TEXT NOT NULL
        CHECK (length(action) >= 1 AND length(action) <= 128),
    route TEXT NOT NULL
        CHECK (length(route) >= 1 AND length(route) <= 256),
    target_kind TEXT NOT NULL
        CHECK (length(target_kind) >= 1 AND length(target_kind) <= 64),
    target_id TEXT NOT NULL
        CHECK (length(target_id) >= 1 AND length(target_id) <= 255),
    outcome TEXT NOT NULL
        CHECK (outcome IN ('succeeded', 'failed', 'denied', 'noop')),
    reason_code TEXT
        CHECK (
            reason_code IS NULL
            OR (length(reason_code) >= 1 AND length(reason_code) <= 64)
        ),
    causation_sequence INTEGER,
    listener_id TEXT
        CHECK (
            listener_id IS NULL
            OR (length(listener_id) >= 1 AND length(listener_id) <= 128)
        ),
    agent_id TEXT
        CHECK (
            agent_id IS NULL
            OR (length(agent_id) >= 1 AND length(agent_id) <= 128)
        ),
    task_id TEXT
        CHECK (
            task_id IS NULL
            OR (length(task_id) >= 1 AND length(task_id) <= 128)
        ),
    payload_build_id TEXT
        CHECK (
            payload_build_id IS NULL
            OR (
                length(payload_build_id) >= 1
                AND length(payload_build_id) <= 128
            )
        ),
    file_name TEXT
        CHECK (
            file_name IS NULL
            OR (length(file_name) >= 1 AND length(file_name) <= 255)
        ),
    terminal_session_id TEXT
        CHECK (
            terminal_session_id IS NULL
            OR (
                length(terminal_session_id) >= 1
                AND length(terminal_session_id) <= 128
            )
        ),
    FOREIGN KEY (causation_sequence)
        REFERENCES audit_events (seq)
        ON UPDATE RESTRICT
        ON DELETE SET NULL
);

CREATE INDEX idx_audit_events_occurred_seq
    ON audit_events (occurred_at DESC, seq DESC);

CREATE INDEX idx_audit_events_actor_seq
    ON audit_events (actor_kind, actor_id, seq DESC);

CREATE INDEX idx_audit_events_action_seq
    ON audit_events (action, seq DESC);

CREATE INDEX idx_audit_events_target_seq
    ON audit_events (target_kind, target_id, seq DESC);

CREATE INDEX idx_audit_events_outcome_seq
    ON audit_events (outcome, seq DESC);

CREATE INDEX idx_audit_events_listener_seq
    ON audit_events (listener_id, seq DESC)
    WHERE listener_id IS NOT NULL;

CREATE INDEX idx_audit_events_agent_seq
    ON audit_events (listener_id, agent_id, seq DESC)
    WHERE agent_id IS NOT NULL;

CREATE INDEX idx_audit_events_task_seq
    ON audit_events (listener_id, task_id, seq DESC)
    WHERE task_id IS NOT NULL;

CREATE INDEX idx_audit_events_payload_seq
    ON audit_events (payload_build_id, seq DESC)
    WHERE payload_build_id IS NOT NULL;

CREATE INDEX idx_audit_events_causation
    ON audit_events (causation_sequence)
    WHERE causation_sequence IS NOT NULL;

ALTER TABLE tasks
    ADD COLUMN created_audit_event_seq INTEGER
        REFERENCES audit_events (seq)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

ALTER TABLE payload_builds
    ADD COLUMN created_audit_event_seq INTEGER
        REFERENCES audit_events (seq)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

ALTER TABLE listener_events
    ADD COLUMN audit_event_seq INTEGER
        REFERENCES audit_events (seq)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;

CREATE INDEX idx_tasks_created_audit_event
    ON tasks (created_audit_event_seq)
    WHERE created_audit_event_seq IS NOT NULL;

CREATE INDEX idx_payload_builds_created_audit_event
    ON payload_builds (created_audit_event_seq)
    WHERE created_audit_event_seq IS NOT NULL;

CREATE INDEX idx_listener_events_audit_event
    ON listener_events (audit_event_seq)
    WHERE audit_event_seq IS NOT NULL;

INSERT INTO audit_events (
    schema_version,
    occurred_at,
    actor_kind,
    actor_id,
    action,
    route,
    target_kind,
    target_id,
    outcome,
    reason_code,
    listener_id,
    agent_id,
    task_id
)
SELECT
    1,
    created_at,
    'system',
    'migration:0004',
    'task.migrated',
    'internal:migration',
    'task',
    task_id,
    'succeeded',
    'pre_audit_state',
    listener_id,
    agent_id,
    task_id
FROM tasks
ORDER BY seq;

UPDATE tasks
SET created_audit_event_seq = (
    SELECT event.seq
    FROM audit_events AS event
    WHERE event.action = 'task.migrated'
      AND event.listener_id = tasks.listener_id
      AND event.task_id = tasks.task_id
    ORDER BY event.seq DESC
    LIMIT 1
);

INSERT INTO audit_events (
    schema_version,
    occurred_at,
    actor_kind,
    actor_id,
    action,
    route,
    target_kind,
    target_id,
    outcome,
    reason_code,
    listener_id,
    payload_build_id
)
SELECT
    1,
    created_at,
    'system',
    'migration:0004',
    'payload_build.migrated',
    'internal:migration',
    'payload_build',
    id,
    'succeeded',
    'pre_audit_state',
    listener_id,
    id
FROM payload_builds
ORDER BY created_at, id;

UPDATE payload_builds
SET created_audit_event_seq = (
    SELECT event.seq
    FROM audit_events AS event
    WHERE event.action = 'payload_build.migrated'
      AND event.payload_build_id = payload_builds.id
    ORDER BY event.seq DESC
    LIMIT 1
);

INSERT INTO audit_events (
    schema_version,
    occurred_at,
    actor_kind,
    actor_id,
    action,
    route,
    target_kind,
    target_id,
    outcome,
    reason_code,
    listener_id
)
SELECT
    1,
    occurred_at,
    'system',
    'migration:0004',
    'listener_event.migrated',
    'internal:migration',
    'listener_event',
    CAST(seq AS TEXT),
    'succeeded',
    'pre_audit_state',
    listener_id
FROM listener_events
ORDER BY seq;

UPDATE listener_events
SET audit_event_seq = (
    SELECT event.seq
    FROM audit_events AS event
    WHERE event.action = 'listener_event.migrated'
      AND event.target_kind = 'listener_event'
      AND event.target_id = CAST(listener_events.seq AS TEXT)
    ORDER BY event.seq DESC
    LIMIT 1
);
