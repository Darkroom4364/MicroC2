CREATE TABLE listeners (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    config_json BLOB NOT NULL,
    config_sha256 TEXT NOT NULL
        CHECK (
            length(config_sha256) = 64
            AND config_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    status TEXT NOT NULL
        CHECK (status IN ('ACTIVE', 'STOPPED', 'ERROR', 'DELETED')),
    last_error TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE UNIQUE INDEX idx_listeners_live_name
    ON listeners (lower(name))
    WHERE deleted_at IS NULL;

CREATE TABLE listener_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    listener_id TEXT NOT NULL CHECK (length(listener_id) > 0),
    event_type TEXT NOT NULL CHECK (length(event_type) > 0),
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);

CREATE INDEX idx_listener_events_listener_seq
    ON listener_events (listener_id, seq);

CREATE TABLE agents (
    listener_id TEXT NOT NULL CHECK (length(listener_id) > 0),
    agent_id TEXT NOT NULL CHECK (length(agent_id) > 0),
    payload_id TEXT NOT NULL,
    os TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    ip_list_json BLOB NOT NULL,
    last_commands_json BLOB NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (listener_id, agent_id)
);

CREATE INDEX idx_agents_last_seen
    ON agents (last_seen_at);

CREATE TABLE tasks (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    listener_id TEXT NOT NULL CHECK (length(listener_id) > 0),
    task_id TEXT NOT NULL CHECK (length(task_id) > 0),
    agent_id TEXT NOT NULL CHECK (length(agent_id) > 0),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    task_type TEXT NOT NULL CHECK (length(task_type) > 0),
    command TEXT NOT NULL,
    timeout_seconds INTEGER NOT NULL
        CHECK (timeout_seconds > 0 AND timeout_seconds <= 3600),
    status TEXT NOT NULL
        CHECK (
            status IN (
                'queued',
                'dispatched',
                'running',
                'completed',
                'failed',
                'cancelled',
                'expired'
            )
        ),
    created_at TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    dispatched_at TEXT,
    last_delivery_at TEXT,
    server_started_at TEXT,
    accepted_running_at TEXT,
    server_completed_at TEXT,
    expires_at TEXT,
    legacy_origin INTEGER NOT NULL CHECK (legacy_origin IN (0, 1)),
    UNIQUE (listener_id, task_id)
);

CREATE INDEX idx_tasks_agent_seq
    ON tasks (listener_id, agent_id, seq);

CREATE INDEX idx_tasks_dispatch
    ON tasks (listener_id, agent_id, status, seq);

CREATE TABLE task_results (
    listener_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    agent_id TEXT NOT NULL CHECK (length(agent_id) > 0),
    outcome TEXT NOT NULL CHECK (outcome IN ('completed', 'failed')),
    agent_started_at TEXT NOT NULL,
    agent_completed_at TEXT NOT NULL,
    exit_code INTEGER
        CHECK (
            exit_code IS NULL
            OR (exit_code >= -2147483648 AND exit_code <= 2147483647)
        ),
    stdout TEXT NOT NULL,
    stderr TEXT NOT NULL,
    error TEXT NOT NULL,
    PRIMARY KEY (listener_id, task_id),
    FOREIGN KEY (listener_id, task_id)
        REFERENCES tasks (listener_id, task_id)
        ON DELETE CASCADE
);

CREATE TABLE legacy_results (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    listener_id TEXT NOT NULL CHECK (length(listener_id) > 0),
    agent_id TEXT NOT NULL CHECK (length(agent_id) > 0),
    source_task_id TEXT NOT NULL CHECK (length(source_task_id) > 0),
    command TEXT NOT NULL,
    output TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE (listener_id, source_task_id)
);

CREATE INDEX idx_legacy_results_agent_seq
    ON legacy_results (listener_id, agent_id, seq);

CREATE TABLE payload_builds (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    payload_id TEXT NOT NULL CHECK (length(payload_id) > 0),
    listener_id TEXT NOT NULL CHECK (length(listener_id) > 0),
    mutation_seed TEXT NOT NULL,
    filename TEXT NOT NULL CHECK (length(filename) > 0),
    relative_path TEXT NOT NULL CHECK (length(relative_path) > 0),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL
        CHECK (
            sha256 = ''
            OR (
                length(sha256) = 64
                AND sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
    created_at TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (
            state IN (
                'building',
                'completed',
                'failed',
                'interrupted',
                'missing',
                'corrupt'
            )
        ),
    state_detail TEXT NOT NULL,
    provenance_json BLOB NOT NULL
);
