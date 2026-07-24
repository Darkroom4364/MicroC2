CREATE INDEX idx_agents_agent_id
    ON agents (agent_id);

CREATE UNIQUE INDEX idx_payload_builds_id_listener
    ON payload_builds (id, listener_id);

CREATE TABLE enrollment_server_keys (
    singleton INTEGER PRIMARY KEY
        CHECK (singleton = 1),
    hmac_key BLOB NOT NULL
        CHECK (
            typeof(hmac_key) = 'blob'
            AND length(hmac_key) = 32
        ),
    created_at TEXT NOT NULL
        CHECK (length(created_at) > 0)
);

CREATE TRIGGER enrollment_server_keys_immutable
BEFORE UPDATE ON enrollment_server_keys
BEGIN
    SELECT RAISE(ABORT, 'enrollment server key is immutable');
END;

CREATE TRIGGER enrollment_server_keys_no_delete
BEFORE DELETE ON enrollment_server_keys
BEGIN
    SELECT RAISE(ABORT, 'enrollment server key cannot be deleted');
END;

CREATE TABLE payload_bootstrap_credentials (
    payload_build_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(payload_build_id) > 0),
    listener_id TEXT NOT NULL
        CHECK (length(listener_id) > 0),
    bootstrap_sha256 BLOB NOT NULL
        CHECK (
            typeof(bootstrap_sha256) = 'blob'
            AND length(bootstrap_sha256) = 32
        ),
    max_sessions INTEGER NOT NULL
        CHECK (
            typeof(max_sessions) = 'integer'
            AND max_sessions >= 1
            AND max_sessions <= 64
        ),
    activated_at TEXT NOT NULL
        CHECK (length(activated_at) > 0),
    revoked_at TEXT
        CHECK (revoked_at IS NULL OR length(revoked_at) > 0),
    UNIQUE (payload_build_id, listener_id),
    FOREIGN KEY (payload_build_id, listener_id)
        REFERENCES payload_builds (id, listener_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE INDEX idx_payload_bootstrap_listener
    ON payload_bootstrap_credentials (listener_id, payload_build_id);

CREATE TRIGGER payload_bootstrap_credentials_immutable
BEFORE UPDATE OF
    payload_build_id,
    listener_id,
    bootstrap_sha256,
    max_sessions,
    activated_at
ON payload_bootstrap_credentials
BEGIN
    SELECT RAISE(ABORT, 'payload bootstrap credential is immutable');
END;

CREATE TABLE agent_enrollment_sessions (
    session_id BLOB NOT NULL PRIMARY KEY
        CHECK (
            typeof(session_id) = 'blob'
            AND length(session_id) = 32
        ),
    listener_id TEXT NOT NULL
        CHECK (length(listener_id) > 0),
    agent_id TEXT NOT NULL
        CHECK (length(agent_id) > 0),
    payload_build_id TEXT NOT NULL
        CHECK (length(payload_build_id) > 0),
    current_generation INTEGER NOT NULL
        CHECK (
            typeof(current_generation) = 'integer'
            AND current_generation >= 1
        ),
    pending_generation INTEGER
        CHECK (
            pending_generation IS NULL
            OR (
                typeof(pending_generation) = 'integer'
                AND current_generation < 9223372036854775807
                AND pending_generation = current_generation + 1
            )
        ),
    bootstrap_consumed_at TEXT NOT NULL
        CHECK (length(bootstrap_consumed_at) > 0),
    session_confirmed_at TEXT
        CHECK (
            session_confirmed_at IS NULL
            OR length(session_confirmed_at) > 0
        ),
    reenrollment_required_at TEXT
        CHECK (
            reenrollment_required_at IS NULL
            OR length(reenrollment_required_at) > 0
        ),
    last_reenrolled_at TEXT
        CHECK (
            last_reenrolled_at IS NULL
            OR length(last_reenrolled_at) > 0
        ),
    revoked_at TEXT
        CHECK (revoked_at IS NULL OR length(revoked_at) > 0),
    created_at TEXT NOT NULL
        CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL
        CHECK (length(updated_at) > 0),
    UNIQUE (listener_id, agent_id),
    FOREIGN KEY (payload_build_id, listener_id)
        REFERENCES payload_bootstrap_credentials (
            payload_build_id,
            listener_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE INDEX idx_agent_enrollment_listener_active
    ON agent_enrollment_sessions (listener_id, agent_id)
    WHERE revoked_at IS NULL
        AND reenrollment_required_at IS NULL;

CREATE INDEX idx_agent_enrollment_build_active
    ON agent_enrollment_sessions (payload_build_id, listener_id)
    WHERE revoked_at IS NULL
        AND reenrollment_required_at IS NULL;
