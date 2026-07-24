CREATE TABLE payload_enrollment_allocations (
    payload_build_id TEXT NOT NULL
        CHECK (length(payload_build_id) > 0),
    listener_id TEXT NOT NULL
        CHECK (length(listener_id) > 0),
    agent_id TEXT NOT NULL
        CHECK (length(agent_id) > 0),
    allocated_at TEXT NOT NULL
        CHECK (length(allocated_at) > 0),
    PRIMARY KEY (payload_build_id, listener_id, agent_id),
    FOREIGN KEY (payload_build_id, listener_id)
        REFERENCES payload_bootstrap_credentials (
            payload_build_id,
            listener_id
        )
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE INDEX idx_payload_enrollment_allocations_listener
    ON payload_enrollment_allocations (listener_id, agent_id);

INSERT INTO payload_enrollment_allocations (
    payload_build_id,
    listener_id,
    agent_id,
    allocated_at
)
SELECT
    payload_build_id,
    listener_id,
    agent_id,
    bootstrap_consumed_at
FROM agent_enrollment_sessions;

CREATE TRIGGER payload_enrollment_allocations_immutable
BEFORE UPDATE ON payload_enrollment_allocations
BEGIN
    SELECT RAISE(ABORT, 'payload enrollment allocation is immutable');
END;

CREATE TRIGGER payload_enrollment_allocations_no_delete
BEFORE DELETE ON payload_enrollment_allocations
BEGIN
    SELECT RAISE(ABORT, 'payload enrollment allocation cannot be deleted');
END;
