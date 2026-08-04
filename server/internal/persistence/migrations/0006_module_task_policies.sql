CREATE TABLE module_task_policies (
    listener_id TEXT NOT NULL CHECK (length(listener_id) > 0),
    task_id TEXT NOT NULL CHECK (length(task_id) > 0),
    module_id TEXT NOT NULL
        CHECK (module_id = 'agent.capability_inventory.v1'),
    module_version INTEGER NOT NULL CHECK (module_version = 1),
    input_max_bytes INTEGER NOT NULL CHECK (input_max_bytes = 1024),
    output_max_bytes INTEGER NOT NULL CHECK (output_max_bytes = 1024),
    max_timeout_seconds INTEGER NOT NULL CHECK (max_timeout_seconds = 5),
    risk_level TEXT NOT NULL CHECK (risk_level = 'read_only'),
    target_scope TEXT NOT NULL CHECK (target_scope = 'self'),
    evidence_required INTEGER NOT NULL CHECK (evidence_required = 1),
    approval_required INTEGER NOT NULL CHECK (approval_required = 0),
    PRIMARY KEY (listener_id, task_id),
    FOREIGN KEY (listener_id, task_id)
        REFERENCES tasks (listener_id, task_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_module_task_policies_listener_module
    ON module_task_policies (listener_id, module_id);
