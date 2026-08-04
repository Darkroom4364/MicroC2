ALTER TABLE tasks
ADD COLUMN arguments_json TEXT NOT NULL DEFAULT '{}';

UPDATE tasks
SET arguments_json = json_object('command', command)
WHERE task_type = 'shell';

ALTER TABLE task_results
ADD COLUMN data_json TEXT;

ALTER TABLE agents
ADD COLUMN module_ids_json TEXT NOT NULL DEFAULT '[]';
