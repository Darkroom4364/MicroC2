'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');

const schemaDirectory = __dirname;
const exampleDirectory = path.join(schemaDirectory, 'examples');
const ajv = new Ajv2020({
    allErrors: true,
    strict: true
});
addFormats(ajv);

const schemaFiles = fs.readdirSync(schemaDirectory)
    .filter(file => file.endsWith('.schema.json'))
    .sort();

for (const file of schemaFiles) {
    const schema = readJSON(path.join(schemaDirectory, file));
    ajv.addSchema(schema);
}

const exampleSchemas = new Map([
    ['module-capability-inventory-input-v1.json', 'module-capability-inventory-input-v1.schema.json'],
    ['module-capability-inventory-output-v1.json', 'module-capability-inventory-output-v1.schema.json'],
    ['module-catalog-v1.json', 'module-catalog-v1.schema.json'],
    ['audit-page-v1.json', 'audit-page-v1.schema.json'],
    ['task-create-request-v1.json', 'task-create-request-v1.schema.json'],
    ['task-dispatched-v1.json', 'task-v1.schema.json'],
    ['task-page-v1.json', 'task-page-v1.schema.json'],
    ['task-result-failed-v1.json', 'task-result-v1.schema.json'],
    ['task-module-create-request-v1.json', 'task-create-request-v1.schema.json'],
    ['task-module-dispatched-v1.json', 'task-v1.schema.json'],
    ['task-module-result-v1.json', 'task-result-v1.schema.json'],
    ['task-result-v1.json', 'task-result-v1.schema.json'],
    ['task-status-update-v1.json', 'task-status-update-v1.schema.json'],
    ['task-v1.json', 'task-v1.schema.json']
]);

let failed = false;
const exampleFiles = fs.readdirSync(exampleDirectory)
    .filter(file => file.endsWith('.json'))
    .sort();

for (const file of exampleFiles) {
    const schemaFile = exampleSchemas.get(file);
    if (!schemaFile) {
        console.error(`No schema mapping is defined for ${file}`);
        failed = true;
        continue;
    }

    const validate = ajv.getSchema(schemaID(schemaFile));
    if (!validate) {
        console.error(`Schema ${schemaFile} was not loaded for ${file}`);
        failed = true;
        continue;
    }

    const example = readJSON(path.join(exampleDirectory, file));
    if (!validate(example)) {
        console.error(`${file} does not satisfy ${schemaFile}:`);
        console.error(ajv.errorsText(validate.errors, {separator: '\n'}));
        failed = true;
    }
}

for (const file of exampleSchemas.keys()) {
    if (!exampleFiles.includes(file)) {
        console.error(`Expected contract example is missing: ${file}`);
        failed = true;
    }
}

const queuedTask = readJSON(path.join(exampleDirectory, 'task-v1.json'));
const dispatchedTask = readJSON(path.join(exampleDirectory, 'task-dispatched-v1.json'));
const completedResult = readJSON(path.join(exampleDirectory, 'task-result-v1.json'));
const failedResult = readJSON(path.join(exampleDirectory, 'task-result-failed-v1.json'));
const runningStatusUpdate = readJSON(
    path.join(exampleDirectory, 'task-status-update-v1.json')
);
const runningTask = {
    ...dispatchedTask,
    status: 'running',
    started_at: completedResult.started_at
};
const completedTask = {
    ...runningTask,
    status: 'completed',
    completed_at: completedResult.completed_at,
    result: completedResult
};
const failedTask = {
    ...runningTask,
    status: 'failed',
    completed_at: failedResult.completed_at,
    result: failedResult
};
const cancelledTask = {
    ...queuedTask,
    status: 'cancelled',
    completed_at: '2026-07-23T16:30:01Z'
};
const expiredQueuedTask = {
    ...queuedTask,
    status: 'expired',
    completed_at: queuedTask.expires_at
};
const expiredDispatchedTask = {
    ...dispatchedTask,
    status: 'expired',
    completed_at: dispatchedTask.expires_at
};

const lifecyclePositiveCases = [
    {name: 'running task', value: runningTask},
    {name: 'completed task', value: completedTask},
    {name: 'failed task', value: failedTask},
    {name: 'cancelled task', value: cancelledTask},
    {name: 'queued task expiry', value: expiredQueuedTask},
    {name: 'dispatched task expiry retains dispatched_at', value: expiredDispatchedTask}
];

for (const testCase of lifecyclePositiveCases) {
    const validate = ajv.getSchema(schemaID('task-v1.schema.json'));
    if (!validate || !validate(testCase.value)) {
        console.error(`Schema contract failed lifecycle case: ${testCase.name}`);
        if (validate) {
            console.error(ajv.errorsText(validate.errors, {separator: '\n'}));
        }
        failed = true;
    }
}

const negativeCases = [
    {
        name: 'audit event rejects arbitrary details',
        schema: 'audit-event-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'audit-page-v1.json')).events[0],
            details: 'terminal output must never appear here'
        }
    },
    {
        name: 'audit event rejects a credential-shaped arbitrary field',
        schema: 'audit-event-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'audit-page-v1.json')).events[0],
            token: 'must-not-be-recorded'
        }
    },
    {
        name: 'audit page rejects an excessive offset',
        schema: 'audit-page-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'audit-page-v1.json')),
            offset: 1000001
        }
    },
    {
        name: 'create request rejects a blank command',
        schema: 'task-create-request-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-create-request-v1.json')),
            arguments: {command: '   '}
        }
    },
    {
        name: 'create request rejects an oversized command',
        schema: 'task-create-request-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-create-request-v1.json')),
            arguments: {command: 'x'.repeat(8193)}
        }
    },
    {
        name: 'create request rejects unknown fields',
        schema: 'task-create-request-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-create-request-v1.json')),
            future_option: true
        }
    },
    {
        name: 'status update rejects a non-ASCII-safe task id',
        schema: 'task-status-update-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-status-update-v1.json')),
            task_id: 'task/one'
        }
    },
    {
        name: 'result rejects an oversized agent id',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            agent_id: 'a'.repeat(129)
        }
    },
    {
        name: 'result rejects an overlong RFC3339 timestamp',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            started_at: '2026-07-23T16:30:05.12345678901234567890Z'
        }
    },
    {
        name: 'result rejects oversized stdout',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            output: {
                stdout: 'x'.repeat(1048577),
                stderr: ''
            }
        }
    },
    {
        name: 'result rejects an oversized error',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            error: 'x'.repeat(8193)
        }
    },
    {
        name: 'completed result requires exit code zero',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            exit_code: 1
        }
    },
    {
        name: 'result rejects an exit code above signed 32-bit range',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-failed-v1.json')),
            exit_code: 2147483648
        }
    },
    {
        name: 'completed result forbids error',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            error: 'unexpected failure'
        }
    },
    {
        name: 'completed result forbids an explicitly empty error',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-v1.json')),
            error: ''
        }
    },
    {
        name: 'failed result requires error',
        schema: 'task-result-v1.schema.json',
        value: withoutProperty(
            readJSON(path.join(exampleDirectory, 'task-result-failed-v1.json')),
            'error'
        )
    },
    {
        name: 'failed result rejects a blank error',
        schema: 'task-result-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-result-failed-v1.json')),
            error: ' \t '
        }
    },
    {
        name: 'task requires expires_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(
            readJSON(path.join(exampleDirectory, 'task-v1.json')),
            'expires_at'
        )
    },
    {
        name: 'task rejects a blank command',
        schema: 'task-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-v1.json')),
            arguments: {command: '\t'}
        }
    },
    {
        name: 'dispatched task requires dispatched_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(
            readJSON(path.join(exampleDirectory, 'task-dispatched-v1.json')),
            'dispatched_at'
        )
    },
    {
        name: 'running task requires dispatched_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(runningTask, 'dispatched_at')
    },
    {
        name: 'running task requires started_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(runningTask, 'started_at')
    },
    {
        name: 'completed task requires result',
        schema: 'task-v1.schema.json',
        value: withoutProperty(completedTask, 'result')
    },
    {
        name: 'failed task requires completed_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(failedTask, 'completed_at')
    },
    {
        name: 'completed task result outcome matches status',
        schema: 'task-v1.schema.json',
        value: {
            ...completedTask,
            result: failedResult
        }
    },
    {
        name: 'failed task result outcome matches status',
        schema: 'task-v1.schema.json',
        value: {
            ...failedTask,
            result: completedResult
        }
    },
    {
        name: 'cancelled task requires completed_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(cancelledTask, 'completed_at')
    },
    {
        name: 'expired task requires completed_at',
        schema: 'task-v1.schema.json',
        value: withoutProperty(expiredDispatchedTask, 'completed_at')
    },
    {
        name: 'task page rejects full output in a summary',
        schema: 'task-page-v1.schema.json',
        value: taskPageWithResultOutput()
    },
    {
        name: 'task page rejects more than 100 summaries',
        schema: 'task-page-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-page-v1.json')),
            tasks: Array.from(
                {length: 101},
                () => readJSON(path.join(exampleDirectory, 'task-page-v1.json')).tasks[0]
            )
        }
    },
    {
        name: 'task page rejects a negative offset',
        schema: 'task-page-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-page-v1.json')),
            offset: -1
        }
    },
    {
        name: 'module input rejects undeclared properties',
        schema: 'module-capability-inventory-input-v1.schema.json',
        value: {target: 'another host'}
    },
    {
        name: 'module output rejects undeclared sensitive metadata',
        schema: 'module-capability-inventory-output-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'module-capability-inventory-output-v1.json')),
            hostname: 'must-not-leak'
        }
    },
    {
        name: 'module task rejects shell command arguments',
        schema: 'task-create-request-v1.schema.json',
        value: {
            ...readJSON(path.join(exampleDirectory, 'task-module-create-request-v1.json')),
            arguments: {
                module_id: 'agent.capability_inventory.v1',
                input: {},
                command: 'whoami'
            }
        }
    },
    ...forbiddenStateCases(
        'queued',
        queuedTask,
        ['dispatched_at', 'started_at', 'completed_at', 'result']
    ),
    ...forbiddenStateCases(
        'dispatched',
        dispatchedTask,
        ['started_at', 'completed_at', 'result']
    ),
    ...forbiddenStateCases(
        'running',
        runningTask,
        ['completed_at', 'result']
    ),
    ...forbiddenStateCases(
        'cancelled',
        cancelledTask,
        ['dispatched_at', 'started_at', 'result']
    ),
    ...forbiddenStateCases(
        'expired',
        expiredDispatchedTask,
        ['started_at', 'result']
    )
];

for (const testCase of negativeCases) {
    const validate = ajv.getSchema(schemaID(testCase.schema));
    if (!validate || validate(testCase.value)) {
        console.error(`Schema contract failed negative case: ${testCase.name}`);
        failed = true;
    }
}

const semanticResultExamples = [
    {name: 'completed result example', value: completedResult},
    {name: 'failed result example', value: failedResult},
    {
        name: 'task page result summary',
        value: readJSON(path.join(exampleDirectory, 'task-page-v1.json')).tasks[0].result
    }
];
for (const testCase of semanticResultExamples) {
    const error = validateResultTimeline(testCase.value);
    if (error) {
        console.error(`Result timeline failed for ${testCase.name}: ${error}`);
        failed = true;
    }
}

const statusTimestampError = validateStatusTimestamp(runningStatusUpdate);
if (statusTimestampError) {
    console.error(`Status timestamp failed for running status example: ${statusTimestampError}`);
    failed = true;
}

const semanticNegativeCases = [
    {
        name: 'result completion precedes start',
        value: {
            ...completedResult,
            completed_at: '2026-07-23T16:30:04Z'
        }
    },
    {
        name: 'result rejects the zero start instant',
        value: {
            ...completedResult,
            started_at: '0001-01-01T00:00:00Z'
        }
    },
    {
        name: 'result rejects the zero completion instant',
        value: {
            ...completedResult,
            completed_at: '0001-01-01T00:00:00Z'
        }
    }
];
for (const testCase of semanticNegativeCases) {
    if (!validateResultTimeline(testCase.value)) {
        console.error(`Semantic contract failed negative case: ${testCase.name}`);
        failed = true;
    }
}

const semanticStatusNegativeCases = [
    {
        name: 'status update rejects the zero timestamp instant',
        value: {
            ...runningStatusUpdate,
            timestamp: '0001-01-01T00:00:00Z'
        }
    }
];
for (const testCase of semanticStatusNegativeCases) {
    if (!validateStatusTimestamp(testCase.value)) {
        console.error(`Semantic contract failed negative case: ${testCase.name}`);
        failed = true;
    }
}

if (failed) {
    process.exitCode = 1;
} else {
    console.log(
        `Validated ${exampleFiles.length} examples, ${lifecyclePositiveCases.length} lifecycle states, ${negativeCases.length} schema-negative cases, and ${semanticNegativeCases.length + semanticStatusNegativeCases.length} semantic-negative cases against ${schemaFiles.length} Draft 2020-12 schemas.`
    );
}

function readJSON(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function schemaID(file) {
    return `https://microc2.local/schemas/${file}`;
}

function withoutProperty(value, property) {
    const clone = {...value};
    delete clone[property];
    return clone;
}

function forbiddenStateCases(state, value, properties) {
    return properties.map(property => ({
        name: `${state} task forbids ${property}`,
        schema: 'task-v1.schema.json',
        value: {
            ...value,
            [property]: forbiddenLifecycleValue(property)
        }
    }));
}

function forbiddenLifecycleValue(property) {
    if (property === 'result') {
        return completedResult;
    }
    return '2026-07-23T16:30:02Z';
}

function taskPageWithResultOutput() {
    const page = readJSON(path.join(exampleDirectory, 'task-page-v1.json'));
    return {
        ...page,
        tasks: page.tasks.map(task => ({
            ...task,
            result: {
                ...task.result,
                output: {
                    stdout: 'must not be listed',
                    stderr: ''
                }
            }
        }))
    };
}

function validateResultTimeline(result) {
    const startedAt = Date.parse(result.started_at);
    const completedAt = Date.parse(result.completed_at);
    if (!Number.isFinite(startedAt) || !Number.isFinite(completedAt)) {
        return 'timestamps must be valid RFC3339 instants';
    }
    const zeroInstant = Date.parse('0001-01-01T00:00:00Z');
    if (startedAt === zeroInstant) {
        return 'started_at must not be the zero instant';
    }
    if (completedAt === zeroInstant) {
        return 'completed_at must not be the zero instant';
    }
    if (completedAt < startedAt) {
        return 'completed_at must not precede started_at';
    }
    return '';
}

function validateStatusTimestamp(update) {
    const timestamp = Date.parse(update.timestamp);
    if (!Number.isFinite(timestamp)) {
        return 'timestamp must be a valid RFC3339 instant';
    }
    if (timestamp === Date.parse('0001-01-01T00:00:00Z')) {
        return 'timestamp must not be the zero instant';
    }
    return '';
}
