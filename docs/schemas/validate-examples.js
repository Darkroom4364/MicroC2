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
    ['audit-page-v1.json', 'audit-page-v1.schema.json'],
    ['defensive-research-categories-v1.json', 'defensive-research-categories-v1.schema.json'],
    ['defensive-research-category-reference-v1.json', 'defensive-research-category-reference-v1.schema.json'],
    ['defensive-research-detection-measurement-rubric-v1.json', 'defensive-research-detection-measurement-rubric-v1.schema.json'],
    ['task-create-request-v1.json', 'task-create-request-v1.schema.json'],
    ['task-dispatched-v1.json', 'task-v1.schema.json'],
    ['task-page-v1.json', 'task-page-v1.schema.json'],
    ['task-result-failed-v1.json', 'task-result-v1.schema.json'],
    ['task-result-v1.json', 'task-result-v1.schema.json'],
    ['task-status-update-v1.json', 'task-status-update-v1.schema.json'],
    ['task-v1.json', 'task-v1.schema.json'],
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

const registryExample = readJSON(path.join(exampleDirectory, 'defensive-research-categories-v1.json'));
const referenceExample = readJSON(path.join(exampleDirectory, 'defensive-research-category-reference-v1.json'));

const registryReferencePositiveCases = [
    {name: 'registry structure', error: validateRegistry(registryExample)},
    {name: 'reference structure', error: validateCategoryReference(referenceExample, registryExample)}
];
for (const testCase of registryReferencePositiveCases) {
    if (testCase.error) {
        console.error(`Defensive research contract failed positive case ${testCase.name}: ${testCase.error}`);
        failed = true;
    }
}

// Semantic negative: the duplicate-ID and unknown-category fixtures
// satisfy their respective JSON Schemas; only the semantic helper
// must reject them.  The mismatched-version reference is deliberately
// schema-invalid (const mismatch) — the semantic helper must
// independently reject it regardless.
const registryNegativeCases = [
    {
        name: 'registry rejects duplicate category id',
        kind: 'registry',
        expectSchemaValid: true,
        value: {
            ...registryExample,
            categories: [
                ...registryExample.categories,
                {
                    ...registryExample.categories[0],
                    label: 'Different Label',
                    purpose: 'A completely different defensive research purpose for the duplicate-id negative test case.',
                    allowed_evidence_classes: ['synthetic-control-summary']
                }
            ]
        }
    },
    {
        name: 'reference rejects unknown category id',
        kind: 'reference',
        expectSchemaValid: true,
        value: {
            ...referenceExample,
            category_id: 'nonexistent-category'
        }
    },
    {
        name: 'reference rejects mismatched registry version',
        kind: 'reference',
        value: {
            ...referenceExample,
            registry_version: '2.0.0'
        }
    }
];
for (const testCase of registryNegativeCases) {
    if (testCase.expectSchemaValid) {
        const schemaId = testCase.kind === 'registry'
            ? schemaID('defensive-research-categories-v1.schema.json')
            : schemaID('defensive-research-category-reference-v1.schema.json');
        const validateFn = ajv.getSchema(schemaId);
        if (!validateFn) {
            console.error(`Defensive research contract schema not loaded: ${schemaId}`);
            failed = true;
            continue;
        }
        if (!validateFn(testCase.value)) {
            console.error(`Defensive research contract negative fixture ${testCase.name} must be schema-valid before semantic rejection but is not: ${ajv.errorsText(validateFn.errors)}`);
            failed = true;
            continue;
        }
    }
    if (testCase.kind === 'registry') {
        if (validateRegistry(testCase.value)) continue;
    } else {
        if (validateCategoryReference(testCase.value, registryExample)) continue;
    }
    console.error(`Defensive research contract failed negative case: ${testCase.name}`);
    failed = true;
}

const rubricExample = readJSON(path.join(exampleDirectory, 'defensive-research-detection-measurement-rubric-v1.json'));

const rubricPositiveCases = [
    {name: 'rubric structure', error: validateRubric(rubricExample, registryExample)}
];
for (const testCase of rubricPositiveCases) {
    if (testCase.error) {
        console.error(`Defensive research contract failed positive case ${testCase.name}: ${testCase.error}`);
        failed = true;
    }
}

// Schema-negative cases: schema must reject malformed inputs.
const rubricNegativeCases = [
    {
        name: 'rubric rejects 4 dimensions',
        kind: 'rubric',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.slice(0, 4)
        }
    },
    {
        name: 'rubric rejects invalid handling suppress',
        kind: 'rubric',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d, i) =>
                i === 0 ? { ...d, invalid_handling: 'suppress' } : d
            )
        }
    },
    {
        name: 'rubric rejects uncertainty disclosure none',
        kind: 'rubric',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d, i) =>
                i === 2 ? { ...d, uncertainty_disclosure: 'none' } : d
            )
        }
    },
    {
        name: 'rubric rejects out-of-global-enum evidence class',
        kind: 'rubric',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d, i) =>
                i === 1
                    ? { ...d, admissible_evidence_classes: ['arbitrary-custom-tooling'] }
                    : d
            )
        }
    }
];
for (const testCase of rubricNegativeCases) {
    const schemaId = schemaID('defensive-research-detection-measurement-rubric-v1.schema.json');
    const validateFn = ajv.getSchema(schemaId);
    if (!validateFn) {
        console.error(`Defensive research contract schema not loaded: ${schemaId}`);
        failed = true;
        continue;
    }
    if (validateFn(testCase.value)) {
        console.error(`Defensive research contract failed negative case ${testCase.name}: schema accepted invalid value`);
        failed = true;
    }
}

// Semantic-negative cases: fixtures are schema-valid before semantic
// rejection unless explicitly marked expectSchemaValid: false.
const rubricSemanticNegativeCases = [
    {
        name: 'rubric rejects duplicate dimension id',
        value: {
            ...rubricExample,
            dimensions: [
                rubricExample.dimensions[0],
                rubricExample.dimensions[1],
                rubricExample.dimensions[2],
                rubricExample.dimensions[3],
                {
                    ...rubricExample.dimensions[0],
                    definition: 'A completely different definition for the duplicate-id negative test case that describes an alternative provenance measurement methodology.',
                    admissible_evidence_classes: ['redacted-observation-summary']
                }
            ]
        }
    },
    {
        name: 'rubric rejects missing dimension id',
        expectSchemaValid: false,
        value: {
            ...rubricExample,
            dimensions: [
                rubricExample.dimensions[0],
                rubricExample.dimensions[2],
                rubricExample.dimensions[3],
                rubricExample.dimensions[4]
            ]
        }
    },
    {
        name: 'rubric rejects category-disallowed evidence class',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d, i) =>
                i === 0
                    ? { ...d, admissible_evidence_classes: ['synthetic-control-summary'] }
                    : d
            )
        }
    },
    {
        name: 'rubric rejects unknown category id',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d, i) =>
                i === 3
                    ? {
                        ...d,
                        category_reference: {
                            ...d.category_reference,
                            category_id: 'nonexistent-category'
                        }
                    }
                    : d
            )
        }
    },
    {
        name: 'rubric rejects missing-unknown-data with exclude-from-comparison',
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d) =>
                d.id === 'missing-unknown-data'
                    ? { ...d, unknown_handling: 'exclude-from-comparison' }
                    : d
            )
        }
    },
    {
        name: 'rubric rejects incompatible registry version',
        expectSchemaValid: false,
        value: {
            ...rubricExample,
            dimensions: rubricExample.dimensions.map((d) => ({
                ...d,
                category_reference: {
                    ...d.category_reference,
                    registry_version: '2.0.0'
                }
            }))
        }
    }
];
const rubricSchemaId = schemaID('defensive-research-detection-measurement-rubric-v1.schema.json');
const rubricValidateFn = ajv.getSchema(rubricSchemaId);
if (!rubricValidateFn) {
    console.error(`Defensive research contract schema not loaded: ${rubricSchemaId}`);
    failed = true;
}
if (rubricValidateFn) {
    for (const testCase of rubricSemanticNegativeCases) {
        if (testCase.expectSchemaValid !== false) {
            if (!rubricValidateFn(testCase.value)) {
                console.error(`Defensive research semantic-negative fixture ${testCase.name} must be schema-valid before semantic rejection but is not: ${ajv.errorsText(rubricValidateFn.errors)}`);
                failed = true;
                continue;
            }
        }
        const err = validateRubric(testCase.value, registryExample);
        if (!err) {
            console.error(`Defensive research contract failed semantic-negative case: ${testCase.name}`);
            failed = true;
        }
    }
}

if (failed) {
    process.exitCode = 1;
} else {
    console.log(
        `Validated ${exampleFiles.length} examples, ${lifecyclePositiveCases.length} lifecycle states, ${negativeCases.length} schema-negative cases, ${semanticNegativeCases.length + semanticStatusNegativeCases.length} semantic-negative cases, ${registryReferencePositiveCases.length} registry-positive cases, ${registryNegativeCases.length} registry-negative cases, ${rubricNegativeCases.length} rubric schema-negative cases, ${rubricPositiveCases.length} rubric-positive cases, and ${rubricSemanticNegativeCases.length} rubric semantic-negative cases against ${schemaFiles.length} Draft 2020-12 schemas.`
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

function validateRegistry(registry) {
    const ids = new Set();
    for (const cat of registry.categories) {
        if (ids.has(cat.id)) {
            return `duplicate category id ${cat.id}`;
        }
        ids.add(cat.id);
    }
    return '';
}

function validateCategoryReference(ref, registry) {
    if (ref.registry_id !== registry.registry_id || ref.registry_version !== registry.registry_version) {
        return `reference pins ${ref.registry_id}@${ref.registry_version} but registry is ${registry.registry_id}@${registry.registry_version}`;
    }
    const catIds = new Set(registry.categories.map(c => c.id));
    if (!catIds.has(ref.category_id)) {
        return `referenced category_id ${ref.category_id} is not present in the pinned registry`;
    }
    return '';
}

function validateRubric(rubric, registry) {
    const expectedIDs = new Set([
        'provenance',
        'collection-coverage',
        'validity',
        'uncertainty',
        'missing-unknown-data'
    ]);
    const seenIDs = new Set();
    const catMap = new Map(registry.categories.map(c => [c.id, c]));

    for (const dim of rubric.dimensions) {
        if (seenIDs.has(dim.id)) {
            return `duplicate dimension id ${dim.id}`;
        }
        seenIDs.add(dim.id);

        // Resolve category reference using the existing reusable helper.
        const refErr = validateCategoryReference(dim.category_reference, registry);
        if (refErr) {
            return `dimension ${dim.id}: ${refErr}`;
        }

        // Each dimension's admissible_evidence_classes must be a subset
        // of the referenced category's allowed_evidence_classes.
        const cat = catMap.get(dim.category_reference.category_id);
        const allowed = new Set(cat.allowed_evidence_classes);
        for (const cls of dim.admissible_evidence_classes) {
            if (!allowed.has(cls)) {
                return `dimension ${dim.id}: evidence class ${cls} is not allowed by category ${cat.id}`;
            }
        }

        // missing-unknown-data must use report-as-unknown.
        if (dim.id === 'missing-unknown-data' && dim.unknown_handling !== 'report-as-unknown') {
            return `dimension missing-unknown-data: unknown_handling must be report-as-unknown, got ${dim.unknown_handling}`;
        }
    }

    // Exact five-ID set: detect missing IDs.
    for (const id of expectedIDs) {
        if (!seenIDs.has(id)) {
            return `missing required dimension id ${id}`;
        }
    }

    return '';
}
