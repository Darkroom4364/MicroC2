'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
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
    ['defensive-research-categories-v1.json', 'defensive-research-categories-v1.schema.json'],
    ['defensive-research-category-reference-v1.json', 'defensive-research-category-reference-v1.schema.json'],
    ['defensive-research-detection-measurement-rubric-v1.json', 'defensive-research-detection-measurement-rubric-v1.schema.json'],
    ['task-create-request-v1.json', 'task-create-request-v1.schema.json'],
    ['task-dispatched-v1.json', 'task-v1.schema.json'],
    ['task-page-v1.json', 'task-page-v1.schema.json'],
    ['task-result-failed-v1.json', 'task-result-v1.schema.json'],
    ['task-module-create-request-v1.json', 'task-create-request-v1.schema.json'],
    ['task-module-dispatched-v1.json', 'task-v1.schema.json'],
    ['task-module-result-v1.json', 'task-result-v1.schema.json'],
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

const evidencePackageSchemaFile = 'defensive-research-experiment-evidence-package-manifest-v1.schema.json';
const evidencePackageSchemaId = schemaID(evidencePackageSchemaFile);
const evidencePackageFixtureDirectory = path.join(
    exampleDirectory,
    'defensive-research-experiment-evidence-package-manifest-v1'
);
const evidencePackageManifest = readJSON(path.join(evidencePackageFixtureDirectory, 'manifest.json'));
const evidenceEntryFixture = readJSON(path.join(evidencePackageFixtureDirectory, 'evidence-001.json'));
const auditEventSchema = readJSON(path.join(schemaDirectory, 'audit-event-v1.schema.json'));
const evidencePackageValidate = ajv.getSchema(evidencePackageSchemaId);
const evidenceEntryValidate = ajv.getSchema(`${evidencePackageSchemaId}#/$defs/evidenceEntry`);
const evidencePackageContext = {
    manifestValidate: evidencePackageValidate,
    entryValidate: evidenceEntryValidate,
    rubric: rubricExample,
    registry: registryExample,
    auditEventSchema,
    derivativeProfileID: 'microc2-audit-event-v1-identifier-free-summary',
    derivativeProfileVersion: '1.0.0'
};
const evidencePackageMappingCases = [
    {
        name: 'provenance mapping',
        rubricDimensionID: 'provenance',
        evidenceClass: 'integrity-metadata'
    },
    {
        name: 'collection coverage mapping',
        rubricDimensionID: 'collection-coverage',
        evidenceClass: 'synthetic-control-summary'
    },
    {
        name: 'validity mapping',
        rubricDimensionID: 'validity',
        evidenceClass: 'redacted-observation-summary'
    },
    {
        name: 'uncertainty mapping',
        rubricDimensionID: 'uncertainty',
        evidenceClass: 'aggregate-measurement-summary'
    },
    {
        name: 'missing unknown data mapping',
        rubricDimensionID: 'missing-unknown-data',
        evidenceClass: 'aggregate-measurement-summary'
    }
];
const evidencePackagePositiveCases = [];
if (!evidencePackageValidate || !evidenceEntryValidate) {
    console.error('Evidence package contract schema or entry subschema was not loaded.');
    failed = true;
} else {
    evidencePackagePositiveCases.push({
        name: 'package fixture',
        error: validateEvidencePackageDirectory(evidencePackageFixtureDirectory, evidencePackageContext)
    });
    for (const testCase of evidencePackageMappingCases) {
        const error = withTemporaryEvidencePackage(
            evidencePackageFixtureDirectory,
            (temporaryDirectory) => {
                const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
                const entry = readJSON(entryPath);
                entry.rubric_dimension_id = testCase.rubricDimensionID;
                entry.evidence_class = testCase.evidenceClass;
                writeJSON(entryPath, entry);
                updateEvidencePackageDigest(temporaryDirectory, 'evidence-001');
            },
            (temporaryDirectory) => validateEvidencePackageDirectory(temporaryDirectory, evidencePackageContext)
        );
        evidencePackagePositiveCases.push({name: testCase.name, error});
    }
}
for (const testCase of evidencePackagePositiveCases) {
    if (testCase.error) {
        console.error(`Evidence package contract failed positive case ${testCase.name}: ${testCase.error}`);
        failed = true;
    }
}

const evidencePackageSchemaNegativeCases = [
    {
        name: 'package rejects incompatible package version',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            package_version: '2.0.0'
        }
    },
    {
        name: 'package rejects incompatible rubric version',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            rubric_reference: {
                ...evidencePackageManifest.rubric_reference,
                rubric_version: '2.0.0'
            }
        }
    },
    {
        name: 'package rejects incompatible registry version',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            registry_reference: {
                ...evidencePackageManifest.registry_reference,
                registry_version: '2.0.0'
            }
        }
    },
    {
        name: 'package rejects incompatible Audit Event schema identity',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            provenance: {
                ...evidencePackageManifest.provenance,
                audit_event_schema_id: 'https://microc2.local/schemas/audit-event-v2.schema.json'
            }
        }
    },
    {
        name: 'package rejects incompatible Audit Event schema version',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            provenance: {
                ...evidencePackageManifest.provenance,
                audit_event_schema_version: 2
            }
        }
    },
    {
        name: 'package rejects incompatible derivative profile id',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            provenance: {
                ...evidencePackageManifest.provenance,
                derivative_profile_id: 'arbitrary-profile'
            }
        }
    },
    {
        name: 'package rejects incompatible derivative profile version',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            provenance: {
                ...evidencePackageManifest.provenance,
                derivative_profile_version: '2.0.0'
            }
        }
    },
    {
        name: 'package rejects an unapproved file role',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            files: evidencePackageManifest.files.map((file) =>
                file.role === 'audit-event-v1-evidence'
                    ? {...file, role: 'artifact'}
                    : file
            )
        }
    },
    {
        name: 'package rejects an uppercase digest',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            files: evidencePackageManifest.files.map((file) =>
                file.role === 'audit-event-v1-evidence'
                    ? {...file, sha256: file.sha256.toUpperCase()}
                    : file
            )
        }
    },
    {
        name: 'package rejects a path-shaped file name',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            files: evidencePackageManifest.files.map((file) =>
                file.role === 'audit-event-v1-evidence'
                    ? {...file, file_name: '/evidence-001.json'}
                    : file
            )
        }
    },
    {
        name: 'package rejects arbitrary metadata',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            metadata: 'not-permitted'
        }
    },
    {
        name: 'package rejects an arbitrary URL',
        kind: 'manifest',
        value: {
            ...evidencePackageManifest,
            url: 'not-permitted'
        }
    },
    ...[
        'actor',
        'action',
        'route',
        'target',
        'outcome',
        'identifier',
        'body',
        'raw_log',
        'artifact',
        'endpoint',
        'command',
        'output',
        'credential',
        'full_path',
        'database',
        'payload',
        'listener',
        'task',
        'result',
        'network',
        'export'
    ].map((property) => ({
        name: `evidence entry rejects ${property}`,
        kind: 'entry',
        value: {
            ...evidenceEntryFixture,
            [property]: 'not-permitted'
        }
    })),
    {
        name: 'evidence entry rejects an unapproved source mode',
        kind: 'entry',
        value: {
            ...evidenceEntryFixture,
            source_mode: 'live'
        }
    },
    {
        name: 'evidence entry rejects a non-count summary',
        kind: 'entry',
        value: {
            ...evidenceEntryFixture,
            derivative_summary: {
                ...evidenceEntryFixture.derivative_summary,
                summary_kind: 'details'
            }
        }
    }
];
if (evidencePackageValidate && evidenceEntryValidate) {
    for (const testCase of evidencePackageSchemaNegativeCases) {
        const validate = testCase.kind === 'manifest'
            ? evidencePackageValidate
            : evidenceEntryValidate;
        if (validate(testCase.value)) {
            console.error(`Evidence package contract failed schema-negative case: ${testCase.name}`);
            failed = true;
        }
    }
}

const evidencePackageSemanticNegativeCases = [
    {
        name: 'package rejects category-valid but rubric-invalid evidence class',
        expectedReason: 'rubric evidence-class mapping',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            const entry = readJSON(entryPath);
            entry.evidence_class = 'aggregate-measurement-summary';
            writeJSON(entryPath, entry);
            updateEvidencePackageDigest(temporaryDirectory, 'evidence-001');
        }
    },
    {
        name: 'package rejects duplicate rubric dimension',
        expectedReason: 'duplicate rubric dimension',
        mutate: (temporaryDirectory) => {
            const entry = readJSON(path.join(temporaryDirectory, 'evidence-001.json'));
            const duplicateEntry = {
                ...entry,
                entry_id: 'evidence-002'
            };
            const duplicatePath = path.join(temporaryDirectory, 'evidence-002.json');
            writeJSON(duplicatePath, duplicateEntry);
            const manifestPath = path.join(temporaryDirectory, 'manifest.json');
            const manifest = readJSON(manifestPath);
            manifest.files.push({
                file_id: 'evidence-002',
                file_name: 'evidence-002.json',
                role: 'audit-event-v1-evidence',
                sha256: sha256File(duplicatePath)
            });
            writeJSON(manifestPath, manifest);
        }
    },
    {
        name: 'package rejects descriptor entry id mismatch',
        expectedReason: 'descriptor-entry mapping',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            const entry = readJSON(entryPath);
            entry.entry_id = 'evidence-002';
            writeJSON(entryPath, entry);
            updateEvidencePackageDigest(temporaryDirectory, 'evidence-001');
        }
    },
    {
        name: 'package rejects a missing declared file',
        expectedReason: 'missing file',
        preconditionScope: 'manifest-only',
        mutate: (temporaryDirectory) => {
            fs.rmSync(path.join(temporaryDirectory, 'evidence-001.json'));
        }
    },
    {
        name: 'package rejects a digest mismatch',
        expectedReason: 'digest mismatch',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            const entry = readJSON(entryPath);
            entry.derivative_summary.record_count = 2;
            writeJSON(entryPath, entry);
        }
    },
    {
        name: 'package rejects an undeclared file',
        expectedReason: 'undeclared directory entry',
        mutate: (temporaryDirectory) => {
            fs.writeFileSync(path.join(temporaryDirectory, 'undeclared.json'), '{}\n');
        }
    },
    {
        name: 'package rejects a directory',
        expectedReason: 'non-regular directory entry',
        preconditionScope: 'manifest-only',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            fs.rmSync(entryPath);
            fs.mkdirSync(entryPath);
        }
    },
    {
        name: 'package rejects a sidecar symlink',
        expectedReason: 'symbolic link',
        preconditionScope: 'manifest-only',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            fs.rmSync(entryPath);
            return createEvidencePackageSymlink(
                path.join(temporaryDirectory, 'manifest.json'),
                entryPath
            );
        }
    },
    {
        name: 'package rejects a malformed manifest',
        expectedReason: 'manifest is not valid JSON',
        expectSchemaValid: false,
        mutate: (temporaryDirectory) => {
            fs.writeFileSync(path.join(temporaryDirectory, 'manifest.json'), '{"package_id":');
        }
    },
    {
        name: 'package rejects a manifest symlink',
        expectedReason: 'symbolic link',
        expectSchemaValid: false,
        mutate: (temporaryDirectory) => {
            const manifestPath = path.join(temporaryDirectory, 'manifest.json');
            fs.rmSync(manifestPath);
            return createEvidencePackageSymlink(
                path.join(temporaryDirectory, 'evidence-001.json'),
                manifestPath
            );
        }
    },
    {
        name: 'package rejects duplicate manifest members before schema validation',
        expectedReason: 'duplicate JSON member name',
        mutate: (temporaryDirectory) => {
            const manifestPath = path.join(temporaryDirectory, 'manifest.json');
            writeJSONWithDiscardedDuplicate(
                manifestPath,
                readJSON(manifestPath),
                'package_version',
                'discarded-unsafe-looking-text'
            );
        }
    },
    {
        name: 'package rejects duplicate sidecar members before digest validation',
        expectedReason: 'duplicate JSON member name',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            writeJSONWithDiscardedDuplicate(
                entryPath,
                readJSON(entryPath),
                'source_mode',
                'discarded-command-output-like-text'
            );
            updateEvidencePackageDigest(temporaryDirectory, 'evidence-001');
        }
    },
    {
        name: 'package rejects decoded duplicate nested sidecar members before digest validation',
        expectedReason: 'duplicate JSON member name',
        mutate: (temporaryDirectory) => {
            const entryPath = path.join(temporaryDirectory, 'evidence-001.json');
            writeJSONWithDiscardedNestedDuplicate(
                entryPath,
                readJSON(entryPath),
                'derivative_summary',
                'record_count',
                'discarded-unsafe-looking-text',
                '"record_\\u0063ount"'
            );
            updateEvidencePackageDigest(temporaryDirectory, 'evidence-001');
        }
    }
];
if (evidencePackageValidate && evidenceEntryValidate) {
    for (const testCase of evidencePackageSemanticNegativeCases) {
        let shouldValidate = true;
        const error = withTemporaryEvidencePackage(
            evidencePackageFixtureDirectory,
            (temporaryDirectory) => {
                shouldValidate = testCase.mutate(temporaryDirectory) !== false;
            },
            (temporaryDirectory) => {
                if (!shouldValidate) return '';
                if (testCase.expectSchemaValid !== false) {
                    const preconditionError = validateEvidencePackageOrdinarySchemaPrecondition(
                        temporaryDirectory,
                        evidencePackageContext,
                        testCase.preconditionScope || 'full'
                    );
                    if (preconditionError) {
                        return `test precondition failed: ${preconditionError}`;
                    }
                }
                return validateEvidencePackageDirectory(temporaryDirectory, evidencePackageContext);
            }
        );
        if (!shouldValidate) {
            console.log(`Evidence package contract skipped creation-level symlink case: ${testCase.name}`);
            continue;
        }
        if (error.startsWith('test precondition failed:')) {
            console.error(`Evidence package contract invalid semantic-negative precondition ${testCase.name}: ${error}`);
            failed = true;
            continue;
        }
        if (!error || !error.includes(testCase.expectedReason)) {
            console.error(`Evidence package contract failed semantic-negative case: ${testCase.name}`);
            failed = true;
        }
    }
}

if (failed) {
    process.exitCode = 1;
} else {
    console.log(
        `Validated ${exampleFiles.length} examples, ${lifecyclePositiveCases.length} lifecycle states, ${negativeCases.length} schema-negative cases, ${semanticNegativeCases.length + semanticStatusNegativeCases.length} semantic-negative cases, ${registryReferencePositiveCases.length} registry-positive cases, ${registryNegativeCases.length} registry-negative cases, ${rubricNegativeCases.length} rubric schema-negative cases, ${rubricPositiveCases.length} rubric-positive cases, ${rubricSemanticNegativeCases.length} rubric semantic-negative cases, ${evidencePackagePositiveCases.length} evidence-package positive cases, ${evidencePackageSchemaNegativeCases.length} evidence-package schema-negative cases, and ${evidencePackageSemanticNegativeCases.length} evidence-package semantic-negative cases against ${schemaFiles.length} Draft 2020-12 schemas.`
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

function validateEvidencePackageDirectory(directory, context) {
    const inventory = inspectEvidencePackageDirectory(directory);
    if (inventory.error) return inventory.error;

    const manifestResult = readEvidencePackageJSON(inventory.entryPaths.get('manifest.json'), 'manifest');
    if (manifestResult.error) return manifestResult.error;

    return validateEvidencePackage(manifestResult.value, inventory, context);
}

function inspectEvidencePackageDirectory(directory) {
    let root;
    try {
        root = fs.lstatSync(directory);
    } catch {
        return {error: 'package root cannot be inspected'};
    }
    if (root.isSymbolicLink()) {
        return {error: 'package root must not be a symbolic link'};
    }
    if (!root.isDirectory()) {
        return {error: 'package root is not a directory'};
    }

    let names;
    try {
        names = fs.readdirSync(directory);
    } catch {
        return {error: 'package directory cannot be read'};
    }

    const entryPaths = new Map();
    for (const name of names) {
        const entryPath = path.join(directory, name);
        let entry;
        try {
            entry = fs.lstatSync(entryPath);
        } catch {
            return {error: 'package directory entry cannot be inspected'};
        }
        if (entry.isSymbolicLink()) {
            return {error: 'package contains a symbolic link'};
        }
        if (!entry.isFile()) {
            return {error: 'package contains a non-regular directory entry'};
        }
        entryPaths.set(name, entryPath);
    }
    if (!entryPaths.has('manifest.json')) {
        return {error: 'package is missing manifest.json'};
    }

    return {entryPaths};
}

function readEvidencePackageJSON(file, documentKind) {
    let source;
    try {
        source = fs.readFileSync(file, 'utf8');
    } catch {
        return {error: `${documentKind} cannot be read`};
    }

    const scanError = scanEvidencePackageJSONForDuplicateKeys(source);
    if (scanError === 'duplicate') {
        return {error: `${documentKind} contains duplicate JSON member name`};
    }
    if (scanError) {
        return {error: `${documentKind} is not valid JSON`};
    }

    try {
        return {value: JSON.parse(source)};
    } catch {
        return {error: `${documentKind} is not valid JSON`};
    }
}

function scanEvidencePackageJSONForDuplicateKeys(source) {
    const state = {source, index: 0};
    try {
        skipEvidencePackageJSONWhitespace(state);
        scanEvidencePackageJSONValue(state);
        skipEvidencePackageJSONWhitespace(state);
        if (state.index !== source.length) {
            throw {kind: 'invalid'};
        }
        return '';
    } catch (error) {
        return error && error.kind === 'duplicate' ? 'duplicate' : 'invalid';
    }
}

function scanEvidencePackageJSONValue(state) {
    skipEvidencePackageJSONWhitespace(state);
    const character = state.source[state.index];
    if (character === '{') {
        scanEvidencePackageJSONObject(state);
        return;
    }
    if (character === '[') {
        scanEvidencePackageJSONArray(state);
        return;
    }
    if (character === '"') {
        scanEvidencePackageJSONString(state);
        return;
    }
    if (character === '-' || isEvidencePackageJSONDigit(character)) {
        scanEvidencePackageJSONNumber(state);
        return;
    }
    if (state.source.startsWith('true', state.index)) {
        state.index += 4;
        return;
    }
    if (state.source.startsWith('false', state.index)) {
        state.index += 5;
        return;
    }
    if (state.source.startsWith('null', state.index)) {
        state.index += 4;
        return;
    }
    throw {kind: 'invalid'};
}

function scanEvidencePackageJSONObject(state) {
    state.index += 1;
    skipEvidencePackageJSONWhitespace(state);
    if (state.source[state.index] === '}') {
        state.index += 1;
        return;
    }

    const keys = new Set();
    while (true) {
        if (state.source[state.index] !== '"') {
            throw {kind: 'invalid'};
        }
        const key = scanEvidencePackageJSONString(state);
        if (keys.has(key)) {
            throw {kind: 'duplicate'};
        }
        keys.add(key);

        skipEvidencePackageJSONWhitespace(state);
        if (state.source[state.index] !== ':') {
            throw {kind: 'invalid'};
        }
        state.index += 1;
        scanEvidencePackageJSONValue(state);
        skipEvidencePackageJSONWhitespace(state);

        if (state.source[state.index] === '}') {
            state.index += 1;
            return;
        }
        if (state.source[state.index] !== ',') {
            throw {kind: 'invalid'};
        }
        state.index += 1;
        skipEvidencePackageJSONWhitespace(state);
    }
}

function scanEvidencePackageJSONArray(state) {
    state.index += 1;
    skipEvidencePackageJSONWhitespace(state);
    if (state.source[state.index] === ']') {
        state.index += 1;
        return;
    }

    while (true) {
        scanEvidencePackageJSONValue(state);
        skipEvidencePackageJSONWhitespace(state);
        if (state.source[state.index] === ']') {
            state.index += 1;
            return;
        }
        if (state.source[state.index] !== ',') {
            throw {kind: 'invalid'};
        }
        state.index += 1;
        skipEvidencePackageJSONWhitespace(state);
    }
}

function scanEvidencePackageJSONString(state) {
    if (state.source[state.index] !== '"') {
        throw {kind: 'invalid'};
    }
    state.index += 1;
    let decoded = '';
    while (state.index < state.source.length) {
        const character = state.source[state.index];
        state.index += 1;
        if (character === '"') {
            return decoded;
        }
        if (character === '\\') {
            const escape = state.source[state.index];
            state.index += 1;
            if (escape === '"' || escape === '\\' || escape === '/') {
                decoded += escape;
                continue;
            }
            if (escape === 'b') {
                decoded += '\b';
                continue;
            }
            if (escape === 'f') {
                decoded += '\f';
                continue;
            }
            if (escape === 'n') {
                decoded += '\n';
                continue;
            }
            if (escape === 'r') {
                decoded += '\r';
                continue;
            }
            if (escape === 't') {
                decoded += '\t';
                continue;
            }
            if (escape === 'u') {
                decoded += String.fromCharCode(scanEvidencePackageJSONHexCodeUnit(state));
                continue;
            }
            throw {kind: 'invalid'};
        }
        if (character.charCodeAt(0) <= 0x1f) {
            throw {kind: 'invalid'};
        }
        decoded += character;
    }
    throw {kind: 'invalid'};
}

function scanEvidencePackageJSONHexCodeUnit(state) {
    if (state.index + 4 > state.source.length) {
        throw {kind: 'invalid'};
    }
    let value = 0;
    for (let offset = 0; offset < 4; offset += 1) {
        const digit = evidencePackageJSONHexValue(state.source[state.index + offset]);
        if (digit < 0) {
            throw {kind: 'invalid'};
        }
        value = (value * 16) + digit;
    }
    state.index += 4;
    return value;
}

function scanEvidencePackageJSONNumber(state) {
    if (state.source[state.index] === '-') {
        state.index += 1;
    }
    if (state.source[state.index] === '0') {
        state.index += 1;
        if (isEvidencePackageJSONDigit(state.source[state.index])) {
            throw {kind: 'invalid'};
        }
    } else {
        if (!isEvidencePackageJSONNonzeroDigit(state.source[state.index])) {
            throw {kind: 'invalid'};
        }
        state.index += 1;
        while (isEvidencePackageJSONDigit(state.source[state.index])) {
            state.index += 1;
        }
    }
    if (state.source[state.index] === '.') {
        state.index += 1;
        if (!isEvidencePackageJSONDigit(state.source[state.index])) {
            throw {kind: 'invalid'};
        }
        while (isEvidencePackageJSONDigit(state.source[state.index])) {
            state.index += 1;
        }
    }
    if (state.source[state.index] === 'e' || state.source[state.index] === 'E') {
        state.index += 1;
        if (state.source[state.index] === '+' || state.source[state.index] === '-') {
            state.index += 1;
        }
        if (!isEvidencePackageJSONDigit(state.source[state.index])) {
            throw {kind: 'invalid'};
        }
        while (isEvidencePackageJSONDigit(state.source[state.index])) {
            state.index += 1;
        }
    }
}

function skipEvidencePackageJSONWhitespace(state) {
    while (
        state.source[state.index] === ' ' ||
        state.source[state.index] === '\n' ||
        state.source[state.index] === '\r' ||
        state.source[state.index] === '\t'
    ) {
        state.index += 1;
    }
}

function isEvidencePackageJSONDigit(character) {
    return character >= '0' && character <= '9';
}

function isEvidencePackageJSONNonzeroDigit(character) {
    return character >= '1' && character <= '9';
}

function evidencePackageJSONHexValue(character) {
    if (character >= '0' && character <= '9') return character.charCodeAt(0) - 48;
    if (character >= 'a' && character <= 'f') return character.charCodeAt(0) - 87;
    if (character >= 'A' && character <= 'F') return character.charCodeAt(0) - 55;
    return -1;
}

function validateEvidencePackage(manifest, inventory, context) {
    if (!context.manifestValidate(manifest)) {
        return 'manifest does not satisfy its schema';
    }

    const pinError = validateEvidencePackagePins(manifest, context);
    if (pinError) return pinError;

    const descriptorsByName = new Map();
    const descriptorsByID = new Map();
    let manifestCount = 0;
    for (const descriptor of manifest.files) {
        if (descriptorsByName.has(descriptor.file_name)) {
            return 'package inventory has duplicate descriptor names';
        }
        if (descriptorsByID.has(descriptor.file_id)) {
            return 'package inventory has duplicate descriptor ids';
        }
        descriptorsByName.set(descriptor.file_name, descriptor);
        descriptorsByID.set(descriptor.file_id, descriptor);
        if (descriptor.role === 'manifest') {
            manifestCount += 1;
        } else if (descriptor.file_name !== `${descriptor.file_id}.json`) {
            return 'package inventory has invalid evidence descriptor naming';
        }
    }
    if (manifestCount !== 1) {
        return 'package inventory has invalid manifest descriptor count';
    }

    for (const name of inventory.entryPaths.keys()) {
        if (!descriptorsByName.has(name)) {
            return 'package contains an undeclared directory entry';
        }
    }
    for (const name of descriptorsByName.keys()) {
        if (!inventory.entryPaths.has(name)) {
            return 'package declares a missing file';
        }
    }

    const parsedEntries = [];
    for (const descriptor of manifest.files) {
        if (descriptor.role === 'manifest') continue;
        const entryResult = readEvidencePackageJSON(
            inventory.entryPaths.get(descriptor.file_name),
            'evidence entry'
        );
        if (entryResult.error) return entryResult.error;
        parsedEntries.push({
            descriptor,
            entry: entryResult.value,
            entryPath: inventory.entryPaths.get(descriptor.file_name)
        });
    }

    const dimensionsByID = new Map(context.rubric.dimensions.map(dimension => [dimension.id, dimension]));
    const categoriesByID = new Map(context.registry.categories.map(category => [category.id, category]));
    const seenDimensions = new Set();
    for (const {descriptor, entry, entryPath} of parsedEntries) {
        if (!context.entryValidate(entry)) {
            return 'evidence entry does not satisfy its schema';
        }
        if (entry.entry_id !== descriptor.file_id) {
            return 'package has a descriptor-entry mapping mismatch';
        }

        let digest;
        try {
            digest = sha256File(entryPath);
        } catch {
            return 'evidence entry cannot be read';
        }
        if (digest !== descriptor.sha256) {
            return 'evidence entry has a digest mismatch';
        }
        if (seenDimensions.has(entry.rubric_dimension_id)) {
            return 'package has a duplicate rubric dimension';
        }
        seenDimensions.add(entry.rubric_dimension_id);

        const dimension = dimensionsByID.get(entry.rubric_dimension_id);
        if (!dimension) {
            return 'pinned rubric dimension is invalid';
        }
        if (
            dimension.category_reference.registry_id !== manifest.registry_reference.registry_id ||
            dimension.category_reference.registry_version !== manifest.registry_reference.registry_version ||
            dimension.category_reference.schema_version !== manifest.registry_reference.schema_version
        ) {
            return 'pinned rubric category reference does not match the manifest registry pin';
        }
        if (validateCategoryReference(dimension.category_reference, context.registry)) {
            return 'pinned rubric category reference is invalid';
        }

        const category = categoriesByID.get(dimension.category_reference.category_id);
        if (!category.allowed_evidence_classes.includes(entry.evidence_class)) {
            return 'registry evidence-class mapping is invalid';
        }
        if (!dimension.admissible_evidence_classes.includes(entry.evidence_class)) {
            return 'rubric evidence-class mapping is invalid';
        }
    }

    return '';
}

function validateEvidencePackageOrdinarySchemaPrecondition(directory, context, scope) {
    const manifestResult = readEvidencePackageJSONOrdinarily(path.join(directory, 'manifest.json'));
    if (manifestResult.error) return manifestResult.error;
    if (!context.manifestValidate(manifestResult.value)) {
        return 'ordinary manifest parse is not schema-valid';
    }

    // Missing or non-regular declared entries are inventory cases; their valid
    // manifest is the only applicable schema precondition.
    if (scope === 'manifest-only') return '';

    for (const descriptor of manifestResult.value.files) {
        if (descriptor.role === 'manifest') continue;
        const entryResult = readEvidencePackageJSONOrdinarily(
            path.join(directory, descriptor.file_name)
        );
        if (entryResult.error) return entryResult.error;
        if (!context.entryValidate(entryResult.value)) {
            return 'ordinary evidence entry parse is not schema-valid';
        }
    }
    return '';
}

function readEvidencePackageJSONOrdinarily(file) {
    let source;
    try {
        source = fs.readFileSync(file, 'utf8');
    } catch {
        return {error: 'ordinary JSON precondition cannot read package input'};
    }
    try {
        return {value: JSON.parse(source)};
    } catch {
        return {error: 'ordinary JSON precondition cannot parse package input'};
    }
}

function validateEvidencePackagePins(manifest, context) {
    if (
        manifest.rubric_reference.rubric_id !== context.rubric.rubric_id ||
        manifest.rubric_reference.rubric_version !== context.rubric.rubric_version ||
        manifest.rubric_reference.schema_version !== context.rubric.schema_version
    ) {
        return 'manifest rubric reference does not match the pinned rubric';
    }
    if (
        manifest.registry_reference.registry_id !== context.registry.registry_id ||
        manifest.registry_reference.registry_version !== context.registry.registry_version ||
        manifest.registry_reference.schema_version !== context.registry.schema_version
    ) {
        return 'manifest registry reference does not match the pinned registry';
    }

    const auditEventSchemaVersion = context.auditEventSchema.properties.schema_version.const;
    if (
        manifest.provenance.audit_event_schema_id !== context.auditEventSchema.$id ||
        manifest.provenance.audit_event_schema_version !== auditEventSchemaVersion
    ) {
        return 'manifest provenance does not match the pinned Audit Event schema';
    }
    if (
        manifest.provenance.derivative_profile_id !== context.derivativeProfileID ||
        manifest.provenance.derivative_profile_version !== context.derivativeProfileVersion
    ) {
        return 'manifest provenance does not match the fixed derivative profile';
    }

    return '';
}

function withTemporaryEvidencePackage(fixtureDirectory, mutate, validate) {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'microc2-evidence-package-'));
    const temporaryDirectory = path.join(temporaryRoot, 'package');
    try {
        fs.cpSync(fixtureDirectory, temporaryDirectory, {recursive: true, dereference: true});
        mutate(temporaryDirectory);
        return validate(temporaryDirectory);
    } finally {
        fs.rmSync(temporaryRoot, {recursive: true, force: true});
    }
}

function createEvidencePackageSymlink(target, linkPath) {
    try {
        fs.symlinkSync(target, linkPath);
        return true;
    } catch (error) {
        // Windows may deny unprivileged symlink setup; Linux CI still covers
        // the validator path, and this reports a setup-only skipped case.
        if (
            process.platform === 'win32' &&
            (error && (error.code === 'EPERM' || error.code === 'EACCES'))
        ) {
            return false;
        }
        throw error;
    }
}

function updateEvidencePackageDigest(directory, entryID) {
    const manifestPath = path.join(directory, 'manifest.json');
    const manifest = readJSON(manifestPath);
    const descriptor = manifest.files.find(file => file.file_id === entryID);
    if (!descriptor) {
        throw new Error(`missing descriptor for ${entryID}`);
    }
    descriptor.sha256 = sha256File(path.join(directory, descriptor.file_name));
    writeJSON(manifestPath, manifest);
}

function sha256File(file) {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function writeJSON(file, value) {
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function writeJSONWithDiscardedDuplicate(file, value, property, discardedValue) {
    const members = [];
    for (const [key, memberValue] of Object.entries(value)) {
        if (key === property) {
            members.push(`${JSON.stringify(key)}: ${JSON.stringify(discardedValue)}`);
        }
        members.push(`${JSON.stringify(key)}: ${JSON.stringify(memberValue)}`);
    }
    fs.writeFileSync(file, `{\n  ${members.join(',\n  ')}\n}\n`);
}

function writeJSONWithDiscardedNestedDuplicate(
    file,
    value,
    parentProperty,
    property,
    discardedValue,
    encodedProperty
) {
    const members = [];
    for (const [key, memberValue] of Object.entries(value)) {
        if (key !== parentProperty) {
            members.push(`${JSON.stringify(key)}: ${JSON.stringify(memberValue)}`);
            continue;
        }

        const nestedMembers = [];
        for (const [nestedKey, nestedValue] of Object.entries(memberValue)) {
            if (nestedKey === property) {
                nestedMembers.push(`${JSON.stringify(nestedKey)}: ${JSON.stringify(discardedValue)}`);
                nestedMembers.push(`${encodedProperty}: ${JSON.stringify(nestedValue)}`);
                continue;
            }
            nestedMembers.push(`${JSON.stringify(nestedKey)}: ${JSON.stringify(nestedValue)}`);
        }
        members.push(`${JSON.stringify(key)}: {\n    ${nestedMembers.join(',\n    ')}\n  }`);
    }
    fs.writeFileSync(file, `{\n  ${members.join(',\n  ')}\n}\n`);
}
