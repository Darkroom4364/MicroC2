'use strict';

const assert = require('node:assert/strict');
const {afterEach, test} = require('node:test');
const {DashboardManager} = require('./index.js');

const originalDocument = global.document;
const originalFetch = global.fetch;

afterEach(() => {
    global.document = originalDocument;
    global.fetch = originalFetch;
    delete globalThis.__dashboardXssTriggered;
});

test('typed task submission uses the canonical v1 create request', async () => {
    const output = new FakeElement('div');
    const input = new FakeElement('input');
    input.value = 'whoami';
    installDocument({output, input});

    let request;
    global.fetch = async (url, options) => {
        request = {url, options};
        return response({
            status: 202,
            body: {
                schema_version: 1,
                id: 'task-one',
                agent_id: 'agent-one',
                status: 'queued'
            }
        });
    };

    const manager = createManager();
    manager.appendLogEntry = () => {};
    manager.loadAgentResults = async () => {};

    await manager.sendCommand();

    assert.equal(request.url, '/api/agents/agent-one/tasks');
    assert.equal(request.options.method, 'POST');
    assert.deepEqual(JSON.parse(request.options.body), {
        schema_version: 1,
        type: 'shell',
        arguments: {command: 'whoami'},
        timeout_seconds: 30,
        expires_in_seconds: 300
    });
    assert.equal(input.value, '');
});

test('a superseded task poll cannot overwrite the newest response', async () => {
    const output = new FakeElement('div');
    installDocument({output});

    const pendingRequests = [];
    global.fetch = (url, options) => new Promise(resolve => {
        pendingRequests.push({url, options, resolve});
    });

    const manager = createManager();
    const firstPoll = manager.loadAgentResults('agent-one');
    manager.selectedAgentID = 'agent-two';
    const secondPoll = manager.loadAgentResults('agent-two');

    assert.equal(pendingRequests.length, 2);
    assert.equal(pendingRequests[0].options.signal.aborted, true);

    pendingRequests[1].resolve(response({
        body: taskList([task('task-new', 'echo newest', 'running', 'agent-two')])
    }));
    await secondPoll;

    pendingRequests[0].resolve(response({
        body: taskList([task('task-old', 'echo stale', 'queued')])
    }));
    await firstPoll;

    assert.equal(output.children.length, 1);
    assert.equal(output.children[0].children[0].textContent, 'echo newest');
});

test('task polling renders HTTP failures separately from an empty task list', async () => {
    const output = new FakeElement('div');
    installDocument({output});
    global.fetch = async () => response({
        status: 503,
        statusText: 'Service Unavailable'
    });

    const manager = createManager();
    await manager.loadAgentResults('agent-one');

    assert.equal(output.children.length, 1);
    assert.equal(
        output.children[0].textContent,
        'Error loading tasks: Task request failed with HTTP 503 Service Unavailable'
    );
});

test('a slow same-agent poll is shared instead of aborted by the next tick', async () => {
    const output = new FakeElement('div');
    installDocument({output});

    const pendingRequests = [];
    global.fetch = (url, options) => new Promise(resolve => {
        pendingRequests.push({url, options, resolve});
    });

    const manager = createManager();
    const firstPoll = manager.loadAgentResults('agent-one');
    const nextTick = manager.loadAgentResults('agent-one');

    assert.equal(firstPoll, nextTick);
    assert.equal(pendingRequests.length, 1);
    assert.equal(pendingRequests[0].options.signal.aborted, false);

    pendingRequests[0].resolve(response({
        body: taskList([task('task-one', 'echo eventual', 'running')])
    }));
    await Promise.all([firstPoll, nextTick]);

    assert.equal(output.children.length, 1);
    assert.equal(output.children[0].children[0].textContent, 'echo eventual');
});

test('task history navigation fetches one bounded page at a time', async () => {
    const output = new FakeElement('div');
    installDocument({output});
    const newestTasks = Array.from(
        {length: 50},
        (_, index) => task(`task-${index}`, `echo ${index}`, 'completed')
    );
    const requestedURLs = [];
    global.fetch = async url => {
        requestedURLs.push(url);
        if (url.endsWith('offset=50')) {
            return response({
                body: taskList(
                    [task('task-50', 'echo oldest', 'completed')],
                    {offset: 50, total: 51}
                )
            });
        }
        return response({
            body: taskList(
                newestTasks,
                {total: 51, nextOffset: 50}
            )
        });
    };

    const manager = createManager();
    await manager.loadAgentResults('agent-one');

    assert.deepEqual(requestedURLs, [
        '/api/agents/agent-one/tasks?limit=50&offset=0'
    ]);
    assert.equal(findAllByClass(output, 'command-result').length, 50);
    let pagination = findByClass(output, 'task-pagination');
    assert.equal(findByClass(pagination, 'timestamp').textContent, 'Tasks 1-50 of 51');
    assert.deepEqual(
        findAllByTag(pagination, 'button').map(button => button.textContent),
        ['Older']
    );

    findAllByTag(pagination, 'button')[0].click();
    await waitFor(() => requestedURLs.length === 2);
    await waitFor(() => output.children[0].children[0].textContent === 'echo oldest');

    assert.equal(
        requestedURLs[1],
        '/api/agents/agent-one/tasks?limit=50&offset=50'
    );
    assert.equal(findAllByClass(output, 'command-result').length, 1);
    pagination = findByClass(output, 'task-pagination');
    assert.equal(findByClass(pagination, 'timestamp').textContent, 'Tasks 51-51 of 51');
    assert.deepEqual(
        findAllByTag(pagination, 'button').map(button => button.textContent),
        ['Newer']
    );

    findAllByTag(pagination, 'button')[0].click();
    await waitFor(() => requestedURLs.length === 3);
    await waitFor(() => findAllByClass(output, 'command-result').length === 50);
    assert.equal(
        requestedURLs[2],
        '/api/agents/agent-one/tasks?limit=50&offset=0'
    );
});

test('a superseded same-agent page request cannot overwrite the selected page', async () => {
    const output = new FakeElement('div');
    installDocument({output});

    const pendingRequests = [];
    global.fetch = (url, options) => new Promise(resolve => {
        pendingRequests.push({url, options, resolve});
    });

    const manager = createManager();
    const olderPage = manager.loadAgentResults('agent-one', 50);
    const newestPage = manager.loadAgentResults('agent-one', 0);

    assert.equal(pendingRequests.length, 2);
    assert.equal(pendingRequests[0].options.signal.aborted, true);

    pendingRequests[1].resolve(response({
        body: taskList([task('task-new', 'echo newest', 'queued')])
    }));
    await newestPage;
    pendingRequests[0].resolve(response({
        body: taskList(
            [task('task-old', 'echo stale', 'completed')],
            {offset: 50, total: 51}
        )
    }));
    await olderPage;

    assert.equal(output.children.length, 1);
    assert.equal(output.children[0].children[0].textContent, 'echo newest');
});

test('task polling rejects an incomplete page envelope', async () => {
    const output = new FakeElement('div');
    installDocument({output});
    global.fetch = async () => response({
        body: {
            schema_version: 1,
            tasks: [],
            total: 0,
            next_offset: null
        }
    });

    const manager = createManager();
    await manager.loadAgentResults('agent-one');

    assert.equal(
        output.children[0].textContent,
        'Error loading tasks: Task list response did not match schema version 1'
    );
});

test('listener metadata is text-only and actions preserve the original values', async () => {
    const listeners = new FakeElement('div');
    installDocument({elements: {'active-listeners': listeners}});
    const injection = `x'"><img src=x onerror="globalThis.__dashboardXssTriggered=true">`;
    globalThis.__dashboardXssTriggered = false;
    global.fetch = async () => response({
        body: [{
            id: injection,
            name: injection,
            protocol: injection,
            host: injection,
            port: injection,
            status: injection,
            error: injection
        }]
    });

    const calls = [];
    const manager = createManager();
    manager.stopListener = id => calls.push(['stop', id]);
    manager.deleteListener = (id, name) => calls.push(['delete', id, name]);

    await manager.loadActiveListeners();

    assert.equal(globalThis.__dashboardXssTriggered, false);
    assert.equal(listeners.innerHTMLWrites, 0);
    assert.equal(listeners.children.length, 1);
    const card = listeners.children[0];
    assert.equal(card.dataset.id, injection);
    assert.equal(findByClass(card, 'listener-name').textContent, injection);
    assert.equal(findByClass(card, 'listener-type').textContent, injection);
    assert.equal(findByClass(card, 'listener-id').textContent, `ID: ${injection}`);
    assert.equal(
        findByClass(card, 'listener-details').children[1].textContent,
        `Host: ${injection}:${injection}`
    );
    assert.equal(findByClass(card, 'status-unknown').textContent, injection);
    assert.equal(findByClass(card, 'error-message').textContent, `Error: ${injection}`);

    const buttons = findAllByTag(card, 'button');
    buttons[0].click();
    buttons[1].click();
    assert.deepEqual(calls, [
        ['stop', injection],
        ['delete', injection, injection]
    ]);
});

test('agent metadata is text-only and actions preserve the original ID', async () => {
    const agents = new FakeElement('div');
    installDocument({elements: {'agent-list': agents}});
    const injection = `agent'"><svg onload="globalThis.__dashboardXssTriggered=true">`;
    globalThis.__dashboardXssTriggered = false;
    let requestURL;
    global.fetch = async url => {
        requestURL = url;
        return response({
            body: {
                malicious: {
                    id: injection,
                    type: injection,
                    ip: injection,
                    hostname: injection,
                    os: injection,
                    connected: true,
                    last_seen: '2026-07-23T16:30:00Z'
                }
            }
        });
    };

    const calls = [];
    const manager = createManager();
    manager.interactWithAgent = id => calls.push(['interact', id]);
    manager.removeAgent = id => calls.push(['remove', id]);

    await manager.loadActiveAgents();

    assert.equal(requestURL, '/api/agents/list?limit=100&offset=0');
    assert.equal(globalThis.__dashboardXssTriggered, false);
    assert.equal(agents.innerHTMLWrites, 0);
    assert.equal(agents.children.length, 1);
    const card = agents.children[0];
    assert.equal(card.dataset.id, injection);
    assert.equal(findByClass(card, 'agent-name').textContent, injection);
    assert.equal(findByClass(card, 'agent-type').textContent, injection);
    const detailText = findByClass(card, 'agent-details').children.map(child => child.textContent);
    assert.equal(detailText[1], `IP: ${injection}`);
    assert.equal(detailText[2], `Hostname: ${injection}`);
    assert.equal(detailText[3], `OS: ${injection}`);

    const buttons = findAllByTag(card, 'button');
    buttons[0].click();
    buttons[1].click();
    assert.deepEqual(calls, [
        ['interact', injection],
        ['remove', injection]
    ]);
});

test('terminal task output is fetched on demand and rendered as text', async () => {
    const output = new FakeElement('div');
    installDocument({output});
    const agentID = 'agent:name';
    const taskID = 'task:one';
    const injection = '<img src=x onerror="globalThis.__dashboardXssTriggered=true">';
    globalThis.__dashboardXssTriggered = false;
    const requestedURLs = [];
    global.fetch = async url => {
        requestedURLs.push(url);
        if (url.includes('?limit=')) {
            return response({
                body: taskList([completedTask(taskID, agentID, null)])
            });
        }
        return response({
            body: completedTask(taskID, agentID, {
                schema_version: 1,
                task_id: taskID,
                agent_id: agentID,
                outcome: 'completed',
                started_at: '2026-07-23T16:30:02Z',
                completed_at: '2026-07-23T16:30:03Z',
                exit_code: 0,
                output: {stdout: injection, stderr: injection}
            })
        });
    };

    const manager = createManager();
    manager.selectedAgentID = agentID;
    await manager.loadAgentResults(agentID);

    assert.equal(
        requestedURLs[0],
        '/api/agents/agent%3Aname/tasks?limit=50&offset=0'
    );
    const loadButton = findAllByTag(output, 'button')[0];
    assert.equal(loadButton.textContent, 'Load output');
    loadButton.click();
    await waitFor(() => manager.taskDetailRequests.size === 0);

    assert.equal(
        requestedURLs[1],
        '/api/agents/agent%3Aname/tasks/task%3Aone'
    );
    assert.equal(globalThis.__dashboardXssTriggered, false);
    const streams = findAllByTag(output, 'pre');
    assert.deepEqual(
        streams.map(stream => stream.textContent),
        [injection, injection]
    );
    assert.equal(findAllByTag(output, 'button').length, 0);
});

test('a stale task-detail response cannot update a newly selected agent', async () => {
    const output = new FakeElement('div');
    installDocument({output});
    let resolveDetail;
    global.fetch = (url, options) => {
        if (url === '/api/agents/agent-one/tasks?limit=50&offset=0') {
            return Promise.resolve(response({
                body: taskList([completedTask('task-one', 'agent-one', null)])
            }));
        }
        if (url === '/api/agents/agent-two/tasks?limit=50&offset=0') {
            return Promise.resolve(response({
                body: taskList([task('task-two', 'echo agent two', 'queued', 'agent-two')])
            }));
        }
        return new Promise(resolve => {
            resolveDetail = body => resolve(response({body}));
            assert.equal(options.signal.aborted, false);
        });
    };

    const manager = createManager();
    await manager.loadAgentResults('agent-one');
    findAllByTag(output, 'button')[0].click();
    const detailRequest = manager.taskDetailRequests.get(
        manager.taskCacheKey('agent-one', 'task-one')
    );
    assert.ok(detailRequest);

    manager.selectedAgentID = 'agent-two';
    manager.abortTaskDetailRequests();
    assert.equal(detailRequest.controller.signal.aborted, true);
    await manager.loadAgentResults('agent-two');

    resolveDetail(completedTask('task-one', 'agent-one', {
        schema_version: 1,
        task_id: 'task-one',
        agent_id: 'agent-one',
        outcome: 'completed',
        started_at: '2026-07-23T16:30:02Z',
        completed_at: '2026-07-23T16:30:03Z',
        exit_code: 0,
        output: {stdout: 'stale output', stderr: ''}
    }));
    await detailRequest.promise;

    assert.equal(output.children.length, 1);
    assert.equal(output.children[0].children[0].textContent, 'echo agent two');
    assert.equal(findAllByTag(output, 'pre').length, 0);
});

function createManager() {
    const manager = Object.create(DashboardManager.prototype);
    manager.previousListenerStates = new Map();
    manager.previousAgentStates = new Map();
    manager.selectedAgentID = 'agent-one';
    manager.taskStates = new Map();
    manager.taskRequestSequence = 0;
    manager.taskRequestController = null;
    manager.taskRequestAgentID = null;
    manager.taskRequestOffset = null;
    manager.taskRequestPromise = null;
    manager.taskPageAgentID = null;
    manager.taskPageOffset = 0;
    manager.taskDetailCache = new Map();
    manager.taskDetailRequests = new Map();
    manager.taskElements = new Map();
    manager.TASK_PAGE_LIMIT = 50;
    manager.MAX_TASK_DETAIL_CACHE = 20;
    manager.agentInteractionSequence = 0;
    return manager;
}

function installDocument({
    output = new FakeElement('div'),
    input = new FakeElement('input'),
    elements = {}
}) {
    const elementByID = {
        'command-output': output,
        'command-input': input,
        ...elements
    };
    global.document = {
        createElement: tag => new FakeElement(tag),
        createTextNode: text => {
            const node = new FakeElement('#text');
            node.textContent = String(text);
            return node;
        },
        getElementById: id => {
            if (Object.hasOwn(elementByID, id)) {
                return elementByID[id];
            }
            throw new Error(`Unexpected element id: ${id}`);
        }
    };
}

function response({status = 200, statusText = 'OK', body = null}) {
    return {
        ok: status >= 200 && status < 300,
        status,
        statusText,
        json: async () => body
    };
}

function taskList(
    tasks,
    {
        limit = 50,
        offset = 0,
        total = tasks.length,
        nextOffset = null
    } = {}
) {
    return {
        schema_version: 1,
        tasks,
        limit,
        offset,
        total,
        next_offset: nextOffset
    };
}

function task(id, command, status, agentID = 'agent-one') {
    const value = {
        schema_version: 1,
        id,
        agent_id: agentID,
        type: 'shell',
        arguments: {command},
        timeout_seconds: 30,
        status,
        created_at: '2026-07-23T16:30:00Z',
        queued_at: '2026-07-23T16:30:00Z',
        expires_at: '2026-07-23T16:35:00Z'
    };
    if (status !== 'queued') {
        value.dispatched_at = '2026-07-23T16:30:01Z';
    }
    if (status === 'running') {
        value.started_at = '2026-07-23T16:30:02Z';
    }
    return value;
}

function completedTask(id, agentID, result) {
    return {
        ...task(id, 'echo complete', 'completed', agentID),
        started_at: '2026-07-23T16:30:02Z',
        completed_at: '2026-07-23T16:30:03Z',
        ...(result ? {result} : {
            result: {
                schema_version: 1,
                task_id: id,
                agent_id: agentID,
                outcome: 'completed',
                started_at: '2026-07-23T16:30:02Z',
                completed_at: '2026-07-23T16:30:03Z',
                exit_code: 0
            }
        })
    };
}

async function waitFor(predicate) {
    for (let attempt = 0; attempt < 20; attempt++) {
        if (predicate()) {
            return;
        }
        await new Promise(resolve => setImmediate(resolve));
    }
    assert.fail('Timed out waiting for asynchronous dashboard work');
}

class FakeElement {
    constructor(tag) {
        this.tag = tag;
        this.children = [];
        this.className = '';
        this.textContent = '';
        this.value = '';
        this.dataset = {};
        this.eventListeners = new Map();
        this.innerHTMLWrites = 0;
    }

    appendChild(child) {
        this.children.push(child);
        return child;
    }

    hasChildNodes() {
        return this.children.length > 0;
    }

    replaceChildren(...children) {
        this.children = children;
    }

    addEventListener(event, listener) {
        const listeners = this.eventListeners.get(event) || [];
        listeners.push(listener);
        this.eventListeners.set(event, listeners);
    }

    click() {
        for (const listener of this.eventListeners.get('click') || []) {
            listener({target: this});
        }
    }

    set innerHTML(value) {
        this.innerHTMLWrites++;
        this.children = [];
        if (String(value).includes('__dashboardXssTriggered')) {
            globalThis.__dashboardXssTriggered = true;
        }
    }
}

function findByClass(root, className) {
    if (!root) {
        return null;
    }
    if (root.className.split(/\s+/).includes(className)) {
        return root;
    }
    for (const child of root.children) {
        const match = findByClass(child, className);
        if (match) {
            return match;
        }
    }
    return null;
}

function findAllByClass(root, className) {
    const matches = root.className.split(/\s+/).includes(className) ? [root] : [];
    for (const child of root.children) {
        matches.push(...findAllByClass(child, className));
    }
    return matches;
}

function findAllByTag(root, tag) {
    const matches = root.tag === tag ? [root] : [];
    for (const child of root.children) {
        matches.push(...findAllByTag(child, tag));
    }
    return matches;
}
