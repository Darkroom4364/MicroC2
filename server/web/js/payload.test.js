'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {normalizePayloadFormConfig} = require('./payload.js');

test('payload form normalization preserves explicit zero OPSEC values', () => {
    const config = normalizePayloadFormConfig({
        socks5_enabled: '',
        socks5_host: '',
        socks5_port: '',
        sleep: '60',
        proc_scan_interval_secs: '0',
        base_threshold_enter_full_opsec: '0',
        base_threshold_enter_reduced_activity: '0',
        min_duration_full_opsec_secs: '0',
        min_duration_reduced_activity_secs: '0',
        min_duration_background_opsec_secs: '0',
        reduced_activity_sleep_secs: '0',
        base_max_consecutive_c2_failures: '0',
        c2_failure_threshold_increase_factor: '0',
        c2_failure_threshold_decrease_factor: '0',
        c2_threshold_adjust_interval_secs: '0',
        c2_dynamic_threshold_max_multiplier: '0'
    });

    for (const [field, value] of Object.entries(config)) {
        if (field === 'socks5_enabled') {
            assert.equal(value, false);
        } else if (field === 'socks5_host') {
            assert.equal(value, '');
        } else if (field === 'sleep') {
            assert.equal(value, 60);
        } else {
            assert.equal(value, 0, `${field} was replaced by a default`);
        }
    }
});

test('payload form normalization defaults omitted numeric values', () => {
    const config = normalizePayloadFormConfig({});

    assert.equal(config.proc_scan_interval_secs, 300);
    assert.equal(config.base_threshold_enter_full_opsec, 60);
    assert.equal(config.base_threshold_enter_reduced_activity, 20);
    assert.equal(config.c2_failure_threshold_increase_factor, 1.1);
    assert.equal(config.c2_failure_threshold_decrease_factor, 0.9);
    assert.equal(config.c2_threshold_adjust_interval_secs, 3600);
    assert.equal(config.c2_dynamic_threshold_max_multiplier, 2);
});
