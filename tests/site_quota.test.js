'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const sandbox = { window: {}, URL };
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/static/js/form-validation.js'), 'utf8'), sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/static/js/pages/sites.js'), 'utf8'), sandbox);

test('quota cards use the billing cycle, independently of lifetime usage', () => {
  const summary = sandbox.siteQuotaSummary({ traffic_used: 110, monthly_traffic: 30, traffic_quota: 100, traffic_reset_day: 1 });
  assert.equal(summary.used, 30);
  assert.equal(summary.remaining, 70);
  assert.equal(summary.percent, 30);
});

test('quota cards clamp exhausted quotas and describe disabled resets and unlimited sites', () => {
  const exceeded = sandbox.siteQuotaSummary({ monthly_traffic: 150, traffic_quota: 100, traffic_reset_day: 0 });
  assert.equal(exceeded.remaining, 0);
  assert.equal(exceeded.percent, 100);
  assert.equal(exceeded.reset, '不自动重置');
  const unlimited = sandbox.siteQuotaSummary({ monthly_traffic: 30, traffic_quota: 0, traffic_billing_mode: 'outbound' });
  assert.equal(unlimited.remaining, null);
  assert.equal(unlimited.billing, '仅出站');
});
