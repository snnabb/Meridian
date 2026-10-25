'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

test('legacy updater remains usable and stale beta preference is removed', async () => {
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {hidden:false, disabled:false, textContent:'', querySelector:node});
    return nodes.get(id);
  };
  const panel = {isConnected:true, querySelector:node};
  const preferences = new Map([['meridian-update-channel', 'beta']]);
  const requests = [];
  const sandbox = {
    localStorage: {removeItem: key => preferences.delete(key)},
    API: {
      systemUpdateStatus: async () => ({state:'idle', message:'ready'}),
      checkSystemUpdate: async (...args) => {
        requests.push(args);
        return {current_version:'v1.14.2', latest_version:'v1.15.0', update_available:true, update_supported:true, release_url:'https://github.com/snnabb/Meridian/releases/tag/v1.15.0'};
      }
    }
  };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/static/js/pages/global-settings.js'), 'utf8'), sandbox);
  sandbox.bindUpdateSettings({querySelector: () => panel});
  await Promise.resolve();
  assert.equal(preferences.has('meridian-update-channel'), false);
  assert.equal(node('#update-rollback').hidden, true);
  assert.match(node('#rollback-status').textContent, /支持正式版更新/);
  await node('#update-check').onclick();
  assert.deepEqual(requests, [[]]);
  assert.equal(node('#update-install').hidden, false);
});

