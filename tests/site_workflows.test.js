const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/static/js/pages/site-workflows.js'), 'utf8'), sandbox);
test('duplicate opens a draft without identity, binding, secrets, counters or accounts', () => {
 const draft = sandbox.siteDraft({id: 7, name: 'Movie', target_url: 'https://origin.example', ingress_mode:'host',public_host:'old.example',listen_port:9000,account_count:3,traffic_used:100,upstream_headers:[{name:'Authorization',configured:true}],accounts:[{password:'secret'}],speed_limit:10,total_speed_limit:20});
 assert.equal(draft.id, undefined); assert.equal(draft.account_count, undefined);
 assert.equal(draft.public_host,''); assert.equal(draft.listen_port,0);
 assert.equal(draft.traffic_used,undefined); assert.equal(draft.accounts.length,0);
 assert.equal(draft.upstream_headers.length,0); assert.equal(draft.total_speed_limit,20);
 assert.equal(draft.target_url,'https://origin.example');
});
test('bulk limits distinguish unchanged fields from explicit unlimited and reject invalid numbers', () => {
 const payload = sandbox.siteBulkPayload([1,2], 'limits', {traffic_quota:'2', speed_limit:'', total_speed_limit:'0'});
 assert.equal(payload.traffic_quota, 2*1073741824); assert.equal(payload.total_speed_limit,0);
 assert.equal(Object.hasOwn(payload,'speed_limit'), false);
 for (const raw of ['-1','1.5','1e3','NaN','1000001']) assert.throws(() => sandbox.siteBulkPayload([1], 'limits', {speed_limit:raw}));
 assert.throws(() => sandbox.siteBulkPayload([1], 'limits', {}));
});
