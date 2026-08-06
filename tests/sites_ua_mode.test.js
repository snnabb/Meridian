'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_JS = path.join(__dirname, '..', 'web', 'static', 'js');
const STYLE_CSS = path.join(__dirname, '..', 'web', 'static', 'css', 'style.css');

function loadSiteHelpers() {
  const source = fs.readFileSync(path.join(STATIC_JS, 'pages', 'sites.js'), 'utf8');
  const sandbox = { window: {}, esc: value => String(value) };
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: 'sites.js' });
  return sandbox;
}

// Loads page scripts into one shared sandbox, mirroring how index.html evaluates
// them as classic <script> tags sharing a single global.
function loadPageScripts(...relativePaths) {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  for (const relativePath of relativePaths) {
    const filename = path.join(STATIC_JS, relativePath);
    vm.runInContext(fs.readFileSync(filename, 'utf8'), sandbox, { filename: relativePath });
  }
  return sandbox;
}

test('custom UA form state exposes and hydrates all fields', () => {
  const { customUAFormState } = loadSiteHelpers();
  const state = customUAFormState('custom', {
    custom_user_agent: 'Meridian Custom/1.0',
    custom_client: 'Meridian Custom',
    custom_version: '1.0.0',
  });

  assert.equal(state.visible, true);
  assert.equal(state.required, true);
  assert.equal(state.customUserAgent, 'Meridian Custom/1.0');
  assert.equal(state.customClient, 'Meridian Custom');
  assert.equal(state.customVersion, '1.0.0');
});

test('every non-custom UA mode hides, unrequires and clears custom identity', () => {
  const { customUAFormState } = loadSiteHelpers();
  for (const mode of ['infuse', 'web', 'client', 'passthrough']) {
    const state = customUAFormState(mode, {
      custom_user_agent: 'stale',
      custom_client: 'stale',
      custom_version: 'stale',
    });
    assert.equal(state.visible, false, mode);
    assert.equal(state.required, false, mode);
    assert.equal(state.customUserAgent, '', mode);
    assert.equal(state.customClient, '', mode);
    assert.equal(state.customVersion, '', mode);
  }
});

test('hidden semantics override display utilities for the custom identity group', () => {
  const css = fs.readFileSync(STYLE_CSS, 'utf8');
  assert.match(css, /\[hidden\]\s*\{[^}]*display:\s*none\s*!important;[^}]*\}/);
  assert.match(css, /\.form-input-stack\s*\{[^}]*display:\s*flex;/);
  const valueRule = /\.site-row-value\s*\{([^}]*)\}/.exec(css)?.[1] || '';
  assert.match(valueRule, /font-size:/);
  assert.match(valueRule, /font-weight:/);
  assert.match(valueRule, /color:\s*var\(--white-60\)/);

  const source = fs.readFileSync(path.join(STATIC_JS, 'pages', 'sites.js'), 'utf8');
  assert.match(source, /id="m-custom-ua-group" hidden/);
  assert.match(source, /customUAGroup\.hidden = !state\.visible/);
  assert.match(source, /input\.required = state\.required/);
});

test('custom UA payload trims custom values and preset payload clears them', () => {
  const { buildCustomUAPayload } = loadSiteHelpers();
  const custom = buildCustomUAPayload('custom', ' UA ', ' Client ', ' 1.2.3 ');
  assert.equal(custom.custom_user_agent, 'UA');
  assert.equal(custom.custom_client, 'Client');
  assert.equal(custom.custom_version, '1.2.3');

  const preset = buildCustomUAPayload('infuse', 'stale', 'stale', 'stale');
  assert.equal(preset.custom_user_agent, '');
  assert.equal(preset.custom_client, '');
  assert.equal(preset.custom_version, '');
});

test('passthrough form state hides, unrequires and clears the custom triplet', () => {
  const { customUAFormState } = loadSiteHelpers();
  const state = customUAFormState('passthrough', {
    custom_user_agent: 'stale',
    custom_client: 'stale',
    custom_version: 'stale',
  });

  assert.equal(state.visible, false);
  assert.equal(state.required, false);
  assert.equal(state.customUserAgent, '');
  assert.equal(state.customClient, '');
  assert.equal(state.customVersion, '');
});

test('passthrough payload clears the custom triplet', () => {
  const { buildCustomUAPayload } = loadSiteHelpers();
  const payload = buildCustomUAPayload('passthrough', 'stale UA', 'stale Client', '1.0');
  assert.equal(payload.custom_user_agent, '');
  assert.equal(payload.custom_client, '');
  assert.equal(payload.custom_version, '');
});

test('upstream header payload keeps configured rows write-only', () => {
	const { buildUpstreamHeaderPayload } = loadSiteHelpers();
	const payload = buildUpstreamHeaderPayload([
		{ name: ' EMOS-PROXY-ID ', value: '', configured: true },
		{ name: ' X-New-Header ', value: ' new-value ', configured: false },
		{ name: '', value: '', configured: false },
	]);

	assert.deepEqual(JSON.parse(JSON.stringify(payload)), [
		{ name: 'EMOS-PROXY-ID', value: '' },
		{ name: 'X-New-Header', value: 'new-value' },
	]);
});

test('configured upstream header rows stay write-only and use semantic responsive markup', () => {
  const { renderUpstreamHeaderRows } = loadSiteHelpers();
  const html = renderUpstreamHeaderRows([
    { name: 'X-Origin-Secret', value: 'must-not-render', configured: true },
  ], true);

  assert.ok(!html.includes('must-not-render'));
  assert.match(html, /<fieldset class="form-list-row upstream-header-row">/);
  assert.match(html, /type="password"[^>]*value=""/);
  assert.match(html, /placeholder="已配置；留空保持不变"/);
  assert.match(html, /aria-label="删除上游请求头 1"/);
});

test('passthrough mode label maps to 透传 with an existing pill class', () => {
  const sandbox = loadPageScripts('pages/dashboard.js', 'pages/sites.js');
  const { uaNameMap, uaClassMap } = vm.runInContext('({ uaNameMap, uaClassMap })', sandbox);

  assert.equal(uaNameMap.passthrough, '透传');
  assert.ok(
    ['pill-blue', 'pill-green', 'pill-orange', 'pill-purple'].includes(uaClassMap.passthrough),
    'passthrough must reuse an existing pill class, not introduce a new one',
  );
});

test('diagnostics renders passthrough status instead of UA value rows', () => {
  const { renderHeadersCard } = loadPageScripts('api.js', 'pages/diag.js');
  const html = renderHeadersCard({
    passthrough: true,
    ua_applied: false,
    current_ua: 'Sneaky-UA',
    client_field: 'Sneaky-Client',
    version_field: '9.9.9',
  }, 'stagger-5');

  assert.ok(html.includes('UA 透传'), 'passthrough row must be rendered');
  assert.ok(html.includes('保留客户端原值'), 'passthrough row must state the client value is kept');
  assert.ok(!html.includes('UA 改写'), 'UA 改写 row must not render for passthrough');
  assert.ok(!html.includes('当前 UA'), 'empty 当前 UA row must not render for passthrough');
  assert.ok(!html.includes('Client 字段'), 'Client 字段 row must not render for passthrough');
  assert.ok(!html.includes('Version 字段'), 'Version 字段 row must not render for passthrough');
  assert.ok(!html.includes('Sneaky-UA'), 'real request UA must never be rendered');
  assert.ok(!html.includes('Sneaky-Client'), 'real request client must never be rendered');
  assert.ok(!html.includes('9.9.9'), 'real request version must never be rendered');
});

test('diagnostics keeps configured UA rows for non-passthrough modes', () => {
  const { renderHeadersCard } = loadPageScripts('api.js', 'pages/diag.js');
  const html = renderHeadersCard({
    ua_applied: true,
    current_ua: 'Infuse/7.8.1',
    client_field: 'Infuse',
    version_field: '7.8.1',
  }, 'stagger-5');

  assert.ok(html.includes('UA 改写'), 'UA 改写 row must still render');
  assert.ok(html.includes('已启用'), 'enabled rewrite status must still render');
  assert.ok(html.includes('Infuse/7.8.1'), 'configured UA must still render');
  assert.ok(html.includes('Client 字段'), 'Client 字段 row must still render');
  assert.ok(html.includes('Version 字段'), 'Version 字段 row must still render');
});
