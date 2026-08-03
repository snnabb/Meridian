'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_JS = path.join(__dirname, '..', 'web', 'static', 'js');
const PAYLOAD = '"><img src=x onerror=alert(1)>';

// Loads browser scripts into one shared sandbox, mirroring how index.html
// evaluates them as classic <script> tags sharing a single global. Only function
// declarations become sandbox properties, which is why esc must stay a function.
function loadScripts(...relativePaths) {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  for (const relativePath of relativePaths) {
    const filename = path.join(STATIC_JS, relativePath);
    vm.runInContext(fs.readFileSync(filename, 'utf8'), sandbox, { filename: relativePath });
  }
  return sandbox;
}

test('esc ships with the shared api client, not a page script', () => {
  const { esc } = loadScripts('api.js');
  assert.equal(typeof esc, 'function');

  for (const pageScript of ['pages/dashboard.js', 'pages/sites.js', 'pages/traffic.js', 'pages/diag.js']) {
    const source = fs.readFileSync(path.join(STATIC_JS, pageScript), 'utf8');
    assert.ok(
      !/function\s+esc\s*\(/.test(source),
      `${pageScript} must not define esc; escaping lives in api.js so a page script failing to load cannot disable it`,
    );
  }
});

test('esc escapes every HTML-significant character', () => {
  const { esc } = loadScripts('api.js');
  assert.equal(esc(`&<>"'`), '&amp;&lt;&gt;&quot;&#39;');
  assert.equal(esc(PAYLOAD), '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(esc(0), '0');
  assert.equal(esc(undefined), 'undefined');
});

test('diagnostics probe type is escaped before it reaches innerHTML', () => {
  const { probeLabel, renderHealthCard } = loadScripts('api.js', 'pages/diag.js');
  // probeLabel keeps returning the raw label; escaping belongs at the sink so a
  // caller that needs plain text is not handed double-escaped markup.
  assert.equal(probeLabel({ kind: 'metadata_api' }), 'Metadata / API 探针');

  const html = renderHealthCard('主回源健康', '探针结果', { health: { probe: { kind: PAYLOAD } } }, 'stagger-2');
  assert.ok(!html.includes(PAYLOAD), 'probe.kind must not be interpolated raw');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'probe.kind must be escaped');
});

test('diagnostics proxy card escapes listen port and keeps its placeholder', () => {
  const { renderProxyCard } = loadScripts('api.js', 'pages/diag.js');

  const html = renderProxyCard({ running: true, listen_port: PAYLOAD, total_requests: 7 }, 'stagger-6');
  assert.ok(!html.includes(PAYLOAD), 'proxy.listen_port must not be interpolated raw');

  // Pinned so a later switch to diagText cannot silently turn 0 into "0".
	assert.ok(renderProxyCard({ ingress_mode: 'port', port_listening: true, listen_port: 8096 }, 'stagger-6').includes('>:8096（监听中）<'));
	assert.ok(renderProxyCard({ ingress_mode: 'port', listen_port: 0 }, 'stagger-6').includes('>:--（未监听）<'));
});

test('diagnostics proxy card escapes an unknown ingress mode', () => {
  const { renderProxyCard } = loadScripts('api.js', 'pages/diag.js');

  const html = renderProxyCard({ ingress_mode: PAYLOAD, listen_port: 8096 }, 'stagger-6');
  assert.ok(!html.includes(PAYLOAD), 'unknown ingress_mode must not be interpolated raw');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'unknown ingress_mode must be escaped');
});
