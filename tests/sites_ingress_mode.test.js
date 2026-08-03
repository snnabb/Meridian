'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadHelpers() {
  const source = loadSitesSource();
  const sandbox = { window: {}, URL, esc: value => String(value) };
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: 'sites.js' });
  return sandbox;
}

function loadSitesSource() {
  return fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'sites.js'), 'utf8');
}

test('ingress form exposes the secure host-only mode without a listener', () => {
  const { ingressFormState } = loadHelpers();
  const host = ingressFormState('host');
  assert.equal(host.showPublicHost, true);
  assert.equal(host.requirePublicHost, true);
  assert.match(host.portLabel, /保留端口/);
  assert.match(host.warning, /不会绑定/);
});

test('ingress payload clears stale host for port mode and preserves it otherwise', () => {
  const { buildIngressPayload } = loadHelpers();
  assert.deepEqual(JSON.parse(JSON.stringify(buildIngressPayload('port', '8001', 'stale.example.com'))), {
    ingress_mode: 'port', listen_port: 8001, public_host: '',
  });
  assert.deepEqual(JSON.parse(JSON.stringify(buildIngressPayload('host', '8002', ' media.example.com '))), {
    ingress_mode: 'host', listen_port: 8002, public_host: 'media.example.com',
  });
  assert.deepEqual(JSON.parse(JSON.stringify(buildIngressPayload('both', '8003', 'media.example.com'))), {
    ingress_mode: 'both', listen_port: 8003, public_host: 'media.example.com',
  });
});

test('new-site ingress defaults follow backend host-only capability', () => {
  const { defaultIngressMode } = loadHelpers();
  assert.equal(defaultIngressMode({ host_only_available: true }), 'host');
  assert.equal(defaultIngressMode({ host_only_available: false }), 'port');
  assert.equal(defaultIngressMode(undefined), 'host');
});

test('ingress summary never presents a host-only reserve port as listening', () => {
  const { renderIngressSummary } = loadHelpers();
  const hostOnly = renderIngressSummary({ ingress_mode: 'host', public_host: 'media.example.com', listen_port: 8123 });
  assert.match(hostOnly, /仅共享域名/);
  assert.match(hostOnly, /media\.example\.com/);
	assert.match(hostOnly, /Host:/);
	assert.ok(!hostOnly.includes('https://'));
  assert.ok(!hostOnly.includes(':8123'));

  const both = renderIngressSummary({ ingress_mode: 'both', public_host: 'media.example.com', listen_port: 8123 });
  assert.match(both, /:8123/);
});

test('target authority comparison ignores path and explicit default ports', () => {
  const { normalizedTargetAuthority } = loadHelpers();
	assert.equal(normalizedTargetAuthority('https://origin.example.com/emby'), 'https://origin.example.com:443');
	assert.equal(normalizedTargetAuthority('https://origin.example.com:443/other'), 'https://origin.example.com:443');
	assert.equal(normalizedTargetAuthority('origin.example.com:443/other'), 'https://origin.example.com:443');
  assert.notEqual(normalizedTargetAuthority('https://origin.example.com'), normalizedTargetAuthority('https://other.example.com'));
});

test('site modal always loads deployment capabilities for create and edit flows', () => {
  const source = loadSitesSource();
  const start = source.indexOf('async function showSiteModal(site)');
  const end = source.indexOf('// Global actions', start);
  const modalSource = source.slice(start, end);

  assert.match(modalSource, /normalizeSiteCapabilities\(await API\.ingressCapabilities\(\)\)/);
  assert.doesNotMatch(modalSource, /if \(!isEdit\)[\s\S]{0,200}ingressCapabilities/);
});

test('stream host normalization accepts the array API and legacy JSON strings', () => {
  const { normalizeStreamHosts, renderPlaybackRow } = loadHelpers();
  assert.deepEqual(JSON.parse(JSON.stringify(normalizeStreamHosts([' one.example ', '', 42, 'two.example']))), [
    'one.example',
    'two.example',
  ]);
  assert.deepEqual(JSON.parse(JSON.stringify(normalizeStreamHosts('[" legacy-one.example ","legacy-two.example"]'))), [
    'legacy-one.example',
    'legacy-two.example',
  ]);
  assert.deepEqual(JSON.parse(JSON.stringify(normalizeStreamHosts('{'))), []);

  const html = renderPlaybackRow({
    playback_target_url: 'https://primary.example',
    stream_hosts: ['https://array-extra.example'],
    playback_mode: 'redirect',
  });
  assert.match(html, /array-extra\.example/);
});

test('playback limit follows backend capabilities and has a safe compatibility default', () => {
  const { normalizeSiteCapabilities, canAddPlaybackAddress } = loadHelpers();
  const configured = normalizeSiteCapabilities({
    host_only_available: false,
    upstream_headers_available: false,
    max_playback_addresses: 100,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(configured)), {
    host_only_available: false,
    upstream_headers_available: false,
    max_playback_addresses: 100,
  });
  assert.equal(canAddPlaybackAddress(99, configured.max_playback_addresses), true);
  assert.equal(canAddPlaybackAddress(100, configured.max_playback_addresses), false);

  const fallback = normalizeSiteCapabilities({});
  assert.equal(fallback.host_only_available, true);
  assert.equal(fallback.upstream_headers_available, true);
  assert.equal(fallback.max_playback_addresses, 128);
});

test('missing upstream header key disables edits but leaves deletion available', () => {
  const { renderUpstreamHeaderRows } = loadHelpers();
  const disabled = renderUpstreamHeaderRows([
    { name: 'X-Origin-Secret', configured: true },
  ], false);
  assert.equal((disabled.match(/ disabled/g) || []).length, 2, 'name and value inputs must be disabled');
  const removeButton = disabled.match(/<button[^>]*m-upstream-header-remove[^>]*>/)?.[0] || '';
  assert.ok(removeButton, 'configured row must retain a delete control');
  assert.ok(!removeButton.includes('disabled'), 'delete control must remain enabled');

  const enabled = renderUpstreamHeaderRows([
    { name: 'X-Origin-Secret', configured: true },
  ], true);
  assert.ok(!enabled.includes(' disabled'), 'configured key must keep inputs editable');
});
