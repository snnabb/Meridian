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

test('new-site ingress always defaults to a single port listener', () => {
  const { defaultIngressMode } = loadHelpers();
  assert.equal(defaultIngressMode({ host_only_available: true }), 'port');
  assert.equal(defaultIngressMode({ host_only_available: false }), 'port');
  assert.equal(defaultIngressMode(undefined), 'port');
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

test('plain site-card values share one semantic style while addresses remain monospace', () => {
  const { renderIngressSummary, renderDynamicSiteSummary, renderPlaybackRow } = loadHelpers();
  const ingress = renderIngressSummary({ ingress_mode: 'host', public_host: 'media.example.com', listen_port: 8123 });
  assert.match(ingress, /class="site-row-value">仅共享域名<\/span>/);
  assert.match(ingress, /class="mono">Host: media\.example\.com<\/span>/);

  const discovery = renderDynamicSiteSummary({
    dynamic_discovery_enabled: true,
    dynamic_profile: 'safe',
    dynamic_domain_rules: [],
    dynamic_allow_https_downgrade: false,
  });
  assert.match(discovery, /class="site-row-value">已启用 · Safe（安全）<\/span>/);

  const inheritedPlayback = renderPlaybackRow({ target_url: 'https://origin.example' });
  assert.match(inheritedPlayback, /class="site-row-value">跟随主回源<\/span>/);
  const configuredPlayback = renderPlaybackRow({
    target_url: 'https://origin.example',
    playback_target_url: 'https://playback.example',
    stream_hosts: [],
    playback_mode: 'redirect',
  });
  assert.match(configuredPlayback, /class="mono">https:\/\/playback\.example<\/span>/);
  assert.match(configuredPlayback, /class="site-row-value">重定向跟随<\/span>/);

  const source = loadSitesSource();
  assert.ok(source.includes('<span class="site-row-value">${upstreamHeaderCount} 个（加密）</span>'));
  assert.ok(source.includes('<span class="site-row-value">${formatBytes(s.traffic_used)}</span>'));
  assert.match(source, /class="pill \$\{uaClassMap\[s\.ua_mode\]/);
});

test('target authority comparison ignores path and explicit default ports', () => {
  const { normalizedTargetAuthority } = loadHelpers();
	assert.equal(normalizedTargetAuthority('https://origin.example.com/emby'), 'https://origin.example.com:443');
	assert.equal(normalizedTargetAuthority('https://origin.example.com:443/other'), 'https://origin.example.com:443');
	assert.equal(normalizedTargetAuthority('origin.example.com:443/other'), 'https://origin.example.com:443');
  assert.notEqual(normalizedTargetAuthority('https://origin.example.com'), normalizedTargetAuthority('https://other.example.com'));
});

test('empty state directs the user to the create action', () => {
  const { renderSitesEmptyState } = loadHelpers();
  const html = renderSitesEmptyState();
  assert.match(html, /还没有站点/);
  assert.match(html, /“添加站点”/);
  assert.match(html, /role="status"/);
});

test('proxy optimization payload uses the exact shared boolean fields', () => {
  const { buildProxyOptimizationPayload } = loadHelpers();
  assert.deepEqual(JSON.parse(JSON.stringify(buildProxyOptimizationPayload(true, false, true))), {
    ping_cache_enabled: true,
    image_cache_enabled: false,
    progress_coalescing_enabled: true,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(buildProxyOptimizationPayload(1, null, 'yes'))), {
    ping_cache_enabled: false,
    image_cache_enabled: false,
    progress_coalescing_enabled: false,
  });
});

test('cache and request policy uses neutral naming and explicit progress semantics', () => {
  const source = loadSitesSource();
  assert.match(source, /function buildProxyOptimizationPayload/);
  assert.equal((source.match(/buildProxyOptimizationPayload/g) || []).length, 3);
  assert.match(source, /data-site-group="cache-request-policy"/);
  assert.match(source, /<legend>缓存与请求策略<\/legend>/);
  assert.match(source, /<strong>播放进度优化<\/strong>/);
  assert.match(source, /密集更新时仅保留最新一条待发往上游的进度/);
  assert.match(source, /发送 Stopped 前会先向上游发送最终位置/);
  assert.doesNotMatch(source, /播放进度合并/);
  assert.match(source, /<strong>流量与速度限制<\/strong>/);
});

test('request limit payload is opt-in and preserves the existing backend fields', () => {
  const { buildRequestLimitPayload } = loadHelpers();
  assert.deepEqual(JSON.parse(JSON.stringify(buildRequestLimitPayload(false, '2', '25'))), {
    traffic_quota: 0,
    speed_limit: 0,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(buildRequestLimitPayload(true, '2', '25'))), {
    traffic_quota: 2 * 1073741824,
    speed_limit: 25,
  });
  assert.deepEqual(JSON.parse(JSON.stringify(buildRequestLimitPayload(true, '0', '12'))), {
    traffic_quota: 0,
    speed_limit: 12,
  });
});

test('site modal focus cycle traps forward and reverse tab movement', () => {
  const { cycleSiteModalFocus } = loadHelpers();
  const focused = [];
  const first = { focus() { focused.push('first'); } };
  const last = { focus() { focused.push('last'); } };
  const forward = { key: 'Tab', shiftKey: false, preventDefault() { focused.push('prevent-forward'); } };
  const reverse = { key: 'Tab', shiftKey: true, preventDefault() { focused.push('prevent-reverse'); } };
  assert.equal(cycleSiteModalFocus(forward, [first, last], last), true);
  assert.equal(cycleSiteModalFocus(reverse, [first, last], first), true);
  assert.deepEqual(focused, ['prevent-forward', 'first', 'prevent-reverse', 'last']);
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
  assert.match(disabled, /<fieldset class="form-list-row upstream-header-row">/);
  assert.match(disabled, /<legend class="sr-only">上游请求头 1<\/legend>/);
  assert.match(disabled, /for="m-upstream-header-name-0"/);
  assert.match(disabled, /for="m-upstream-header-value-0"/);
  assert.match(disabled, /type="password" class="form-input m-upstream-header-value"/);
  assert.match(disabled, /class="btn-ghost danger form-row-action m-upstream-header-remove"/);
  assert.ok(!disabled.includes('style='), 'row layout must be class-based for responsive stacking');

  const enabled = renderUpstreamHeaderRows([
    { name: 'X-Origin-Secret', configured: true },
  ], true);
  assert.ok(!enabled.includes(' disabled'), 'configured key must keep inputs editable');
});
