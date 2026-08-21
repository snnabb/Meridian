'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_JS = path.join(__dirname, '..', 'web', 'static', 'js');
const ATTACK = '\"><img src=x onerror=alert(1)>';
const EXTREME_OBSERVATION_REASON_CASES = [
  { source: 'playback_info', reason: 'request_unclassified' },
  { source: 'playback_info', reason: 'structured_body_limit' },
  { source: 'playback_info', reason: 'playback_info_denied' },
  { source: 'hls', reason: 'hls_feature_denied' },
  { source: 'dash', reason: 'dash_feature_denied' },
  { source: 'redirect', reason: 'redirect_body_replay_denied' },
];

function loadScripts(...relativePaths) {
  const sandbox = { window: {}, URL };
  vm.createContext(sandbox);
  for (const relativePath of relativePaths) {
    vm.runInContext(
      fs.readFileSync(path.join(STATIC_JS, relativePath), 'utf8'),
      sandbox,
      { filename: relativePath },
    );
  }
  return sandbox;
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function discoveryProfile(id, overrides = {}) {
  const values = {
    safe: [3, 256, 4096, 256, 4 * 1024 * 1024, 16, 60, 32, 30 * 60, 8 * 60 * 60],
    compatible: [5, 1024, 16384, 1024, 16 * 1024 * 1024, 32, 300, 128, 2 * 60 * 60, 24 * 60 * 60],
    extreme: [10, 4096, 65536, 4096, 64 * 1024 * 1024, 64, 1200, 512, 24 * 60 * 60, 7 * 24 * 60 * 60],
  }[id];
  const anyPort = id !== 'safe';
  return {
    id,
    label: id[0].toUpperCase() + id.slice(1),
    recommended: id === 'compatible',
    limits: {
      allowed_schemes: anyPort ? ['http', 'https'] : ['https'],
      allowed_ports: anyPort ? [] : [443],
      allow_any_port: anyPort,
      max_redirects: values[0],
      max_authorities: values[1],
      max_active_capabilities: values[2],
      max_urls_per_response: values[3],
      max_body_bytes: values[4],
      max_dns_ips: values[5],
      max_new_authorities_per_minute: values[6],
      max_streams: values[7],
      idle_expiry_seconds: values[8],
      absolute_lifetime_seconds: values[9],
    },
    features: {
      redirect_discovery: true,
      playback_info: true,
      hls: id !== 'safe',
      dash: id !== 'safe',
      private_targets: false,
      custom_ca: false,
      raw_fallback: false,
    },
    ...overrides,
  };
}

function structuredDiscoveryResponse(overrides = {}) {
  return {
    stage: 'structured-discovery',
    available: true,
    key_configured: true,
    profiles: [
      discoveryProfile('safe'),
      discoveryProfile('compatible'),
      discoveryProfile('extreme'),
    ],
    global_limits: {
      max_authorities: 16384,
      max_active_capabilities: 131072,
      max_streams: 1024,
      max_new_authorities_per_minute: 2400,
      max_dns_workers: 32,
      max_concurrent_parses: 8,
      max_site_concurrent_parses: 2,
      max_parse_memory_bytes: 256 * 1024 * 1024,
      max_site_parse_memory_bytes: 64 * 1024 * 1024,
      max_capability_memory_bytes: 256 * 1024 * 1024,
      max_site_capability_memory_bytes: 64 * 1024 * 1024,
      max_parse_depth: 64,
      max_string_bytes: 1024 * 1024,
      max_target_url_bytes: 4096,
    },
    ...overrides,
  };
}

class FakeElement {
  constructor(ownerDocument, id = '') {
    this.ownerDocument = ownerDocument;
    this.id = id;
    this._innerHTML = '';
    this._children = [];
    this.classNames = new Set();
    this.dataset = {};
    this.style = {};
    this.value = '';
    this.textContent = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.required = false;
    this.title = '';
  }

  set innerHTML(value) {
    this._innerHTML = String(value);
    this._children = this.ownerDocument.parseElements(this._innerHTML);
  }

  get innerHTML() {
    return this._innerHTML;
  }

  querySelectorAll(selector) {
    if (!selector.startsWith('.')) return [];
    const className = selector.slice(1);
    return this._children.filter(element => element.classNames.has(className));
  }

  addEventListener(type, handler) {
    this[`on${type}`] = handler;
  }

  focus() {}
}

class FakeDocument {
  constructor() {
    this.elements = new Map();
    for (const id of ['modal-title', 'modal-body', 'modal-footer']) {
      this.elements.set(id, new FakeElement(this, id));
    }
  }

  getElementById(id) {
    return this.elements.get(id) || null;
  }

  parseElements(html) {
    const elements = [];
    const tags = /<([a-z][a-z0-9-]*)\b([^>]*)>/gi;
    let tag;
    while ((tag = tags.exec(html)) !== null) {
      const attributes = tag[2];
      const id = /\bid="([^"]+)"/.exec(attributes)?.[1] || '';
      const element = id && this.elements.has(id)
        ? this.elements.get(id)
        : new FakeElement(this, id);
      if (id) this.elements.set(id, element);

      const classValue = /\bclass="([^"]*)"/.exec(attributes)?.[1] || '';
      element.classNames = new Set(classValue.split(/\s+/).filter(Boolean));
      element.value = /\bvalue="([^"]*)"/.exec(attributes)?.[1] || '';
      element.checked = /(?:^|\s)checked(?:\s|$)/.test(attributes);
      element.disabled = /(?:^|\s)disabled(?:\s|$)/.test(attributes);
      for (const match of attributes.matchAll(/\bdata-([a-z0-9-]+)="([^"]*)"/gi)) {
        const key = match[1].replace(/-([a-z])/g, (_, character) => character.toUpperCase());
        element.dataset[key] = match[2];
      }
      elements.push(element);
    }
    return elements;
  }
}

function loadModalHarness() {
  const document = new FakeDocument();
  const state = {
    confirmationResult: false,
    confirmations: [],
    observationGets: [],
    observationDeletes: [],
    creates: [],
    updates: [],
    successes: [],
    errors: [],
    opened: 0,
  };
  const sandbox = {
    document,
    window: {
      confirm(message) {
        state.confirmations.push(message);
        return state.confirmationResult;
      },
    },
    URL,
    API: {
      ingressCapabilities: async () => ({
        host_only_available: true,
        upstream_headers_available: true,
        max_playback_addresses: 128,
      }),
      getDynamicProfiles: async () => structuredDiscoveryResponse(),
      getDynamicObservations: async siteId => {
        state.observationGets.push(siteId);
        return {
          observations: [{
            canonical_authority: 'https://media.example:443',
            source: 'redirect',
            decision: 'allowed',
            reason_code: 'redirect_allowed',
            first_seen_ms: 0,
            last_seen_ms: 1,
            count: 2,
          }],
          dropped_observations: 3,
        };
      },
      deleteDynamicObservations: async siteId => {
        state.observationDeletes.push(siteId);
        return { observations: [], dropped_observations: 0 };
      },
      createSite: async payload => { state.creates.push(clone(payload)); },
      updateSite: async (siteId, payload) => { state.updates.push({ siteId, payload: clone(payload) }); },
    },
    Toast: {
      success(message) { state.successes.push(message); },
      error(message) { state.errors.push(message); },
    },
    esc(value) {
      return String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      })[character]);
    },
    openModal() { state.opened++; },
    closeModal() {},
    loadSites() {},
    formatBytes(value) { return String(value); },
    uaClassMap: {},
    uaNameMap: {},
  };
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(STATIC_JS, 'pages', 'sites.js'), 'utf8'),
    sandbox,
    { filename: 'pages/sites.js' },
  );
  return { sandbox, document, state };
}

test('only the exact structured-discovery capability envelope is recognized', async () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const accepted = structuredDiscoveryResponse();

  assert.equal(sandbox.isStructuredDiscoveryContract(accepted), true);
  assert.deepEqual(plain(sandbox.normalizeDynamicProfiles(accepted)), {
    stage: 'structured-discovery',
    available: true,
    key_configured: true,
    recognized: true,
    profiles: accepted.profiles,
    global_limits: accepted.global_limits,
  });

  const malformed = [];
  malformed.push(null, {}, { ...accepted, stage: 'redirect-discovery' });
  malformed.push({ ...accepted, available: false, key_configured: true });

  const missingGlobalLimit = clone(accepted);
  delete missingGlobalLimit.global_limits.max_dns_workers;
  malformed.push(missingGlobalLimit);

  const duplicateProfile = clone(accepted);
  duplicateProfile.profiles[2].id = 'compatible';
  malformed.push(duplicateProfile);

  const missingLimit = clone(accepted);
  delete missingLimit.profiles[0].limits.max_redirects;
  malformed.push(missingLimit);

  const invalidPort = clone(accepted);
  invalidPort.profiles[0].limits.allowed_ports = [0];
  malformed.push(invalidPort);

  const missingFeature = clone(accepted);
  delete missingFeature.profiles[0].features.raw_fallback;
  malformed.push(missingFeature);

  const wrongRedirectFeature = clone(accepted);
  wrongRedirectFeature.profiles[1].features.redirect_discovery = false;
  malformed.push(wrongRedirectFeature);

  const prematurelyEnabledLaterFeature = clone(accepted);
  prematurelyEnabledLaterFeature.profiles[2].features.private_targets = true;
  malformed.push(prematurelyEnabledLaterFeature);

  const missingStructuredFeature = clone(accepted);
  delete missingStructuredFeature.profiles[0].features.playback_info;
  malformed.push(missingStructuredFeature);

  const manifestEnabledInSafe = clone(accepted);
  manifestEnabledInSafe.profiles[0].features.hls = true;
  malformed.push(manifestEnabledInSafe);

  for (const value of malformed) {
    assert.equal(sandbox.isStructuredDiscoveryContract(value), false);
    const normalized = sandbox.normalizeDynamicProfiles(value);
    assert.equal(normalized.recognized, false);
    assert.equal(normalized.available, false);
    assert.equal(normalized.key_configured, false);
  }

  vm.runInContext('API.getDynamicProfiles = async () => { throw new Error("missing"); }', sandbox);
  const missing = await sandbox.loadDynamicProfiles();
  assert.equal(missing.recognized, false);
  assert.equal(missing.available, false);
  assert.equal(missing.key_configured, false);
});

test('availability and key status gate enablement without hiding legacy editing', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const available = structuredDiscoveryResponse();
  const unavailable = structuredDiscoveryResponse({ available: false, key_configured: false });
  const policy = { dynamic_discovery_enabled: true };

  const enabledControl = sandbox.renderDynamicEnableControl(available, policy);
  assert.match(enabledControl, /id="m-dynamic-enabled"[^>]*checked/);
  assert.doesNotMatch(enabledControl, /id="m-dynamic-enabled"[^>]*disabled/);

  const disabledControl = sandbox.renderDynamicEnableControl(unavailable, policy);
  assert.doesNotMatch(disabledControl, /id="m-dynamic-enabled"[^>]*disabled/);
  assert.match(disabledControl, /id="m-dynamic-enabled"[^>]*checked/);
  assert.doesNotMatch(disabledControl, /m-dynamic-source-/);

	  const unavailablePayload = sandbox.buildDynamicPolicyPayload(policy, unavailable);
	  assert.equal(unavailablePayload.dynamic_discovery_enabled, true);
	  assert.equal(Object.hasOwn(unavailablePayload, 'dynamic_discovery_sources'), false);

  const unavailableNewControl = sandbox.renderDynamicEnableControl(unavailable, {});
  assert.match(unavailableNewControl, /id="m-dynamic-enabled"[^>]*disabled/);
  assert.doesNotMatch(unavailableNewControl, /id="m-dynamic-enabled"[^>]*checked/);
  assert.equal(sandbox.buildDynamicPolicyPayload({}, unavailable).dynamic_discovery_enabled, false);
	const unrecognizedControl = sandbox.renderDynamicEnableControl({ stage: 'redirect-discovery' }, policy);
	assert.match(unrecognizedControl, /id="m-dynamic-enabled"[^>]*disabled/);
  assert.doesNotMatch(unrecognizedControl, /m-dynamic-source-/);
  assert.deepEqual(plain(sandbox.buildDynamicPolicyPayload(policy, { stage: 'redirect-discovery' })), {});
});

test('structured-discovery status reports delivered sources and only unavailable opt-ins', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const capabilities = structuredDiscoveryResponse({
    dynamic_route_key: 'raw-secret-must-not-render',
    target_url: 'https://target-must-not-render.example/private?token=secret',
  });
  const status = sandbox.renderDynamicStatus(capabilities);

  assert.match(status, /自动发现/);
  assert.match(status, /默认处理 HTTP 30x 和 PlaybackInfo/);
  assert.doesNotMatch(status, /raw-secret-must-not-render|target-must-not-render/);
});

test('profile risk notices and transition confirmations match the approved product gates', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  assert.equal(discoveryProfile('extreme').limits.max_body_bytes, 64 * 1024 * 1024);

  const safe = sandbox.renderDynamicProfileRisk('safe');
  const compatible = sandbox.renderDynamicProfileRisk('compatible');
  const extreme = sandbox.renderDynamicProfileRisk('extreme');
  assert.match(safe, /data-profile-risk="safe"/);
  assert.match(safe, /推荐/);
  assert.match(compatible, /data-profile-risk="compatible"/);
  assert.match(compatible, /默认/);
  assert.match(compatible, /适合大多数后端/);
  assert.match(extreme, /data-profile-risk="extreme"/);
  assert.match(extreme, /高风险/);
  assert.match(extreme, /输入站点名称/);

  const disabledSafe = { dynamic_discovery_enabled: false, dynamic_profile: 'safe' };
  const enabledSafe = { dynamic_discovery_enabled: true, dynamic_profile: 'safe' };
  const enabledCompatible = { dynamic_discovery_enabled: true, dynamic_profile: 'compatible' };
  const enabledExtreme = { dynamic_discovery_enabled: true, dynamic_profile: 'extreme' };
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(disabledSafe, enabledCompatible), 'none');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(enabledSafe, enabledCompatible), 'none');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(enabledCompatible, enabledCompatible), 'none');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(enabledExtreme, enabledCompatible), 'none');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(enabledSafe, enabledExtreme), 'extreme');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(enabledExtreme, enabledExtreme), 'none');

  const prompts = [];
  sandbox.window.confirm = message => {
    prompts.push(message);
    return true;
  };
  const compatibleAccepted = sandbox.confirmDynamicProfileChange(enabledSafe, enabledCompatible, 'media-site', false, '');
  assert.equal(compatibleAccepted.ok, true);
  assert.equal(compatibleAccepted.requirement, 'none');
  assert.equal(prompts.length, 0);

  const missingAcknowledgement = sandbox.confirmDynamicProfileChange(enabledSafe, enabledExtreme, 'media-site', false, 'media-site');
  assert.equal(missingAcknowledgement.ok, false);
  assert.match(missingAcknowledgement.error, /勾选/);
  const wrongName = sandbox.confirmDynamicProfileChange(enabledSafe, enabledExtreme, 'media-site', true, 'other-site');
  assert.equal(wrongName.ok, false);
  assert.match(wrongName.error, /准确输入站点名称/);
  const extremeAccepted = sandbox.confirmDynamicProfileChange(enabledSafe, enabledExtreme, 'media-site', true, 'media-site');
  assert.equal(extremeAccepted.ok, true);
  assert.equal(extremeAccepted.requirement, 'extreme');
  assert.match(prompts.at(-1), /显著放大公网发现/);

  const unchangedExtreme = sandbox.confirmDynamicProfileChange(enabledExtreme, enabledExtreme, 'media-site', false, '');
  assert.equal(unchangedExtreme.ok, true);
  assert.equal(unchangedExtreme.requirement, 'none');
});

test('site modal presents proxy, direct main-video, and automatic discovery controls', async () => {
  const { sandbox, document } = loadModalHarness();
  await sandbox.showSiteModal(null);
  const body = document.getElementById('modal-body').innerHTML;

  assert.match(body, /主视频流策略/);
  assert.match(body, /反代/);
  assert.match(body, /直连/);
  assert.match(body, /直连仅适用于主视频文件/);
  assert.match(body, /面板、API、HLS\/DASH 等仍由 Meridian 代理/);
	  assert.equal(document.getElementById('m-main-video-mode').value, 'proxy');
	  assert.ok(document.getElementById('m-dynamic-enabled'));
	  assert.ok(document.getElementById('m-dynamic-profile'));
	  assert.ok(document.getElementById('m-target-scheme'));
	  assert.equal(document.getElementById('m-target-scheme').value, 'https');
	  assert.equal(document.getElementById('m-target-port').value, '443');
	  assert.equal(document.getElementById('m-dynamic-source-hls'), null);
	  assert.equal(document.getElementById('m-dynamic-source-dash'), null);
	  assert.equal(document.getElementById('m-dynamic-downgrade'), null);
	  assert.match(body, /自动发现/);
	  assert.match(body, /Compatible|兼容/);
	  assert.match(body, /端口留空时自动使用 HTTPS 443 或 HTTP 80/);
	  assert.match(body, /处理来源与 HTTPS 降级策略由所选模式自动设置/);
	  assert.doesNotMatch(body, /播放回源/);
});

test('upstream line helpers preserve legacy targets and default new HTTPS ports', () => {
	  const sandbox = loadScripts('api.js', 'pages/sites.js');

	  assert.deepEqual(plain(sandbox.splitUpstreamTargetAddress('', 'https')), {
	    scheme: 'https',
	    address: '',
	    port: '443',
	  });
	  assert.deepEqual(plain(sandbox.splitUpstreamTargetAddress('media.example.com:443/emby', 'https')), {
	    scheme: 'https',
	    address: 'media.example.com/emby',
	    port: '443',
	  });
	  assert.deepEqual(plain(sandbox.splitUpstreamTargetAddress('media.example.com:8096/emby', 'https')), {
	    scheme: 'http',
	    address: 'media.example.com/emby',
	    port: '8096',
	  });
	  assert.deepEqual(plain(sandbox.splitUpstreamTargetAddress('https://media.example.com/base?q=1', 'http')), {
	    scheme: 'https',
	    address: 'media.example.com/base?q=1',
	    port: '443',
	  });
	  assert.equal(sandbox.joinUpstreamTargetAddress('https', 'media.example.com/emby', ''), 'https://media.example.com/emby');
	  assert.equal(sandbox.joinUpstreamTargetAddress('http', 'media.example.com/emby', ''), 'http://media.example.com/emby');
	  assert.equal(sandbox.joinUpstreamTargetAddress('https', 'media.example.com/emby', '8443'), 'https://media.example.com:8443/emby');
	  assert.equal(sandbox.joinUpstreamTargetAddress('https', 'user:secret@media.example.com', '443'), '');
	  assert.equal(sandbox.joinUpstreamTargetAddress('https', 'media.example.com/#fragment', '443'), '');
});

test('new site submission derives automatic discovery from the selected profile', async () => {
	  const { sandbox, document, state } = loadModalHarness();
	  await sandbox.showSiteModal(null);
	  document.getElementById('m-name').value = 'Media';
	  document.getElementById('m-target-scheme').value = 'https';
	  document.getElementById('m-target-address').value = 'origin.example';
	  document.getElementById('m-target-port').value = '';
  document.getElementById('m-ingress-mode').value = 'port';
  document.getElementById('m-ingress-mode').onchange();
  document.getElementById('m-port').value = '8096';

  await document.getElementById('m-submit').onclick();

  assert.equal(state.creates.length, 1);
  assert.equal(state.creates[0].target_url, 'https://origin.example');
  assert.equal(state.creates[0].playback_target_url, '');
  assert.equal(state.creates[0].playback_mode, 'direct');
  assert.equal(state.creates[0].main_video_stream_mode, 'proxy');
  assert.equal(state.creates[0].client_ip_mode, 'both');
	  assert.deepEqual(state.creates[0].stream_hosts, []);
	  assert.equal(state.creates[0].dynamic_discovery_enabled, true);
	  assert.equal(state.creates[0].dynamic_profile, 'compatible');
	  assert.equal(Object.hasOwn(state.creates[0], 'dynamic_discovery_sources'), false);
	  assert.equal(state.creates[0].dynamic_allow_https_downgrade, true);
});

test('enabled discovery policy normalizes sources and rules and omits the response-only revision', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const hydrated = sandbox.normalizeDynamicSitePolicy({
    dynamic_discovery_enabled: true,
    dynamic_profile: ' COMPATIBLE ',
    dynamic_domain_rules: [
      { type: ' EXACT ', value: ' Media.Example.COM ' },
      { type: 'suffix', value: ' CDN.Example.COM ' },
      { type: 'wildcard', value: 'ignored.example' },
      null,
    ],
    dynamic_allow_https_downgrade: true,
    dynamic_policy_revision: 9,
  });

  assert.equal(hydrated.dynamic_policy_revision, 9);
  assert.deepEqual(plain(hydrated.dynamic_discovery_sources), ['redirect', 'playback_info']);
	  const payload = sandbox.buildDynamicPolicyPayload(hydrated, structuredDiscoveryResponse());
	  assert.deepEqual(plain(payload), {
	    dynamic_discovery_enabled: true,
	    dynamic_profile: 'compatible',
	    dynamic_domain_rules: [
      { type: 'exact', value: 'media.example.com' },
      { type: 'suffix', value: 'cdn.example.com' },
    ],
    dynamic_allow_https_downgrade: true,
  });
  assert.equal(Object.hasOwn(payload, 'dynamic_policy_revision'), false, 'revision is response-only');

  const partial = sandbox.normalizeDynamicSitePolicy({
    dynamic_discovery_sources: ['HLS', 'dash', 'redirect', 'REDIRECT', 'unknown', null],
  });
	  assert.deepEqual(plain(partial.dynamic_discovery_sources), ['redirect', 'hls', 'dash']);
	  assert.equal(Object.hasOwn(sandbox.buildDynamicPolicyPayload(partial, structuredDiscoveryResponse()), 'dynamic_discovery_sources'), false);
});

test('Safe enablement requires a plausible exact or suffix DNS rule', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');

  assert.equal(sandbox.hasRequiredSafeDynamicRules('safe', []), false);
  assert.equal(sandbox.hasRequiredSafeDynamicRules('safe', [{ type: 'exact', value: 'Media.Example.COM' }]), true);
  assert.equal(sandbox.hasRequiredSafeDynamicRules('safe', [{ type: 'suffix', value: 'cdn.example.net.' }]), true);
  for (const value of [
    '*.example.com',
    '.example.com',
    'https://example.com',
    'example.com/path',
    'user@example.com',
    '127.0.0.1',
    'localhost',
    'example.123',
    '-edge.example.com',
  ]) {
    assert.equal(
      sandbox.hasRequiredSafeDynamicRules('safe', [{ type: 'exact', value }]),
      false,
      `${value} must not satisfy the Safe DNS-rule requirement`,
    );
  }
  assert.equal(sandbox.hasRequiredSafeDynamicRules('compatible', []), true);
  assert.equal(sandbox.hasRequiredSafeDynamicRules('extreme', []), true);
});

test('observation normalization accepts only finite enums and privacy-safe aggregate fields', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const finiteReasonRows = EXTREME_OBSERVATION_REASON_CASES.map(({ source, reason }, index) => ({
    canonical_authority: `https://reason-${index}.example:443`,
    source,
    decision: 'denied',
    reason_code: reason,
    first_seen_ms: 10 + (index * 2),
    last_seen_ms: 11 + (index * 2),
    count: index + 1,
  }));
  const sensitiveValues = [
    'unknown_reason_token_secret',
    'https://media.example:443/private/video.m3u8?access_token=normalization-secret',
    '/private/video.m3u8',
    'access_token=normalization-secret',
    'Bearer normalization-header-secret',
    'normalization-body-secret',
  ];
  const normalized = sandbox.normalizeDynamicObservationsResponse({
    observations: [
      {
        canonical_authority: 'HTTPS://Media.Example.COM:443',
        source: 'redirect',
        decision: 'allowed',
        reason_code: 'redirect_allowed',
        first_seen_ms: 0,
        last_seen_ms: 1700000000123,
        count: 3,
      },
      {
        canonical_authority: 'http://[2001:DB8::1]:8080',
        source: 'redirect',
        decision: 'denied',
        reason_code: 'scheme_denied',
        first_seen_ms: 1,
        last_seen_ms: 2,
        count: Number.MAX_SAFE_INTEGER,
      },
      ...finiteReasonRows,
      {
        canonical_authority: 'https://unknown.example:443',
        source: 'playback_info',
        decision: 'denied',
        reason_code: sensitiveValues[0],
        first_seen_ms: 30,
        last_seen_ms: 31,
        count: 1,
        full_url: sensitiveValues[1],
        path: sensitiveValues[2],
        query: sensitiveValues[3],
        request_headers: { Authorization: sensitiveValues[4] },
        response_body: sensitiveValues[5],
      },
    ],
    dropped_observations: 4,
  });

  assert.deepEqual(plain(normalized.observations.slice(0, 2)), [
    {
      authority: 'https://media.example.com:443',
      source: 'redirect',
      decision: 'allowed',
      reason: 'redirect_allowed',
      firstSeen: '1970-01-01 08:00:00',
      lastSeen: '2023-11-15 06:13:20',
      count: 3,
    },
    {
      authority: 'http://[2001:db8::1]:8080',
      source: 'redirect',
      decision: 'denied',
      reason: 'scheme_denied',
      firstSeen: '1970-01-01 08:00:00',
      lastSeen: '1970-01-01 08:00:00',
      count: Number.MAX_SAFE_INTEGER,
    },
  ]);
  assert.deepEqual(
    plain(normalized.observations.slice(2, 2 + EXTREME_OBSERVATION_REASON_CASES.length)),
    EXTREME_OBSERVATION_REASON_CASES.map(({ source, reason }, index) => ({
      authority: `https://reason-${index}.example:443`,
      source,
      decision: 'denied',
      reason,
      firstSeen: '1970-01-01 08:00:00',
      lastSeen: '1970-01-01 08:00:00',
      count: index + 1,
    })),
  );
  assert.deepEqual(plain(normalized.observations[normalized.observations.length - 1]), {
    authority: 'https://unknown.example:443',
    source: 'playback_info',
    decision: 'denied',
    reason: '—',
    firstSeen: '1970-01-01 08:00:00',
    lastSeen: '1970-01-01 08:00:00',
    count: 1,
  });
  assert.equal(normalized.dropped, 4);
  const normalizedJSON = JSON.stringify(normalized);
  for (const value of sensitiveValues) assert.ok(!normalizedJSON.includes(value));

  for (const authority of [
    'https://media.example',
    'https://media.example:443/path',
    'https://media.example:443?query=secret',
    'https://user@media.example:443',
    'ftp://media.example:21',
    'https://bad_host.example:443',
    'https://media.example:65536',
  ]) {
    assert.equal(sandbox.privacySafeObservationAuthority(authority), '—');
  }
  assert.equal(sandbox.normalizeDynamicObservationsResponse({ dropped_observations: -1 }).dropped, '—');
});

test('dynamic rendering escapes values and never renders sensitive observation detail', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const capabilities = structuredDiscoveryResponse({
    profiles: [
      discoveryProfile('safe'),
      discoveryProfile('compatible', { label: ATTACK }),
      discoveryProfile('extreme'),
    ],
  });
  const options = sandbox.renderDynamicProfileOptions(capabilities, 'safe');
  const summaries = sandbox.renderDynamicProfileSummaries(capabilities);
  const ruleRows = sandbox.renderDynamicRuleRows([{ type: 'exact', value: ATTACK }]);

  for (const html of [options, summaries, ruleRows]) {
    assert.ok(!html.includes(ATTACK));
    assert.match(html, /&quot;&gt;&lt;img src=x onerror=alert\(1\)&gt;/);
  }

  const sensitiveValues = [
    'https://media.example:443/private/video.m3u8?access_token=top-secret',
    '/private/video.m3u8',
    'access_token=top-secret',
    'Bearer header-secret',
    'body-secret-value',
    'unknown_reason_token_secret',
  ];
  const finiteReasonRows = EXTREME_OBSERVATION_REASON_CASES.map(({ source, reason }, index) => ({
    canonical_authority: `https://render-reason-${index}.example:443`,
    source,
    decision: 'denied',
    reason_code: reason,
    first_seen_ms: 10 + (index * 2),
    last_seen_ms: 11 + (index * 2),
    count: index + 1,
  }));
  const observations = sandbox.renderDynamicObservations({
    observations: [
      {
        canonical_authority: 'https://media.example:443',
        source: 'redirect',
        decision: 'allowed',
        reason_code: 'redirect_allowed',
        first_seen_ms: 0,
        last_seen_ms: 1,
        count: 2,
        full_url: sensitiveValues[0],
        path: sensitiveValues[1],
        query: sensitiveValues[2],
        token: 'top-secret',
        request_headers: { Authorization: sensitiveValues[3] },
        response_body: sensitiveValues[4],
      },
      ...finiteReasonRows,
      {
        canonical_authority: 'https://unknown.example:443',
        source: 'playback_info',
        decision: 'denied',
        reason_code: sensitiveValues[5],
        first_seen_ms: 30,
        last_seen_ms: 31,
        count: 1,
        full_url: sensitiveValues[0],
        path: sensitiveValues[1],
        query: sensitiveValues[2],
        token: 'top-secret',
        request_headers: { Authorization: sensitiveValues[3] },
        response_body: sensitiveValues[4],
      },
    ],
    dropped_observations: 7,
  });

  assert.match(observations, /https:\/\/media\.example:443/);
  assert.match(observations, /https:\/\/unknown\.example:443/);
  assert.match(observations, /已丢弃观察记录：7/);
  for (const { reason } of EXTREME_OBSERVATION_REASON_CASES) assert.ok(observations.includes(reason));
  for (const value of sensitiveValues) assert.ok(!observations.includes(value));
  assert.ok(!observations.includes('top-secret'));
  assert.ok(!observations.includes('header-secret'));
  assert.ok(!observations.includes('body-secret-value'));

  const panel = sandbox.renderDynamicObservationsPanel(true);
  for (const phrase of ['规范化权威', '有限原因代码', '聚合时间/次数', '完整 URL', '路径', '查询参数', '令牌', '请求头', '正文']) {
    assert.match(panel, new RegExp(phrase));
  }
});

test('edit modal exposes discovery policy and observation controls', async () => {
  const { sandbox, document, state } = loadModalHarness();
  const site = {
    id: 17,
    name: 'Media',
    target_url: 'https://origin.example',
    ingress_mode: 'port',
    listen_port: 8096,
    public_host: '',
    ua_mode: 'infuse',
    client_ip_mode: 'real_ip',
    playback_target_url: '',
    main_video_stream_mode: 'direct',
    stream_hosts: [],
    upstream_headers: [],
    dynamic_discovery_enabled: true,
    dynamic_profile: 'safe',
    dynamic_discovery_sources: ['redirect', 'playback_info'],
    dynamic_domain_rules: [{ type: 'exact', value: 'media.example' }],
    dynamic_allow_https_downgrade: false,
    dynamic_policy_revision: 2,
  };

  await sandbox.showSiteModal(site);
  assert.equal(state.opened, 1);
  assert.ok(document.getElementById('m-refresh-dynamic-observations'));
  assert.ok(document.getElementById('m-clear-dynamic-observations'));
  assert.ok(document.getElementById('m-dynamic-observations'));
  assert.deepEqual(state.observationGets, [17]);
  assert.deepEqual(state.observationDeletes, []);
  assert.deepEqual(state.confirmations, []);
  assert.deepEqual(state.errors, []);
  assert.equal(document.getElementById('m-main-video-mode').value, 'direct');
  assert.equal(document.getElementById('m-client-ip-mode').value, 'real_ip');
});

test('client IP forwarding selector exposes only the three node-level modes', () => {
  const source = fs.readFileSync(path.join(STATIC_JS, 'pages', 'sites.js'), 'utf8');
  for (const value of ['both', 'real_ip', 'none']) {
    assert.match(source, new RegExp(`<option value="${value}"`));
  }
  assert.doesNotMatch(source, /client_ip_mode[^\n]*(inherit|global)|继承全局/i);
  assert.match(source, /clientIPModeSelect\.value = isEdit[^\n]+: 'both'/);
  assert.match(source, /client_ip_mode: clientIPModeSelect\.value/);
});

test('main video strategy uses a compact selector and defaults to proxy', () => {
  const source = fs.readFileSync(path.join(STATIC_JS, 'pages', 'sites.js'), 'utf8');
  assert.match(source, /<select[^>]+id="m-main-video-mode"/);
  assert.match(source, /<option value="proxy"[^>]*>反代<\/option>/);
  assert.match(source, /<option value="direct"[^>]*>直连<\/option>/);
  assert.doesNotMatch(source, /m-main-video-(?:proxy|direct)|main-video-mode-control/);
  assert.match(source, /mainVideoModeSelect\.value = isEdit[^\n]+: 'proxy'/);
  assert.match(source, /main_video_stream_mode: mainVideoModeSelect\.value/);
});

test('advanced settings align main video with the separate cache limit row', () => {
  const source = fs.readFileSync(path.join(STATIC_JS, 'pages', 'sites.js'), 'utf8');
  const style = fs.readFileSync(path.join(STATIC_JS, '..', 'css', 'style.css'), 'utf8');
  assert.match(source, /class="form-group cache-limit-group"/);
  assert.match(source, /class="cache-limit-grid"/);
  assert.match(style, /"video cache-limits \."/);
  assert.match(style, /\.cache-limit-group \{ grid-area: cache-limits; \}/);
});
