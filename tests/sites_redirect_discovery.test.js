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
  const discoverySources = id === 'safe'
    ? ['redirect', 'playback_info']
    : ['redirect', 'playback_info', 'hls', 'dash'];
  return {
    id,
    label: id[0].toUpperCase() + id.slice(1),
    recommended: id === 'safe',
    discovery_sources: discoverySources,
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
    empty_rules_semantics: 'public_dns_https_443',
    default_policy: {
      dynamic_discovery_enabled: true,
      dynamic_profile: 'safe',
      dynamic_discovery_sources: ['redirect', 'playback_info'],
      dynamic_domain_rules: [],
      dynamic_allow_https_downgrade: false,
    },
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

function existingSite(overrides = {}) {
  return {
    id: 17,
    name: 'Media',
    target_url: 'https://origin.example',
    ingress_mode: 'port',
    listen_port: 8096,
    public_host: '',
    ua_mode: 'infuse',
    playback_mode: 'direct',
    playback_target_url: '',
    stream_hosts: [],
    upstream_headers: [],
    dynamic_discovery_enabled: true,
    dynamic_profile: 'safe',
    dynamic_domain_rules: [],
    dynamic_allow_https_downgrade: false,
    ping_cache_enabled: false,
    image_cache_enabled: false,
    progress_coalescing_enabled: false,
    traffic_quota: 0,
    speed_limit: 0,
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
    this.open = false;
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

  focus() {
    this.ownerDocument.activeElement = this;
  }
}

class FakeDocument {
  constructor() {
    this.elements = new Map();
    for (const id of ['modal-title', 'modal-body', 'modal-footer', 'sites-count', 'sites-grid']) {
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
      element.hidden = /(?:^|\s)hidden(?:\s|$)/.test(attributes);
      element.open = /(?:^|\s)open(?:\s|$)/.test(attributes);
      element.required = /(?:^|\s)required(?:\s|$)/.test(attributes);
      for (const match of attributes.matchAll(/\bdata-([a-z0-9-]+)="([^"]*)"/gi)) {
        const key = match[1].replace(/-([a-z])/g, (_, character) => character.toUpperCase());
        element.dataset[key] = match[2];
      }
      elements.push(element);
    }
    return elements;
  }
}

function loadModalHarness(options = {}) {
  const document = new FakeDocument();
  const state = {
    confirmationResult: false,
    confirmations: [],
    observationGets: [],
    observationDeletes: [],
    successes: [],
    errors: [],
    created: [],
    updated: [],
    opened: 0,
    closed: 0,
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
      ingressCapabilities: async () => options.siteCapabilities || ({
        host_only_available: true,
        upstream_headers_available: true,
        max_playback_addresses: 128,
      }),
      listSites: async () => [],
      getDynamicProfiles: async () => options.dynamicResponse === undefined
        ? structuredDiscoveryResponse()
        : options.dynamicResponse,
      createSite: async data => { state.created.push(clone(data)); },
      updateSite: async (siteId, data) => { state.updated.push({ siteId, data: clone(data) }); },
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
    closeModal() { state.closed++; },
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

test('catalog recognition requires canonical sources, default policy, and empty-rule semantics', async () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const accepted = structuredDiscoveryResponse();
  assert.equal(sandbox.isStructuredDiscoveryContract(accepted), true);
  const normalized = sandbox.normalizeDynamicProfiles(accepted);
  assert.equal(normalized.recognized, true);
  assert.equal(normalized.empty_rules_semantics, 'public_dns_https_443');
  assert.deepEqual(plain(sandbox.dynamicSourcesForProfile(normalized, 'safe')), ['redirect', 'playback_info']);
  assert.deepEqual(plain(sandbox.dynamicSourcesForProfile(normalized, 'compatible')), ['redirect', 'playback_info', 'hls', 'dash']);
  assert.deepEqual(plain(normalized.default_policy), accepted.default_policy);

  const malformed = [null, {}, { ...accepted, stage: 'redirect-discovery' }, { ...accepted, available: false, key_configured: true }, { ...accepted, empty_rules_semantics: 'deny_all' }];
  const missingDefault = clone(accepted);
  delete missingDefault.default_policy;
  malformed.push(missingDefault);
  const wrongSafeSources = clone(accepted);
  wrongSafeSources.profiles[0].discovery_sources.push('hls');
  malformed.push(wrongSafeSources);
  const wrongDefaultSources = clone(accepted);
  wrongDefaultSources.default_policy.dynamic_discovery_sources = ['redirect'];
  malformed.push(wrongDefaultSources);
  const missingGlobalLimit = clone(accepted);
  delete missingGlobalLimit.global_limits.max_dns_workers;
  malformed.push(missingGlobalLimit);
  for (const value of malformed) {
    assert.equal(sandbox.isStructuredDiscoveryContract(value), false);
    assert.equal(sandbox.normalizeDynamicProfiles(value).recognized, false);
  }
  vm.runInContext('API.getDynamicProfiles = async () => { throw new Error("missing"); }', sandbox);
  assert.equal((await sandbox.loadDynamicProfiles()).recognized, false);
});

test('new-site discovery defaults only from a ready Safe catalog policy', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  assert.deepEqual(plain(sandbox.defaultDynamicSitePolicy(structuredDiscoveryResponse())), {
    dynamic_discovery_enabled: true,
    dynamic_profile: 'safe',
    dynamic_playback_info_enabled: true,
    dynamic_domain_rules: [],
    dynamic_allow_https_downgrade: false,
  });
  const unavailable = structuredDiscoveryResponse({ available: false, key_configured: false });
  assert.equal(sandbox.defaultDynamicSitePolicy(unavailable).dynamic_discovery_enabled, false);
  const defaultOff = structuredDiscoveryResponse();
  defaultOff.default_policy.dynamic_discovery_enabled = false;
  assert.equal(sandbox.isStructuredDiscoveryContract(defaultOff), true);
  assert.equal(sandbox.defaultDynamicSitePolicy(defaultOff).dynamic_discovery_enabled, false);
});

test('create modal defaults to Safe PlaybackInfo inspection without exposing a source matrix', async () => {
  const { sandbox, document } = loadModalHarness();
  await sandbox.showSiteModal(null);
  assert.equal(document.getElementById('m-ingress-mode').value, 'port');
  assert.equal(document.getElementById('m-dynamic-enabled').checked, true);
  assert.equal(document.getElementById('m-dynamic-profile').value, 'safe');
  assert.equal(document.getElementById('m-dynamic-playback-info').checked, true);
  assert.equal(document.getElementById('m-dynamic-source-redirect'), null);
  assert.equal(document.getElementById('m-dynamic-source-playback_info'), null);
  assert.equal(document.getElementById('m-dynamic-source-hls'), null);
  assert.equal(document.getElementById('m-dynamic-source-dash'), null);
  assert.equal(document.getElementById('m-dynamic-policy-fields').disabled, false);
  assert.equal(document.getElementById('m-dynamic-advanced').hidden, true);
  assert.equal(document.getElementById('m-dynamic-downgrade').checked, false);
  assert.match(document.getElementById('m-dynamic-domain-warning').textContent, /公网 DNS 主机名的 HTTPS:443/);
  const modalMarkup = document.getElementById('modal-body').innerHTML;
  assert.match(modalMarkup, /解析 PlaybackInfo/);
  assert.match(modalMarkup, /PlaybackInfo 正文不再解析或改写/);
  assert.match(modalMarkup, /HTTP 30x 后端发现仍保持启用，动态跟随后的最终响应仍执行 Header 清洗/);
  assert.match(modalMarkup, /外部 URL 不再封装为受控能力链接，可能直接交给客户端/);
});

test('create modal keeps discovery off and policy controls disabled when the catalog is unavailable', async () => {
  const { sandbox, document } = loadModalHarness({ dynamicResponse: structuredDiscoveryResponse({ available: false, key_configured: false }) });
  await sandbox.showSiteModal(null);
  assert.equal(document.getElementById('m-dynamic-enabled').checked, false);
  assert.equal(document.getElementById('m-dynamic-enabled').disabled, true);
  assert.equal(document.getElementById('m-dynamic-playback-info').checked, true);
  assert.equal(document.getElementById('m-dynamic-policy-fields').disabled, true);
  assert.equal(document.getElementById('m-ingress-mode').value, 'port');
  assert.match(document.getElementById('modal-body').innerHTML, /DYNAMIC_ROUTE_KEY 未配置/);
});

test('edit modal preserves stored state and auto-opens an enabled downgrade', async () => {
  const { sandbox, document } = loadModalHarness();
  await sandbox.showSiteModal(existingSite({
    ingress_mode: 'both', public_host: 'media.example.com', dynamic_profile: 'compatible',
    dynamic_domain_rules: [{ type: 'suffix', value: 'media.example.com' }], dynamic_allow_https_downgrade: true,
    ping_cache_enabled: true, image_cache_enabled: true, progress_coalescing_enabled: true,
  }));
  assert.equal(document.getElementById('m-ingress-mode').value, 'both');
  assert.equal(document.getElementById('m-dynamic-profile').value, 'compatible');
  assert.equal(document.getElementById('m-dynamic-playback-info').checked, true, 'a missing source array keeps inspection on');
  assert.equal(document.getElementById('m-dynamic-downgrade').checked, true);
  assert.equal(document.getElementById('m-dynamic-advanced').hidden, false);
  assert.equal(document.getElementById('m-dynamic-advanced').open, true);
  assert.equal(document.getElementById('m-ping-cache-enabled').checked, true);
  assert.equal(document.getElementById('m-image-cache-enabled').checked, true);
  assert.equal(document.getElementById('m-progress-coalescing-enabled').checked, true);
});

test('edit modal hydrates canonical PlaybackInfo-off source sets for every profile', async () => {
  const cases = [
    ['safe', ['redirect']],
    ['compatible', ['redirect', 'hls', 'dash']],
    ['extreme', ['redirect', 'hls', 'dash']],
  ];
  for (const [profile, dynamicDiscoverySources] of cases) {
    const { sandbox, document } = loadModalHarness();
    await sandbox.showSiteModal(existingSite({
      dynamic_profile: profile,
      dynamic_discovery_sources: dynamicDiscoverySources,
    }));
    assert.equal(document.getElementById('m-dynamic-playback-info').checked, false, profile);
  }
});

test('existing request limits hydrate the peer checkbox and revealed fields', async () => {
  const { sandbox, document } = loadModalHarness();
  await sandbox.showSiteModal(existingSite({
    traffic_quota: 3 * 1073741824,
    speed_limit: 24,
  }));
  assert.equal(document.getElementById('m-request-limits-enabled').checked, true);
  assert.equal(document.getElementById('m-request-limit-fields').hidden, false);
  assert.equal(document.getElementById('m-quota').value, '3');
  assert.equal(document.getElementById('m-speed').value, '24');
  assert.equal(document.getElementById('m-quota').disabled, false);
  assert.equal(document.getElementById('m-speed').disabled, false);
});

test('selected-profile risk and approved transition gates remain active', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const capabilities = structuredDiscoveryResponse();
  assert.match(sandbox.renderDynamicProfileRisk('safe', capabilities), /HTTP 30x、PlaybackInfo/);
  assert.match(sandbox.renderDynamicProfileRisk('compatible', capabilities), /任意公网域名和端口/);
  assert.match(sandbox.renderDynamicProfileRisk('extreme', capabilities), /重放有界请求体/);
  const safe = { dynamic_discovery_enabled: true, dynamic_profile: 'safe' };
  const compatible = { dynamic_discovery_enabled: true, dynamic_profile: 'compatible' };
  const extreme = { dynamic_discovery_enabled: true, dynamic_profile: 'extreme' };
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(safe, compatible), 'compatible');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(compatible, compatible), 'none');
  assert.equal(sandbox.dynamicProfileConfirmationRequirement(safe, extreme), 'extreme');
  const prompts = [];
  sandbox.window.confirm = message => { prompts.push(message); return true; };
  assert.equal(sandbox.confirmDynamicProfileChange(safe, compatible, 'Media', false, '').ok, true);
  assert.match(prompts.at(-1), /1–65535/);
  assert.match(sandbox.confirmDynamicProfileChange(safe, extreme, 'Media', false, 'Media').error, /勾选/);
  assert.match(sandbox.confirmDynamicProfileChange(safe, extreme, 'Media', true, 'Other').error, /准确输入/);
  assert.equal(sandbox.confirmDynamicProfileChange(safe, extreme, 'Media', true, 'Media').ok, true);
});

test('profile interaction preserves PlaybackInfo choice and conditionally reveals risk controls', async () => {
  const { sandbox, document } = loadModalHarness();
  await sandbox.showSiteModal(null);
  const profile = document.getElementById('m-dynamic-profile');
  const playbackInfo = document.getElementById('m-dynamic-playback-info');
  const profileRisk = document.getElementById('m-dynamic-profile-risk');
  const downgrade = document.getElementById('m-dynamic-downgrade');
  const advanced = document.getElementById('m-dynamic-advanced');
  const extremeConfirmation = document.getElementById('m-dynamic-extreme-confirm');
  assert.equal(playbackInfo.checked, true);
  playbackInfo.checked = false;
  playbackInfo.onchange();
  assert.doesNotMatch(profileRisk.innerHTML, /PlaybackInfo/);
  profile.value = 'compatible';
  profile.onchange();
  assert.equal(playbackInfo.checked, false);
  assert.match(profileRisk.innerHTML, /HTTP 30x、HLS、DASH/);
  assert.equal(advanced.hidden, false);
  downgrade.checked = true;
  profile.value = 'safe';
  profile.onchange();
  assert.equal(playbackInfo.checked, false);
  assert.equal(advanced.hidden, true);
  assert.equal(downgrade.checked, false);
  profile.value = 'extreme';
  profile.onchange();
  assert.equal(playbackInfo.checked, false);
  assert.equal(advanced.hidden, false);
  assert.equal(extremeConfirmation.hidden, false);
});

test('policy normalization and payload use only canonical PlaybackInfo ON or OFF source sets', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const capabilities = structuredDiscoveryResponse();
  const hydrated = sandbox.normalizeDynamicSitePolicy({
    dynamic_discovery_enabled: true, dynamic_profile: ' COMPATIBLE ', dynamic_discovery_sources: ['redirect'],
    dynamic_domain_rules: [{ type: ' EXACT ', value: ' Media.Example.COM ' }, { type: 'suffix', value: ' CDN.Example.COM ' }],
    dynamic_allow_https_downgrade: true, dynamic_policy_revision: 9,
  });
  assert.equal(hydrated.dynamic_playback_info_enabled, false);
  assert.equal(sandbox.normalizeDynamicSitePolicy({ dynamic_discovery_sources: ['playback_info'] }).dynamic_playback_info_enabled, true);
  assert.equal(sandbox.normalizeDynamicSitePolicy({}).dynamic_playback_info_enabled, true, 'missing arrays default inspection on');
  assert.equal(sandbox.normalizeDynamicSitePolicy({ dynamic_discovery_sources: 'playback_info' }).dynamic_playback_info_enabled, true, 'invalid arrays default inspection on');
  const payload = sandbox.buildDynamicPolicyPayload(hydrated, capabilities);
  assert.deepEqual(plain(payload), {
    dynamic_discovery_enabled: true, dynamic_profile: 'compatible',
    dynamic_discovery_sources: ['redirect', 'hls', 'dash'],
    dynamic_domain_rules: [{ type: 'exact', value: 'media.example.com' }, { type: 'suffix', value: 'cdn.example.com' }],
    dynamic_allow_https_downgrade: true,
  });
  assert.equal(Object.hasOwn(payload, 'dynamic_playback_info_enabled'), false);
  assert.equal(Object.hasOwn(hydrated, 'dynamic_policy_revision'), false);

  const sourceCases = [
    ['safe', ['redirect', 'playback_info'], ['redirect']],
    ['compatible', ['redirect', 'playback_info', 'hls', 'dash'], ['redirect', 'hls', 'dash']],
    ['extreme', ['redirect', 'playback_info', 'hls', 'dash'], ['redirect', 'hls', 'dash']],
  ];
  for (const [profile, enabledSources, disabledSources] of sourceCases) {
    const enabled = sandbox.buildDynamicPolicyPayload({ dynamic_profile: profile, dynamic_playback_info_enabled: true }, capabilities);
    const disabled = sandbox.buildDynamicPolicyPayload({ dynamic_profile: profile, dynamic_playback_info_enabled: false }, capabilities);
    assert.deepEqual(plain(enabled.dynamic_discovery_sources), enabledSources, `${profile} ON`);
    assert.deepEqual(plain(disabled.dynamic_discovery_sources), disabledSources, `${profile} OFF`);
  }

  assert.equal(sandbox.buildDynamicPolicyPayload({ dynamic_profile: 'safe', dynamic_allow_https_downgrade: true }, capabilities).dynamic_allow_https_downgrade, false);
  assert.deepEqual(plain(sandbox.buildDynamicPolicyPayload({ dynamic_discovery_enabled: true }, {}, true)), { dynamic_discovery_enabled: false });
  assert.deepEqual(plain(sandbox.buildDynamicPolicyPayload({ dynamic_discovery_enabled: true }, {}, false)), {});
});

test('Safe empty-rule warning and last-restriction transition match public HTTPS semantics', () => {
  const sandbox = loadScripts('api.js', 'pages/sites.js');
  const empty = sandbox.dynamicDomainRuleWarning('safe', []);
  assert.equal(empty.tone, 'info');
  assert.match(empty.message, /公网 DNS 主机名的 HTTPS:443/);
  assert.match(empty.message, /IP 字面量始终拒绝/);
  assert.equal(sandbox.dynamicDomainRuleWarning('safe', [{ type: 'exact', value: 'media.example.com' }]).message, '');
  assert.equal(sandbox.dynamicDomainRuleWarning('safe', [{ type: 'exact', value: '127.0.0.1' }]).tone, 'warning');
  const restriction = [{ type: 'exact', value: 'media.example.com' }];
  assert.equal(sandbox.safeRulesBecomeUnrestricted(true, 'safe', restriction, []), true);
  assert.equal(sandbox.safeRulesBecomeUnrestricted(false, 'safe', restriction, []), false);
  const rows = sandbox.renderDynamicRuleRows([{ type: 'exact', value: 'origin.example.com' }, { type: 'suffix', value: 'cdn.example.com' }]);
  assert.match(rows, /value="exact" selected/);
  assert.match(rows, /value="suffix" selected/);
  assert.match(rows, /<fieldset class="form-list-row dynamic-rule-row/);
  assert.match(rows, /for="m-dynamic-rule-value-1"/);
});

test('create submission includes default Safe discovery sources and proxy optimization toggles', async () => {
  const { sandbox, document, state } = loadModalHarness();
  await sandbox.showSiteModal(null);
  document.getElementById('m-name').value = 'Media';
  document.getElementById('m-target').value = 'https://origin.example';
  document.getElementById('m-port').value = '8096';
  document.getElementById('m-playback-mode').value = 'direct';
  document.getElementById('m-ping-cache-enabled').checked = true;
  document.getElementById('m-progress-coalescing-enabled').checked = true;
  await document.getElementById('m-submit').onclick();
  assert.equal(state.created.length, 1);
  const payload = state.created[0];
  assert.equal(payload.ingress_mode, 'port');
  assert.equal(payload.dynamic_discovery_enabled, true);
  assert.deepEqual(payload.dynamic_discovery_sources, ['redirect', 'playback_info']);
  assert.equal(Object.hasOwn(payload, 'dynamic_playback_info_enabled'), false);
  assert.equal(payload.ping_cache_enabled, true);
  assert.equal(payload.image_cache_enabled, false);
  assert.equal(payload.progress_coalescing_enabled, true);
  assert.deepEqual(state.errors, []);
});

test('create profile switch submits the exact PlaybackInfo-off Compatible sources', async () => {
  const { sandbox, document, state } = loadModalHarness();
  await sandbox.showSiteModal(null);
  const playbackInfo = document.getElementById('m-dynamic-playback-info');
  const profile = document.getElementById('m-dynamic-profile');
  playbackInfo.checked = false;
  playbackInfo.onchange();
  profile.value = 'compatible';
  profile.onchange();
  assert.equal(playbackInfo.checked, false);
  document.getElementById('m-name').value = 'Media';
  document.getElementById('m-target').value = 'https://origin.example';
  document.getElementById('m-port').value = '8096';
  document.getElementById('m-playback-mode').value = 'direct';
  state.confirmationResult = true;
  await document.getElementById('m-submit').onclick();
  assert.equal(state.created.length, 1);
  assert.deepEqual(state.created[0].dynamic_discovery_sources, ['redirect', 'hls', 'dash']);
  assert.equal(Object.hasOwn(state.created[0], 'dynamic_playback_info_enabled'), false);
  assert.match(state.confirmations.at(-1), /Compatible/);
  assert.deepEqual(state.errors, []);
});

test('edit submission toggles PlaybackInfo on and restores the selected profile full sources', async () => {
  const { sandbox, document, state } = loadModalHarness();
  await sandbox.showSiteModal(existingSite({
    dynamic_profile: 'compatible',
    dynamic_discovery_sources: ['redirect', 'hls', 'dash'],
  }));
  const playbackInfo = document.getElementById('m-dynamic-playback-info');
  assert.equal(playbackInfo.checked, false);
  playbackInfo.checked = true;
  playbackInfo.onchange();
  document.getElementById('m-playback-mode').value = 'direct';
  await document.getElementById('m-submit').onclick();
  assert.equal(state.updated.length, 1);
  assert.equal(state.updated[0].siteId, 17);
  assert.deepEqual(state.updated[0].data.dynamic_discovery_sources, ['redirect', 'playback_info', 'hls', 'dash']);
  assert.equal(Object.hasOwn(state.updated[0].data, 'dynamic_playback_info_enabled'), false);
  assert.deepEqual(state.errors, []);
});

test('request limit toggle reveals fields and unchecked submission sends zeroes', async () => {
  const { sandbox, document, state } = loadModalHarness();
  await sandbox.showSiteModal(null);
  const toggle = document.getElementById('m-request-limits-enabled');
  const fields = document.getElementById('m-request-limit-fields');
  const quota = document.getElementById('m-quota');
  const speed = document.getElementById('m-speed');
  assert.equal(toggle.checked, false);
  assert.equal(fields.hidden, true);
  assert.equal(quota.disabled, true);
  assert.equal(speed.disabled, true);

  toggle.checked = true;
  toggle.onchange();
  assert.equal(fields.hidden, false);
  assert.equal(quota.disabled, false);
  assert.equal(speed.disabled, false);
  quota.value = '2';
  speed.value = '25';

  toggle.checked = false;
  toggle.onchange();
  assert.equal(fields.hidden, true);
  document.getElementById('m-name').value = 'Media';
  document.getElementById('m-target').value = 'https://origin.example';
  document.getElementById('m-port').value = '8096';
  document.getElementById('m-playback-mode').value = 'direct';
  await document.getElementById('m-submit').onclick();
  assert.equal(state.created.length, 1);
  assert.equal(state.created[0].traffic_quota, 0);
  assert.equal(state.created[0].speed_limit, 0);
  assert.equal(Object.hasOwn(state.created[0], 'request_limits_enabled'), false);
  assert.deepEqual(state.errors, []);
});

test('enabled request limits require one positive value and submit existing fields only', async () => {
  const { sandbox, document, state } = loadModalHarness();
  await sandbox.showSiteModal(null);
  document.getElementById('m-name').value = 'Media';
  document.getElementById('m-target').value = 'https://origin.example';
  document.getElementById('m-port').value = '8096';
  document.getElementById('m-playback-mode').value = 'direct';
  const toggle = document.getElementById('m-request-limits-enabled');
  toggle.checked = true;
  toggle.onchange();
  document.getElementById('m-quota').value = '0';
  document.getElementById('m-speed').value = '0';
  await document.getElementById('m-submit').onclick();
  assert.equal(state.created.length, 0);
  assert.match(state.errors.at(-1), /至少一项必须大于 0/);

  document.getElementById('m-quota').value = '2';
  document.getElementById('m-speed').value = '25';
  await document.getElementById('m-submit').onclick();
  assert.equal(state.created.length, 1);
  assert.equal(state.created[0].traffic_quota, 2 * 1073741824);
  assert.equal(state.created[0].speed_limit, 25);
  assert.equal(Object.hasOwn(state.created[0], 'request_limits_enabled'), false);
});

test('create keeps discovery disabled when the structured catalog is unavailable', async () => {
  const { sandbox, document, state } = loadModalHarness({ dynamicResponse: {} });
  await sandbox.showSiteModal(null);
  document.getElementById('m-name').value = 'Fallback';
  document.getElementById('m-target').value = 'https://origin.example';
  document.getElementById('m-port').value = '8096';
  document.getElementById('m-playback-mode').value = 'direct';
  await document.getElementById('m-submit').onclick();
  assert.equal(state.created.length, 1);
  assert.equal(state.created[0].dynamic_discovery_enabled, false);
  assert.equal(Object.hasOwn(state.created[0], 'dynamic_profile'), false);
  assert.equal(Object.hasOwn(state.created[0], 'dynamic_discovery_sources'), false);
  assert.deepEqual(state.errors, []);
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
      firstSeen: '1970-01-01T00:00:00.000Z',
      lastSeen: '2023-11-14T22:13:20.123Z',
      count: 3,
    },
    {
      authority: 'http://[2001:db8::1]:8080',
      source: 'redirect',
      decision: 'denied',
      reason: 'scheme_denied',
      firstSeen: '1970-01-01T00:00:00.001Z',
      lastSeen: '1970-01-01T00:00:00.002Z',
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
      firstSeen: new Date(10 + (index * 2)).toISOString(),
      lastSeen: new Date(11 + (index * 2)).toISOString(),
      count: index + 1,
    })),
  );
  assert.deepEqual(plain(normalized.observations[normalized.observations.length - 1]), {
    authority: 'https://unknown.example:443',
    source: 'playback_info',
    decision: 'denied',
    reason: '—',
    firstSeen: '1970-01-01T00:00:00.030Z',
    lastSeen: '1970-01-01T00:00:00.031Z',
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
      discoveryProfile('safe', { label: ATTACK }),
      discoveryProfile('compatible'),
      discoveryProfile('extreme'),
    ],
  });
  const options = sandbox.renderDynamicProfileOptions(capabilities, 'safe');
  const ruleRows = sandbox.renderDynamicRuleRows([{ type: 'exact', value: ATTACK }]);

  for (const html of [options, ruleRows]) {
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

test('edit modal refreshes observations and confirms before clearing them', async () => {
  const { sandbox, document, state } = loadModalHarness();
  const site = {
    id: 17,
    name: 'Media',
    target_url: 'https://origin.example',
    ingress_mode: 'port',
    listen_port: 8096,
    public_host: '',
    ua_mode: 'infuse',
    playback_target_url: '',
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
  await Promise.resolve();
  await Promise.resolve();

  const refresh = document.getElementById('m-refresh-dynamic-observations');
  const clear = document.getElementById('m-clear-dynamic-observations');
  const observations = document.getElementById('m-dynamic-observations');
  assert.equal(state.opened, 1);
  assert.deepEqual(state.observationGets, [17], 'opening an edit modal must perform the initial refresh');
  assert.match(observations.innerHTML, /https:\/\/media\.example:443/);
  assert.match(observations.innerHTML, /已丢弃观察记录：3/);

  await refresh.onclick();
  assert.deepEqual(state.observationGets, [17, 17]);
  assert.equal(state.confirmations.length, 0, 'refresh must not prompt for destructive confirmation');

  await clear.onclick();
  assert.deepEqual(state.observationDeletes, [], 'cancelled confirmation must not clear observations');
  assert.equal(state.confirmations.length, 1);
  assert.match(state.confirmations[0], /不可撤销/);

  state.confirmationResult = true;
  await clear.onclick();
  assert.deepEqual(state.observationDeletes, [17]);
  assert.deepEqual(state.successes, ['观察记录已清空']);
  assert.match(observations.innerHTML, /已丢弃观察记录：0/);
  assert.match(observations.innerHTML, /暂无观察记录/);
  assert.equal(refresh.disabled, false);
  assert.equal(clear.disabled, false);
  assert.deepEqual(state.errors, []);
});
