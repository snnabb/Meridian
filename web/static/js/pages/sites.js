// Sites management page
function renderSites() {
  const page = document.getElementById('page-sites');
  page.innerHTML = `
    <h1 class="section-title fade-up">站点管理</h1>
    <p class="section-sub fade-up stagger-1">管理 Emby 反代站点、入口与播放策略</p>
    <div class="page-toolbar fade-up stagger-1">
      <div class="toolbar-info" id="sites-count"></div>
      <button class="btn-add" id="btn-add-site">
        <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        添加站点
      </button>
    </div>
    <div class="sites-grid" id="sites-grid"></div>
  `;

  document.getElementById('btn-add-site').onclick = () => showSiteModal();
  loadSites();
}

async function loadSites() {
  try {
    const sites = await API.listSites();
    document.getElementById('sites-count').innerHTML = `共 <strong>${sites.length}</strong> 个站点`;

    const grid = document.getElementById('sites-grid');
    if (!sites || sites.length === 0) {
      grid.innerHTML = renderSitesEmptyState();
      return;
    }

	grid.innerHTML = sites.map((s, i) => {
      const pct = s.traffic_quota > 0 ? (s.traffic_used / s.traffic_quota * 100).toFixed(1) : 0;
      const pctClass = pct > 85 ? 'danger' : pct > 50 ? 'warn' : 'normal';
		const playbackRow = renderPlaybackRow(s);
		const upstreamHeaderCount = Array.isArray(s.upstream_headers) ? s.upstream_headers.length : 0;
		const ingressRows = renderIngressSummary(s);
		const discoveryRow = renderDynamicSiteSummary(s);

      return `
      <div class="site-card fade-up stagger-${Math.min(i + 1, 6)}">
        <div class="site-top">
          <div class="site-name">${esc(s.name)}</div>
          <span class="status-badge">
            <span class="status-led ${s.running ? 'on' : 'off'}"></span>
            ${s.running ? '运行中' : '已停止'}
          </span>
        </div>
        <div class="site-rows">
          <div class="site-row">
            <span class="site-row-label">主回源地址</span>
            <span class="mono">${esc(s.target_url)}</span>
          </div>
          ${playbackRow}
		  ${ingressRows}
		  ${discoveryRow}
		  ${upstreamHeaderCount > 0 ? `
		  <div class="site-row">
			<span class="site-row-label">上游请求头</span>
			<span class="site-row-value">${upstreamHeaderCount} 个（加密）</span>
		  </div>` : ''}
          <div class="site-row">
            <span class="site-row-label">UA 模式</span>
            <span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${esc(uaNameMap[s.ua_mode] || s.ua_mode)}</span>
          </div>
          ${s.traffic_quota > 0 ? `
          <div class="progress-wrap">
            <div class="progress-labels">
              <span>已用 ${formatBytes(s.traffic_used)}</span>
              <span>${formatBytes(s.traffic_quota)}</span>
            </div>
            <div class="progress-track">
              <div class="progress-fill ${pctClass}" style="width:${Math.min(pct, 100)}%"></div>
            </div>
          </div>
          ` : `
          <div class="site-row">
            <span class="site-row-label">已用流量</span>
            <span class="site-row-value">${formatBytes(s.traffic_used)}</span>
          </div>
          `}
        </div>
        <div class="site-actions">
          <button class="btn-ghost" data-site-action="toggle" data-site-id="${s.id}">${s.enabled ? '停用' : '启用'}</button>
          <button class="btn-ghost" data-site-action="edit" data-site-id="${s.id}">编辑</button>
          <button class="btn-ghost danger" data-site-action="delete" data-site-id="${s.id}">删除</button>
        </div>
      </div>`;
    }).join('');

    const sitesById = new Map(sites.map(site => [site.id, site]));
    grid.querySelectorAll('[data-site-action]').forEach(button => {
      button.addEventListener('click', () => {
        const id = Number(button.dataset.siteId);
        const site = sitesById.get(id);
        if (!site) return;
        if (button.dataset.siteAction === 'toggle') toggleSiteAction(id);
        if (button.dataset.siteAction === 'edit') showSiteModal(site);
        if (button.dataset.siteAction === 'delete') deleteSiteAction(id, site.name);
      });
    });
  } catch (e) {
    Toast.error('加载站点失败: ' + e.message);
  }
}

function renderPlaybackRow(site) {
  const playback = (site.playback_target_url || '').trim();
  const extraHosts = normalizeStreamHosts(site.stream_hosts);
  const totalHosts = (playback ? 1 : 0) + extraHosts.length;

  if (totalHosts === 0) {
    return `
      <div class="site-row">
        <span class="site-row-label">播放回源</span>
        <span class="site-row-value">跟随主回源</span>
      </div>
    `;
  }

  if (totalHosts === 1 && playback === (site.target_url || '').trim()) {
    return `
      <div class="site-row">
        <span class="site-row-label">播放回源</span>
        <span class="site-row-value">与主回源相同</span>
      </div>
    `;
  }

  const modeLabel = site.playback_mode === 'redirect' ? '重定向跟随' : '直连分流';
  let rows = '';
  if (playback) {
    rows += `
    <div class="site-row">
      <span class="site-row-label">播放回源</span>
      <span class="mono">${esc(playback)}</span>
    </div>`;
  }
  for (const h of extraHosts) {
    rows += `
    <div class="site-row">
      <span class="site-row-label">播放回源</span>
      <span class="mono">${esc(h)}</span>
    </div>`;
  }
  rows += `
    <div class="site-row">
      <span class="site-row-label">播放模式</span>
      <span class="site-row-value">${modeLabel}</span>
    </div>`;
  return rows;
}

function renderSitesEmptyState() {
	return '<div class="sites-empty" role="status"><strong>还没有站点</strong><span>选择“添加站点”连接第一个 Emby 回源。</span></div>';
}

function renderDynamicSiteSummary(site) {
	const policy = normalizeDynamicSitePolicy(site);
	const profile = DYNAMIC_PROFILE_LABELS[policy.dynamic_profile] || policy.dynamic_profile;
	return `
	  <div class="site-row">
		<span class="site-row-label">自动发现</span>
		<span class="site-row-value">${policy.dynamic_discovery_enabled ? '已启用' : '已关闭'} · ${esc(profile)}</span>
	  </div>`;
}

function buildProxyOptimizationPayload(pingCacheEnabled, imageCacheEnabled, progressCoalescingEnabled) {
	return {
		ping_cache_enabled: pingCacheEnabled === true,
		image_cache_enabled: imageCacheEnabled === true,
		progress_coalescing_enabled: progressCoalescingEnabled === true,
	};
}

function buildRequestLimitPayload(enabled, quotaGB, speedMbps) {
	const quota = parseInt(quotaGB, 10);
	const speed = parseInt(speedMbps, 10);
	return {
		traffic_quota: enabled === true && Number.isFinite(quota) && quota > 0 ? quota * 1073741824 : 0,
		speed_limit: enabled === true && Number.isFinite(speed) && speed > 0 ? speed : 0,
	};
}

function cycleSiteModalFocus(event, elements, activeElement) {
	if (!event || event.key !== 'Tab') return false;
	const focusable = Array.from(elements || []).filter(Boolean);
	if (focusable.length === 0) return false;
	const activeIndex = focusable.indexOf(activeElement);
	let target = null;
	if (event.shiftKey && activeIndex <= 0) target = focusable[focusable.length - 1];
	if (!event.shiftKey && (activeIndex === -1 || activeIndex === focusable.length - 1)) target = focusable[0];
	if (!target) return false;
	event.preventDefault();
	target.focus();
	return true;
}

function setupSiteModalFocus() {
	const modal = document.getElementById('modal');
	const initialFocus = document.getElementById('m-name');
	if (modal) {
		if (modal._siteModalFocusHandler && typeof modal.removeEventListener === 'function') {
			modal.removeEventListener('keydown', modal._siteModalFocusHandler);
		}
		modal._siteModalFocusHandler = event => {
			if (!document.getElementById('m-name')) return;
			const elements = Array.from(modal.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), summary, [href], [tabindex]:not([tabindex="-1"])'))
				.filter(element => !element.hidden && (typeof element.getClientRects !== 'function' || element.getClientRects().length > 0));
			cycleSiteModalFocus(event, elements, document.activeElement);
		};
		modal.addEventListener('keydown', modal._siteModalFocusHandler);
	}
	if (initialFocus) initialFocus.focus();
}

function customUAFormState(mode, site) {
  const isCustom = mode === 'custom';
  return {
    visible: isCustom,
    required: isCustom,
    customUserAgent: isCustom && site ? (site.custom_user_agent || '') : '',
    customClient: isCustom && site ? (site.custom_client || '') : '',
    customVersion: isCustom && site ? (site.custom_version || '') : '',
  };
}

function buildCustomUAPayload(mode, customUserAgent, customClient, customVersion) {
  if (mode !== 'custom') {
    return {
      custom_user_agent: '',
      custom_client: '',
      custom_version: '',
    };
  }
  return {
    custom_user_agent: String(customUserAgent || '').trim(),
    custom_client: String(customClient || '').trim(),
    custom_version: String(customVersion || '').trim(),
  };
}

function buildUpstreamHeaderPayload(headers) {
	return headers
		.filter(header => header.configured || String(header.name || '').trim() || String(header.value || '').trim())
		.map(header => ({
			name: String(header.name || '').trim(),
			value: String(header.value || '').trim(),
		}));
}

const DEFAULT_MAX_PLAYBACK_ADDRESSES = 128;

function normalizeStreamHosts(value) {
	let hosts = value;
	if (typeof hosts === 'string') {
		try {
			hosts = JSON.parse(hosts || '[]');
		} catch (_) {
			return [];
		}
	}
	if (!Array.isArray(hosts)) return [];
	return hosts
		.filter(host => typeof host === 'string' && host.trim())
		.map(host => host.trim());
}

function normalizeSiteCapabilities(value) {
	const capabilities = value && typeof value === 'object' ? value : {};
	const requestedMax = Number(capabilities.max_playback_addresses);
	return {
		host_only_available: capabilities.host_only_available !== false,
		upstream_headers_available: capabilities.upstream_headers_available !== false,
		max_playback_addresses: Number.isInteger(requestedMax) && requestedMax > 0
			? requestedMax
			: DEFAULT_MAX_PLAYBACK_ADDRESSES,
	};
}

const DYNAMIC_PROFILE_IDS = ['safe', 'compatible', 'extreme'];
const DYNAMIC_SOURCE_IDS = ['redirect', 'playback_info', 'hls', 'dash'];
const DYNAMIC_SOURCE_LABELS = {
	redirect: 'HTTP 30x',
	playback_info: 'PlaybackInfo',
	hls: 'HLS',
	dash: 'DASH',
};
const DYNAMIC_PROFILE_LABELS = {
	safe: 'Safe（安全）',
	compatible: 'Compatible（兼容）',
	extreme: 'Extreme（极限）',
};
const DYNAMIC_PROFILE_NETWORK_DEFAULTS = {
	safe: { allowed_schemes: ['https'], allowed_ports: [443], allow_any_port: false },
	compatible: { allowed_schemes: ['http', 'https'], allowed_ports: [], allow_any_port: true },
	extreme: { allowed_schemes: ['http', 'https'], allowed_ports: [], allow_any_port: true },
};
const DYNAMIC_LIMIT_FIELDS = [
	'allowed_schemes',
	'allowed_ports',
	'allow_any_port',
	'max_redirects',
	'max_authorities',
	'max_active_capabilities',
	'max_urls_per_response',
	'max_body_bytes',
	'max_dns_ips',
	'max_new_authorities_per_minute',
	'max_streams',
	'idle_expiry_seconds',
	'absolute_lifetime_seconds',
];
const DYNAMIC_GLOBAL_LIMIT_FIELDS = [
	'max_authorities',
	'max_active_capabilities',
	'max_streams',
	'max_new_authorities_per_minute',
	'max_dns_workers',
	'max_concurrent_parses',
	'max_site_concurrent_parses',
	'max_parse_memory_bytes',
	'max_site_parse_memory_bytes',
	'max_capability_memory_bytes',
	'max_site_capability_memory_bytes',
	'max_parse_depth',
	'max_string_bytes',
	'max_target_url_bytes',
];
const DYNAMIC_FEATURES = [
	['redirect_discovery', 'HTTP 30x 发现', true],
	['playback_info', 'PlaybackInfo 改写', true],
	['hls', 'HLS 解析', true],
	['dash', 'DASH 解析', true],
	['private_targets', '私网目标', false],
	['custom_ca', '自定义 CA', false],
	['raw_fallback', '原始响应回退', false],
];
const DYNAMIC_OBSERVATION_REASON_CODES = new Set([
	'redirect_allowed',
	'candidate_allowed',
	'invalid_location',
	'unsupported_status',
	'redirect_loop',
	'hop_limit',
	'scheme_denied',
	'port_denied',
	'domain_denied',
	'https_downgrade_denied',
	'self_target',
	'dns_failure',
	'address_denied',
	'dial_failure',
	'tls_failure',
	'capacity_limit',
	'rate_limit',
	'parse_failure',
	'request_unclassified',
	'structured_body_limit',
	'playback_info_denied',
	'hls_feature_denied',
	'dash_feature_denied',
	'redirect_body_replay_denied',
	'capability_invalid',
	'capability_expired',
	'response_failure',
	'runtime_unavailable',
]);

function hasOwnDynamicField(value, field) {
	return Object.prototype.hasOwnProperty.call(value, field);
}

function dynamicSourceListMatchesProfile(profile) {
	if (!profile || !Array.isArray(profile.discovery_sources)) return false;
	const expected = ['redirect', 'playback_info'];
	if (profile.features && profile.features.hls === true) expected.push('hls');
	if (profile.features && profile.features.dash === true) expected.push('dash');
	return profile.discovery_sources.length === expected.length
		&& profile.discovery_sources.every((source, index) => source === expected[index]);
}

function isDynamicDefaultPolicy(value, profiles) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	if (typeof value.dynamic_discovery_enabled !== 'boolean') return false;
	if (!DYNAMIC_PROFILE_IDS.includes(value.dynamic_profile)) return false;
	if (typeof value.dynamic_allow_https_downgrade !== 'boolean') return false;
	if (!Array.isArray(value.dynamic_domain_rules) || !Array.isArray(value.dynamic_discovery_sources)) return false;
	const normalizedRules = normalizeDynamicDomainRules(value.dynamic_domain_rules);
	if (normalizedRules.length !== value.dynamic_domain_rules.length) return false;
	if (normalizedRules.some((rule, index) => rule.type !== value.dynamic_domain_rules[index].type || rule.value !== value.dynamic_domain_rules[index].value)) return false;
	const profile = profiles.get(value.dynamic_profile);
	return !!profile
		&& value.dynamic_discovery_sources.length === profile.discovery_sources.length
		&& value.dynamic_discovery_sources.every((source, index) => source === profile.discovery_sources[index]);
}

function isStructuredDiscoveryContract(value) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	if (value.stage !== 'structured-discovery' || typeof value.available !== 'boolean' || typeof value.key_configured !== 'boolean') return false;
	if (value.available !== value.key_configured || value.empty_rules_semantics !== 'public_dns_https_443') return false;
	if (!value.global_limits || typeof value.global_limits !== 'object' || Array.isArray(value.global_limits)) return false;
	if (!DYNAMIC_GLOBAL_LIMIT_FIELDS.every(field => hasOwnDynamicField(value.global_limits, field) && Number.isInteger(value.global_limits[field]) && value.global_limits[field] > 0)) return false;
	if (!Array.isArray(value.profiles) || value.profiles.length !== DYNAMIC_PROFILE_IDS.length) return false;

	const profiles = new Map(value.profiles.map(profile => [profile && profile.id, profile]));
	if (profiles.size !== DYNAMIC_PROFILE_IDS.length) return false;
	const profilesValid = DYNAMIC_PROFILE_IDS.every(id => {
		const profile = profiles.get(id);
		if (!profile || typeof profile.label !== 'string' || typeof profile.recommended !== 'boolean') return false;
		if (!profile.limits || typeof profile.limits !== 'object' || Array.isArray(profile.limits)) return false;
		if (!DYNAMIC_LIMIT_FIELDS.every(field => hasOwnDynamicField(profile.limits, field))) return false;
		if (!Array.isArray(profile.limits.allowed_schemes) || profile.limits.allowed_schemes.length === 0 || !profile.limits.allowed_schemes.every(scheme => scheme === 'http' || scheme === 'https')) return false;
		if (!Array.isArray(profile.limits.allowed_ports) || !profile.limits.allowed_ports.every(port => Number.isInteger(port) && port > 0 && port <= 65535)) return false;
		if (typeof profile.limits.allow_any_port !== 'boolean') return false;
		if (!DYNAMIC_LIMIT_FIELDS.slice(3).every(field => Number.isInteger(profile.limits[field]) && profile.limits[field] > 0)) return false;
		if (!profile.features || typeof profile.features !== 'object' || Array.isArray(profile.features)) return false;
		const featuresValid = DYNAMIC_FEATURES.every(([field, , expected]) => {
			const profileExpected = id === 'safe' && (field === 'hls' || field === 'dash') ? false : expected;
			return hasOwnDynamicField(profile.features, field) && profile.features[field] === profileExpected;
		});
		return featuresValid && dynamicSourceListMatchesProfile(profile);
	});
	return profilesValid && isDynamicDefaultPolicy(value.default_policy, profiles);
}

function normalizeDynamicProfiles(value) {
	const recognized = isStructuredDiscoveryContract(value);
	const sourceProfiles = recognized
		? new Map(value.profiles.map(profile => [profile.id, profile]))
		: new Map();
	return {
		stage: 'structured-discovery',
		available: recognized && value.available === true,
		key_configured: recognized && value.key_configured === true,
		empty_rules_semantics: recognized ? value.empty_rules_semantics : '',
		default_policy: recognized ? {
			...value.default_policy,
			dynamic_discovery_sources: [...value.default_policy.dynamic_discovery_sources],
			dynamic_domain_rules: value.default_policy.dynamic_domain_rules.map(rule => ({ ...rule })),
		} : {
			dynamic_discovery_enabled: false,
			dynamic_profile: 'safe',
			dynamic_discovery_sources: [],
			dynamic_domain_rules: [],
			dynamic_allow_https_downgrade: false,
		},
		recognized,
		profiles: DYNAMIC_PROFILE_IDS.map(id => {
			const profile = sourceProfiles.get(id);
			return {
				id,
				label: profile ? profile.label : DYNAMIC_PROFILE_LABELS[id],
				recommended: profile ? profile.recommended : id === 'safe',
				limits: profile ? profile.limits : DYNAMIC_PROFILE_NETWORK_DEFAULTS[id],
				features: profile ? profile.features : {},
				discovery_sources: profile ? [...profile.discovery_sources] : [],
			};
		}),
		global_limits: recognized ? value.global_limits : {},
	};
}

async function loadDynamicProfiles() {
	try {
		return normalizeDynamicProfiles(await API.getDynamicProfiles());
	} catch (_) {
		return normalizeDynamicProfiles(null);
	}
}

function normalizeDynamicProfile(value) {
	const profile = String(value || '').trim().toLowerCase();
	return DYNAMIC_PROFILE_IDS.includes(profile) ? profile : 'safe';
}

function dynamicSourcesForProfile(capabilities, value) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const profile = dynamicCapabilities.profiles.find(candidate => candidate.id === normalizeDynamicProfile(value));
	return profile ? [...profile.discovery_sources] : [];
}

function dynamicSourcesForPlaybackInfoInspection(capabilities, profile, enabled) {
	const sources = dynamicSourcesForProfile(capabilities, profile);
	return enabled === false ? sources.filter(source => source !== 'playback_info') : sources;
}

function defaultDynamicSitePolicy(capabilities) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const policy = normalizeDynamicSitePolicy(dynamicCapabilities.default_policy);
	if (!dynamicCapabilities.recognized || !dynamicCapabilities.available || !policy.dynamic_discovery_enabled || policy.dynamic_profile !== 'safe') {
		return normalizeDynamicSitePolicy(null);
	}
	return policy;
}

function normalizeDynamicDomainRules(value) {
	if (!Array.isArray(value)) return [];
	return value.flatMap(rule => {
		if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return [];
		const type = String(rule.type || '').trim().toLowerCase();
		const host = String(rule.value || '').trim().toLowerCase();
		if ((type !== 'exact' && type !== 'suffix') || !host) return [];
		return [{ type, value: host }];
	});
}

function isPlausibleSafeDynamicDNSRule(rule) {
	const normalized = normalizeDynamicDomainRules([rule])[0];
	if (!normalized) return false;
	let host = normalized.value;
	if (host.startsWith('.') || host.includes('*') || /[\s/\\@?#:%]/.test(host)) return false;
	host = host.replace(/\.$/, '');
	if (!host) return false;
	let asciiHost;
	try {
		asciiHost = new URL(`https://${host}/`).hostname.toLowerCase();
	} catch (_) {
		return false;
	}
	if (!asciiHost || asciiHost.startsWith('[') || /^\d+(?:\.\d+){3}$/.test(asciiHost)) return false;
	const labels = asciiHost.split('.');
	if (labels.length < 2 || !/[a-z]/.test(labels[labels.length - 1])) return false;
	return labels.every(label => label.length > 0 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-') && /^[a-z0-9-]+$/.test(label));
}

function dynamicDomainRuleWarning(profile, rules) {
	const normalized = normalizeDynamicDomainRules(rules);
	if (normalized.some(rule => !isPlausibleSafeDynamicDNSRule(rule))) {
		return {
			tone: 'warning',
			message: '域名规则仅接受 DNS 主机名；不要填写 IP、通配符、协议、端口或路径。',
		};
	}
	if (normalizeDynamicProfile(profile) === 'safe' && normalized.length === 0) {
		return {
			tone: 'info',
			message: 'Safe 未设置规则时允许任意公网 DNS 主机名的 HTTPS:443；IP 字面量始终拒绝。添加规则会收窄为精确与后缀规则的并集。',
		};
	}
	return { tone: '', message: '' };
}

function safeRulesBecomeUnrestricted(enabled, profile, beforeRules, afterRules) {
	if (enabled !== true || normalizeDynamicProfile(profile) !== 'safe') return false;
	const beforeRestricted = normalizeDynamicDomainRules(beforeRules).some(isPlausibleSafeDynamicDNSRule);
	const afterRestricted = normalizeDynamicDomainRules(afterRules).some(isPlausibleSafeDynamicDNSRule);
	return beforeRestricted && !afterRestricted;
}

function renderDynamicDomainWarning(profile, rules) {
	const warning = dynamicDomainRuleWarning(profile, rules);
	const toneClass = warning.tone ? ` form-warning-${warning.tone}` : '';
	return `<div class="form-warning${toneClass}" id="m-dynamic-domain-warning" role="status" aria-live="polite" ${warning.message ? '' : 'hidden'}>${esc(warning.message)}</div>`;
}

function dynamicDowngradeFormState(profile, enabled) {
	const visible = normalizeDynamicProfile(profile) !== 'safe';
	return {
		visible,
		checked: visible && enabled === true,
		open: visible && enabled === true,
	};
}

function normalizeDynamicSitePolicy(site) {
	const value = site && typeof site === 'object' ? site : {};
	const profile = normalizeDynamicProfile(value.dynamic_profile);
	const playbackInfoEnabled = typeof value.dynamic_playback_info_enabled === 'boolean'
		? value.dynamic_playback_info_enabled
		: !Array.isArray(value.dynamic_discovery_sources) || value.dynamic_discovery_sources.includes('playback_info');
	return {
		dynamic_discovery_enabled: value.dynamic_discovery_enabled === true,
		dynamic_profile: profile,
		dynamic_playback_info_enabled: playbackInfoEnabled,
		dynamic_domain_rules: normalizeDynamicDomainRules(value.dynamic_domain_rules),
		dynamic_allow_https_downgrade: profile !== 'safe' && value.dynamic_allow_https_downgrade === true,
	};
}

function buildDynamicPolicyPayload(policy, capabilities, forCreate) {
	const normalized = normalizeDynamicSitePolicy(policy);
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	if (!dynamicCapabilities.recognized) return forCreate ? { dynamic_discovery_enabled: false } : {};
	return {
		dynamic_discovery_enabled: normalized.dynamic_discovery_enabled,
		dynamic_profile: normalized.dynamic_profile,
		dynamic_discovery_sources: dynamicSourcesForPlaybackInfoInspection(
			dynamicCapabilities,
			normalized.dynamic_profile,
			normalized.dynamic_playback_info_enabled,
		),
		dynamic_domain_rules: normalized.dynamic_domain_rules,
		dynamic_allow_https_downgrade: normalized.dynamic_allow_https_downgrade,
	};
}

function renderDynamicProfileOptions(capabilities, selectedProfile) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const selected = normalizeDynamicProfile(selectedProfile);
	return dynamicCapabilities.profiles.map(profile => `
		<option value="${esc(profile.id)}" ${profile.id === selected ? 'selected' : ''}>${esc(profile.label)}${profile.recommended ? '（推荐）' : ''}</option>
	`).join('');
}


function renderDynamicRuleRows(rules) {
	const rows = Array.isArray(rules) ? rules : [];
	return rows.map((rule, index) => {
		const type = rule && rule.type === 'suffix' ? 'suffix' : 'exact';
		const value = rule && rule.value !== undefined ? rule.value : '';
		return `
		<fieldset class="form-list-row dynamic-rule-row m-dynamic-rule-row" data-idx="${index}">
		  <legend class="sr-only">域名规则 ${index + 1}</legend>
		  <label class="sr-only" for="m-dynamic-rule-type-${index}">规则类型</label>
		  <select class="form-select modal-select m-dynamic-rule-type" id="m-dynamic-rule-type-${index}" data-idx="${index}">
			<option value="exact" ${type === 'exact' ? 'selected' : ''}>精确</option>
			<option value="suffix" ${type === 'suffix' ? 'selected' : ''}>后缀</option>
		  </select>
		  <label class="sr-only" for="m-dynamic-rule-value-${index}">域名</label>
		  <input type="text" class="form-input m-dynamic-rule-value" id="m-dynamic-rule-value-${index}" data-idx="${index}" value="${esc(value)}" placeholder="media.example.com" maxlength="253" autocapitalize="none" autocorrect="off" spellcheck="false">
		  <button type="button" class="btn-ghost danger form-row-action m-dynamic-rule-remove" data-idx="${index}" aria-label="删除域名规则 ${index + 1}">删除</button>
		</fieldset>`;
	}).join('');
}

function renderDynamicStatus(capabilities) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	if (!dynamicCapabilities.recognized) {
		return '<div class="form-warning" role="alert">无法读取兼容的发现策略目录；新站点将保持关闭，编辑时不会覆盖已存策略。</div>';
	}
	if (!dynamicCapabilities.available) {
		return '<div class="form-warning" role="alert">DYNAMIC_ROUTE_KEY 未配置，无法为新站点启用自动发现；已有策略仍会保留。</div>';
	}
	return '';
}

function dynamicProfileRiskNotice(profile, capabilities, playbackInfoEnabled = true) {
	const normalized = normalizeDynamicProfile(profile);
	const sources = dynamicSourcesForPlaybackInfoInspection(capabilities, normalized, playbackInfoEnabled)
		.map(source => DYNAMIC_SOURCE_LABELS[source] || source)
		.join('、');
	const sourceText = sources ? `${sources}；` : '';
	switch (normalized) {
	case 'compatible':
		return {
			level: 'compatible',
			badge: '需确认',
			message: `${sourceText}可访问任意公网域名和端口，启用时需要确认。`,
		};
	case 'extreme':
		return {
			level: 'extreme',
			badge: '高风险',
			message: `${sourceText}扩大公网发现与协议兼容，并可能重放有界请求体。`,
		};
	default:
		return {
			level: 'safe',
			badge: '推荐',
			message: `${sourceText}仅允许公网 HTTPS:443，拒绝 IP 字面量。`,
		};
	}
}

function renderDynamicProfileRisk(profile, capabilities, playbackInfoEnabled = true) {
	const notice = dynamicProfileRiskNotice(profile, capabilities, playbackInfoEnabled);
	return `<div class="profile-risk profile-risk-${esc(notice.level)}" data-profile-risk="${esc(notice.level)}"><span class="profile-risk-badge" data-profile-risk-badge="${esc(notice.level)}">${esc(notice.badge)}</span><span>${esc(notice.message)}</span></div>`;
}

function dynamicProfileConfirmationRequirement(initialPolicy, nextPolicy) {
	const initial = normalizeDynamicSitePolicy(initialPolicy);
	const next = normalizeDynamicSitePolicy(nextPolicy);
	if (!next.dynamic_discovery_enabled) return 'none';
	if (next.dynamic_profile === 'extreme' && (!initial.dynamic_discovery_enabled || initial.dynamic_profile !== 'extreme')) return 'extreme';
	if (next.dynamic_profile === 'compatible' && (!initial.dynamic_discovery_enabled || initial.dynamic_profile === 'safe')) return 'compatible';
	return 'none';
}

function confirmDynamicProfileChange(initialPolicy, nextPolicy, siteName, extremeAcknowledged, extremeTypedName) {
	const requirement = dynamicProfileConfirmationRequirement(initialPolicy, nextPolicy);
	if (requirement === 'compatible') {
		const accepted = window.confirm('Compatible（兼容）可访问任意公网域名和 1–65535 端口。仍会拒绝私网、特殊地址和未验证拨号。确定启用吗？');
		return { ok: accepted, requirement, error: '' };
	}
	if (requirement === 'extreme') {
		if (!extremeAcknowledged) return { ok: false, requirement, error: '启用 Extreme 前必须勾选高风险确认' };
		if (String(extremeTypedName || '').trim() !== String(siteName || '').trim()) return { ok: false, requirement, error: '启用 Extreme 时必须准确输入站点名称' };
		const accepted = window.confirm('Extreme（极限）会启用全数据面 30x/303、受限请求体重放和更宽的 PlaybackInfo/HLS/DASH 兼容，并显著放大公网发现与并发上限。请求体可能被重放到上游指定且通过安全校验的公网目标；仍不启用私网、自定义 CA、原始地址回退或未签名 target。确定继续吗？');
		return { ok: accepted, requirement, error: '' };
	}
	return { ok: true, requirement, error: '' };
}

function renderDynamicEnableControl(capabilities, policy) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const dynamicPolicy = normalizeDynamicSitePolicy(policy);
	const enableEditable = dynamicCapabilities.recognized && (dynamicCapabilities.available || dynamicPolicy.dynamic_discovery_enabled);
	return `
		<label class="form-check form-check-compact" for="m-dynamic-enabled">
		  <input type="checkbox" id="m-dynamic-enabled" ${dynamicPolicy.dynamic_discovery_enabled ? 'checked' : ''} ${enableEditable ? '' : 'disabled'}>
		  <span>启用自动播放后端发现</span>
		</label>
	`;
}

function privacySafeObservationAuthority(value) {
	if (typeof value !== 'string') return '—';
	const match = /^(https?):\/\/(\[[0-9a-f:.]+\]|[a-z0-9.-]+):([0-9]{1,5})$/i.exec(value.trim());
	if (!match) return '—';
	const port = Number(match[3]);
	if (!Number.isInteger(port) || port < 1 || port > 65535) return '—';
	const host = match[2].toLowerCase();
	if (!host.startsWith('[')) {
		const labels = host.split('.');
		if (!labels.every(label => label.length > 0 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-') && /^[a-z0-9-]+$/.test(label))) return '—';
	}
	try {
		new URL(`${match[1].toLowerCase()}://${host}:${port}/`);
	} catch (_) {
		return '—';
	}
	return `${match[1].toLowerCase()}://${host}:${port}`;
}

function privacySafeObservationReason(value) {
	return typeof value === 'string' && DYNAMIC_OBSERVATION_REASON_CODES.has(value) ? value : '—';
}

function formatObservationTimestamp(value) {
	if (!Number.isSafeInteger(value) || value < 0) return '—';
	const timestamp = new Date(value);
	return Number.isNaN(timestamp.getTime()) ? '—' : timestamp.toISOString();
}

function normalizeDynamicObservationsResponse(value) {
	const response = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
	const observations = Array.isArray(response.observations) ? response.observations : [];
	return {
		observations: observations.map(observation => {
			const item = observation && typeof observation === 'object' && !Array.isArray(observation) ? observation : {};
			return {
				authority: privacySafeObservationAuthority(item.canonical_authority),
				source: DYNAMIC_SOURCE_IDS.includes(item.source) ? item.source : '—',
				decision: item.decision === 'allowed' || item.decision === 'denied' ? item.decision : '—',
				reason: privacySafeObservationReason(item.reason_code),
				firstSeen: formatObservationTimestamp(item.first_seen_ms),
				lastSeen: formatObservationTimestamp(item.last_seen_ms),
				count: Number.isSafeInteger(item.count) && item.count > 0 ? item.count : '—',
			};
		}),
		dropped: Number.isSafeInteger(response.dropped_observations) && response.dropped_observations >= 0
			? response.dropped_observations
			: '—',
	};
}

function renderDynamicObservations(value) {
	const response = normalizeDynamicObservationsResponse(value);
	const rows = response.observations.map(observation => `
		<tr>
		  <td>${esc(observation.authority)}</td>
		  <td>${esc(observation.source)}</td>
		  <td>${esc(observation.decision)}</td>
		  <td>${esc(observation.reason)}</td>
		  <td>${esc(observation.firstSeen)}</td>
		  <td>${esc(observation.lastSeen)}</td>
		  <td>${esc(observation.count)}</td>
		</tr>
	`).join('');
	return `
		<div class="form-help">已丢弃观察记录：${esc(response.dropped)}</div>
		${rows ? `
		<div style="overflow-x:auto;margin-top:8px">
		  <table>
			<thead><tr><th>规范化权威</th><th>来源</th><th>决策</th><th>原因代码</th><th>首次观察</th><th>最近观察</th><th>次数</th></tr></thead>
			<tbody>${rows}</tbody>
		  </table>
		</div>` : '<div class="form-help" style="margin-top:8px">暂无观察记录。</div>'}
	`;
}

function renderDynamicObservationsPanel(supported) {
	return `
		<details class="site-disclosure" id="m-dynamic-observations-disclosure">
		  <summary>自动发现观察记录</summary>
		  <div class="site-disclosure-body">
			<div class="form-help">仅显示规范化权威、有限原因代码和聚合时间/次数；不显示完整 URL、路径、查询参数、令牌、请求头或正文。</div>
			<div class="form-inline-actions">
			  <button type="button" class="btn-ghost" id="m-refresh-dynamic-observations" ${supported ? '' : 'disabled'}>刷新</button>
			  <button type="button" class="btn-ghost danger" id="m-clear-dynamic-observations" ${supported ? '' : 'disabled'}>清空</button>
			</div>
			<div id="m-dynamic-observations">${supported ? '<div class="form-help">正在读取观察记录…</div>' : '<div class="form-help">当前后端不提供自动发现观察记录。</div>'}</div>
		  </div>
		</details>
	`;
}

function canAddPlaybackAddress(currentCount, maxPlaybackAddresses) {
	return currentCount < maxPlaybackAddresses;
}

function renderUpstreamHeaderRows(headers, upstreamHeadersAvailable) {
	return headers.map((header, idx) => `
		<fieldset class="form-list-row upstream-header-row">
		  <legend class="sr-only">上游请求头 ${idx + 1}</legend>
		  <label class="sr-only" for="m-upstream-header-name-${idx}">请求头名称</label>
		  <input type="text" class="form-input m-upstream-header-name" id="m-upstream-header-name-${idx}" data-idx="${idx}" value="${esc(header.name)}" placeholder="Header 名称" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false" ${upstreamHeadersAvailable ? '' : 'disabled'}>
		  <label class="sr-only" for="m-upstream-header-value-${idx}">请求头值</label>
		  <input type="password" class="form-input m-upstream-header-value" id="m-upstream-header-value-${idx}" data-idx="${idx}" value="" placeholder="${header.configured ? '已配置；留空保持不变' : 'Header 值'}" maxlength="1024" autocomplete="new-password" ${upstreamHeadersAvailable ? '' : 'disabled'}>
		  <button type="button" class="btn-ghost danger form-row-action m-upstream-header-remove" data-idx="${idx}" aria-label="删除上游请求头 ${idx + 1}">删除</button>
		</fieldset>
	`).join('');
}

function normalizedIngressMode(site) {
	const mode = String((site && site.ingress_mode) || '').trim().toLowerCase();
	if (mode === 'port' || mode === 'host' || mode === 'both') return mode;
	return site && String(site.public_host || '').trim() ? 'host' : 'port';
}

function ingressFormState(mode) {
	const normalized = ['port', 'host', 'both'].includes(mode) ? mode : 'host';
	return {
		mode: normalized,
		showPublicHost: normalized !== 'port',
		requirePublicHost: normalized !== 'port',
		portLabel: normalized === 'host' ? '保留端口（此模式不监听）' : '监听端口',
		warning: normalized === 'both'
			? '此模式会同时开放独立高端口；若前方使用 CDN，请用防火墙限制该端口，避免绕过 CDN。'
			: normalized === 'port'
				? '独立端口会绑定所有网络接口；公网部署时请配置防火墙。'
				: '仅通过共享 Host 入口代理，不会绑定保留端口；要求面板绑定回环地址，或用 TRUSTED_PROXY_CIDRS 限定可信入口来源。',
	};
}

function buildIngressPayload(mode, port, publicHost) {
	const state = ingressFormState(mode);
	return {
		ingress_mode: state.mode,
		listen_port: parseInt(port),
		public_host: state.showPublicHost ? String(publicHost || '').trim() : '',
	};
}

function defaultIngressMode() {
	return 'port';
}

function renderIngressSummary(site) {
	const mode = normalizedIngressMode(site);
	const labels = { port: '仅独立端口', host: '仅共享域名', both: '共享域名 + 独立端口' };
	let rows = `
	  <div class="site-row">
		<span class="site-row-label">入口模式</span>
		<span class="site-row-value">${labels[mode]}</span>
	  </div>`;
	if (mode === 'port' || mode === 'both') {
		rows += `
	  <div class="site-row">
		<span class="site-row-label">监听端口</span>
		<span class="mono">:${site.listen_port}</span>
	  </div>`;
	}
	if (mode === 'host' || mode === 'both') {
		rows += `
	  <div class="site-row">
		<span class="site-row-label">共享入口</span>
		<span class="mono">Host: ${esc(site.public_host || '')}</span>
	  </div>`;
	}
	return rows;
}

function normalizedTargetAuthority(value) {
	let candidate = String(value || '').trim().replaceAll('：', ':');
	if (!candidate) return '';
	if (!candidate.includes('://')) {
		const authority = candidate.split(/[/?#]/, 1)[0];
		candidate = authority.endsWith(':443') ? `https://${candidate}` : `http://${candidate}`;
	}
	try {
		const parsed = new URL(candidate);
		const scheme = parsed.protocol.toLowerCase();
		if (scheme !== 'http:' && scheme !== 'https:') return '';
		const defaultPort = scheme === 'https:' ? '443' : '80';
		return `${scheme}//${parsed.hostname.toLowerCase()}:${parsed.port || defaultPort}`;
	} catch (_) {
		return '';
	}
}

async function showSiteModal(site) {
  const isEdit = !!site;
  const title = isEdit ? '编辑站点' : '添加站点';
	let siteCapabilities;
	try {
		siteCapabilities = normalizeSiteCapabilities(await API.ingressCapabilities());
	} catch (error) {
		Toast.error(`无法读取站点能力：${error.message}`);
		return;
	}
	const hostOnlyAvailable = siteCapabilities.host_only_available;
	const upstreamHeadersAvailable = siteCapabilities.upstream_headers_available;
	const maxPlaybackAddresses = siteCapabilities.max_playback_addresses;
	const dynamicCapabilities = await loadDynamicProfiles();
	const dynamicPolicy = isEdit
		? normalizeDynamicSitePolicy(site)
		: defaultDynamicSitePolicy(dynamicCapabilities);
	const dynamicPolicyEditable = dynamicCapabilities.recognized && dynamicCapabilities.available;
	const dynamicDowngradeState = dynamicDowngradeFormState(dynamicPolicy.dynamic_profile, dynamicPolicy.dynamic_allow_https_downgrade);
	const optimizationState = buildProxyOptimizationPayload(
		isEdit && site.ping_cache_enabled === true,
		isEdit && site.image_cache_enabled === true,
		isEdit && site.progress_coalescing_enabled === true,
	);
	const hasPlaybackConfiguration = isEdit && (
		String(site.playback_target_url || '').trim()
		|| normalizeStreamHosts(site.stream_hosts).length > 0
		|| site.playback_mode === 'redirect'
		|| site.ua_mode === 'custom'
		|| site.ua_mode === 'passthrough'
	);
	const hasUpstreamHeaders = isEdit && Array.isArray(site.upstream_headers) && site.upstream_headers.length > 0;
	const hasRequestLimits = isEdit && ((site.traffic_quota || 0) > 0 || (site.speed_limit || 0) > 0);

  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = `
    <div class="site-form" id="site-form">
      <fieldset class="site-form-section" data-site-group="basic">
        <legend>基本信息</legend>
        <div class="form-group">
          <label for="m-name">站点名称</label>
          <input type="text" class="form-input" id="m-name" value="${isEdit ? esc(site.name) : ''}" placeholder="如：Emby-US-01" maxlength="100" required>
        </div>
        <div class="form-group">
          <label for="m-target">主回源地址</label>
          <input type="text" class="form-input" id="m-target" value="${isEdit ? esc(site.target_url) : ''}" placeholder="如：192.168.1.10:8096" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048" required>
        </div>
      </fieldset>

      <fieldset class="site-form-section" data-site-group="access">
        <legend>访问入口</legend>
        <div class="form-group">
          <label for="m-ingress-mode">入口模式</label>
          <select class="form-select modal-select" id="m-ingress-mode">
            <option value="port">仅独立端口</option>
            <option value="host" ${hostOnlyAvailable ? '' : 'disabled'}>仅共享域名${hostOnlyAvailable ? '' : '（当前部署不可用）'}</option>
            <option value="both">共享域名 + 独立端口（高风险）</option>
          </select>
          <div class="form-warning form-warning-info" id="m-ingress-warning" role="status"></div>
          ${hostOnlyAvailable ? '' : '<div class="form-warning" role="alert">请先设置 PANEL_BIND_ADDR 或 TRUSTED_PROXY_CIDRS 并重启，才能使用共享域名入口。</div>'}
        </div>
        <div class="form-group" id="m-port-group">
          <label for="m-port" id="m-port-label">监听端口</label>
          <input type="number" class="form-input" id="m-port" value="${isEdit ? site.listen_port : ''}" placeholder="如：8001" min="1" max="65535" inputmode="numeric" required>
        </div>
        <div class="form-group" id="m-public-host-group">
          <label for="m-public-host">共享入口域名</label>
          <input type="text" class="form-input" id="m-public-host" value="${isEdit ? esc(site.public_host || '') : ''}" placeholder="如：emby.example.com" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="253">
        </div>
        <details class="site-disclosure" id="m-access-advanced" ${hasUpstreamHeaders || !upstreamHeadersAvailable ? 'open' : ''}>
          <summary>固定上游请求头</summary>
          <div class="site-disclosure-body">
            <div id="m-upstream-headers"></div>
            <button type="button" class="btn-ghost form-add-action" id="m-add-upstream-header" ${upstreamHeadersAvailable ? '' : 'disabled'}>+ 添加请求头</button>
            <div class="form-help">值不会回显；留空保留已有值。更换主回源时需重新输入。</div>
            ${upstreamHeadersAvailable ? '' : '<div class="form-warning" role="alert">UPSTREAM_HEADER_KEY 未配置：名称和值不可编辑，但仍可删除旧请求头。</div>'}
          </div>
        </details>
      </fieldset>

      <fieldset class="site-form-section" data-site-group="playback">
        <legend>播放</legend>
        <div class="form-group">
          <div class="form-label">自动播放后端发现</div>
          ${renderDynamicStatus(dynamicCapabilities)}
          ${renderDynamicEnableControl(dynamicCapabilities, dynamicPolicy)}
          <fieldset class="dynamic-policy-fields" id="m-dynamic-policy-fields" ${dynamicPolicyEditable ? '' : 'disabled'}>
            <legend class="sr-only">自动发现策略</legend>
            <label for="m-dynamic-profile">安全配置</label>
            <select class="form-select modal-select" id="m-dynamic-profile">
              ${renderDynamicProfileOptions(dynamicCapabilities, dynamicPolicy.dynamic_profile)}
            </select>
            <div id="m-dynamic-profile-risk">${renderDynamicProfileRisk(dynamicPolicy.dynamic_profile, dynamicCapabilities, dynamicPolicy.dynamic_playback_info_enabled)}</div>
            <div class="form-toggle-list">
              <label class="form-check form-check-panel" for="m-dynamic-playback-info">
                <input type="checkbox" id="m-dynamic-playback-info" ${dynamicPolicy.dynamic_playback_info_enabled ? 'checked' : ''}>
                <span><strong>解析 PlaybackInfo</strong><small>关闭后，PlaybackInfo 正文不再解析或改写；HTTP 30x 后端发现仍保持启用，动态跟随后的最终响应仍执行 Header 清洗。PlaybackInfo 中的外部 URL 不再封装为受控能力链接，可能直接交给客户端。</small></span>
              </label>
            </div>
            <div class="form-warning form-warning-danger extreme-confirmation" id="m-dynamic-extreme-confirm" hidden>
              <label class="form-check" for="m-dynamic-extreme-ack">
                <input type="checkbox" id="m-dynamic-extreme-ack">
                <span>我理解 Extreme 会扩大公网发现与协议兼容，并可能重放有界请求体。</span>
              </label>
              <label class="sr-only" for="m-dynamic-extreme-name">输入站点名称以确认 Extreme</label>
              <input type="text" class="form-input" id="m-dynamic-extreme-name" placeholder="输入站点名称以确认" maxlength="100" autocomplete="off">
            </div>
            ${renderDynamicDomainWarning(dynamicPolicy.dynamic_profile, dynamicPolicy.dynamic_domain_rules)}
            <details class="site-disclosure" id="m-dynamic-rules-disclosure" ${dynamicPolicy.dynamic_domain_rules.length > 0 || dynamicPolicy.dynamic_profile !== 'safe' ? 'open' : ''}>
              <summary>域名范围</summary>
              <div class="site-disclosure-body">
                <div id="m-dynamic-rules"></div>
                <button type="button" class="btn-ghost form-add-action" id="m-add-dynamic-rule">+ 添加域名规则</button>
                <div class="form-help">精确与后缀规则可同时使用；后缀规则包含该域名及其子域名。</div>
                <details class="site-disclosure nested-disclosure" id="m-dynamic-advanced" ${dynamicDowngradeState.visible ? '' : 'hidden'} ${dynamicDowngradeState.open ? 'open' : ''}>
                  <summary>高级兼容设置</summary>
                  <div class="site-disclosure-body">
                    <label class="form-check" for="m-dynamic-downgrade">
                      <input type="checkbox" id="m-dynamic-downgrade" ${dynamicDowngradeState.checked ? 'checked' : ''}>
                      <span>允许动态目标从 HTTPS 降级到 HTTP</span>
                    </label>
                    <div class="form-warning">仅在确有 HTTP 播放后端时启用；目标仍须通过服务器安全策略。</div>
                  </div>
                </details>
              </div>
            </details>
          </fieldset>
          ${isEdit ? renderDynamicObservationsPanel(dynamicCapabilities.recognized) : ''}
        </div>

        <details class="site-disclosure" id="m-playback-advanced" ${hasPlaybackConfiguration ? 'open' : ''}>
          <summary>手动播放回源与客户端身份</summary>
          <div class="site-disclosure-body">
            <div class="form-group">
              <div class="form-label">播放回源（可选）</div>
              <div id="m-playback-list"></div>
              <button type="button" class="btn-ghost form-add-action" id="m-add-playback">+ 添加播放回源</button>
              <div class="form-help">首个地址用于播放，其余地址仅作为重定向允许列表（最多 ${maxPlaybackAddresses} 个）。</div>
            </div>
            <div class="form-group" id="playback-mode-group" hidden>
              <label for="m-playback-mode">播放模式</label>
              <select class="form-select modal-select" id="m-playback-mode">
                <option value="direct" ${(!isEdit || site.playback_mode !== 'redirect') ? 'selected' : ''}>直连分流</option>
                <option value="redirect" ${isEdit && site.playback_mode === 'redirect' ? 'selected' : ''}>重定向跟随</option>
              </select>
            </div>
            <div class="form-group">
              <label for="m-ua">UA 模式</label>
              <select class="form-select modal-select" id="m-ua">
                <option value="infuse" ${(!isEdit || site.ua_mode === 'infuse') ? 'selected' : ''}>Infuse</option>
                <option value="web" ${isEdit && site.ua_mode === 'web' ? 'selected' : ''}>Web</option>
                <option value="client" ${isEdit && site.ua_mode === 'client' ? 'selected' : ''}>客户端</option>
                <option value="custom">自定义</option>
                <option value="passthrough" ${isEdit && site.ua_mode === 'passthrough' ? 'selected' : ''}>透传（保留客户端身份）</option>
              </select>
            </div>
            <div class="form-group form-input-stack" id="m-custom-ua-group" hidden>
              <div class="form-label">自定义身份</div>
              <label class="sr-only" for="m-custom-ua">User-Agent</label>
              <input type="text" class="form-input" id="m-custom-ua" placeholder="User-Agent" maxlength="1024" autocapitalize="none" autocorrect="off" spellcheck="false">
              <label class="sr-only" for="m-custom-client">Emby Client</label>
              <input type="text" class="form-input" id="m-custom-client" placeholder="Emby Client" maxlength="128" autocapitalize="none" autocorrect="off" spellcheck="false">
              <label class="sr-only" for="m-custom-version">Emby Version</label>
              <input type="text" class="form-input" id="m-custom-version" placeholder="Emby Version" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false">
            </div>
          </div>
        </details>
      </fieldset>

      <fieldset class="site-form-section" data-site-group="cache-request-policy">
        <legend>缓存与请求策略</legend>
        <div class="form-toggle-list">
          <label class="form-check form-check-panel" for="m-ping-cache-enabled">
            <input type="checkbox" id="m-ping-cache-enabled" ${optimizationState.ping_cache_enabled ? 'checked' : ''}>
            <span><strong>Ping 缓存</strong><small>复用短期连通性结果</small></span>
          </label>
          <label class="form-check form-check-panel" for="m-image-cache-enabled">
            <input type="checkbox" id="m-image-cache-enabled" ${optimizationState.image_cache_enabled ? 'checked' : ''}>
            <span><strong>图片缓存</strong><small>缓存常用图片响应</small></span>
          </label>
          <label class="form-check form-check-panel" for="m-progress-coalescing-enabled">
            <input type="checkbox" id="m-progress-coalescing-enabled" ${optimizationState.progress_coalescing_enabled ? 'checked' : ''}>
            <span><strong>播放进度优化</strong><small>密集更新时仅保留最新一条待发往上游的进度；发送 Stopped 前会先向上游发送最终位置。</small></span>
          </label>
          <label class="form-check form-check-panel" for="m-request-limits-enabled">
            <input type="checkbox" id="m-request-limits-enabled" aria-controls="m-request-limit-fields" ${hasRequestLimits ? 'checked' : ''}>
            <span><strong>流量与速度限制</strong><small>启用后，流量额度或单连接限速至少填写一项大于 0 的值</small></span>
          </label>
          <div class="form-input-stack request-limit-fields" id="m-request-limit-fields" ${hasRequestLimits ? '' : 'hidden'}>
            <div class="form-group">
              <label for="m-quota">流量额度（GB）</label>
              <input type="number" class="form-input" id="m-quota" value="${isEdit ? Math.round((site.traffic_quota || 0) / 1073741824) : 0}" placeholder="0" min="0" inputmode="numeric">
            </div>
            <div class="form-group">
              <label for="m-speed">单连接限速（Mbps）</label>
              <input type="number" class="form-input" id="m-speed" value="${isEdit ? (site.speed_limit || 0) : 0}" placeholder="0" min="0" max="1000000" step="1" inputmode="numeric">
            </div>
          </div>
        </div>
      </fieldset>

    </div>
  `;

  document.getElementById('modal-footer').innerHTML = `
    <button type="button" class="btn-modal secondary" id="m-cancel">取消</button>
    <button type="button" class="btn-modal primary" id="m-submit">${isEdit ? '保存' : '创建'}</button>
  `;

	document.getElementById('m-cancel').addEventListener('click', closeModal);

	const ingressSelect = document.getElementById('m-ingress-mode');
	const publicHostGroup = document.getElementById('m-public-host-group');
	const publicHostInput = document.getElementById('m-public-host');
	const portLabel = document.getElementById('m-port-label');
	const ingressWarning = document.getElementById('m-ingress-warning');
	ingressSelect.value = isEdit ? normalizedIngressMode(site) : defaultIngressMode(siteCapabilities);
	function updateIngressFields() {
		const state = ingressFormState(ingressSelect.value);
		publicHostGroup.hidden = !state.showPublicHost;
		publicHostInput.required = state.requirePublicHost;
		portLabel.textContent = state.portLabel;
		ingressWarning.textContent = state.warning;
	}
	updateIngressFields();
	ingressSelect.addEventListener('change', updateIngressFields);

	const uaSelect = document.getElementById('m-ua');
  const customUAGroup = document.getElementById('m-custom-ua-group');
  const customUAInputs = [
    document.getElementById('m-custom-ua'),
    document.getElementById('m-custom-client'),
    document.getElementById('m-custom-version'),
  ];
  const initialUAState = customUAFormState(isEdit ? site.ua_mode : 'infuse', site);
  uaSelect.value = isEdit && site.ua_mode ? site.ua_mode : 'infuse';
  customUAInputs[0].value = initialUAState.customUserAgent;
  customUAInputs[1].value = initialUAState.customClient;
  customUAInputs[2].value = initialUAState.customVersion;

  function toggleCustomUAFields() {
    const state = customUAFormState(uaSelect.value);
    customUAGroup.hidden = !state.visible;
    customUAInputs.forEach(input => {
      input.required = state.required;
    });
  }
  toggleCustomUAFields();
  uaSelect.addEventListener('change', toggleCustomUAFields);

	const requestLimitsEnabledInput = document.getElementById('m-request-limits-enabled');
	const requestLimitFields = document.getElementById('m-request-limit-fields');
	const requestLimitInputs = [
		document.getElementById('m-quota'),
		document.getElementById('m-speed'),
	];
	function toggleRequestLimitFields() {
		const enabled = requestLimitsEnabledInput.checked;
		requestLimitFields.hidden = !enabled;
		requestLimitInputs.forEach(input => {
			input.disabled = !enabled;
		});
	}
	toggleRequestLimitFields();
	requestLimitsEnabledInput.addEventListener('change', toggleRequestLimitFields);

	const dynamicEnabledInput = document.getElementById('m-dynamic-enabled');
	const dynamicProfileSelect = document.getElementById('m-dynamic-profile');
	dynamicProfileSelect.value = dynamicPolicy.dynamic_profile;
	const dynamicPlaybackInfoInput = document.getElementById('m-dynamic-playback-info');
	const dynamicDowngradeInput = document.getElementById('m-dynamic-downgrade');
	const dynamicAdvancedDisclosure = document.getElementById('m-dynamic-advanced');
	const dynamicRulesDisclosure = document.getElementById('m-dynamic-rules-disclosure');
	const dynamicRulesContainer = document.getElementById('m-dynamic-rules');
	const dynamicDomainWarningElement = document.getElementById('m-dynamic-domain-warning');
	const dynamicProfileRiskContainer = document.getElementById('m-dynamic-profile-risk');
	const dynamicExtremeConfirmation = document.getElementById('m-dynamic-extreme-confirm');
	const dynamicExtremeAcknowledged = document.getElementById('m-dynamic-extreme-ack');
	const dynamicExtremeTypedName = document.getElementById('m-dynamic-extreme-name');
	let dynamicRules = dynamicPolicy.dynamic_domain_rules.map(rule => ({ ...rule }));
	let safeRuleExpansionConfirmed = false;

	function updateDynamicDomainWarning() {
		const warning = dynamicDomainRuleWarning(dynamicProfileSelect.value, dynamicRules);
		dynamicDomainWarningElement.hidden = !warning.message;
		dynamicDomainWarningElement.className = `form-warning${warning.tone ? ` form-warning-${warning.tone}` : ''}`;
		dynamicDomainWarningElement.textContent = warning.message;
	}

	function updateDynamicProfileState() {
		dynamicProfileRiskContainer.innerHTML = renderDynamicProfileRisk(dynamicProfileSelect.value, dynamicCapabilities, dynamicPlaybackInfoInput.checked);
		const requirement = dynamicProfileConfirmationRequirement(dynamicPolicy, {
			dynamic_discovery_enabled: dynamicEnabledInput.checked,
			dynamic_profile: dynamicProfileSelect.value,
		});
		dynamicExtremeConfirmation.hidden = requirement !== 'extreme';
		if (dynamicExtremeConfirmation.hidden) {
			dynamicExtremeAcknowledged.checked = false;
			dynamicExtremeTypedName.value = '';
		}
		const downgradeState = dynamicDowngradeFormState(dynamicProfileSelect.value, dynamicDowngradeInput.checked);
		dynamicAdvancedDisclosure.hidden = !downgradeState.visible;
		if (!downgradeState.visible) dynamicDowngradeInput.checked = false;
		if (downgradeState.visible) dynamicRulesDisclosure.open = true;
		updateDynamicDomainWarning();
	}
	dynamicProfileSelect.addEventListener('change', () => {
		dynamicExtremeAcknowledged.checked = false;
		dynamicExtremeTypedName.value = '';
		safeRuleExpansionConfirmed = false;
		updateDynamicProfileState();
	});
	dynamicEnabledInput.addEventListener('change', updateDynamicProfileState);
	dynamicPlaybackInfoInput.addEventListener('change', updateDynamicProfileState);
	updateDynamicProfileState();

	function renderDynamicRules() {
		dynamicRulesContainer.innerHTML = renderDynamicRuleRows(dynamicRules);
		dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-type').forEach(input => {
			input.onchange = () => {
				dynamicRules[Number(input.dataset.idx)].type = input.value;
				safeRuleExpansionConfirmed = false;
				updateDynamicDomainWarning();
			};
		});
		dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-value').forEach(input => {
			input.oninput = () => {
				dynamicRules[Number(input.dataset.idx)].value = input.value;
				safeRuleExpansionConfirmed = false;
				updateDynamicDomainWarning();
			};
		});
		dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-remove').forEach(button => {
			button.onclick = () => {
				const index = Number(button.dataset.idx);
				const nextRules = dynamicRules.filter((_, ruleIndex) => ruleIndex !== index);
				if (safeRulesBecomeUnrestricted(dynamicEnabledInput.checked, dynamicProfileSelect.value, dynamicRules, nextRules)) {
					const accepted = window.confirm('删除最后一条 Safe 域名限制后，将允许任意公网 DNS 主机名的 HTTPS:443。确定删除吗？');
					if (!accepted) return;
					safeRuleExpansionConfirmed = true;
				}
				dynamicRules = nextRules;
				renderDynamicRules();
				updateDynamicDomainWarning();
			};
		});
	}
	renderDynamicRules();

	document.getElementById('m-add-dynamic-rule').onclick = () => {
		dynamicRules.push({ type: 'exact', value: '' });
		safeRuleExpansionConfirmed = false;
		renderDynamicRules();
		updateDynamicDomainWarning();
		const inputs = dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-value');
		if (inputs.length) inputs[inputs.length - 1].focus();
	};

	const dynamicObservationsContainer = isEdit ? document.getElementById('m-dynamic-observations') : null;
	const refreshDynamicObservationsButton = isEdit ? document.getElementById('m-refresh-dynamic-observations') : null;
	const clearDynamicObservationsButton = isEdit ? document.getElementById('m-clear-dynamic-observations') : null;
	let dynamicObservationRequest = 0;

	function dynamicObservationsPanelIsCurrent() {
		return dynamicObservationsContainer && document.getElementById('m-dynamic-observations') === dynamicObservationsContainer;
	}

	function setDynamicObservationButtonsDisabled(disabled) {
		if (refreshDynamicObservationsButton) refreshDynamicObservationsButton.disabled = disabled;
		if (clearDynamicObservationsButton) clearDynamicObservationsButton.disabled = disabled;
	}

	async function refreshDynamicObservations() {
		if (!isEdit || !dynamicCapabilities.recognized || !dynamicObservationsContainer) return;
		const request = ++dynamicObservationRequest;
		setDynamicObservationButtonsDisabled(true);
		dynamicObservationsContainer.innerHTML = '<div class="form-help">正在读取观察记录…</div>';
		try {
			const response = await API.getDynamicObservations(site.id);
			if (request !== dynamicObservationRequest || !dynamicObservationsPanelIsCurrent()) return;
			dynamicObservationsContainer.innerHTML = renderDynamicObservations(response);
		} catch (_) {
			if (request !== dynamicObservationRequest || !dynamicObservationsPanelIsCurrent()) return;
			dynamicObservationsContainer.innerHTML = '<div class="form-help" style="color:var(--orange)">无法读取观察记录；未显示任何后端返回值。</div>';
		} finally {
			if (request === dynamicObservationRequest && dynamicObservationsPanelIsCurrent()) setDynamicObservationButtonsDisabled(false);
		}
	}

	if (isEdit && dynamicCapabilities.recognized) {
		refreshDynamicObservationsButton.onclick = refreshDynamicObservations;
		clearDynamicObservationsButton.onclick = async () => {
			if (!window.confirm('确定清空本站点的全部动态观察记录吗？此操作不可撤销。')) return;
			const request = ++dynamicObservationRequest;
			setDynamicObservationButtonsDisabled(true);
			try {
				const response = await API.deleteDynamicObservations(site.id);
				if (request !== dynamicObservationRequest || !dynamicObservationsPanelIsCurrent()) return;
				dynamicObservationsContainer.innerHTML = renderDynamicObservations(response);
				Toast.success('观察记录已清空');
			} catch (_) {
				if (request === dynamicObservationRequest && dynamicObservationsPanelIsCurrent()) Toast.error('无法清空观察记录');
			} finally {
				if (request === dynamicObservationRequest && dynamicObservationsPanelIsCurrent()) setDynamicObservationButtonsDisabled(false);
			}
		};
	}

  // Build initial playback list from existing data
  const listContainer = document.getElementById('m-playback-list');
  const modeGroup = document.getElementById('playback-mode-group');
  const addPlaybackButton = document.getElementById('m-add-playback');
  let existingHosts = [];
  if (isEdit) {
    if ((site.playback_target_url || '').trim()) existingHosts.push(site.playback_target_url.trim());
    for (const host of normalizeStreamHosts(site.stream_hosts)) existingHosts.push(host);
  }
  if (existingHosts.length === 0) existingHosts = [''];

  function updatePlaybackAddState() {
    const canAdd = canAddPlaybackAddress(existingHosts.length, maxPlaybackAddresses);
    addPlaybackButton.disabled = !canAdd;
    addPlaybackButton.title = canAdd ? '' : `每个站点最多配置 ${maxPlaybackAddresses} 个播放回源`;
  }

  function renderPlaybackInputs() {
    listContainer.innerHTML = existingHosts.map((val, idx) => `
      <fieldset class="form-list-row playback-address-row">
        <legend class="sr-only">播放回源 ${idx + 1}</legend>
        <label class="sr-only" for="m-playback-address-${idx}">${idx === 0 ? '主播放回源地址' : `额外播放回源地址 ${idx}`}</label>
        <input type="text" class="form-input m-pb-input" id="m-playback-address-${idx}" value="${esc(val)}" placeholder="${idx === 0 ? '主播放回源地址' : '额外播放回源地址'}" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048">
        ${existingHosts.length > 1 ? `<button type="button" class="btn-ghost danger form-row-action m-pb-remove" data-idx="${idx}" aria-label="删除播放回源 ${idx + 1}">删除</button>` : ''}
      </fieldset>
    `).join('');
    listContainer.querySelectorAll('.m-pb-remove').forEach(btn => {
      btn.onclick = () => {
        existingHosts.splice(parseInt(btn.dataset.idx), 1);
        renderPlaybackInputs();
        toggleModeGroup();
      };
    });
    listContainer.querySelectorAll('.m-pb-input').forEach((inp, idx) => {
      inp.oninput = () => { existingHosts[idx] = inp.value; toggleModeGroup(); };
    });
    updatePlaybackAddState();
  }
  renderPlaybackInputs();

  addPlaybackButton.onclick = () => {
    if (!canAddPlaybackAddress(existingHosts.length, maxPlaybackAddresses)) {
      Toast.error(`每个站点最多配置 ${maxPlaybackAddresses} 个播放回源`);
      return;
    }
    existingHosts.push('');
    renderPlaybackInputs();
    const inputs = listContainer.querySelectorAll('.m-pb-input');
    if (inputs.length) inputs[inputs.length - 1].focus();
  };

  function toggleModeGroup() {
    const hasAny = existingHosts.some(h => h.trim());
    modeGroup.hidden = !hasAny;
  }
  toggleModeGroup();

  const upstreamHeadersContainer = document.getElementById('m-upstream-headers');
  let upstreamHeaders = isEdit && Array.isArray(site.upstream_headers)
    ? site.upstream_headers.map(header => ({ name: header.name || '', value: '', configured: !!header.configured }))
    : [];

  function renderUpstreamHeaders() {
    upstreamHeadersContainer.innerHTML = renderUpstreamHeaderRows(upstreamHeaders, upstreamHeadersAvailable);
    upstreamHeadersContainer.querySelectorAll('.m-upstream-header-name').forEach(input => {
      input.oninput = () => { upstreamHeaders[Number(input.dataset.idx)].name = input.value; };
    });
    upstreamHeadersContainer.querySelectorAll('.m-upstream-header-value').forEach(input => {
      input.oninput = () => { upstreamHeaders[Number(input.dataset.idx)].value = input.value; };
    });
    upstreamHeadersContainer.querySelectorAll('.m-upstream-header-remove').forEach(button => {
      button.onclick = () => {
        upstreamHeaders.splice(Number(button.dataset.idx), 1);
        renderUpstreamHeaders();
      };
    });
  }
  renderUpstreamHeaders();

  const addUpstreamHeaderButton = document.getElementById('m-add-upstream-header');
  addUpstreamHeaderButton.onclick = () => {
    if (!upstreamHeadersAvailable) {
      Toast.error('请先配置 UPSTREAM_HEADER_KEY 并重启 Meridian');
      return;
    }
    if (upstreamHeaders.length >= 16) {
      Toast.error('每个站点最多配置 16 个上游请求头');
      return;
    }
    upstreamHeaders.push({ name: '', value: '', configured: false });
    renderUpstreamHeaders();
    const inputs = upstreamHeadersContainer.querySelectorAll('.m-upstream-header-name');
    if (inputs.length) inputs[inputs.length - 1].focus();
  };

  document.getElementById('m-submit').onclick = async () => {
    const allHosts = existingHosts.map(h => h.trim()).filter(Boolean);
    if (allHosts.length > maxPlaybackAddresses) {
      Toast.error(`每个站点最多配置 ${maxPlaybackAddresses} 个播放回源`);
      return;
    }
    const uaMode = uaSelect.value;
    const customUAPayload = buildCustomUAPayload(
      uaMode,
      customUAInputs[0].value,
      customUAInputs[1].value,
      customUAInputs[2].value,
    );
		const ingressPayload = buildIngressPayload(
		  ingressSelect.value,
		  document.getElementById('m-port').value,
		  publicHostInput.value,
		);
		const data = {
	      name: document.getElementById('m-name').value.trim(),
	      target_url: document.getElementById('m-target').value.trim(),
      playback_target_url: allHosts.length > 0 ? allHosts[0] : '',
      playback_mode: document.getElementById('m-playback-mode').value,
		stream_hosts: allHosts.length > 1 ? allHosts.slice(1) : [],
			...ingressPayload,
		upstream_headers: buildUpstreamHeaderPayload(upstreamHeaders),
      ua_mode: uaMode,
      ...customUAPayload,
      ...buildDynamicPolicyPayload({
        dynamic_discovery_enabled: dynamicEnabledInput.checked,
        dynamic_profile: dynamicProfileSelect.value,
        dynamic_playback_info_enabled: dynamicPlaybackInfoInput.checked,
        dynamic_domain_rules: dynamicRules,
        dynamic_allow_https_downgrade: dynamicDowngradeInput.checked,
      }, dynamicCapabilities, !isEdit),
      ...buildProxyOptimizationPayload(
        document.getElementById('m-ping-cache-enabled').checked,
        document.getElementById('m-image-cache-enabled').checked,
        document.getElementById('m-progress-coalescing-enabled').checked,
      ),
      ...buildRequestLimitPayload(
        requestLimitsEnabledInput.checked,
        document.getElementById('m-quota').value,
        document.getElementById('m-speed').value,
      ),
    };

		if (!data.name || !data.target_url || !data.listen_port || ((data.ingress_mode === 'host' || data.ingress_mode === 'both') && !data.public_host)) {
	      Toast.error('请填写所有必填项');
	      return;
	    }
	  if (requestLimitsEnabledInput.checked && !(data.traffic_quota > 0 || data.speed_limit > 0)) {
		Toast.error('启用“流量与速度限制”后，流量额度或单连接限速至少一项必须大于 0');
		return;
	  }
	  const domainRuleState = dynamicDomainRuleWarning(data.dynamic_profile, data.dynamic_domain_rules);
	  if (domainRuleState.tone === 'warning') {
		Toast.error(domainRuleState.message);
		return;
	  }
	  if (!safeRuleExpansionConfirmed && safeRulesBecomeUnrestricted(
		data.dynamic_discovery_enabled,
		data.dynamic_profile,
		dynamicPolicy.dynamic_domain_rules,
		data.dynamic_domain_rules,
	  )) {
		const accepted = window.confirm('保存后 Safe 将允许任意公网 DNS 主机名的 HTTPS:443。确定继续吗？');
		if (!accepted) return;
		safeRuleExpansionConfirmed = true;
	  }
	  const profileConfirmation = confirmDynamicProfileChange(
		dynamicPolicy,
		data,
		data.name,
		dynamicExtremeAcknowledged.checked,
		dynamicExtremeTypedName.value,
	  );
	  if (!profileConfirmation.ok) {
		if (profileConfirmation.error) Toast.error(profileConfirmation.error);
		return;
	  }
	  if (uaMode === 'custom' && (!data.custom_user_agent || !data.custom_client || !data.custom_version)) {
      Toast.error('请完整填写自定义 User-Agent、Client 和 Version');
		return;
	  }
	  const invalidHeader = upstreamHeaders.some(header => {
		const name = String(header.name || '').trim();
		const value = String(header.value || '').trim();
		if (!header.configured && !name && !value) return false;
		return !name || (!header.configured && !value);
	  });
		if (invalidHeader) {
			Toast.error('请完整填写新增请求头的名称和值；已有值可留空保持不变');
			return;
		}
		if (isEdit && normalizedTargetAuthority(site.target_url) !== normalizedTargetAuthority(data.target_url)) {
			const retainedSecret = upstreamHeaders.some(header => header.configured && !String(header.value || '').trim());
			if (retainedSecret) {
				Toast.error('主回源的协议、域名或端口已变化，请重新输入每个已配置的固定请求头，或删除对应行');
				return;
			}
		}

    try {
      if (isEdit) {
        await API.updateSite(site.id, data);
        Toast.success('站点已更新');
      } else {
        await API.createSite(data);
        Toast.success('站点已创建');
      }
      closeModal();
      loadSites();
    } catch (e) {
      Toast.error(e.message);
    }
  };

  openModal({ closeOnBackdrop: false });
  setupSiteModalFocus();
	if (isEdit && dynamicCapabilities.recognized) refreshDynamicObservations();
}

// Global actions
window.toggleSiteAction = async function(id) {
  try {
    const res = await API.toggleSite(id);
    Toast.success(res.enabled ? '站点已启用' : '站点已停用');
    loadSites();
  } catch (e) {
    Toast.error(e.message);
  }
};

window.editSiteAction = async function(id) {
  try {
    const sites = await API.listSites();
    const site = sites.find(s => s.id === id);
    if (site) showSiteModal(site);
  } catch (e) {
    Toast.error(e.message);
  }
};

window.deleteSiteAction = function(id, name) {
  document.getElementById('modal-title').textContent = '确认删除';
  const modalBody = document.getElementById('modal-body');
  modalBody.replaceChildren();
  const message = document.createElement('p');
  message.style.color = 'var(--white-60)';
  message.append('确定要删除站点 ');
  const strong = document.createElement('strong');
  strong.textContent = String(name);
  message.append(strong, ' 吗？此操作不可撤销。');
  modalBody.appendChild(message);
  document.getElementById('modal-footer').innerHTML = `
    <button class="btn-modal secondary" id="delete-cancel">取消</button>
    <button class="btn-modal primary" id="delete-confirm" style="background:var(--red)">删除</button>
  `;
  document.getElementById('delete-cancel').addEventListener('click', closeModal);
  document.getElementById('delete-confirm').addEventListener('click', () => confirmDelete(id));
  openModal({ closeOnBackdrop: true });
};

window.confirmDelete = async function(id) {
  try {
    await API.deleteSite(id);
    Toast.success('站点已删除');
    closeModal();
    loadSites();
  } catch (e) {
    Toast.error(e.message);
  }
};
