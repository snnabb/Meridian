// Sites management page
let siteSortingCleanup = null;
let sitesLoadGeneration = 0;
function renderSites() {
  const page = document.getElementById('page-sites');
  page.innerHTML = `
    <div class="sites-page-head fade-up">
      <div><h1 class="section-title">站点管理</h1><p class="section-sub">管理所有 Emby 反代站点与回源配置</p></div>
      <div class="toolbar-info" id="sites-count"></div>
    </div>
    <div class="page-toolbar sites-toolbar fade-up stagger-1">
      <button class="btn-add" id="btn-add-site">
        <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        添加站点
      </button>
      <label class="sites-search"><span class="sr-only">搜索站点</span><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="16" y1="16" x2="21" y2="21"/></svg><input id="sites-search" type="search" placeholder="搜索站点名称或回源地址"></label>
      <button class="btn-ghost btn-test-all" id="btn-test-all-sites"><span aria-hidden="true">⌁</span> 全部测速</button>
    </div>
    <div class="sites-grid" id="sites-grid"></div>
  `;

  document.getElementById('btn-add-site').onclick = () => showSiteModal();
  document.getElementById('btn-test-all-sites').onclick = testAllSitesLatency;
  document.getElementById('sites-search').addEventListener('input', event => filterSiteCards(event.target.value));
  loadSites();
}

async function loadSites() {
  const generation = ++sitesLoadGeneration;
  try {
	const [sites, capabilities] = await Promise.all([API.listSites(), API.ingressCapabilities()]);
	if (generation !== sitesLoadGeneration || Router.current !== 'sites') return;
	siteIngressCapabilities = normalizeSiteCapabilities(capabilities);
    document.getElementById('sites-count').innerHTML = `共 <strong>${sites.length}</strong> 个站点`;

    const grid = document.getElementById('sites-grid');
    if (!sites || sites.length === 0) {
      grid.innerHTML = '<div style="text-align:center;color:var(--white-38);padding:60px;grid-column:1/-1">暂无站点，点击右上角添加</div>';
      return;
    }

	grid.innerHTML = sites.map((s, i) => {
      const pct = s.traffic_quota > 0 ? (s.traffic_used / s.traffic_quota * 100).toFixed(1) : 0;
      const pctClass = pct > 85 ? 'danger' : pct > 50 ? 'warn' : 'normal';
		const upstreamHeaderCount = Array.isArray(s.upstream_headers) ? s.upstream_headers.length : 0;
		const accessAddress = siteAccessAddress(s, siteIngressCapabilities);

      return `
      <div class="site-card" data-site-id="${s.id}" data-site-search="${esc(`${s.name} ${s.target_url} ${s.public_host || ''}`.toLowerCase())}">
        <div class="site-top">
          <div class="site-heading">
            <button type="button" class="site-drag-handle" data-site-drag-handle aria-label="拖拽调整 ${esc(s.name)} 的顺序" title="拖拽调整顺序">
              <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="7" cy="5" r="1.25"></circle><circle cx="13" cy="5" r="1.25"></circle><circle cx="7" cy="10" r="1.25"></circle><circle cx="13" cy="10" r="1.25"></circle><circle cx="7" cy="15" r="1.25"></circle><circle cx="13" cy="15" r="1.25"></circle></svg>
            </button>
            <div class="site-heading-content"><div class="site-name">${esc(s.name)}</div><span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${esc(uaNameMap[s.ua_mode] || s.ua_mode)}</span></div>
          </div>
          <div class="site-card-state">
            <span class="site-mode-badge">${siteIngressModeLabel(s)}</span>
            <span class="status-badge site-status">
              <span class="status-led ${s.running ? 'on' : 'off'}"></span>
              ${s.running ? '运行中' : '已停止'}
            </span>
          </div>
        </div>
        <div class="site-latency-line"><span class="status-led ${s.running ? 'on' : 'off'}"></span><span>回源延迟：</span><strong class="site-latency" id="site-latency-${s.id}">未测试</strong></div>
		<div class="site-rows">
		  <div class="site-row site-access-row">
		    <span class="site-row-label">访问地址</span>
		    <span class="site-access-value"><span class="mono site-access-address is-hidden" data-access-address="${esc(accessAddress)}">********</span><button type="button" class="icon-button site-access-toggle" data-site-action="access" data-site-id="${s.id}" aria-label="显示访问地址" title="显示访问地址">◉</button><button type="button" class="icon-button site-access-copy" data-site-action="copy" data-site-id="${s.id}" aria-label="复制访问地址" title="复制访问地址"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="10" height="10" rx="2"></rect><path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1"></path></svg></button></span>
		  </div>
          <div class="site-row site-upstream-row">
            <span class="site-row-label">主回源地址</span>
            <span class="mono">${esc(s.target_url)}</span>
          </div>
		  ${upstreamHeaderCount > 0 ? `
		  <div class="site-row">
			<span class="site-row-label">上游请求头</span>
			<span>${upstreamHeaderCount} 个（加密）</span>
		  </div>` : ''}
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
            <span>${formatBytes(s.traffic_used)}</span>
          </div>
          `}
        </div>
        <div class="site-actions">
          <button class="btn-ghost site-action-test" data-site-action="latency" data-site-id="${s.id}">测速</button>
          <button class="btn-ghost" data-site-action="toggle" data-site-id="${s.id}" ${normalizedIngressMode(s) === 'unset' ? 'disabled title="请先编辑并配置入口"' : ''}>${normalizedIngressMode(s) === 'unset' ? '待配置' : (s.enabled ? '停用' : '启用')}</button>
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
		if (button.dataset.siteAction === 'latency') testSiteLatency(id, button);
		if (button.dataset.siteAction === 'access') toggleSiteAccessAddress(button);
		if (button.dataset.siteAction === 'copy') copySiteAccessAddress(button);
		if (button.dataset.siteAction === 'toggle') toggleSiteAction(id);
        if (button.dataset.siteAction === 'edit') showSiteModal(site);
        if (button.dataset.siteAction === 'delete') deleteSiteAction(id, site.name);
      });
    });
    setupSiteSorting(grid);
  } catch (e) {
    Toast.error('加载站点失败: ' + e.message);
  }
}

function filterSiteCards(query) {
  const needle = String(query || '').trim().toLowerCase();
  const grid = document.getElementById('sites-grid');
  if (!grid) return;
  grid.classList.toggle('is-filtered', !!needle);
  grid.querySelectorAll('.site-card').forEach(card => {
    card.hidden = !!needle && !String(card.dataset.siteSearch || '').includes(needle);
  });
  grid.querySelectorAll('[data-site-drag-handle]').forEach(handle => {
    handle.disabled = !!needle;
    handle.title = needle ? '清除搜索后可调整顺序' : '拖拽调整顺序';
  });
}

function siteOrderFromGrid(grid) {
  return [...grid.querySelectorAll('.site-card[data-site-id]')]
    .map(card => Number(card.dataset.siteId))
    .filter(Number.isSafeInteger);
}

function captureSiteDropSlots(grid, draggedCard) {
  const scrollX = typeof window !== 'undefined' ? (window.scrollX || 0) : 0;
  const scrollY = typeof window !== 'undefined' ? (window.scrollY || 0) : 0;
  return [...grid.children]
    .filter(node => node !== draggedCard && !node.hidden)
    .map(node => {
      const rect = node.getBoundingClientRect();
      return {
        x: rect.left + rect.width / 2 + scrollX,
        y: rect.top + rect.height / 2 + scrollY,
        width: Math.max(rect.width, 1),
        height: Math.max(rect.height, 1),
      };
    });
}

function moveSitePlaceholderAtPoint(grid, draggedCard, placeholder, dropSlots, clientX, clientY) {
  if (!placeholder || !dropSlots.length) return;
  const scrollX = typeof window !== 'undefined' ? (window.scrollX || 0) : 0;
  const scrollY = typeof window !== 'undefined' ? (window.scrollY || 0) : 0;
  const pointerX = clientX + scrollX;
  const pointerY = clientY + scrollY;
  let desiredIndex = 0;
  let nearestDistance = Number.POSITIVE_INFINITY;
  dropSlots.forEach((slot, index) => {
    const dx = (pointerX - slot.x) / slot.width;
    const dy = (pointerY - slot.y) / slot.height;
    const distance = dx * dx + dy * dy;
    if (distance < nearestDistance) {
      desiredIndex = index;
      nearestDistance = distance;
    }
  });

  const orderedCards = [...grid.querySelectorAll('.site-card[data-site-id]')]
    .filter(card => card !== draggedCard);
  const reference = orderedCards[desiredIndex] || null;
  if (reference !== placeholder.nextSibling) grid.insertBefore(placeholder, reference);
}

function positionDraggedSiteCard(card, clientX, clientY, offsetX, offsetY) {
  card.style.left = `${clientX - offsetX}px`;
  card.style.top = `${clientY - offsetY}px`;
  card.style.transform = 'translate3d(0, 0, 0)';
}

async function persistSiteOrder(grid) {
  const siteIds = siteOrderFromGrid(grid);
  const nextOrder = siteIds.join(',');
  if (!siteIds.length || nextOrder === grid.dataset.siteOrder) return;
  grid.classList.add('is-saving-order');
  try {
    await API.reorderSites(siteIds);
    grid.dataset.siteOrder = nextOrder;
    Toast.success('站点顺序已保存，仪表盘已同步');
  } catch (error) {
    Toast.error('保存站点顺序失败: ' + error.message);
    await loadSites();
  } finally {
    grid.classList.remove('is-saving-order');
  }
}

function setupSiteSorting(grid) {
  if (typeof siteSortingCleanup === 'function') siteSortingCleanup();
  const cards = [...grid.querySelectorAll('.site-card[data-site-id]')];
  grid.dataset.siteOrder = siteOrderFromGrid(grid).join(',');
  let draggedCard = null;
  let placeholder = null;
  let dragOffsetX = 0;
  let dragOffsetY = 0;
  let dropSlots = [];
  let activeHandle = null;
  let activePointerId = null;

  const beginDrag = (card, event) => {
    const rect = card.getBoundingClientRect();
    draggedCard = card;
    dragOffsetX = event.clientX - rect.left;
    dragOffsetY = event.clientY - rect.top;
    placeholder = document.createElement('div');
    placeholder.className = 'site-card-placeholder';
    placeholder.setAttribute('aria-hidden', 'true');
    placeholder.style.height = `${rect.height}px`;
    grid.insertBefore(placeholder, card);

    card.style.position = 'fixed';
    card.style.left = `${rect.left}px`;
    card.style.top = `${rect.top}px`;
    card.style.width = `${rect.width}px`;
    card.style.height = `${rect.height}px`;
    card.style.margin = '0';
    card.style.transform = 'translate3d(0, 0, 0)';
    card.classList.add('is-dragging');
    grid.classList.add('is-reordering');
    document.body.classList.add('is-site-dragging');
    dropSlots = captureSiteDropSlots(grid, card);
  };
  const finishDrag = card => {
    if (draggedCard !== card) return;
    if (placeholder && placeholder.parentElement === grid) grid.insertBefore(card, placeholder);
    if (placeholder) placeholder.remove();
    placeholder = null;
    dropSlots = [];
    card.style.position = '';
    card.style.left = '';
    card.style.top = '';
    card.style.width = '';
    card.style.height = '';
    card.style.margin = '';
    card.style.transform = '';
    card.classList.remove('is-dragging');
    grid.classList.remove('is-reordering');
    document.body.classList.remove('is-site-dragging');
    draggedCard = null;
    void persistSiteOrder(grid);
  };

  const movePointer = event => {
    if (!draggedCard) return;
    if (event.type === 'pointermove' && activePointerId !== null && event.pointerId !== activePointerId) return;
    if (event.cancelable) event.preventDefault();
    positionDraggedSiteCard(draggedCard, event.clientX, event.clientY, dragOffsetX, dragOffsetY);
    const edge = 64;
    if (typeof window !== 'undefined' && window.scrollBy) {
      if (event.clientY < edge) window.scrollBy(0, -12);
      if (event.clientY > window.innerHeight - edge) window.scrollBy(0, 12);
    }
    moveSitePlaceholderAtPoint(grid, draggedCard, placeholder, dropSlots, event.clientX, event.clientY);
  };

  const finishPointer = event => {
    if (!draggedCard) return;
    if (event.type.startsWith('pointer') && activePointerId !== null && event.pointerId !== activePointerId) return;
    const card = draggedCard;
    if (activeHandle && activePointerId !== null && activeHandle.releasePointerCapture && activeHandle.hasPointerCapture) {
      try {
        if (activeHandle.hasPointerCapture(activePointerId)) activeHandle.releasePointerCapture(activePointerId);
      } catch (_) {}
    }
    activeHandle = null;
    activePointerId = null;
    finishDrag(card);
  };

  cards.forEach(card => {
    const handle = card.querySelector('[data-site-drag-handle]');
    if (!handle) return;

    handle.addEventListener('pointerdown', event => {
      if (handle.disabled || (Number.isFinite(event.button) && event.button !== 0)) return;
      event.preventDefault();
      activeHandle = handle;
      activePointerId = event.pointerId;
      beginDrag(card, event);
      if (handle.setPointerCapture) {
        try { handle.setPointerCapture(event.pointerId); } catch (_) {}
      }
    });
  });

  window.addEventListener('pointermove', movePointer, { passive: false });
  window.addEventListener('pointerup', finishPointer);
  window.addEventListener('pointercancel', finishPointer);
  // Mouse fallbacks cover browsers and automation surfaces that begin with a
  // PointerEvent but only deliver compatibility mouse movement afterwards.
  window.addEventListener('mousemove', movePointer, { passive: false });
  window.addEventListener('mouseup', finishPointer);
  siteSortingCleanup = () => {
    window.removeEventListener('pointermove', movePointer);
    window.removeEventListener('pointerup', finishPointer);
    window.removeEventListener('pointercancel', finishPointer);
    window.removeEventListener('mousemove', movePointer);
    window.removeEventListener('mouseup', finishPointer);
    if (draggedCard) finishPointer({ type: 'pointercancel', pointerId: activePointerId });
    siteSortingCleanup = null;
  };
}

async function testSiteLatency(id, button) {
  const value = document.getElementById(`site-latency-${id}`);
  if (button) button.disabled = true;
  if (value) value.textContent = '测速中…';
  try {
    const result = await API.diagSite(id);
    const health = result && result.upstreams && result.upstreams.primary
      ? result.upstreams.primary.health || {}
      : (result && result.health) || {};
    if (health.status === 'online' && Number.isFinite(Number(health.latency_ms))) {
      const latency = Number(health.latency_ms);
      if (value) {
        value.textContent = `${latency} ms`;
        value.className = `site-latency ${latency < 200 ? 'good' : latency < 800 ? 'warn' : 'bad'}`;
      }
    } else {
      throw new Error(health.error || '回源不可用');
    }
  } catch (error) {
    if (value) {
      value.textContent = '测速失败';
      value.className = 'site-latency bad';
      value.title = error.message || '测速失败';
    }
  } finally {
    if (button) button.disabled = false;
  }
}

async function testAllSitesLatency() {
  const button = document.getElementById('btn-test-all-sites');
  if (!button || button.disabled) return;
  button.disabled = true;
  button.textContent = '全部测速中…';
  const buttons = [...document.querySelectorAll('[data-site-action="latency"]')];
  await Promise.all(buttons.map(siteButton => testSiteLatency(Number(siteButton.dataset.siteId), siteButton)));
  button.disabled = false;
  button.textContent = '全部测速';
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
	const normalized = {
		host_only_available: capabilities.host_only_available !== false,
		upstream_headers_available: capabilities.upstream_headers_available !== false,
		max_playback_addresses: Number.isInteger(requestedMax) && requestedMax > 0
			? requestedMax
			: DEFAULT_MAX_PLAYBACK_ADDRESSES,
	};
	// Keep the legacy capability object's enumerable shape stable for embedded
	// clients while exposing the new fields to the UI.
	Object.defineProperties(normalized, {
		domain_prefix_available: { value: capabilities.domain_prefix_available === undefined ? undefined : capabilities.domain_prefix_available === true, enumerable: false },
		route_domain: { value: String(capabilities.route_domain || '').trim().toLowerCase(), enumerable: false },
		panel_tls_enabled: { value: capabilities.panel_tls_enabled === true, enumerable: false },
		path_ingress_available: { value: capabilities.path_ingress_available !== false, enumerable: false },
		panel_access_url: { value: String(capabilities.panel_access_url || '').replace(/\/$/, ''), enumerable: false },
	});
	return normalized;
}

const DYNAMIC_PROFILE_IDS = ['safe', 'compatible', 'extreme'];
const DYNAMIC_SOURCE_IDS = ['redirect', 'playback_info', 'hls', 'dash'];
const DEFAULT_DYNAMIC_SOURCE_IDS = ['redirect', 'playback_info'];
const ADVANCED_DYNAMIC_SOURCE_IDS = ['hls', 'dash'];
const DYNAMIC_SOURCE_LABELS = {
	redirect: 'HTTP 30x',
	playback_info: 'PlaybackInfo',
	hls: 'HLS',
	dash: 'DASH',
};
const DYNAMIC_PROFILE_SOURCE_IDS = {
	safe: ['redirect', 'playback_info'],
	compatible: [...DYNAMIC_SOURCE_IDS],
	extreme: [...DYNAMIC_SOURCE_IDS],
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

function isStructuredDiscoveryContract(value) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	if (value.stage !== 'structured-discovery' || typeof value.available !== 'boolean' || typeof value.key_configured !== 'boolean') return false;
	if (value.available !== value.key_configured) return false;
	if (!value.global_limits || typeof value.global_limits !== 'object' || Array.isArray(value.global_limits)) return false;
	if (!DYNAMIC_GLOBAL_LIMIT_FIELDS.every(field => hasOwnDynamicField(value.global_limits, field) && Number.isInteger(value.global_limits[field]) && value.global_limits[field] > 0)) return false;
	if (!Array.isArray(value.profiles) || value.profiles.length !== DYNAMIC_PROFILE_IDS.length) return false;

	const profiles = new Map(value.profiles.map(profile => [profile && profile.id, profile]));
	if (profiles.size !== DYNAMIC_PROFILE_IDS.length) return false;
	return DYNAMIC_PROFILE_IDS.every(id => {
		const profile = profiles.get(id);
		if (!profile || typeof profile.label !== 'string' || typeof profile.recommended !== 'boolean') return false;
		if (!profile.limits || typeof profile.limits !== 'object' || Array.isArray(profile.limits)) return false;
		if (!DYNAMIC_LIMIT_FIELDS.every(field => hasOwnDynamicField(profile.limits, field))) return false;
		if (!Array.isArray(profile.limits.allowed_schemes) || profile.limits.allowed_schemes.length === 0 || !profile.limits.allowed_schemes.every(scheme => scheme === 'http' || scheme === 'https')) return false;
		if (!Array.isArray(profile.limits.allowed_ports) || !profile.limits.allowed_ports.every(port => Number.isInteger(port) && port > 0 && port <= 65535)) return false;
		if (typeof profile.limits.allow_any_port !== 'boolean') return false;
		if (!DYNAMIC_LIMIT_FIELDS.slice(3).every(field => Number.isInteger(profile.limits[field]) && profile.limits[field] > 0)) return false;
		if (!profile.features || typeof profile.features !== 'object' || Array.isArray(profile.features)) return false;
		return DYNAMIC_FEATURES.every(([field, , expected]) => {
			const profileExpected = id === 'safe' && (field === 'hls' || field === 'dash') ? false : expected;
			return hasOwnDynamicField(profile.features, field) && profile.features[field] === profileExpected;
		});
	});
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
		recognized,
		profiles: DYNAMIC_PROFILE_IDS.map(id => {
			const profile = sourceProfiles.get(id);
			return {
				id,
				label: profile ? profile.label : DYNAMIC_PROFILE_LABELS[id],
				recommended: profile ? profile.recommended : id === 'compatible',
				limits: profile ? profile.limits : DYNAMIC_PROFILE_NETWORK_DEFAULTS[id],
				features: profile ? profile.features : {},
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
	return DYNAMIC_PROFILE_IDS.includes(profile) ? profile : 'compatible';
}
function dynamicSourcesForProfile(value) {
	return [...DYNAMIC_PROFILE_SOURCE_IDS[normalizeDynamicProfile(value)]];
}


function normalizeDynamicDiscoverySources(value, profile = 'compatible') {
	const allowed = new Set(dynamicSourcesForProfile(profile));
	if (!Array.isArray(value)) return DEFAULT_DYNAMIC_SOURCE_IDS.filter(source => allowed.has(source));
	const selected = new Set(value.map(source => String(source || '').trim().toLowerCase()));
	return DYNAMIC_SOURCE_IDS.filter(source => allowed.has(source) && selected.has(source));
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

function hasRequiredSafeDynamicRules(profile, rules) {
	return normalizeDynamicProfile(profile) !== 'safe' || normalizeDynamicDomainRules(rules).some(isPlausibleSafeDynamicDNSRule);
}

function normalizeDynamicSitePolicy(site) {
	const value = site && typeof site === 'object' ? site : {};
	const revision = value.dynamic_policy_revision;
	const profile = normalizeDynamicProfile(value.dynamic_profile);
	return {
		dynamic_discovery_enabled: value.dynamic_discovery_enabled === true,
		dynamic_profile: profile,
		dynamic_discovery_sources: normalizeDynamicDiscoverySources(value.dynamic_discovery_sources, profile),
		dynamic_domain_rules: normalizeDynamicDomainRules(value.dynamic_domain_rules),
		dynamic_allow_https_downgrade: value.dynamic_allow_https_downgrade === true,
		dynamic_policy_revision: Number.isInteger(revision) && revision > 0 ? revision : 1,
	};
}

function buildDynamicPolicyPayload(policy, capabilities) {
	const normalized = normalizeDynamicSitePolicy(policy);
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	if (!dynamicCapabilities.recognized) return {};
	return {
        dynamic_discovery_enabled: normalized.dynamic_discovery_enabled,
		dynamic_profile: normalized.dynamic_profile,
		dynamic_discovery_sources: normalized.dynamic_discovery_sources,
		dynamic_domain_rules: normalized.dynamic_domain_rules,
		dynamic_allow_https_downgrade: normalized.dynamic_allow_https_downgrade,
	};
}

function renderDynamicProfileOptions(capabilities, selectedProfile) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const normalizedSelected = normalizeDynamicProfile(selectedProfile);
	return dynamicCapabilities.profiles.map(profile => `
		<option value="${esc(profile.id)}" ${profile.id === normalizedSelected ? 'selected' : ''}>${esc(profile.label)}${profile.recommended ? '（推荐）' : ''}</option>
	`).join('');
}

function renderDynamicProfileSummaries(capabilities) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	return dynamicCapabilities.profiles.map(profile => {
		const schemes = Array.isArray(profile.limits.allowed_schemes)
			? profile.limits.allowed_schemes.map(scheme => String(scheme).toUpperCase()).join('/')
			: '—';
		const ports = profile.limits.allow_any_port === true
			? '全部端口'
			: (Array.isArray(profile.limits.allowed_ports) ? profile.limits.allowed_ports.join(', ') : '—');
		const sources = dynamicSourcesForProfile(profile.id).map(source => DYNAMIC_SOURCE_LABELS[source]).join(' + ');
		const compatibility = profile.id === 'extreme'
			? '；额外启用全数据面 30x/303、受限请求体重放、PlaybackInfo 完整 URL 兼容、安全 RequiredHttpHeaders、HLS 变量/扩展标签与 DASH 惰性扩展/DRM 元数据'
			: '；使用严格协议字段与已审核结构';
		const accent = profile.id === 'safe' ? 'var(--green)' : profile.id === 'compatible' ? 'var(--orange)' : 'var(--red)';
		return `<div class="form-help" data-profile-summary="${esc(profile.id)}" style="padding:8px 10px;margin-top:6px;border:1px solid ${accent};border-radius:6px;background:var(--surface-hover);color:var(--white-87)"><strong style="color:${accent}">${esc(profile.label)}</strong>：${esc(sources)}；仅公网 ${esc(schemes)}，端口 ${esc(ports)}${esc(compatibility)}</div>`;
	}).join('');
}

function renderDynamicRuleRows(rules) {
	const rows = Array.isArray(rules) ? rules : [];
	return rows.map((rule, index) => {
		const type = rule && rule.type === 'suffix' ? 'suffix' : 'exact';
		const value = rule && rule.value !== undefined ? rule.value : '';
		return `
		<div class="m-dynamic-rule-row" data-idx="${index}" style="display:flex;gap:6px;margin-bottom:6px;align-items:center">
		  <select class="form-select modal-select m-dynamic-rule-type" data-idx="${index}" style="width:auto;flex-shrink:0">
			<option value="exact" ${type === 'exact' ? 'selected' : ''}>精确</option>
			<option value="suffix" ${type === 'suffix' ? 'selected' : ''}>后缀</option>
		  </select>
		  <input type="text" class="form-input m-dynamic-rule-value" data-idx="${index}" value="${esc(value)}" placeholder="media.example.com" maxlength="253" autocapitalize="none" autocorrect="off" spellcheck="false" style="flex:1">
		  <button type="button" class="btn-ghost danger m-dynamic-rule-remove" data-idx="${index}" style="padding:4px 8px;font-size:13px;flex-shrink:0">删除</button>
		</div>`;
	}).join('');
}

function renderDynamicStatus(capabilities) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const keyStatus = !dynamicCapabilities.recognized ? '未知' : dynamicCapabilities.key_configured ? '已配置' : '未配置';
	if (!dynamicCapabilities.recognized) return '<span class="form-help">自动发现能力不可用，请检查后端版本。</span>';
	return `<span class="form-help">自动发现：${dynamicCapabilities.available ? '已可用' : '未启用'} · DYNAMIC_ROUTE_KEY：${keyStatus} · 默认处理 HTTP 30x 和 PlaybackInfo</span>`;
}

function dynamicProfileRiskNotice(profile) {
	const normalized = normalizeDynamicProfile(profile);
	switch (normalized) {
	case 'compatible':
		return {
			level: 'compatible',
			badge: '默认',
			color: 'var(--orange)',
			background: 'var(--orange-dim)',
			message: '适合大多数后端，支持严格 HTTP 30x、PlaybackInfo、HLS 和 DASH；仍拒绝私网、特殊地址和未验证拨号。',
		};
	case 'extreme':
		return {
			level: 'extreme',
			badge: '高风险',
			color: 'var(--red)',
			background: 'var(--red-dim)',
			message: '除放大公网 authority、动态流和生命周期上限外，还会对 CONNECT/Upgrade/保留路径之外的数据面方法和路径处理 30x/303，并可能把有界请求体重放到上游指定且通过安全校验的公网目标；同时启用 PlaybackInfo、HLS 与 DASH 扩展兼容。仍不开放隧道、私网、自定义 CA、原始地址回退或未签名 target。进入此档必须勾选确认、输入站点名称并通过弹窗。',
		};
	default:
		return {
			level: 'safe',
			badge: '推荐',
			color: 'var(--green)',
			background: 'var(--green-dim)',
			message: '仅允许 HTTPS:443，且未知目标必须命中精确或后缀 DNS 域名规则。',
		};
	}
}

function renderDynamicProfileRisk(profile) {
	const notice = dynamicProfileRiskNotice(profile);
	const badgeTextColor = notice.level === 'extreme' ? '#fff' : '#111';
	return `<div class="form-help" data-profile-risk="${esc(notice.level)}" style="padding:8px 10px;border:1px solid ${notice.color};border-radius:8px;background:${notice.background};color:var(--white-87)"><span data-profile-risk-badge="${esc(notice.level)}" style="display:inline-block;padding:2px 7px;border-radius:999px;background:${notice.color};color:${badgeTextColor};font-weight:800;margin-right:5px">${esc(notice.badge)}</span>${esc(notice.message)}</div>`;
}

function dynamicProfileConfirmationRequirement(initialPolicy, nextPolicy) {
	const initial = normalizeDynamicSitePolicy(initialPolicy);
	const next = normalizeDynamicSitePolicy(nextPolicy);
	if (!next.dynamic_discovery_enabled) return 'none';
	if (next.dynamic_profile === 'extreme' && (!initial.dynamic_discovery_enabled || initial.dynamic_profile !== 'extreme')) return 'extreme';
	return 'none';
}

function confirmDynamicProfileChange(initialPolicy, nextPolicy, siteName, extremeAcknowledged, extremeTypedName) {
	const requirement = dynamicProfileConfirmationRequirement(initialPolicy, nextPolicy);
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
		<label class="site-dynamic-toggle"><input type="checkbox" id="m-dynamic-enabled" ${dynamicPolicy.dynamic_discovery_enabled ? 'checked' : ''} ${enableEditable ? '' : 'disabled'}><span>启用自动发现</span></label>
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
	return meridianFormatDateTime(value);
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
		<div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--glass-border)">
		  <label>自动发现观察记录</label>
		  <div class="form-help">记录由服务器限量保留并定期过期清理。这里只显示规范化权威、有限原因代码和聚合时间/次数；不会显示完整 URL、路径、查询参数、令牌、请求头或正文。</div>
		  <div style="display:flex;gap:8px;margin-top:8px">
			<button type="button" class="btn-ghost" id="m-refresh-dynamic-observations" ${supported ? '' : 'disabled'}>刷新</button>
			<button type="button" class="btn-ghost danger" id="m-clear-dynamic-observations" ${supported ? '' : 'disabled'}>清空</button>
		  </div>
		  <div id="m-dynamic-observations" style="margin-top:8px">${supported ? '<div class="form-help">正在读取观察记录…</div>' : '<div class="form-help">当前后端不提供自动发现观察记录。</div>'}</div>
		</div>
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
	if (mode === 'unset' || mode === 'port' || mode === 'path' || mode === 'host' || mode === 'both') return mode;
	return site && String(site.public_host || '').trim() ? 'host' : 'port';
}

function ingressFormState(mode) {
	const normalized = ['unset', 'port', 'path', 'host', 'both'].includes(mode) ? mode : 'host';
	if (normalized === 'unset') {
		return {
			mode: normalized,
			showPublicHost: false,
			requirePublicHost: false,
			requireListenPort: false,
			showPathPrefix: false,
			requirePathPrefix: false,
			portLabel: '监听端口',
			warning: '该站点来自其他服务器，原入口不适用于当前环境。请选择可用入口并保存后再启用。',
		};
	}
	return {
		mode: normalized,
		showPublicHost: normalized === 'host' || normalized === 'both',
		requirePublicHost: normalized === 'host' || normalized === 'both',
		showPathPrefix: normalized === 'path',
		requirePathPrefix: normalized === 'path',
		requireListenPort: normalized === 'port' || normalized === 'both',
		portLabel: normalized === 'host' || normalized === 'path' ? '独立端口（可选，自动分配）' : '监听端口',
		warning: normalized === 'port'
			? '独立端口会绑定所有网络接口；公网部署时请配置防火墙。'
			: normalized === 'path'
				? '路径入口复用面板域名和端口，例如 https://panel.example.com/emby/。客户端服务器地址需要包含该路径。'
			: normalized === 'both'
				? '兼容模式会同时开放独立端口和共享域名，建议迁移到单一入口。'
				: '域名前缀通过面板端口转发，不会绑定站点端口，例如 https://123.example.com:9090。请先在 TLS 页配置面板域名、泛域名并申请证书，完成后再启用。',
	};
}

function buildIngressPayload(mode, port, publicHost, routePrefix, routeDomain, pathPrefix) {
	const state = ingressFormState(mode);
	const parsedPort = parseInt(port, 10);
	const prefix = String(routePrefix || '').trim().toLowerCase();
	const generatedHost = state.showPublicHost && prefix && routeDomain
		? `${prefix}.${String(routeDomain).trim().toLowerCase()}`
		: String(publicHost || '').trim();
	return {
		ingress_mode: state.mode,
		listen_port: Number.isInteger(parsedPort) ? parsedPort : 0,
		public_host: state.showPublicHost ? generatedHost : '',
		path_prefix: state.showPathPrefix ? String(pathPrefix || '').trim() : '',
		...(state.showPublicHost && prefix ? { route_prefix: prefix } : {}),
	};
}

function defaultIngressMode(capabilities) {
	if (!capabilities) return 'host';
	if (capabilities.host_only_available === false) return 'port';
	if (capabilities.domain_prefix_available !== true) return 'port';
	if (capabilities.panel_tls_enabled !== true) return 'port';
	return 'host';
}

function siteAccessAddress(site, capabilities) {
	const mode = normalizedIngressMode(site);
	const locationObject = typeof window !== 'undefined' && window.location
		? window.location
		: { protocol: 'http:', hostname: '127.0.0.1', port: '' };
	const protocol = capabilities && capabilities.panel_tls_enabled ? 'https' : locationObject.protocol.replace(':', '') || 'http';
	if (mode === 'port') {
		const host = locationObject.hostname || '127.0.0.1';
		return `${protocol}://${host}:${Number(site.listen_port) || ''}`;
	}
	if (mode === 'path') {
		// Path ingress is reached through the same public origin the operator is
		// currently using. The configured panel listener may be loopback or an
		// internal reverse-proxy upstream and must never leak into the address.
		const base = `${locationObject.protocol || `${protocol}:`}//${locationObject.host || locationObject.hostname || '127.0.0.1'}`.replace(/\/$/, '');
		const prefix = String(site.path_prefix || '').trim().replace(/^\/+|\/+$/g, '');
		return prefix ? `${base}/${prefix}/` : '';
	}
	const host = String(site.public_host || '').trim();
	const panelPort = locationObject.port || (protocol === 'https' ? '443' : '80');
	return host ? `${protocol}://${host}:${panelPort}` : '';
}

function toggleSiteAccessAddress(button) {
	const row = button.closest('.site-access-row');
	const value = row && row.querySelector('[data-access-address]');
	if (!value) return;
	const hidden = value.classList.toggle('is-hidden');
	value.textContent = hidden ? '********' : value.dataset.accessAddress;
	button.setAttribute('aria-label', hidden ? '显示访问地址' : '隐藏访问地址');
	button.setAttribute('title', hidden ? '显示访问地址' : '隐藏访问地址');
}

async function copySiteAccessAddress(button) {
	const row = button.closest('.site-access-row');
	const value = row && row.querySelector('[data-access-address]');
	const address = String(value && value.dataset.accessAddress || '').trim();
	if (!address) {
		Toast.error('当前站点没有可复制的访问地址');
		return;
	}

	try {
		if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
			await navigator.clipboard.writeText(address);
		} else {
			if (typeof document === 'undefined' || typeof document.execCommand !== 'function') throw new Error('clipboard unavailable');
			const input = document.createElement('textarea');
			input.value = address;
			input.setAttribute('readonly', '');
			input.style.position = 'fixed';
			input.style.opacity = '0';
			document.body.appendChild(input);
			input.select();
			const copied = document.execCommand('copy');
			input.remove();
			if (!copied) throw new Error('copy failed');
		}
		Toast.success('访问地址已复制');
	} catch (_) {
		Toast.error('复制失败，请手动复制访问地址');
	}
}

let siteIngressCapabilities = normalizeSiteCapabilities({});

function siteIngressModeLabel(site) {
	const labels = { unset: '入口未配置', port: '独立端口', path: '路径', host: '域名前缀', both: '域名前缀（兼容）' };
	return labels[normalizedIngressMode(site)] || labels.unset;
}

function routePrefixForSite(site, routeDomain) {
	if (!site || normalizedIngressMode(site) !== 'host') return '';
	const host = String(site.public_host || '').trim().toLowerCase();
	const domain = String(routeDomain || '').trim().toLowerCase();
	if (!host || !domain || !host.endsWith(`.${domain}`)) return '';
	const prefix = host.slice(0, -(domain.length + 1));
	return prefix.includes('.') ? '' : prefix;
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

function renderPanelCertificateStatus(status) {
	if (!status || status.available === false) {
		return '<div class="form-help" style="color:var(--orange)">TLS 数据目录不可写，请检查数据库所在数据目录的权限。</div>';
	}
	if (!status.configured) {
		return '<div class="form-help">尚未申请证书。请先保存域名设置，再点击“申请证书”。</div>';
	}
	return `
	  <div class="diag-row"><span class="diag-key">证书域名</span><span class="diag-val">${esc(status.subject || `*.${status.route_domain || ''}`)}</span></div>
	  <div class="diag-row"><span class="diag-key">证书匹配</span><span class="diag-val ${status.certificate_current ? 'good' : 'warn'}">${status.certificate_current ? '泛域名一致' : '需要申请或更新'}</span></div>
	  <div class="diag-row"><span class="diag-key">到期时间</span><span class="diag-val">${esc(status.expires_at || '—')}</span></div>
	  <div class="diag-row"><span class="diag-key">证书状态</span><span class="diag-val ${status.certificate_valid ? 'good' : 'warn'}">${status.certificate_valid ? '有效' : '已过期或不可用'}</span></div>
	  <div class="diag-row"><span class="diag-key">自动续签</span><span class="diag-val ${status.auto_renew_enabled ? 'good' : 'warn'}">${status.auto_renew_enabled ? '已启用（到期前 30 天）' : '待配置邮箱和 Token'}</span></div>
	  <div class="diag-row"><span class="diag-key">当前监听端口</span><span class="diag-val">${esc(String(status.active_listen_port || '—'))}</span></div>
	  <div class="diag-row"><span class="diag-key">设置监听端口</span><span class="diag-val ${status.listen_port !== status.active_listen_port ? 'warn' : ''}">${esc(String(status.listen_port || '—'))}</span></div>
	  <div class="diag-row"><span class="diag-key">面板 HTTPS</span><span class="diag-val ${status.restart_required ? 'warn' : 'good'}">${status.restart_required ? '等待重启应用' : '已启用'}</span></div>
	`;
}

function panelHTTPSPreview(panelDomain) {
	const port = window.location.port;
	return panelDomain ? `https://${panelDomain}${port && port !== '443' ? `:${port}` : ''}` : '—';
}

function panelDomainFromForm() {
	const prefix = document.getElementById('m-panel-prefix').value.trim().replace(/^\*\./, '');
	const wildcard = document.getElementById('m-wildcard-domain').value.trim().replace(/^\*\./, '');
	return prefix && wildcard ? `${prefix}.${wildcard}` : '';
}

async function waitForPanelRestart(redirectURL) {
	const deadline = Date.now() + 90000;
	while (Date.now() < deadline) {
		try {
			await fetch(`${redirectURL}/api/auth/check`, { mode: 'no-cors', cache: 'no-store' });
			window.location.replace(redirectURL);
			return;
		} catch (_) {
			await new Promise(resolve => setTimeout(resolve, 1500));
		}
	}
	Toast.error('服务重启超时，请稍后手动打开新的 HTTPS 地址');
}

async function showPanelCertificateModal() {
	let status;
	try {
		status = await API.panelCertificate();
	} catch (error) {
		Toast.error(`无法读取证书状态：${error.message}`);
		return;
	}
	document.getElementById('modal-title').textContent = 'TLS 证书';
	document.getElementById('modal-body').innerHTML = `
	  <div id="m-panel-certificate-status">${renderPanelCertificateStatus(status)}</div>
	  <div class="form-group" style="margin-top:18px">
	    <label>面板访问域名前缀</label>
	    <input type="text" class="form-input" id="m-panel-prefix" maxlength="63" value="${esc(status.panel_prefix || '')}" placeholder="panel" autocomplete="off" autocapitalize="none" spellcheck="false">
	    <div class="form-help">只需填写前缀，例如 <code>panel</code>，不要填写完整域名。</div>
	  </div>
	  <div class="form-group">
	    <label>节点泛域名</label>
	    <input type="text" class="form-input" id="m-wildcard-domain" maxlength="255" value="${esc(status.wildcard_domain || (status.route_domain ? `*.${status.route_domain}` : ''))}" placeholder="*.example.com" autocomplete="off" autocapitalize="none" spellcheck="false">
	    <div class="form-help">仅使用泛域名申请证书，例如 <code>*.example.com</code>；请提前将泛域名解析到本机。</div>
	  </div>
	  <div class="form-group">
	    <label>启用后的面板地址</label>
	    <div class="form-help" id="m-panel-address-preview">${esc(panelHTTPSPreview(status.panel_domain || ''))}</div>
	  </div>
	  <div class="form-group">
	    <label>面板监听端口</label>
	    <input type="number" class="form-input" id="m-panel-listen-port" min="1" max="65535" step="1" value="${esc(String(status.listen_port || status.active_listen_port || 9090))}">
	    <div class="form-help">修改端口后需要重启面板；Docker 请使用 host 网络，并在宿主机防火墙中放行新端口。</div>
	  </div>
	  <div class="form-group">
	    <label>ACME 邮箱</label>
	    <input type="email" class="form-input" id="m-acme-email" autocomplete="email" maxlength="254" value="${esc(status.acme_email || '')}" placeholder="admin@example.com">
	    <div class="form-help">邮箱会直接显示在面板中，用于 ACME 账户与证书续签通知。</div>
	  </div>
	  <div class="form-group">
	    <label>DNS 服务商</label>
	    <select class="form-select modal-select" id="m-acme-provider"><option value="cloudflare">Cloudflare DNS</option></select>
	  </div>
	  <div class="form-group">
	    <label>DNS API Token</label>
	    <input type="text" class="form-input mono" id="m-acme-token" autocomplete="off" maxlength="512" value="${esc(status.dns_api_token || '')}" placeholder="Cloudflare DNS API Token">
	    <div class="form-help">Token 会直接显示给已登录管理员；数据库中仍加密保存，并用于证书自动续签。</div>
	  </div>
	  <label style="display:flex;align-items:center;gap:8px;margin-top:10px;color:var(--white-60);font-size:.82rem">
	    <input type="checkbox" id="m-acme-staging" ${status.acme_staging ? 'checked' : ''}>
	    <span>ACME 测试环境</span>
	  </label>
	`;
	document.getElementById('modal-footer').innerHTML = `
	  <button class="btn-modal" id="m-cert-cancel">关闭</button>
	  ${status.restart_required && ((status.configured && status.certificate_current) || (!status.configured && status.listen_port !== status.active_listen_port)) ? `<button class="btn-modal primary" id="m-cert-restart">${status.configured ? '启用 HTTPS 并重启' : '重启应用'}</button>` : ''}
	  <button class="btn-modal" id="m-cert-save">保存设置</button>
	  <button class="btn-modal primary" id="m-cert-issue" ${status.available === false || status.issuing || !status.settings_configured ? 'disabled' : ''}>申请证书</button>
	`;
	const refreshPreview = () => {
		const domain = panelDomainFromForm();
		const port = Number(document.getElementById('m-panel-listen-port').value) || 9090;
		document.getElementById('m-panel-address-preview').textContent = domain ? `https://${domain}${port === 443 ? '' : `:${port}`}` : '—';
	};
	document.getElementById('m-panel-prefix').addEventListener('input', refreshPreview);
	document.getElementById('m-wildcard-domain').addEventListener('input', refreshPreview);
	document.getElementById('m-panel-listen-port').addEventListener('input', refreshPreview);
	document.getElementById('m-cert-cancel').onclick = closeModal;
	const restartButton = document.getElementById('m-cert-restart');
	if (restartButton) restartButton.onclick = async () => {
		if (!window.confirm('重启会短暂中断面板和所有站点连接，确定现在重启吗？')) return;
		restartButton.disabled = true;
		restartButton.textContent = '正在重启…';
		try {
			const result = await API.restartSystem();
			Toast.success('重启请求已发送，正在等待 HTTPS 服务恢复');
			await waitForPanelRestart(result.redirect_url);
		} catch (error) {
			restartButton.disabled = false;
			restartButton.textContent = '启用 HTTPS 并重启';
			Toast.error(error.message);
		}
	};
	const settingsPayload = () => ({
		panel_prefix: document.getElementById('m-panel-prefix').value.trim(),
		wildcard_domain: document.getElementById('m-wildcard-domain').value.trim(),
		listen_port: Number(document.getElementById('m-panel-listen-port').value),
	});
	document.getElementById('m-cert-save').onclick = async () => {
		const button = document.getElementById('m-cert-save');
		const payload = settingsPayload();
		if (!payload.panel_prefix || !payload.wildcard_domain || !Number.isInteger(payload.listen_port) || payload.listen_port < 1 || payload.listen_port > 65535) {
			Toast.error('请填写面板前缀、泛域名和有效监听端口');
			return;
		}
		button.disabled = true;
		button.textContent = '保存中…';
		try {
			await API.savePanelSettings(payload);
			Toast.success('面板设置已保存；证书不会因修改前缀而重新申请');
			closeModal();
			await showPanelCertificateModal();
		} catch (error) {
			button.disabled = false;
			button.textContent = '保存设置';
			Toast.error(error.message);
		}
	};
	document.getElementById('m-cert-issue').onclick = async () => {
		const button = document.getElementById('m-cert-issue');
		const tokenInput = document.getElementById('m-acme-token');
		const settingsPayloadValue = settingsPayload();
		const savedWildcard = String(status.wildcard_domain || '').toLowerCase().replace(/^\*\./, '');
		const formWildcard = settingsPayloadValue.wildcard_domain.toLowerCase().replace(/^\*\./, '');
		if (settingsPayloadValue.panel_prefix !== status.panel_prefix || formWildcard !== savedWildcard || settingsPayloadValue.listen_port !== Number(status.listen_port)) {
			Toast.error('请先点击“保存设置”，再申请证书');
			return;
		}
		const payload = {
			email: document.getElementById('m-acme-email').value.trim(),
			dns_provider: document.getElementById('m-acme-provider').value,
			dns_api_token: tokenInput.value.trim(),
			staging: document.getElementById('m-acme-staging').checked,
		};
		if (!payload.email || !payload.dns_api_token) {
			Toast.error('请填写 ACME 邮箱和 DNS API Token');
			return;
		}
		button.disabled = true;
		button.textContent = '申请中…';
		try {
			const updated = await API.requestPanelCertificate(payload);
			Toast.success(updated.certificate_reused ? '泛域名未改变，继续使用现有证书' : (updated.restart_required ? '证书已签发，请点击重启按钮' : '证书已签发并热加载'));
			closeModal();
			await showPanelCertificateModal();
		} catch (error) {
			button.disabled = false;
			button.textContent = '申请证书';
			Toast.error(error.message);
		}
	};
	openModal({ closeOnBackdrop: false });
}

async function showSiteModal(site) {
  const isEdit = !!site;
  const title = isEdit ? '编辑站点' : '添加站点';
	let siteCapabilities;
	let dynamicCapabilities;
	try {
		[siteCapabilities, dynamicCapabilities] = await Promise.all([
			API.ingressCapabilities().then(normalizeSiteCapabilities),
			loadDynamicProfiles(),
		]);
	} catch (error) {
		Toast.error(`无法读取站点能力：${error.message}`);
		return;
	}
	dynamicCapabilities = normalizeDynamicProfiles(dynamicCapabilities);
	const hostOnlyAvailable = siteCapabilities.host_only_available;
	const upstreamHeadersAvailable = siteCapabilities.upstream_headers_available;
	const domainPrefixAvailable = siteCapabilities.domain_prefix_available === true;
	const panelTLSReady = siteCapabilities.panel_tls_enabled === true;
	const canUseHostIngress = hostOnlyAvailable && domainPrefixAvailable && (panelTLSReady || (isEdit && String(site.public_host || '').trim() !== ''));
	const splitTargetAddress = value => {
		const raw = String(value || '').trim();
		if (!raw) return { address: '', port: '' };
		const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
		try {
			const parsed = new URL(explicitScheme ? raw : `http://${raw}`);
			const defaultPort = parsed.protocol === 'https:' ? '443' : '80';
			const hostname = parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname;
			const path = `${parsed.pathname === '/' ? '' : parsed.pathname}${parsed.search}${parsed.hash}`;
			return {
				address: `${explicitScheme ? `${parsed.protocol}//` : ''}${hostname}${path}`,
				port: parsed.port || defaultPort,
			};
		} catch (_) {
			return { address: raw, port: '' };
		}
	};
	const joinTargetAddress = (address, port) => {
		const rawAddress = String(address || '').trim();
		const rawPort = String(port || '').trim();
		if (!rawAddress) return '';
		const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawAddress);
		try {
			const parsed = new URL(explicitScheme ? rawAddress : `http://${rawAddress}`);
			parsed.port = rawPort;
			const normalized = parsed.toString().replace(/\/$/, parsed.pathname === '/' && !parsed.search && !parsed.hash ? '' : '/');
			return explicitScheme ? normalized : normalized.replace(/^http:\/\//i, '');
		} catch (_) {
			return rawPort ? `${rawAddress.replace(/:\d+$/, '')}:${rawPort}` : rawAddress;
		}
	};
	const primaryTargetParts = splitTargetAddress(isEdit ? site.target_url : '');
	const hostIngressBlockedHint = !hostOnlyAvailable
		? '当前面板未满足安全的域名前缀转发条件，请先设置 PANEL_BIND_ADDR 或 TRUSTED_PROXY_CIDRS 并重启。'
		: !domainPrefixAvailable
			? '域名前缀通过面板端口转发，不会绑定站点端口，例如 https://123.example.com:9090。请配置 PANEL_ROUTE_DOMAIN。'
			: !panelTLSReady
				? '请先在 TLS 页配置面板域名、泛域名并申请证书，完成后才能启用域名前缀。'
				: '';
	const dynamicPolicy = normalizeDynamicSitePolicy(isEdit ? site : {
		dynamic_discovery_enabled: true,
		dynamic_profile: 'compatible',
		dynamic_discovery_sources: [...DEFAULT_DYNAMIC_SOURCE_IDS, ...ADVANCED_DYNAMIC_SOURCE_IDS],
		dynamic_domain_rules: [],
		dynamic_allow_https_downgrade: true,
	});
	let dynamicRules = [...dynamicPolicy.dynamic_domain_rules];
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = `
    <div class="form-group">
      <label>站点名称</label>
      <input type="text" class="form-input" id="m-name" value="${isEdit ? esc(site.name) : ''}" placeholder="如：Emby-US-01" maxlength="100" required>
    </div>
	<div class="form-group">
	  <label>入口模式</label>
	  <select class="form-select modal-select" id="m-ingress-mode">
		${isEdit && normalizedIngressMode(site) === 'unset' ? '<option value="unset" disabled>未配置（请选择）</option>' : ''}
		<option value="host" ${canUseHostIngress ? '' : 'disabled'}>域名前缀（推荐${canUseHostIngress ? '' : '，需先配置 TLS 和域名'}）</option>
		<option value="path">路径</option>
		<option value="port">独立端口</option>
	  </select>
	  <div class="form-help" id="m-ingress-warning"></div>
	  ${hostIngressBlockedHint ? `<div class="form-help">${hostIngressBlockedHint}</div>` : ''}
	</div>
	<div class="form-group" id="m-port-group">
	  <label id="m-port-label">监听端口</label>
	  <input type="number" class="form-input" id="m-port" value="${isEdit && ['port', 'both'].includes(normalizedIngressMode(site)) ? site.listen_port : ''}" placeholder="如：8001" min="1" max="65535" inputmode="numeric">
	  <div class="form-help" id="m-port-help"></div>
	</div>
	<div class="form-group" id="m-public-host-group">
	  <label>域名前缀</label>
	  <input type="text" class="form-input" id="m-route-prefix" value="${isEdit ? esc(routePrefixForSite(site, siteCapabilities.route_domain)) : ''}" placeholder="如：123" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="63">
	  <input type="hidden" id="m-public-host" value="${isEdit ? esc(site.public_host || '') : ''}">
	  <div class="form-help">访问地址为 https://前缀.${esc(siteCapabilities.route_domain || 'example.com')}:${esc(String((typeof window !== 'undefined' && window.location && window.location.port) || '9090'))}，由面板端口统一转发。</div>
	</div>
	<div class="form-group" id="m-path-prefix-group" hidden>
	  <label>路径前缀</label>
	  <input type="text" class="form-input" id="m-path-prefix" value="${isEdit ? esc(String(site.path_prefix || '').replace(/^\//, '')) : ''}" placeholder="如：emby" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="64">
	  <div class="form-help">只填写一段路径，系统会自动补全为 /emby/；不能使用 api、js、css、_meridian 等系统路径。</div>
	</div>
	<div class="form-group upstream-lines-card">
	  <div class="upstream-lines-head">
	    <div><label>线路列表</label><div class="form-help">主线路失败时按顺序切换，恢复后自动回切。</div></div>
	    <div class="upstream-lines-buttons">
	      <button type="button" class="btn-ghost upstream-test-all" id="m-test-all-lines">线路测速</button>
	      <button type="button" class="btn-add upstream-add-line" id="m-add-failover-line">+ 添加线路</button>
	    </div>
	  </div>
	  <div class="upstream-lines" id="m-upstream-lines">
	    <div class="upstream-line is-primary" data-line="primary">
	      <label class="upstream-line-enabled"><input type="checkbox" checked disabled><span>主</span></label>
	      <div class="upstream-line-field" data-label="线路名称"><input type="text" class="form-input upstream-line-name" id="m-primary-line-name" value="${esc(isEdit ? (site.primary_line_name || '主线路') : '主线路')}" maxlength="100" aria-label="主线路名称"></div>
	      <div class="upstream-line-field" data-label="协议与域名 / 路径"><input type="text" class="form-input upstream-line-address" id="m-target-address" value="${esc(primaryTargetParts.address)}" placeholder="https://emby.example.com" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048" required aria-label="主回源域名或地址"></div>
	      <div class="upstream-line-field" data-label="端口"><input type="number" class="form-input upstream-line-port" id="m-target-port" value="${esc(primaryTargetParts.port)}" placeholder="443" min="1" max="65535" inputmode="numeric" required aria-label="主回源端口"></div>
	      <span class="upstream-line-latency" data-label="延迟">--</span>
	      <div class="upstream-line-actions primary-actions" data-label="线路状态"><span class="upstream-line-primary-note">主线路</span></div>
	      <input type="hidden" id="m-target">
	    </div>
	    <div id="m-failover-lines"></div>
	  </div>
	  <div class="form-help">域名可包含协议和 Base URL 路径；端口单独填写。最多 7 条备用线路。</div>
	</div>
		<div class="form-group site-form-wide">
		  <label>主回源固定请求头（可选）</label>
		  <div id="m-upstream-headers"></div>
		  <button type="button" class="btn-ghost upstream-header-add" id="m-add-upstream-header" ${upstreamHeadersAvailable ? '' : 'disabled'}>+ 添加请求头</button>
		  <div class="form-help">使用 UPSTREAM_HEADER_KEY 加密保存，不会回显；仅发送到主回源。</div>
		  ${upstreamHeadersAvailable ? '' : '<div class="form-help" style="color:var(--orange)">当前部署未配置 UPSTREAM_HEADER_KEY，不能新增、重命名或修改 Header 值；仍可删除旧配置。配置密钥并重启后可恢复编辑。</div>'}
		</div>
		<div class="form-group site-form-wide site-dynamic-card">
		  <div class="site-feature-heading"><div><label>自动发现</label>${renderDynamicStatus(dynamicCapabilities)}</div><span class="site-feature-badge">播放兼容</span></div>
		  <div class="site-dynamic-row">
		    ${renderDynamicEnableControl(dynamicCapabilities, dynamicPolicy)}
		    <label class="site-dynamic-profile"><span>模式</span><select class="form-select modal-select" id="m-dynamic-profile" ${dynamicCapabilities.recognized ? '' : 'disabled'}>${renderDynamicProfileOptions(dynamicCapabilities, dynamicPolicy.dynamic_profile)}</select></label>
		  </div>
		  <div class="site-dynamic-sources" id="m-dynamic-sources" ${dynamicCapabilities.recognized ? '' : 'hidden'}>
		    <span class="site-dynamic-label">处理来源</span>
		    ${DYNAMIC_SOURCE_IDS.map(source => `<label><input type="checkbox" id="m-dynamic-source-${source}" data-dynamic-source="${source}" ${dynamicPolicy.dynamic_discovery_sources.includes(source) ? 'checked' : ''}>${DYNAMIC_SOURCE_LABELS[source]}</label>`).join('')}
		  </div>
		  <div class="site-dynamic-help" id="m-dynamic-help">兼容模式默认处理 HTTP 30x、PlaybackInfo、HLS 和 DASH；仍拒绝私网与回环目标。</div>
		  <div class="site-dynamic-extreme" id="m-dynamic-extreme-confirm" hidden>
		    <label class="site-dynamic-check"><input type="checkbox" id="m-dynamic-extreme-ack"><span>我了解 Extreme 会放宽动态兼容范围</span></label>
		    <input type="text" class="form-input" id="m-dynamic-extreme-name" placeholder="输入站点名称确认" autocomplete="off">
		  </div>
		  <details class="site-dynamic-advanced">
		    <summary>安全规则与观察记录</summary>
		    <div class="site-dynamic-advanced-body">
		      <label class="site-dynamic-check"><input type="checkbox" id="m-dynamic-downgrade" ${dynamicPolicy.dynamic_allow_https_downgrade ? 'checked' : ''}><span>允许 HTTPS 回源降级到 HTTP</span></label>
		      <div class="form-help">仅兼容模式生效；Safe 模式始终禁止。</div>
		      <div class="site-dynamic-rules-head"><span>Safe 域名规则</span><button type="button" class="btn-ghost" id="m-add-dynamic-rule">添加规则</button></div>
		      <div id="m-dynamic-rules"></div>
		      ${isEdit ? renderDynamicObservationsPanel(dynamicCapabilities.recognized && dynamicCapabilities.available) : ''}
		    </div>
		  </details>
		</div>
	    <details class="site-advanced-card site-form-wide" open>
      <summary class="site-advanced-summary">
        <span>高级设置</span>
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
      </summary>
      <div class="site-advanced-body">
      <div class="site-settings-grid">
    <div class="form-group">
      <label>UA 模式</label>
      <select class="form-select modal-select" id="m-ua">
        <option value="passthrough" ${(!isEdit || site.ua_mode === 'passthrough') ? 'selected' : ''}>透传（保留客户端身份）</option>
        <option value="infuse" ${isEdit && site.ua_mode === 'infuse' ? 'selected' : ''}>Infuse</option>
        <option value="web" ${isEdit && site.ua_mode === 'web' ? 'selected' : ''}>Web</option>
        <option value="client" ${isEdit && site.ua_mode === 'client' ? 'selected' : ''}>客户端</option>
        <option value="custom">自定义客户端</option>
      </select>
    </div>
    <div class="form-group" id="m-custom-ua-group" hidden>
      <label>自定义身份</label>
      <input type="text" class="form-input" id="m-custom-ua" placeholder="User-Agent" maxlength="1024" autocapitalize="none" autocorrect="off" spellcheck="false">
      <input type="text" class="form-input" id="m-custom-client" placeholder="Emby Client" maxlength="128" autocapitalize="none" autocorrect="off" spellcheck="false" style="margin-top:8px">
      <input type="text" class="form-input" id="m-custom-version" placeholder="Emby Version" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false" style="margin-top:8px">
      <div class="form-help">只改写 User-Agent、Client、Version；Device 与 DeviceId 保持不变。</div>
    </div>
    <div class="form-group">
      <label>真实客户端 IP 透传</label>
      <select class="form-select modal-select" id="m-client-ip-mode">
        <option value="both" ${!isEdit || !site.client_ip_mode || site.client_ip_mode === 'both' ? 'selected' : ''}>透传 X-Real-IP 和 X-Forwarded-For（推荐）</option>
        <option value="real_ip" ${isEdit && site.client_ip_mode === 'real_ip' ? 'selected' : ''}>仅保留 X-Real-IP</option>
        <option value="none" ${isEdit && site.client_ip_mode === 'none' ? 'selected' : ''}>强制不透传（慎用）</option>
      </select>
      <div class="form-help">与 UA 模式独立；仅影响发往回源的 X-Real-IP 与 X-Forwarded-For。</div>
    </div>
    <div class="form-group">
      <label>主视频流策略</label>
      <select class="form-select modal-select" id="m-main-video-mode">
        <option value="proxy" ${!isEdit || site.main_video_stream_mode !== 'direct' ? 'selected' : ''}>反代</option>
        <option value="direct" ${isEdit && site.main_video_stream_mode === 'direct' ? 'selected' : ''}>直连</option>
      </select>
      <div class="form-help">直连仅适用于主视频文件；面板、API、HLS/DASH 等仍由 Meridian 代理。</div>
      <div class="form-help">自动发现保持启用；私网、回环和链路本地目标始终拒绝。</div>
    </div>
    <section class="form-group cache-limit-group" data-cache-panel aria-labelledby="m-cache-panel-title">
      <div class="site-cache-panel-heading">
        <div>
          <h3 id="m-cache-panel-title">缓存图片与静态资源</h3>
          <p>仅缓存图片与静态资源；视频、音频、HLS/DASH、Range 和私有响应不缓存。</p>
        </div>
        <select class="form-select modal-select" id="m-asset-cache" aria-label="缓存图片与静态资源">
          <option value="off" ${!isEdit || !site.asset_cache_enabled ? 'selected' : ''}>关闭</option>
          <option value="on" ${isEdit && site.asset_cache_enabled ? 'selected' : ''}>开启</option>
        </select>
      </div>
      <div class="site-cache-options" id="m-cache-options" hidden>
        <details class="site-cache-rules-group" id="m-cache-rules-group">
          <summary>自定义缓存规则（可选）</summary>
          <div class="site-cache-rules-body">
            <textarea class="form-input" id="m-cache-rules" rows="3" maxlength="4096" spellcheck="false">${esc(isEdit ? (site.asset_cache_rules || '*/file/*\n*/emby/Items/*/Images/*') : '*/file/*\n*/emby/Items/*/Images/*')}</textarea>
            <div class="form-help">仅在需要覆盖默认的图片和静态资源路径时修改；每行一条，支持 * 通配。</div>
          </div>
        </details>
        <div class="cache-limit-grid">
          <label for="m-cache-ttl">缓存时间（小时）</label>
          <input type="number" class="form-input" id="m-cache-ttl" min="1" max="720" value="${isEdit ? Math.max(1, Math.round((site.asset_cache_ttl_sec || 86400) / 3600)) : 24}">
          <label for="m-cache-max">容量上限（MB）</label>
          <input type="number" class="form-input" id="m-cache-max" min="1" max="20480" value="${isEdit ? Math.max(1, Math.round((site.asset_cache_max_bytes || 536870912) / 1048576)) : 512}">
        </div>
      </div>
    </section>
    <div class="form-group">
      <label>流量额度 (GB, 0=不限)</label>
      <input type="number" class="form-input" id="m-quota" value="${isEdit ? Math.round((site.traffic_quota || 0) / 1073741824) : 0}" placeholder="0" min="0" inputmode="numeric">
    </div>
    <div class="form-group">
      <label>单连接限速 (Mbps, 0=不限)</label>
      <input type="number" class="form-input" id="m-speed" value="${isEdit ? (site.speed_limit || 0) : 0}" placeholder="0" min="0" max="1000000" step="1" inputmode="numeric">
      <div class="form-help">限制单个连接的下行速度，上传不受影响。</div>
      </div>
      </div>
    </details>
  `;

  document.getElementById('modal-footer').innerHTML = `
    <button class="btn-modal secondary" id="m-cancel">取消</button>
    <button class="btn-modal primary" id="m-submit">${isEdit ? '保存' : '创建'}</button>
  `;

	document.getElementById('m-cancel').addEventListener('click', closeModal);

	const failoverLinesContainer = document.getElementById('m-failover-lines');
	let failoverLines = isEdit && Array.isArray(site.failover_lines)
		? site.failover_lines.map(line => ({ name: String(line.name || ''), url: String(line.url || ''), enabled: line.enabled !== false, ...splitTargetAddress(line.url) }))
		: (isEdit && Array.isArray(site.failover_targets)
			? site.failover_targets.map((url, index) => ({ name: `线路${index + 2}`, url: String(url || ''), enabled: true, ...splitTargetAddress(url) }))
			: []);

	function lineActionIcon(kind) {
		if (kind === 'up') return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m18 15-6-6-6 6"/></svg>';
		if (kind === 'down') return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
		if (kind === 'remove') return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2m-9 0 1 14h8l1-14M10 10v6m4-6v6"/></svg>';
		return '';
	}

	function renderFailoverLines() {
		failoverLinesContainer.innerHTML = failoverLines.map((line, index) => `
		  <div class="upstream-line" data-line-index="${index}">
		    <label class="upstream-line-enabled"><input type="checkbox" class="upstream-line-toggle" ${line.enabled ? 'checked' : ''}><span>${line.enabled ? '开' : '关'}</span></label>
		    <div class="upstream-line-field" data-label="线路名称"><input type="text" class="form-input upstream-line-name" value="${esc(line.name)}" placeholder="线路${index + 2}" maxlength="100" aria-label="备用线路名称"></div>
		    <div class="upstream-line-field" data-label="协议与域名 / 路径"><input type="text" class="form-input upstream-line-address" value="${esc(line.address)}" placeholder="https://backup.example.com" maxlength="2048" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" aria-label="备用线路域名或地址"></div>
		    <div class="upstream-line-field" data-label="端口"><input type="number" class="form-input upstream-line-port" value="${esc(line.port)}" placeholder="443" min="1" max="65535" inputmode="numeric" aria-label="备用线路端口"></div>
		    <span class="upstream-line-latency" data-label="延迟">--</span>
		    <div class="upstream-line-actions" data-label="排序 / 删除">
		      <button type="button" class="icon-button upstream-line-move-up" title="上移" aria-label="上移" ${index === 0 ? 'disabled' : ''}>${lineActionIcon('up')}</button>
		      <button type="button" class="icon-button upstream-line-move-down" title="下移" aria-label="下移" ${index === failoverLines.length - 1 ? 'disabled' : ''}>${lineActionIcon('down')}</button>
		      <button type="button" class="icon-button upstream-line-remove" title="删除线路" aria-label="删除线路">${lineActionIcon('remove')}</button>
		    </div>
		  </div>`).join('');

		failoverLinesContainer.querySelectorAll('.upstream-line').forEach(row => {
			const index = Number(row.dataset.lineIndex);
			row.querySelector('.upstream-line-toggle').onchange = event => {
				failoverLines[index].enabled = event.target.checked;
				renderFailoverLines();
			};
			row.querySelector('.upstream-line-name').oninput = event => { failoverLines[index].name = event.target.value; };
			row.querySelector('.upstream-line-address').oninput = event => { failoverLines[index].address = event.target.value; };
			row.querySelector('.upstream-line-port').oninput = event => { failoverLines[index].port = event.target.value; };
			row.querySelector('.upstream-line-move-up').onclick = () => {
				[failoverLines[index - 1], failoverLines[index]] = [failoverLines[index], failoverLines[index - 1]];
				renderFailoverLines();
			};
			row.querySelector('.upstream-line-move-down').onclick = () => {
				[failoverLines[index + 1], failoverLines[index]] = [failoverLines[index], failoverLines[index + 1]];
				renderFailoverLines();
			};
			row.querySelector('.upstream-line-remove').onclick = () => {
				failoverLines.splice(index, 1);
				renderFailoverLines();
			};
		});
	}

	async function testUpstreamLine(row, addressInput, portInput) {
		const latency = row.querySelector('.upstream-line-latency');
		const targetURL = joinTargetAddress(addressInput.value, portInput.value);
		if (!targetURL) {
			latency.textContent = '请填写地址';
			latency.className = 'upstream-line-latency bad';
			return;
		}
		latency.textContent = '测试中…';
		latency.className = 'upstream-line-latency';
		try {
			const result = await API.testUpstream(targetURL);
			if (result && result.status === 'online') {
				const latencyMs = Number(result.latency_ms);
				if (!Number.isFinite(latencyMs) || latencyMs < 0) throw new Error('测速结果无效');
				latency.textContent = `${latencyMs} ms`;
				latency.className = `upstream-line-latency ${latencyMs < 200 ? 'good' : latencyMs < 800 ? 'warn' : 'bad'}`;
			} else {
				throw new Error((result && result.error) || '线路不可用');
			}
		} catch (error) {
			latency.textContent = '失败';
			latency.className = 'upstream-line-latency bad';
			latency.title = error.message || '线路测试失败';
		}
	}

	renderFailoverLines();
	document.getElementById('m-add-failover-line').onclick = () => {
		if (failoverLines.length >= 7) {
			Toast.error('最多添加 7 条备用线路');
			return;
		}
		failoverLines.push({ name: `线路${failoverLines.length + 2}`, url: '', address: '', port: '', enabled: true });
		renderFailoverLines();
		const inputs = failoverLinesContainer.querySelectorAll('.upstream-line-address');
		if (inputs.length) inputs[inputs.length - 1].focus();
	};
	document.getElementById('m-test-all-lines').onclick = async event => {
		const button = event.currentTarget;
		button.disabled = true;
		button.textContent = '测试中…';
		const rows = [...document.querySelectorAll('#m-upstream-lines .upstream-line')].filter(row => {
			if (row.dataset.line === 'primary') return true;
			const index = Number(row.dataset.lineIndex);
			return failoverLines[index] && failoverLines[index].enabled;
		});
		for (const row of rows) {
			await testUpstreamLine(row, row.querySelector('.upstream-line-address'), row.querySelector('.upstream-line-port'));
		}
		button.disabled = false;
		button.textContent = '线路测速';
	};

	const ingressSelect = document.getElementById('m-ingress-mode');
	const publicHostGroup = document.getElementById('m-public-host-group');
	const publicHostInput = document.getElementById('m-public-host');
	const routePrefixInput = document.getElementById('m-route-prefix');
	const pathPrefixGroup = document.getElementById('m-path-prefix-group');
	const pathPrefixInput = document.getElementById('m-path-prefix');
	const portInput = document.getElementById('m-port');
	const portLabel = document.getElementById('m-port-label');
	const portHelp = document.getElementById('m-port-help');
	const ingressWarning = document.getElementById('m-ingress-warning');
	ingressSelect.value = isEdit ? normalizedIngressMode(site) : defaultIngressMode(siteCapabilities);
	function updateIngressFields() {
		const state = ingressFormState(ingressSelect.value);
		publicHostGroup.hidden = !state.showPublicHost;
		publicHostInput.required = state.requirePublicHost;
		routePrefixInput.required = state.requirePublicHost && domainPrefixAvailable;
		routePrefixInput.disabled = !state.showPublicHost;
		pathPrefixGroup.hidden = !state.showPathPrefix;
		pathPrefixInput.required = state.requirePathPrefix;
		pathPrefixInput.disabled = !state.showPathPrefix;
		portInput.required = state.requireListenPort;
		document.getElementById('m-port-group').hidden = !state.requireListenPort;
		portLabel.textContent = state.portLabel;
		portHelp.textContent = state.requireListenPort
			? '独立端口模式需要填写未被占用的监听端口。'
			: '共享入口不会另外开放站点端口。';
		ingressWarning.textContent = state.warning;
	}
	updateIngressFields();
	ingressSelect.addEventListener('change', updateIngressFields);

	const uaSelect = document.getElementById('m-ua');
  const clientIPModeSelect = document.getElementById('m-client-ip-mode');
  const mainVideoModeSelect = document.getElementById('m-main-video-mode');
  const assetCacheSelect = document.getElementById('m-asset-cache');
  const cacheOptionsGroup = document.getElementById('m-cache-options');
  const cacheRulesGroup = document.getElementById('m-cache-rules-group');
  const customUAGroup = document.getElementById('m-custom-ua-group');
  const customUAInputs = [
    document.getElementById('m-custom-ua'),
    document.getElementById('m-custom-client'),
    document.getElementById('m-custom-version'),
  ];
  const initialUAState = customUAFormState(isEdit ? site.ua_mode : 'passthrough', site);
  uaSelect.value = isEdit && site.ua_mode ? site.ua_mode : 'passthrough';
  clientIPModeSelect.value = isEdit && ['both', 'real_ip', 'none'].includes(site.client_ip_mode) ? site.client_ip_mode : 'both';
  mainVideoModeSelect.value = isEdit && site.main_video_stream_mode === 'direct' ? 'direct' : 'proxy';
  customUAInputs[0].value = initialUAState.customUserAgent;
  customUAInputs[1].value = initialUAState.customClient;
  customUAInputs[2].value = initialUAState.customVersion;

  const syncAssetCacheFields = () => {
    const enabled = assetCacheSelect?.value === 'on';
    if (cacheOptionsGroup) cacheOptionsGroup.hidden = !enabled;
    if (cacheRulesGroup) {
      cacheRulesGroup.hidden = !enabled;
      if (!enabled) cacheRulesGroup.open = false;
    }
  };
  syncAssetCacheFields();
  assetCacheSelect?.addEventListener('change', syncAssetCacheFields);

  function toggleCustomUAFields() {
    const state = customUAFormState(uaSelect.value);
    customUAGroup.hidden = !state.visible;
    if (state.visible) {
      if (typeof customUAGroup.style?.removeProperty === 'function') customUAGroup.style.removeProperty('display');
      else if (customUAGroup.style) customUAGroup.style.display = '';
    } else if (typeof customUAGroup.style?.setProperty === 'function') {
      customUAGroup.style.setProperty('display', 'none', 'important');
    } else if (customUAGroup.style) {
      customUAGroup.style.display = 'none';
    }
    if (typeof customUAGroup.setAttribute === 'function') customUAGroup.setAttribute('aria-hidden', state.visible ? 'false' : 'true');
    customUAInputs.forEach(input => {
      input.required = state.required;
      if (!state.visible) input.value = '';
    });
  }
  toggleCustomUAFields();
  uaSelect.addEventListener('change', toggleCustomUAFields);

  const dynamicEnabledInput = document.getElementById('m-dynamic-enabled');
  const dynamicProfileSelect = document.getElementById('m-dynamic-profile');
  const dynamicSourcesContainer = document.getElementById('m-dynamic-sources');
  const dynamicHelp = document.getElementById('m-dynamic-help');
  const dynamicDowngradeInput = document.getElementById('m-dynamic-downgrade');
  const dynamicRulesContainer = document.getElementById('m-dynamic-rules');
  const dynamicRulesButton = document.getElementById('m-add-dynamic-rule');
  const dynamicInitialPolicy = { ...dynamicPolicy };
  const renderDynamicRules = () => {
    if (!dynamicRulesContainer) return;
    dynamicRulesContainer.innerHTML = renderDynamicRuleRows(dynamicRules);
    dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-type').forEach(input => {
      input.onchange = () => { dynamicRules[Number(input.dataset.idx)].type = input.value; };
    });
    dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-value').forEach(input => {
      input.oninput = () => { dynamicRules[Number(input.dataset.idx)].value = input.value; };
    });
    dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-remove').forEach(button => {
      button.onclick = () => { dynamicRules.splice(Number(button.dataset.idx), 1); renderDynamicRules(); };
    });
  };
  const syncDynamicControls = () => {
    const profile = normalizeDynamicProfile(dynamicProfileSelect?.value || dynamicPolicy.dynamic_profile);
    const allowed = new Set(dynamicSourcesForProfile(profile));
    if (dynamicSourcesContainer) dynamicSourcesContainer.querySelectorAll('[data-dynamic-source]').forEach(input => {
      const available = dynamicCapabilities.recognized && allowed.has(input.dataset.dynamicSource);
      input.disabled = !available || dynamicEnabledInput?.checked !== true;
      if (!allowed.has(input.dataset.dynamicSource)) input.checked = false;
    });
    if (dynamicSourcesContainer) dynamicSourcesContainer.hidden = !dynamicCapabilities.recognized || dynamicEnabledInput?.checked !== true;
    const extremeConfirm = document.getElementById('m-dynamic-extreme-confirm');
    if (extremeConfirm) extremeConfirm.hidden = profile !== 'extreme' || dynamicEnabledInput?.checked !== true;
    if (dynamicDowngradeInput) dynamicDowngradeInput.disabled = profile === 'safe' || dynamicEnabledInput?.checked !== true;
    if (dynamicHelp) dynamicHelp.textContent = profile === 'safe'
      ? 'Safe 仅允许 HTTPS:443，并要求命中明确的域名规则。'
      : profile === 'extreme'
        ? 'Extreme 提供更宽的兼容范围；只建议在普通模式无法播放时使用。'
        : '兼容模式默认处理 HTTP 30x、PlaybackInfo、HLS 和 DASH；仍拒绝私网与回环目标。';
  };
  if (dynamicRulesButton) dynamicRulesButton.onclick = () => {
    dynamicRules.push({ type: 'exact', value: '' });
    renderDynamicRules();
    const last = dynamicRulesContainer?.querySelector('.m-dynamic-rule-value:last-child');
    if (last) last.focus();
  };
  if (dynamicProfileSelect) dynamicProfileSelect.onchange = syncDynamicControls;
  if (dynamicEnabledInput) dynamicEnabledInput.onchange = syncDynamicControls;
  renderDynamicRules();
  syncDynamicControls();
  if (isEdit && dynamicCapabilities.recognized && dynamicCapabilities.available) {
    const refreshObservations = async () => {
      const target = document.getElementById('m-dynamic-observations');
      if (!target || !API.getDynamicObservations) return;
      target.innerHTML = '<div class="form-help">正在读取观察记录…</div>';
      try { target.innerHTML = renderDynamicObservations(await API.getDynamicObservations(site.id)); } catch (error) { target.innerHTML = `<div class="form-help" style="color:var(--red)">${esc(error.message)}</div>`; }
    };
    document.getElementById('m-refresh-dynamic-observations')?.addEventListener('click', refreshObservations);
    document.getElementById('m-clear-dynamic-observations')?.addEventListener('click', async () => {
      try { await API.deleteDynamicObservations(site.id); await refreshObservations(); Toast.success('观察记录已清空'); } catch (error) { Toast.error(error.message); }
    });
    refreshObservations();
  }

  const upstreamHeadersContainer = document.getElementById('m-upstream-headers');
  let upstreamHeaders = isEdit && Array.isArray(site.upstream_headers) && site.upstream_headers.length
    ? site.upstream_headers.map(header => ({ name: header.name || '', value: '', configured: !!header.configured }))
    : [{ name: '', value: '', configured: false }];

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
		  routePrefixInput.value,
		  siteCapabilities.route_domain,
		  pathPrefixInput.value,
		);
		const primaryTargetURL = joinTargetAddress(
			document.getElementById('m-target-address').value,
			document.getElementById('m-target-port').value,
		);
		const nextDynamicPolicy = {
			dynamic_discovery_enabled: dynamicEnabledInput?.checked === true,
			dynamic_profile: normalizeDynamicProfile(dynamicProfileSelect?.value || dynamicPolicy.dynamic_profile),
			dynamic_discovery_sources: DYNAMIC_SOURCE_IDS.filter(source => document.getElementById(`m-dynamic-source-${source}`)?.checked === true),
			dynamic_domain_rules: dynamicRules,
			dynamic_allow_https_downgrade: dynamicDowngradeInput?.checked === true,
		};
		const dynamicConfirmation = confirmDynamicProfileChange(
			dynamicInitialPolicy,
			nextDynamicPolicy,
			document.getElementById('m-name').value.trim(),
			document.getElementById('m-dynamic-extreme-ack')?.checked === true,
			document.getElementById('m-dynamic-extreme-name')?.value.trim() || '',
		);
		if (!dynamicConfirmation.ok) {
			if (dynamicConfirmation.error) Toast.error(dynamicConfirmation.error);
			return;
		}
		const dynamicPayload = buildDynamicPolicyPayload(nextDynamicPolicy, dynamicCapabilities);
		const data = {
	      name: document.getElementById('m-name').value.trim(),
	      target_url: primaryTargetURL,
	      primary_line_name: document.getElementById('m-primary-line-name').value.trim() || '主线路',
	      failover_lines: failoverLines.map((line, index) => ({
	        name: String(line.name || '').trim() || `线路${index + 2}`,
	        url: joinTargetAddress(line.address, line.port),
	        enabled: line.enabled !== false,
	      })),
	      failover_targets: failoverLines.filter(line => line.enabled !== false).map(line => joinTargetAddress(line.address, line.port)).filter(Boolean),
      playback_target_url: isEdit ? String(site.playback_target_url || '') : '',
      playback_mode: isEdit ? String(site.playback_mode || 'direct') : 'direct',
		main_video_stream_mode: mainVideoModeSelect.value,
		stream_hosts: isEdit ? normalizeStreamHosts(site.stream_hosts) : [],
			...ingressPayload,
		upstream_headers: buildUpstreamHeaderPayload(upstreamHeaders),
      ua_mode: uaMode,
      client_ip_mode: clientIPModeSelect.value,
      ...customUAPayload,
		...dynamicPayload,
      asset_cache_enabled: document.getElementById('m-asset-cache').value === 'on',
      asset_cache_ttl_sec: parseInt(document.getElementById('m-cache-ttl').value || 24) * 3600,
      asset_cache_max_bytes: parseInt(document.getElementById('m-cache-max').value || 512) * 1048576,
      asset_cache_rules: document.getElementById('m-cache-rules').value.trim(),
      traffic_quota: parseInt(document.getElementById('m-quota').value || 0) * 1073741824,
      speed_limit: parseInt(document.getElementById('m-speed').value || 0),
    };

		const listenPortRequired = ingressFormState(data.ingress_mode).requireListenPort;
		if (data.ingress_mode === 'unset') {
		  Toast.error('请选择当前服务器可用的入口模式');
		  return;
		}
		if (!data.name || !data.target_url || (listenPortRequired && !data.listen_port) || (data.ingress_mode === 'host' && !data.route_prefix && !data.public_host) || (data.ingress_mode === 'path' && !data.path_prefix)) {
	      Toast.error('请填写所有必填项');
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
		if (!document.getElementById('m-target-port').value || data.failover_lines.some((line, index) => !line.url || !String(failoverLines[index].port || '').trim())) {
			Toast.error('请完整填写每条线路的域名和端口，或删除空线路');
			return;
		}
		if (data.failover_targets.length > 0 && upstreamHeaders.some(header => String(header.name || '').trim())) {
			Toast.error('备用线路不能与主回源固定请求头同时使用');
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

  openModal({ closeOnBackdrop: false, modalClass: 'site-config-modal' });
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
