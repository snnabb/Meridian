// Sites management page
function renderSites() {
  const page = document.getElementById('page-sites');
  page.innerHTML = `
    <h1 class="section-title fade-up">站点管理</h1>
    <p class="section-sub fade-up stagger-1">管理所有 Emby 反代站点与双上游配置</p>
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
      grid.innerHTML = '<div style="text-align:center;color:var(--white-38);padding:60px;grid-column:1/-1">暂无站点，点击右上角添加</div>';
      return;
    }

	grid.innerHTML = sites.map((s, i) => {
      const pct = s.traffic_quota > 0 ? (s.traffic_used / s.traffic_quota * 100).toFixed(1) : 0;
      const pctClass = pct > 85 ? 'danger' : pct > 50 ? 'warn' : 'normal';
		const playbackRow = renderPlaybackRow(s);
		const upstreamHeaderCount = Array.isArray(s.upstream_headers) ? s.upstream_headers.length : 0;
		const ingressRows = renderIngressSummary(s);

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
		  ${upstreamHeaderCount > 0 ? `
		  <div class="site-row">
			<span class="site-row-label">上游请求头</span>
			<span>${upstreamHeaderCount} 个（加密）</span>
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
            <span>${formatBytes(s.traffic_used)}</span>
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
        <span class="mono mono-subtle">跟随主回源</span>
      </div>
    `;
  }

  if (totalHosts === 1 && playback === (site.target_url || '').trim()) {
    return `
      <div class="site-row">
        <span class="site-row-label">播放回源</span>
        <span class="mono mono-subtle">与主回源相同</span>
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
      <span class="mono">${modeLabel}</span>
    </div>`;
  return rows;
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

function canAddPlaybackAddress(currentCount, maxPlaybackAddresses) {
	return currentCount < maxPlaybackAddresses;
}

function renderUpstreamHeaderRows(headers, upstreamHeadersAvailable) {
	return headers.map((header, idx) => `
		<div style="display:flex;gap:6px;margin-bottom:6px;align-items:center">
		  <input type="text" class="form-input m-upstream-header-name" data-idx="${idx}" value="${esc(header.name)}" placeholder="Header 名称" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false" style="flex:1" ${upstreamHeadersAvailable ? '' : 'disabled'}>
		  <input type="password" class="form-input m-upstream-header-value" data-idx="${idx}" value="" placeholder="${header.configured ? '已配置；留空保持不变' : 'Header 值'}" maxlength="1024" autocomplete="new-password" style="flex:1" ${upstreamHeadersAvailable ? '' : 'disabled'}>
		  <button type="button" class="btn-ghost danger m-upstream-header-remove" data-idx="${idx}" style="padding:4px 8px;font-size:13px;flex-shrink:0">删除</button>
		</div>
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

function defaultIngressMode(capabilities) {
	return capabilities && capabilities.host_only_available === false ? 'port' : 'host';
}

function renderIngressSummary(site) {
	const mode = normalizedIngressMode(site);
	const labels = { port: '仅独立端口', host: '仅共享域名', both: '共享域名 + 独立端口' };
	let rows = `
	  <div class="site-row">
		<span class="site-row-label">入口模式</span>
		<span>${labels[mode]}</span>
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

  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = `
    <div class="form-group">
      <label>站点名称</label>
      <input type="text" class="form-input" id="m-name" value="${isEdit ? esc(site.name) : ''}" placeholder="如：Emby-US-01" maxlength="100" required>
    </div>
    <div class="form-group">
      <label>主回源地址</label>
      <input type="text" class="form-input" id="m-target" value="${isEdit ? esc(site.target_url) : ''}" placeholder="如：192.168.1.10:8096 或 https://emby.example.com" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048" required>
      <div class="form-help">网页、API 和默认回源都走这里。未写协议时，:443 自动使用 HTTPS，其他端口默认 HTTP。</div>
    </div>
    <div class="form-group">
      <label>播放回源列表（可选，留空跟随主回源）</label>
      <div id="m-playback-list"></div>
      <button type="button" class="btn-ghost" id="m-add-playback" style="margin-top:6px;font-size:13px">+ 添加播放回源</button>
      <div class="form-help">第一个地址是实际播放回源；额外地址仅作为重定向模式的允许列表，不会自动探测、轮询或故障转移（最多 ${maxPlaybackAddresses} 个）。未写协议时，:443 自动使用 HTTPS。</div>
    </div>
    <div class="form-group" id="playback-mode-group" style="display:none">
      <label>播放模式</label>
      <select class="form-select modal-select" id="m-playback-mode">
        <option value="direct" ${(!isEdit || site.playback_mode !== 'redirect') ? 'selected' : ''}>直连分流</option>
        <option value="redirect" ${isEdit && site.playback_mode === 'redirect' ? 'selected' : ''}>重定向跟随</option>
      </select>
      <div class="form-help">直连分流：播放请求直接发送到首个播放回源（适合完整 Emby 实例）。重定向跟随：所有请求经主回源，自动跟随重定向到任一播放回源（适合多节点 CDN）。</div>
    </div>
	<div class="form-group">
	  <label>入口模式</label>
	  <select class="form-select modal-select" id="m-ingress-mode">
		<option value="host" ${hostOnlyAvailable ? '' : 'disabled'}>仅共享域名（推荐${hostOnlyAvailable ? '' : '，当前部署不可用'}）</option>
		<option value="port">仅独立端口</option>
		<option value="both">共享域名 + 独立端口（高风险）</option>
	  </select>
	  <div class="form-help" id="m-ingress-warning"></div>
	  ${hostOnlyAvailable ? '' : '<div class="form-help">当前面板既未绑定回环地址，也没有可信代理来源白名单；请先设置 PANEL_BIND_ADDR 或 TRUSTED_PROXY_CIDRS 并重启，才能启用仅共享域名。</div>'}
	</div>
	<div class="form-group" id="m-port-group">
	  <label id="m-port-label">监听端口</label>
	  <input type="number" class="form-input" id="m-port" value="${isEdit ? site.listen_port : ''}" placeholder="如：8001" min="1" max="65535" inputmode="numeric" required>
	</div>
	<div class="form-group" id="m-public-host-group">
	  <label>共享入口域名</label>
	  <input type="text" class="form-input" id="m-public-host" value="${isEdit ? esc(site.public_host || '') : ''}" placeholder="如：emby.example.com" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="253">
	  <div class="form-help">通过面板监听入口按精确 Host 转发到本站点。只填域名，不填协议、端口、路径或通配符。</div>
	</div>
		<div class="form-group">
		  <label>主回源固定请求头（可选）</label>
		  <div id="m-upstream-headers"></div>
		  <button type="button" class="btn-ghost" id="m-add-upstream-header" style="margin-top:6px;font-size:13px" ${upstreamHeadersAvailable ? '' : 'disabled'}>+ 添加请求头</button>
		  <div class="form-help">值使用 UPSTREAM_HEADER_KEY 加密保存且不会回显，只发送给主回源的精确协议、域名和端口；更换主回源的协议、域名或端口后必须重新输入这些值。</div>
		  ${upstreamHeadersAvailable ? '' : '<div class="form-help" style="color:var(--orange)">当前部署未配置 UPSTREAM_HEADER_KEY，不能新增、重命名或修改 Header 值；仍可删除旧配置。配置密钥并重启后可恢复编辑。</div>'}
		</div>
    <div class="form-group">
      <label>UA 模式</label>
      <select class="form-select modal-select" id="m-ua">
        <option value="infuse" ${(!isEdit || site.ua_mode === 'infuse') ? 'selected' : ''}>Infuse</option>
        <option value="web" ${isEdit && site.ua_mode === 'web' ? 'selected' : ''}>Web</option>
        <option value="client" ${isEdit && site.ua_mode === 'client' ? 'selected' : ''}>客户端</option>
        <option value="custom">自定义</option>
        <option value="passthrough" ${isEdit && site.ua_mode === 'passthrough' ? 'selected' : ''}>透传（保留客户端身份）</option>
      </select>
    </div>
    <div class="form-group" id="m-custom-ua-group" hidden>
      <label>自定义身份</label>
      <input type="text" class="form-input" id="m-custom-ua" placeholder="User-Agent" maxlength="1024" autocapitalize="none" autocorrect="off" spellcheck="false">
      <input type="text" class="form-input" id="m-custom-client" placeholder="Emby Client" maxlength="128" autocapitalize="none" autocorrect="off" spellcheck="false" style="margin-top:8px">
      <input type="text" class="form-input" id="m-custom-version" placeholder="Emby Version" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false" style="margin-top:8px">
      <div class="form-help">仅改写 User-Agent、Client 和 Version；Device 与 DeviceId 保持原样。</div>
    </div>
    <div class="form-group">
      <label>流量额度 (GB, 0=不限)</label>
      <input type="number" class="form-input" id="m-quota" value="${isEdit ? Math.round((site.traffic_quota || 0) / 1073741824) : 0}" placeholder="0" min="0" inputmode="numeric">
    </div>
    <div class="form-group">
      <label>单连接限速 (Mbps, 0=不限)</label>
      <input type="number" class="form-input" id="m-speed" value="${isEdit ? (site.speed_limit || 0) : 0}" placeholder="0" min="0" max="1000000" step="1" inputmode="numeric">
      <div class="form-help">限制单个 HTTP 响应和 WebSocket 下行连接的速度；上传方向不受此项影响。</div>
    </div>
  `;

  document.getElementById('modal-footer').innerHTML = `
    <button class="btn-modal secondary" id="m-cancel">取消</button>
    <button class="btn-modal primary" id="m-submit">${isEdit ? '保存' : '创建'}</button>
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
      <div style="display:flex;gap:6px;margin-bottom:6px;align-items:center">
        <input type="text" class="form-input m-pb-input" value="${esc(val)}" placeholder="${idx === 0 ? '主播放回源地址' : '额外播放回源地址'}" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048" style="flex:1">
        ${existingHosts.length > 1 ? `<button type="button" class="btn-ghost danger m-pb-remove" data-idx="${idx}" style="padding:4px 8px;font-size:13px;flex-shrink:0">删除</button>` : ''}
      </div>
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
    modeGroup.style.display = hasAny ? '' : 'none';
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
      traffic_quota: parseInt(document.getElementById('m-quota').value || 0) * 1073741824,
      speed_limit: parseInt(document.getElementById('m-speed').value || 0),
    };

		if (!data.name || !data.target_url || !data.listen_port || ((data.ingress_mode === 'host' || data.ingress_mode === 'both') && !data.public_host)) {
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
