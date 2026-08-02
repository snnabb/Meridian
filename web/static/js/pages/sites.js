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
          <div class="site-row">
            <span class="site-row-label">监听端口</span>
            <span class="mono">:${s.listen_port}</span>
          </div>
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
  let extraHosts = [];
  try { extraHosts = JSON.parse(site.stream_hosts || '[]'); } catch(e) {}
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

function showSiteModal(site) {
  const isEdit = !!site;
  const title = isEdit ? '编辑站点' : '添加站点';

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
      <div class="form-help">播放、转码或直链资源的独立上游地址。可添加多个；未写协议时，:443 自动使用 HTTPS。</div>
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
      <label>监听端口</label>
      <input type="number" class="form-input" id="m-port" value="${isEdit ? site.listen_port : ''}" placeholder="如：8001" min="1" max="65535" inputmode="numeric" required>
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
  let existingHosts = [];
  if (isEdit) {
    if ((site.playback_target_url || '').trim()) existingHosts.push(site.playback_target_url.trim());
    try {
      const extra = JSON.parse(site.stream_hosts || '[]');
      for (const h of extra) if (h && h.trim()) existingHosts.push(h.trim());
    } catch(e) {}
  }
  if (existingHosts.length === 0) existingHosts = [''];

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
  }
  renderPlaybackInputs();

  document.getElementById('m-add-playback').onclick = () => {
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

  document.getElementById('m-submit').onclick = async () => {
    const allHosts = existingHosts.map(h => h.trim()).filter(Boolean);
    const uaMode = uaSelect.value;
    const customUAPayload = buildCustomUAPayload(
      uaMode,
      customUAInputs[0].value,
      customUAInputs[1].value,
      customUAInputs[2].value,
    );
    const data = {
      name: document.getElementById('m-name').value.trim(),
      target_url: document.getElementById('m-target').value.trim(),
      playback_target_url: allHosts.length > 0 ? allHosts[0] : '',
      playback_mode: document.getElementById('m-playback-mode').value,
      stream_hosts: allHosts.length > 1 ? allHosts.slice(1) : [],
      listen_port: parseInt(document.getElementById('m-port').value),
      ua_mode: uaMode,
      ...customUAPayload,
      traffic_quota: parseInt(document.getElementById('m-quota').value || 0) * 1073741824,
      speed_limit: parseInt(document.getElementById('m-speed').value || 0),
    };

    if (!data.name || !data.target_url || !data.listen_port) {
      Toast.error('请填写所有必填项');
      return;
    }
    if (uaMode === 'custom' && (!data.custom_user_agent || !data.custom_client || !data.custom_version)) {
      Toast.error('请完整填写自定义 User-Agent、Client 和 Version');
      return;
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
