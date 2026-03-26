// Sites management page
function renderSites() {
  const page = document.getElementById('page-sites');
  page.innerHTML = `
    <h1 class="section-title fade-up">站点管理</h1>
    <p class="section-sub fade-up stagger-1">管理所有 Emby 反代站点</p>
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
            <span class="site-row-label">回源地址</span>
            <span class="mono">${esc(s.target_url)}</span>
          </div>
          <div class="site-row">
            <span class="site-row-label">监听端口</span>
            <span class="mono">:${s.listen_port}</span>
          </div>
          <div class="site-row">
            <span class="site-row-label">UA 模式</span>
            <span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${uaNameMap[s.ua_mode] || s.ua_mode}</span>
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
          <button class="btn-ghost" onclick="toggleSiteAction(${s.id})">${s.enabled ? '停用' : '启用'}</button>
          <button class="btn-ghost" onclick="editSiteAction(${s.id})">编辑</button>
          <button class="btn-ghost danger" onclick="deleteSiteAction(${s.id},'${esc(s.name)}')">删除</button>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    Toast.error('加载站点失败: ' + e.message);
  }
}

function showSiteModal(site) {
  const isEdit = !!site;
  const title = isEdit ? '编辑站点' : '添加站点';

  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = `
    <div class="form-group">
      <label>站点名称</label>
      <input type="text" class="form-input" id="m-name" value="${isEdit ? esc(site.name) : ''}" placeholder="如：Emby-US-01" required>
    </div>
    <div class="form-group">
      <label>回源地址</label>
      <input type="text" class="form-input" id="m-target" value="${isEdit ? esc(site.target_url) : ''}" placeholder="如：192.168.1.10:8096 或 https://emby.example.com" required>
    </div>
    <div class="form-group">
      <label>监听端口</label>
      <input type="number" class="form-input" id="m-port" value="${isEdit ? site.listen_port : ''}" placeholder="如：8001" required>
    </div>
    <div class="form-group">
      <label>UA 模式</label>
      <select class="form-input" id="m-ua" style="appearance:auto">
        <option value="infuse" ${(!isEdit || site.ua_mode === 'infuse') ? 'selected' : ''}>Infuse</option>
        <option value="web" ${isEdit && site.ua_mode === 'web' ? 'selected' : ''}>Web</option>
        <option value="client" ${isEdit && site.ua_mode === 'client' ? 'selected' : ''}>客户端</option>
      </select>
    </div>
    <div class="form-group">
      <label>流量额度 (GB, 0=不限)</label>
      <input type="number" class="form-input" id="m-quota" value="${isEdit ? Math.round((site.traffic_quota || 0) / 1073741824) : 0}" placeholder="0">
    </div>
  `;

  document.getElementById('modal-footer').innerHTML = `
    <button class="btn-modal secondary" onclick="closeModal()">取消</button>
    <button class="btn-modal primary" id="m-submit">${isEdit ? '保存' : '创建'}</button>
  `;

  document.getElementById('m-submit').onclick = async () => {
    const data = {
      name: document.getElementById('m-name').value.trim(),
      target_url: document.getElementById('m-target').value.trim(),
      listen_port: parseInt(document.getElementById('m-port').value),
      ua_mode: document.getElementById('m-ua').value,
      traffic_quota: parseInt(document.getElementById('m-quota').value || 0) * 1073741824,
    };

    if (!data.name || !data.target_url || !data.listen_port) {
      Toast.error('请填写所有必填项');
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

  openModal();
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
  document.getElementById('modal-body').innerHTML = `<p style="color:var(--white-60)">确定要删除站点 <strong>${name}</strong> 吗？此操作不可撤销。</p>`;
  document.getElementById('modal-footer').innerHTML = `
    <button class="btn-modal secondary" onclick="closeModal()">取消</button>
    <button class="btn-modal primary" style="background:var(--red)" onclick="confirmDelete(${id})">删除</button>
  `;
  openModal();
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
