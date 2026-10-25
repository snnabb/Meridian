// Global settings pages
let globalSettingsCache = null;
let globalSettingsSection = 'system-ui';
let globalSettingsLoadGeneration = 0;

function applySystemUISettings(settings) {
  if (!settings) return;
  if (typeof meridianSetTimezoneName === 'function' && settings.schedule_timezone) meridianSetTimezoneName(settings.schedule_timezone);
  if (typeof meridianSetTimezoneOffset === 'function') meridianSetTimezoneOffset(settings.schedule_timezone_offset);
  document.documentElement.style.setProperty('--ui-radius', '24px');
}

async function loadAppliedSystemSettings() {
  try {
    const settings = await API.getSystemSettings();
    if (settings) {
      globalSettingsCache = settings;
      applySystemUISettings(settings);
    }
  } catch (_) {}
}

function globalSettingsNav(active) {
  const button = (id, label) => `<button type="button" class="settings-nav-item ${active === id ? 'active' : ''}" data-settings-section="${id}">${label}</button>`;
  return `<aside class="settings-section-nav">
    ${button('system-ui', '系统设置')}${button('logs', '日志设置')}${button('updates', '版本更新')}
    <a href="#settings-tls" class="settings-nav-item ${active === 'tls' ? 'active' : ''}">TLS 设置</a>
    <a href="#telegram-report" class="settings-nav-item ${active === 'telegram' ? 'active' : ''}">Telegram Bot</a>
    <a href="#backup-restore" class="settings-nav-item ${active === 'backup' ? 'active' : ''}">备份与恢复</a>
  </aside>`;
}

function backupPasswordField(id, label) {
  return `<label class="settings-field"><span>${label}</span><div><input class="form-input" id="${id}" type="password" minlength="6" maxlength="128" autocomplete="new-password" placeholder="至少 6 个字符"></div></label>`;
}

function renderBackupRestore() {
  const page = document.getElementById('page-backup-restore');
  if (!page) return;
  page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav('backup')}<main class="settings-content backup-restore-content">
    <section class="settings-panel"><header><h2>数据备份</h2><b>密码加密</b></header>
      <p class="settings-panel-help">备份包含站点、账户、流量与请求日志、全局设置及 Telegram 配置；不包含缓存、.env 或部署密钥文件。</p>
      <div class="settings-grid">${backupPasswordField('backup-password', '备份密码')}${backupPasswordField('backup-password-confirm', '确认备份密码')}</div>
      ${settingsCheck('backup-include-tls', '包含 TLS 设置与证书', false, '勾选后包含域名、端口、证书和 ACME 账户；恢复时会覆盖目标服务器的 TLS 配置。')}
      <div class="backup-warning">备份含账户和凭据，请妥善保管。忘记备份密码后无法恢复。</div>
      <div class="settings-save-bar"><button class="telegram-btn primary" type="button" id="backup-download">下载加密备份</button></div>
    </section>
    <section class="settings-panel backup-restore-danger"><header><h2>数据恢复</h2><b>自动重启</b></header>
      <p class="settings-panel-help">恢复将覆盖当前数据并重启；备份未包含 TLS 时，保留现有证书与 TLS 设置。</p>
      <div class="settings-grid">
        <label class="settings-field"><span>Meridian 备份文件</span><div><input class="form-input backup-file-input" id="restore-file" type="file" accept=".mrbak,application/octet-stream"></div></label>
        ${backupPasswordField('restore-password', '备份密码')}
      </div>
      <label class="settings-field backup-confirm-field"><span>输入“恢复”确认</span><div><input class="form-input" id="restore-confirm" type="text" autocomplete="off" placeholder="恢复"></div><small>恢复前建议先备份当前数据。</small></label>
      <div class="backup-warning danger">恢复后当前登录会失效；请使用备份中的管理员用户名和密码重新登录。</div>
      <div class="settings-save-bar"><button class="telegram-btn danger" type="button" id="backup-restore-submit">校验并恢复</button></div>
    </section>
  </main></div>`;
  bindGlobalSettingsNav(page);
  document.getElementById('backup-download').onclick = downloadMeridianBackup;
  document.getElementById('backup-restore-submit').onclick = restoreMeridianBackup;
}

function backupFilename(disposition) {
  const match = String(disposition || '').match(/filename="?([^";]+)"?/i);
  return match ? match[1] : `meridian-backup-${new Date().toISOString().slice(0, 10)}.mrbak`;
}

async function downloadMeridianBackup() {
  const password = document.getElementById('backup-password').value;
  const confirmation = document.getElementById('backup-password-confirm').value;
  if (password.length < 6) return Toast.error('备份密码至少需要 6 个字符');
  if (password !== confirmation) return Toast.error('两次输入的备份密码不一致');
  const button = document.getElementById('backup-download');
  button.disabled = true;
  button.textContent = '正在创建备份…';
  try {
    const result = await API.exportBackup(password, document.getElementById('backup-include-tls').checked);
    if (!result) return;
    const url = URL.createObjectURL(result.blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = backupFilename(result.disposition);
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    Toast.success('加密备份已创建，请妥善保存');
  } catch (error) {
    Toast.error(error.message);
  } finally {
    if (button.isConnected) {
      button.disabled = false;
      button.textContent = '下载加密备份';
    }
  }
}

async function restoreMeridianBackup() {
  const fileInput = document.getElementById('restore-file');
  const password = document.getElementById('restore-password').value;
  const confirmation = document.getElementById('restore-confirm').value.trim();
  if (!fileInput.files || !fileInput.files[0]) return Toast.error('请选择 Meridian 备份文件');
  if (password.length < 6) return Toast.error('请输入正确的备份密码');
  if (confirmation !== '恢复') return Toast.error('请输入“恢复”确认操作');
  const button = document.getElementById('backup-restore-submit');
  button.disabled = true;
  button.textContent = '正在校验备份…';
  try {
    const result = await API.restoreBackup(fileInput.files[0], password, confirmation);
    if (!result) return;
    Toast.success(result.message || '恢复已开始，Meridian 正在重启');
    button.textContent = '正在重启…';
    setTimeout(() => window.location.reload(), 5000);
  } catch (error) {
    Toast.error(error.message);
    button.disabled = false;
    button.textContent = '校验并恢复';
  }
}

function settingsNumber(id, label, value, min, max, unit, help) {
  return `<label class="settings-field"><span>${label}</span><div><input class="form-input" id="${id}" type="number" min="${min}" max="${max}" step="1" inputmode="numeric" required value="${value}"><em>${unit}</em></div>${help ? `<small>${help}</small>` : ''}</label>`;
}

function trafficResetDaySelect(value) {
  const selected = Number(value);
  const options = ['<option value="0">不重置（累计流量）</option>'];
  for (let day = 1; day <= 31; day++) options.push(`<option value="${day}" ${selected === day ? 'selected' : ''}>每月 ${day} 日</option>`);
  if (selected === 0) options[0] = '<option value="0" selected>不重置（累计流量）</option>';
  return `<label class="settings-field"><span>流量周期</span><div><select class="form-select settings-reset-select" id="setting-traffic-reset-day">${options.join('')}</select></div><small>短月按最后一天重置；选择不重置时使用累计流量。</small></label>`;
}

const COMMON_TIMEZONES = [
  ['UTC', 'UTC'], ['Asia/Shanghai', '中国标准时间（上海）'], ['Asia/Tokyo', '日本标准时间（东京）'], ['Asia/Seoul', '韩国标准时间（首尔）'],
  ['Asia/Singapore', '新加坡标准时间'], ['Asia/Hong_Kong', '香港时间'], ['Asia/Bangkok', '曼谷时间'], ['Asia/Kolkata', '印度标准时间'], ['Asia/Dubai', '海湾标准时间'],
  ['Europe/London', '英国时间（含夏令时）'], ['Europe/Paris', '中欧时间（含夏令时）'], ['Europe/Berlin', '德国时间（含夏令时）'], ['Europe/Moscow', '莫斯科时间'],
  ['America/New_York', '美国东部时间（含夏令时）'], ['America/Chicago', '美国中部时间（含夏令时）'], ['America/Denver', '美国山地时间（含夏令时）'], ['America/Los_Angeles', '美国太平洋时间（含夏令时）'],
  ['Australia/Sydney', '澳大利亚东部时间（含夏令时）'], ['Pacific/Auckland', '新西兰时间（含夏令时）'],
];

function timezoneSelect(value, legacyOffset) {
  const selected = String(value || 'Asia/Shanghai');
  const numericOffset = Number(legacyOffset);
  const offset = Number.isFinite(numericOffset) ? Math.trunc(numericOffset) : 480;
  const options = COMMON_TIMEZONES.map(([name, label]) => `<option value="${name}" ${name === selected ? 'selected' : ''}>${label} · ${name}</option>`);
  return `<label class="settings-field"><span>时区</span><div><select class="form-select" id="setting-schedule-timezone">${options.join('')}</select><input type="hidden" id="setting-schedule-timezone-offset" value="${offset}"></div><small>用于日志时间和定时通知；流量重置按服务器时区计算。</small></label>`;
}

function settingsCheck(id, label, checked, help) {
  return `<label class="settings-check"><input id="${id}" type="checkbox" ${checked ? 'checked' : ''}><span class="settings-check-copy"><strong>${label}</strong>${help ? `<small>${help}</small>` : ''}</span></label>`;
}

function settingsRange(id, label, value, min, max, step, unit, help) {
  return `<label class="settings-range"><span>${label}</span><div><input id="${id}" type="range" min="${min}" max="${max}" step="${step}" value="${value}"><output id="${id}-value">${value} ${unit}</output></div>${help ? `<small>${help}</small>` : ''}</label>`;
}

function renderGlobalSettings() {
  const page = document.getElementById('page-global-settings');
  if (!page) return;
  page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav(globalSettingsSection)}<main class="settings-content"><div class="settings-loading">正在读取设置…</div></main></div>`;
  bindGlobalSettingsNav(page);
  if (globalSettingsCache) paintGlobalSettings(page);
  loadGlobalSettings(page);
}

function bindGlobalSettingsNav(root = document) {
  bindFieldValidation(root);
  root.querySelectorAll('[data-settings-section]').forEach(button => {
    button.onclick = () => {
      globalSettingsSection = button.dataset.settingsSection;
      if (Router.current !== 'global-settings') Router.navigate('global-settings');
      else paintGlobalSettings(document.getElementById('page-global-settings'));
    };
  });
}

async function loadGlobalSettings(page = document.getElementById('page-global-settings')) {
  const generation = ++globalSettingsLoadGeneration;
  try {
    globalSettingsCache = await API.getSystemSettings();
    if (generation !== globalSettingsLoadGeneration || Router.current !== 'global-settings' || !globalSettingsCache || !page) return;
    applySystemUISettings(globalSettingsCache);
    paintGlobalSettings(page);
  } catch (error) {
    if (generation !== globalSettingsLoadGeneration || Router.current !== 'global-settings' || !page) return;
    if (globalSettingsCache) return;
    const content = page.querySelector('.settings-content');
    if (content) content.innerHTML = `<div class="settings-loading request-log-error">读取设置失败：${esc(error.message)}</div>`;
  }
}

function paintGlobalSettings(page = document.getElementById('page-global-settings')) {
  if (!globalSettingsCache || !page) return;
  const nav = page.querySelector('.settings-section-nav');
  if (nav) nav.outerHTML = globalSettingsNav(globalSettingsSection);
  bindGlobalSettingsNav(page);
  const content = page.querySelector('.settings-content');
  if (!content) return;
  content.innerHTML = globalSettingsSection === 'updates' ? renderUpdateSettings() : globalSettingsSection === 'logs'
    ? renderLogSettingsForm(globalSettingsCache)
    : renderSystemUIForm(globalSettingsCache);
  bindUpdateSettings(page);
  const saveButton = page.querySelector('#settings-save');
  if (saveButton) saveButton.onclick = saveGlobalSettings;
  page.querySelectorAll('[data-setting-choice]').forEach(button => {
    button.onclick = () => {
      const group = button.closest('.settings-choice');
      group.querySelectorAll('button').forEach(item => item.classList.toggle('active', item === button));
    };
  });
}

function renderSystemUIForm(s) {
  return `<section class="settings-panel"><header><h2>流量与时间</h2></header>
    <span class="settings-label">计费方向</span><div class="settings-choice" id="traffic-billing-mode-choice"><button data-setting-choice="outbound" class="${s.traffic_billing_mode === 'outbound' ? 'active' : ''}">单向（仅下载）</button><button data-setting-choice="bidirectional" class="${s.traffic_billing_mode !== 'outbound' ? 'active' : ''}">双向（下载 + 上传）</button></div>
    <div class="settings-grid settings-system-fields">
    ${trafficResetDaySelect(s.traffic_reset_day == null ? 1 : s.traffic_reset_day)}
    ${timezoneSelect(s.schedule_timezone, s.schedule_timezone_offset)}
    </div>
  </section>${settingsSaveBar()}`;
}

function renderLogSettingsForm(s) {
  return `<section class="settings-panel"><header><h2>日志设置</h2></header>
    ${settingsCheck('setting-log-enabled', '开启日志记录与查询', s.log_enabled)}
    <span class="settings-label">日志写入模式</span><div class="settings-choice" id="log-level-choice"><button data-setting-choice="info" class="${s.log_level === 'info' ? 'active' : ''}">INFO（常规记录）</button><button data-setting-choice="error" class="${s.log_level === 'error' ? 'active' : ''}">ERROR（仅异常错误）</button></div>
  </section>
  <section class="settings-panel"><header><h2>日志保留</h2></header>
    <div class="settings-grid">
      ${settingsNumber('setting-log-retention', '保存周期', s.log_retention_days, 1, 365, '天', '超过设定天数的历史记录将被自动清理。')}
    </div>
  </section>
  <section class="settings-panel"><header><h2>记录请求类别</h2></header>
    <div class="settings-check-grid">
      ${settingsCheck('setting-write-playback', '播放与串流信息', s.log_write_playback !== false)}
      ${settingsCheck('setting-write-video', '主视频流与分片', s.log_write_video !== false)}
      ${settingsCheck('setting-write-api', '常规系统与 API', s.log_write_api !== false)}
      ${settingsCheck('setting-write-auth', '用户认证登录', s.log_write_auth !== false)}
      ${settingsCheck('setting-write-asset', '前端与静态资源', s.log_write_asset !== false)}
    </div>
  </section>
  <details class="settings-panel settings-advanced-details" style="margin-top:14px;cursor:pointer;">
    <summary style="font-size:.88rem;font-weight:600;color:var(--white-87);padding:4px 0;">高级日志设置</summary>
    <div style="margin-top:16px;">
      <h3 style="font-size:12px;margin:12px 0 8px;color:var(--white-60);">高级存储队列参数</h3>
      <div class="settings-grid">
        ${settingsNumber('setting-log-batch', '单批写入大小', s.log_batch_size, 1, 100, '条')}
        ${settingsNumber('setting-log-retries', '写入重试次数', s.log_retry_count, 0, 10, '次')}
        ${settingsNumber('setting-log-backoff', '重试退避', s.log_retry_backoff_ms, 0, 5000, 'ms')}
      </div>
      <h3 style="font-size:12px;margin:16px 0 8px;color:var(--white-60);">更多请求类别</h3>
      <div class="settings-check-grid">
        ${settingsCheck('setting-write-image', '图片海报', s.log_write_image === true)}
        ${settingsCheck('setting-write-metadata', '媒体元数据', s.log_write_metadata === true)}
        ${settingsCheck('setting-write-subtitle', '字幕文件', s.log_write_subtitle !== false)}
        ${settingsCheck('setting-write-websocket', 'WebSocket 长连接', s.log_write_websocket !== false)}
      </div>
      <div class="settings-two-column" style="margin-top:16px;">
        <div style="background:rgba(255,255,255,0.03);padding:14px;border-radius:12px;">
          <h4 style="font-size:12px;margin:0 0 10px;color:var(--white-87);">写入数据库的字段</h4>
          <div class="settings-check-grid">
            ${settingsCheck('setting-write-node', '节点', s.log_write_node !== false)}
            ${settingsCheck('setting-write-status', '状态码', s.log_write_status !== false)}
            ${settingsCheck('setting-write-ip', '客户端 IP', s.log_write_client_ip !== false)}
            ${settingsCheck('setting-write-ua', '客户端 UA', s.log_write_ua !== false)}
            ${settingsCheck('setting-write-backend-address', '后端地址', s.log_write_backend_address !== false)}
            ${settingsCheck('setting-write-category', '资源类别', s.log_write_category !== false)}
            ${settingsCheck('setting-write-upstream-ua', '上游 UA', s.log_write_upstream_ua !== false)}
            ${settingsCheck('setting-write-timeline', '时间线', s.log_write_timeline !== false)}
          </div>
        </div>
        <div style="background:rgba(255,255,255,0.03);padding:14px;border-radius:12px;">
          <h4 style="font-size:12px;margin:0 0 10px;color:var(--white-87);">日志列表展示的列</h4>
          <div class="settings-check-grid">
            ${settingsCheck('setting-display-node', '节点', s.log_display_node !== false)}
            ${settingsCheck('setting-display-status', '状态码', s.log_display_status !== false)}
            ${settingsCheck('setting-display-ip', '客户端 IP', s.log_display_client_ip !== false)}
            ${settingsCheck('setting-display-ua', '客户端 UA', s.log_display_ua !== false)}
            ${settingsCheck('setting-display-backend-address', '后端地址', s.log_display_backend_address !== false)}
            ${settingsCheck('setting-display-category', '资源类别', s.log_display_category !== false)}
            ${settingsCheck('setting-display-upstream-ua', '上游 UA', s.log_display_upstream_ua !== false)}
            ${settingsCheck('setting-display-timeline', '时间线', s.log_display_timeline !== false)}
          </div>
        </div>
      </div>
    </div>
  </details>
  ${settingsSaveBar()}`;
}

function settingsSaveBar() { return '<div class="settings-save-bar"><button class="telegram-btn primary" type="button" id="settings-save">保存设置</button></div>'; }

function activeSettingChoice(id, fallback) {
  const active = document.querySelector(`#${id} button.active`);
  return active ? active.dataset.settingChoice : fallback;
}

function numericSetting(id, fallback) {
  const input = document.getElementById(id);
  return input ? Number(input.value) : fallback;
}

function checkedSetting(id, fallback) {
  const input = document.getElementById(id);
  return input ? input.checked : fallback;
}

async function saveGlobalSettings() {
  const button = document.getElementById('settings-save');
  if (button.disabled || !validateFields(document.getElementById('page-global-settings'))) return;
  const s = { ...globalSettingsCache };
  if (globalSettingsSection === 'system-ui') {
    s.traffic_billing_mode = activeSettingChoice('traffic-billing-mode-choice', s.traffic_billing_mode || 'bidirectional');
    s.traffic_reset_day = numericSetting('setting-traffic-reset-day', s.traffic_reset_day == null ? 1 : s.traffic_reset_day);
    const timezoneInput = document.getElementById('setting-schedule-timezone');
    s.schedule_timezone = timezoneInput ? timezoneInput.value : (s.schedule_timezone || 'Asia/Shanghai');
    s.schedule_timezone_offset = numericSetting('setting-schedule-timezone-offset', s.schedule_timezone_offset);
  } else {
    s.log_enabled = checkedSetting('setting-log-enabled', s.log_enabled);
    s.log_level = activeSettingChoice('log-level-choice', s.log_level);
    s.log_retention_days = numericSetting('setting-log-retention', s.log_retention_days);
    s.log_batch_size = numericSetting('setting-log-batch', s.log_batch_size);
    s.log_retry_count = numericSetting('setting-log-retries', s.log_retry_count);
    s.log_retry_backoff_ms = numericSetting('setting-log-backoff', s.log_retry_backoff_ms);
    s.log_write_image = checkedSetting('setting-write-image', false);
    s.log_write_playback = checkedSetting('setting-write-playback', true);
    s.log_write_metadata = checkedSetting('setting-write-metadata', false);
    s.log_write_video = checkedSetting('setting-write-video', true);
    s.log_write_subtitle = checkedSetting('setting-write-subtitle', true);
    s.log_write_asset = checkedSetting('setting-write-asset', true);
    s.log_write_websocket = checkedSetting('setting-write-websocket', true);
    s.log_write_api = checkedSetting('setting-write-api', true);
    s.log_write_auth = checkedSetting('setting-write-auth', true);
    s.log_write_node = checkedSetting('setting-write-node', true);
    s.log_write_category = checkedSetting('setting-write-category', true);
    s.log_write_status = checkedSetting('setting-write-status', true);
    s.log_write_client_ip = checkedSetting('setting-write-ip', true);
    s.log_write_colo = checkedSetting('setting-write-colo', s.log_write_colo);
    s.log_write_ua = checkedSetting('setting-write-ua', true);
    s.log_write_upstream_ua = checkedSetting('setting-write-upstream-ua', true);
    s.log_write_backend_address = checkedSetting('setting-write-backend-address', true);
    s.log_write_timeline = checkedSetting('setting-write-timeline', true);
    s.log_display_client_ip = checkedSetting('setting-display-ip', true);
    s.log_display_colo = checkedSetting('setting-display-colo', s.log_display_colo);
    s.log_display_ua = checkedSetting('setting-display-ua', true);
    s.log_display_upstream_ua = checkedSetting('setting-display-upstream-ua', true);
    s.log_display_backend_address = checkedSetting('setting-display-backend-address', true);
    s.log_display_node = checkedSetting('setting-display-node', true);
    s.log_display_category = checkedSetting('setting-display-category', true);
    s.log_display_status = checkedSetting('setting-display-status', true);
    s.log_display_timeline = checkedSetting('setting-display-timeline', true);
    // Search mode is intentionally kept at its server default; the log page uses one simple search box.
  }
  button.disabled = true;
  button.textContent = '保存中…';
  try {
    globalSettingsCache = await API.saveSystemSettings(s);
    applySystemUISettings(globalSettingsCache);
    Toast.success('全局设置已保存');
    paintGlobalSettings(document.getElementById('page-global-settings'));
  } catch (error) {
    Toast.error('保存失败：' + error.message);
  } finally {
    if (button.isConnected) {
      button.disabled = false;
      button.textContent = '保存设置';
    }
  }
}

function renderUpdateSettings() {
  return `<section class="settings-panel" id="system-update-panel">
    <header><h2>版本更新</h2></header>
    <p class="settings-panel-help">仅提供正式版更新。更新前自动备份，启动失败时尝试恢复原版本和数据。</p>
    <div id="update-summary" class="form-help" role="status"></div>
    <div class="settings-save-bar"><button type="button" class="telegram-btn" id="update-check">检查更新</button><button type="button" class="telegram-btn primary" id="update-install" hidden>更新并重启</button></div>
    <details id="update-notes" hidden><summary>版本说明</summary><pre class="update-release-notes"></pre><a target="_blank" rel="noopener noreferrer">在 GitHub 查看发布内容</a></details>
    <div class="settings-save-bar"><button type="button" class="telegram-btn" id="update-rollback" hidden>恢复升级前版本和数据</button></div>
    <p id="rollback-status" class="form-help" role="status"></p>
    <details><summary>恢复升级前快照的适用范围</summary>
      <p class="form-help">仅支持标准 systemd 安装，数据库须位于数据目录内且路径不能包含符号链接。Docker 请使用固定镜像版本和配套数据备份人工恢复。</p>
      <p class="form-help">恢复范围为程序、数据目录和 service 文件；外部证书与 Nginx 配置不包含在内。升级后新增的配置、账号和流量会被替换，操作前会另存当前数据。</p>
      <p class="form-help">每份升级前快照只提供一次快捷恢复；成功后归档保留，按钮消失，下一次成功升级才会生成新的可恢复快照。</p>
    </details>
  </section>`;
}

function bindUpdateSettings(page) {
  const panel = page.querySelector('#system-update-panel');
  if (!panel) return;
  const check = panel.querySelector('#update-check'), install = panel.querySelector('#update-install');
  const summary = panel.querySelector('#update-summary'), notes = panel.querySelector('#update-notes');
  const rollback = panel.querySelector('#update-rollback'), rollbackStatus = panel.querySelector('#rollback-status');
  try { localStorage.removeItem('meridian-update-channel'); } catch (_) {}
  let release = null, polling = false;
  const poll = async () => {
    if (polling) return;
    polling = true; check.disabled = true; install.disabled = true; rollback.disabled = true;
    const deadline = Date.now() + 32 * 60 * 1000;
    while (panel.isConnected && Router.current === 'global-settings' && globalSettingsSection === 'updates' && Date.now() < deadline) {
      try {
        const status = await API.systemUpdateStatus();
        summary.textContent = status.message;
        if (status.state !== 'running') {
          polling = false; check.disabled = false; rollback.disabled = false;
          if (status.state === 'completed') { Toast.success('更新完成'); window.location.reload(); }
          else if (status.state === 'failed') { Toast.error(status.message); install.hidden = true; }
          return;
        }
      } catch (_) { summary.textContent = '服务正在重启，等待重新连接…'; }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    polling = false;
    if (panel.isConnected) { summary.textContent = '等待超时，请刷新查看服务状态。'; check.disabled = false; rollback.disabled = false; }
  };
  check.onclick = async () => {
    if (check.disabled) return;
    check.disabled = true; check.textContent = '检查中…'; install.hidden = true;
    try {
      release = await API.checkSystemUpdate();
      if (!panel.isConnected) return;
      summary.textContent = `当前 ${release.current_version} · 最新 ${release.latest_version}。${release.update_available ? '有新版本可用。' : '当前无需更新。'}${release.update_supported ? '' : release.unsupported_reason || ''}`;
      install.hidden = !(release.update_available && release.update_supported);
      install.disabled = false;
      notes.hidden = !release.notes;
      notes.querySelector('pre').textContent = release.notes || '';
      notes.querySelector('a').href = release.release_url;
    } catch (error) { summary.textContent = '检查失败：' + error.message; }
    finally { if (check.isConnected) { check.disabled = false; check.textContent = '检查更新'; } }
  };
  install.onclick = async () => {
    if (!release || install.disabled || !window.confirm(`更新到 ${release.latest_version}？面板与站点会短暂重启，现有配置会保留。`)) return;
    install.disabled = true; check.disabled = true;
    try { await API.startSystemUpdate(release.latest_version); await poll(); }
    catch (error) { summary.textContent = error.message; install.disabled = false; check.disabled = false; }
  };
  API.systemUpdateStatus().then(status => {
    if (!panel.isConnected) return;
    rollback.hidden = !(status.protocol >= 2 && status.rollback_version);
    if (status.rollback_version) rollback.textContent = '恢复到 ' + status.rollback_version + ' 及升级前数据';
    rollbackStatus.textContent = status.state === 'unavailable' ? status.message : Number(status.protocol || 0) < 2
      ? '当前更新代理支持正式版更新；快捷恢复需要新版更新代理，正式版发布后可运行配套 install.sh install -y 刷新。'
      : status.rollback_version ? '可恢复上次成功升级前的快照。请先阅读下面的范围说明。' : '当前没有完整、可用的升级前快照。';
    if (status.state === 'running') { summary.textContent = status.message; poll(); }
    else if (status.state === 'failed') summary.textContent = status.message;
  }).catch(() => {});
  rollback.onclick = async () => {
    if (rollback.disabled || !window.confirm('恢复升级前版本和数据？升级后新增的配置、账号和流量记录会被替换；系统会先备份当前数据。外部证书和 Nginx 配置不会恢复，此快照成功恢复后将归档。')) return;
    rollback.disabled = true; check.disabled = true;
    try { await API.rollbackSystemUpdate(); await poll(); }
    catch (error) { summary.textContent = error.message; rollback.disabled = false; check.disabled = false; }
  };
}
