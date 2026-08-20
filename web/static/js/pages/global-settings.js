// Global settings pages
let globalSettingsCache = null;
let globalSettingsSection = 'system-ui';
let globalSettingsLoadGeneration = 0;

function applySystemUISettings(settings) {
  if (!settings) return;
  if (typeof meridianSetTimezoneName === 'function' && settings.schedule_timezone) meridianSetTimezoneName(settings.schedule_timezone);
  if (typeof meridianSetTimezoneOffset === 'function') meridianSetTimezoneOffset(settings.schedule_timezone_offset);
  const radius = Math.max(0, Math.min(24, Number(settings.ui_radius || 0)));
  document.documentElement.style.setProperty('--ui-radius', `${radius}px`);
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
    <span>SETTINGS</span><strong>全局设置导航</strong>
    ${button('system-ui', '系统设置')}${button('logs', '日志设置')}
    <a href="#settings-tls" class="settings-nav-item ${active === 'tls' ? 'active' : ''}">TLS 设置</a>
    <a href="#telegram-report" class="settings-nav-item ${active === 'telegram' ? 'active' : ''}">Telegram 通知</a>
    <a href="#diagnostics" class="settings-nav-item ${active === 'diagnostics' ? 'active' : ''}">故障诊断</a>
    <a href="#backup-restore" class="settings-nav-item ${active === 'backup' ? 'active' : ''}">备份与恢复</a>
  </aside>`;
}

function backupPasswordField(id, label) {
  return `<label class="settings-field"><span>${label}</span><div><input class="form-input" id="${id}" type="password" minlength="12" maxlength="128" autocomplete="new-password" placeholder="至少 12 个字符"></div></label>`;
}

function renderBackupRestore() {
  const page = document.getElementById('page-backup-restore');
  if (!page) return;
  page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav('backup')}<main class="settings-content backup-restore-content">
    <section class="settings-panel"><header><span>BACKUP</span><h2>数据备份</h2><b>密码加密</b></header>
      <p class="settings-panel-help">备份包含站点、账户、流量与请求日志、全局设置及 Telegram 配置；不包含缓存、.env 或部署密钥文件。</p>
      <div class="settings-grid">${backupPasswordField('backup-password', '备份密码')}${backupPasswordField('backup-password-confirm', '确认备份密码')}</div>
      ${settingsCheck('backup-include-tls', '包含 TLS 设置与证书', false, '默认不包含。勾选后才会备份面板域名、监听端口、TLS 开关、证书与 ACME 账户；未勾选时，恢复会保留目标服务器现有 TLS 配置。')}
      <div class="backup-warning">备份中含管理员账户、站点地址及加密凭据，必须妥善保存密码和备份文件。忘记密码后无法恢复。</div>
      <div class="settings-save-bar"><button class="telegram-btn primary" type="button" id="backup-download">下载加密备份</button></div>
    </section>
    <section class="settings-panel backup-restore-danger"><header><span>RESTORE</span><h2>数据恢复</h2><b>自动重启</b></header>
      <p class="settings-panel-help">恢复会替换当前数据库并使用备份中的管理员账户；只有备份明确包含 TLS 时才会替换 TLS 数据，否则保留当前服务器的 TLS 设置与证书。文件通过解密、结构检查和 SQLite 完整性检查后，Meridian 才会重启应用。</p>
      <div class="settings-grid">
        <label class="settings-field"><span>Meridian 备份文件</span><div><input class="form-input backup-file-input" id="restore-file" type="file" accept=".mrbak,application/octet-stream"></div></label>
        ${backupPasswordField('restore-password', '备份密码')}
      </div>
      <label class="settings-field backup-confirm-field"><span>确认操作</span><div><input class="form-input" id="restore-confirm" type="text" autocomplete="off" placeholder="请输入：恢复"></div><small>输入“恢复”后才能提交。开始恢复前建议先下载一份当前数据备份。</small></label>
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
  if (password.length < 12) return Toast.error('备份密码至少需要 12 个字符');
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
  if (password.length < 12) return Toast.error('请输入正确的备份密码');
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
  return `<label class="settings-field"><span>${label}</span><div><input class="form-input" id="${id}" type="number" min="${min}" max="${max}" value="${value}"><em>${unit}</em></div>${help ? `<small>${help}</small>` : ''}</label>`;
}

function trafficResetDaySelect(value) {
  const selected = Number(value);
  const options = ['<option value="0">不重置（累计流量）</option>'];
  for (let day = 1; day <= 31; day++) options.push(`<option value="${day}" ${selected === day ? 'selected' : ''}>每月 ${day} 日</option>`);
  if (selected === 0) options[0] = '<option value="0" selected>不重置（累计流量）</option>';
  return `<label class="settings-field"><span>流量周期</span><div><select class="form-select settings-reset-select" id="setting-traffic-reset-day">${options.join('')}</select></div><small>默认每月 1 日；选择不重置后，额度和流量统计使用全部累计值。</small></label>`;
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
  return `<label class="settings-field"><span>时区</span><div><select class="form-select" id="setting-schedule-timezone">${options.join('')}</select><input type="hidden" id="setting-schedule-timezone-offset" value="${offset}"></div><small>使用标准 IANA 时区；夏令时由服务端和浏览器自动处理。旧版 UTC 偏移仍会兼容读取。</small></label>`;
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
  content.innerHTML = globalSettingsSection === 'logs'
    ? renderLogSettingsForm(globalSettingsCache)
    : renderSystemUIForm(globalSettingsCache);
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
  return `<section class="settings-panel"><header><span>SYSTEM</span><h2>系统设置</h2><b>全局运行参数</b></header>
    <p class="settings-panel-help">单向仅计 VPS 发给客户端的出站流量；双向按经过 Meridian 的代理载荷同时计算 VPS 接收与发送流量，例如反代 1 GB 视频约计 2 GB。</p>
    <span class="settings-label">计费方向</span><div class="settings-choice" id="traffic-billing-mode-choice"><button data-setting-choice="outbound" class="${s.traffic_billing_mode === 'outbound' ? 'active' : ''}">单向（仅下载）</button><button data-setting-choice="bidirectional" class="${s.traffic_billing_mode !== 'outbound' ? 'active' : ''}">双向（下载 + 上传）</button></div>
  </section>
  <section class="settings-panel"><header><span>TRAFFIC RESET</span><h2>流量周期</h2><b>可重置或累计</b></header>
    <p class="settings-panel-help">可按每月指定日期重置站点额度和面板周期流量，也可选择不重置。设置为 29、30 或 31 日时，短月自动使用该月最后一天。</p>
    ${trafficResetDaySelect(s.traffic_reset_day == null ? 1 : s.traffic_reset_day)}
  </section>
  <section class="settings-panel"><header><span>RADIUS</span><h2>UI 圆角弧度</h2><b>0-24 px</b></header>
    ${settingsNumber('setting-ui-radius', '圆角弧度', s.ui_radius, 0, 24, 'px', '保存后立即应用到管理面板，不影响代理业务。')}
  </section>
  <section class="settings-panel"><header><span>PROBE</span><h2>健康检查探测</h2><b>1000-180000 ms</b></header>
    <div class="settings-grid">${settingsNumber('setting-probe-timeout', 'GET 超时时间', s.probe_timeout_ms, 1000, 180000, 'ms', '限制健康探测等待时间。')}${settingsNumber('setting-ping-cache', 'Ping 缓存时间', s.ping_cache_minutes, 0, 1440, '分钟', '设置为 0 可关闭短期复用。')}</div>
  </section>
  <section class="settings-panel"><header><span>SCHEDULE</span><h2>调度时区</h2><b>默认 Asia/Shanghai</b></header>
    ${timezoneSelect(s.schedule_timezone, s.schedule_timezone_offset)}
  </section>${settingsSaveBar()}`;
}

function renderLogSettingsForm(s) {
  return `<section class="settings-panel"><header><span>MASTER SWITCH</span><h2>日志功能总开关</h2><b>写入与查询统一控制</b></header>
    ${settingsCheck('setting-log-enabled', '开启日志写入与日志页显示', s.log_enabled)}
    <span class="settings-label">日志写入模式</span><div class="settings-choice" id="log-level-choice"><button data-setting-choice="info" class="${s.log_level === 'info' ? 'active' : ''}">INFO</button><button data-setting-choice="error" class="${s.log_level === 'error' ? 'active' : ''}">ERROR</button></div>
  </section>
  <section class="settings-panel"><header><span>STORAGE</span><h2>日志队列与落盘</h2><b>运行时生效</b></header><div class="settings-grid">
    ${settingsNumber('setting-log-retention', '日志保存', s.log_retention_days, 1, 365, '天')}${settingsNumber('setting-log-delay', '日志写入延迟', s.log_write_delay_minutes, 0, 60, '分钟')}
    ${settingsNumber('setting-log-threshold', '提前写入阈值', s.log_flush_threshold, 1, 1000, '条')}${settingsNumber('setting-log-batch', '单批写入大小', s.log_batch_size, 1, 100, '条')}
    ${settingsNumber('setting-log-retries', '写入重试次数', s.log_retry_count, 0, 10, '次')}${settingsNumber('setting-log-backoff', '重试退避', s.log_retry_backoff_ms, 0, 5000, 'ms')}
    ${settingsNumber('setting-log-lease', '定时任务租约时长', s.log_task_lease_ms, 1000, 900000, 'ms')}
  </div></section>
  <section class="settings-panel"><header><span>RESOURCE CATEGORIES</span><h2>记录哪些请求</h2><b>按需写入</b></header><p class="settings-panel-help">只开启排查时需要的类别，减少日志噪音。</p><div class="settings-check-grid">
    ${settingsCheck('setting-write-playback', '播放信息', s.log_write_playback !== false)}${settingsCheck('setting-write-video', '视频与流媒体', s.log_write_video !== false)}
    ${settingsCheck('setting-write-api', '常规 API', s.log_write_api !== false)}${settingsCheck('setting-write-auth', '用户认证', s.log_write_auth !== false)}
    ${settingsCheck('setting-write-asset', '静态资源', s.log_write_asset !== false)}
  </div><details class="settings-more"><summary>更多类别</summary><div class="settings-check-grid">
    ${settingsCheck('setting-write-image', '图片海报', s.log_write_image === true)}${settingsCheck('setting-write-metadata', '媒体元数据', s.log_write_metadata === true)}
    ${settingsCheck('setting-write-subtitle', '字幕', s.log_write_subtitle !== false)}${settingsCheck('setting-write-websocket', 'WebSocket', s.log_write_websocket !== false)}
  </div></details></section>
  <div class="settings-two-column"><section class="settings-panel"><header><span>WRITE</span><h2>日志字段写入</h2><b>仅影响新日志</b></header><p class="settings-panel-help">关闭不需要的字段可减少存储和页面噪音。</p><div class="settings-check-grid">
    ${settingsCheck('setting-write-node', '节点', s.log_write_node !== false)}${settingsCheck('setting-write-status', '状态码', s.log_write_status !== false)}
    ${settingsCheck('setting-write-ip', '客户端 IP', s.log_write_client_ip !== false)}${settingsCheck('setting-write-ua', '客户端 UA', s.log_write_ua !== false)}
    ${settingsCheck('setting-write-backend-address', '后端地址', s.log_write_backend_address !== false)}
  </div><details class="settings-more"><summary>更多字段</summary><div class="settings-check-grid">
    ${settingsCheck('setting-write-category', '资源类别', s.log_write_category !== false)}${settingsCheck('setting-write-upstream-ua', '上游 UA', s.log_write_upstream_ua !== false)}${settingsCheck('setting-write-timeline', '时间线', s.log_write_timeline !== false)}
  </div></details></section>
  <section class="settings-panel"><header><span>DISPLAY</span><h2>日志字段展示</h2><b>仅影响日志页</b></header><p class="settings-panel-help">只保留排查时真正需要的列，其他字段可在“更多字段”中打开。</p><div class="settings-check-grid">
    ${settingsCheck('setting-display-node', '节点', s.log_display_node !== false)}${settingsCheck('setting-display-status', '状态码', s.log_display_status !== false)}
    ${settingsCheck('setting-display-ip', '客户端 IP', s.log_display_client_ip !== false)}${settingsCheck('setting-display-ua', '客户端 UA', s.log_display_ua !== false)}
    ${settingsCheck('setting-display-backend-address', '后端地址', s.log_display_backend_address !== false)}
  </div><details class="settings-more"><summary>更多字段</summary><div class="settings-check-grid">
    ${settingsCheck('setting-display-category', '资源类别', s.log_display_category !== false)}${settingsCheck('setting-display-upstream-ua', '上游 UA', s.log_display_upstream_ua !== false)}${settingsCheck('setting-display-timeline', '时间线', s.log_display_timeline !== false)}
  </div></details></section></div>${settingsSaveBar()}`;
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
  const s = { ...globalSettingsCache };
  if (globalSettingsSection === 'system-ui') {
    s.traffic_billing_mode = activeSettingChoice('traffic-billing-mode-choice', s.traffic_billing_mode || 'bidirectional');
    s.traffic_reset_day = numericSetting('setting-traffic-reset-day', s.traffic_reset_day == null ? 1 : s.traffic_reset_day);
    s.ui_radius = numericSetting('setting-ui-radius', s.ui_radius);
    s.probe_timeout_ms = numericSetting('setting-probe-timeout', s.probe_timeout_ms);
    s.ping_cache_minutes = numericSetting('setting-ping-cache', s.ping_cache_minutes);
    const timezoneInput = document.getElementById('setting-schedule-timezone');
    s.schedule_timezone = timezoneInput ? timezoneInput.value : (s.schedule_timezone || 'Asia/Shanghai');
    s.schedule_timezone_offset = numericSetting('setting-schedule-timezone-offset', s.schedule_timezone_offset);
  } else {
    s.log_enabled = checkedSetting('setting-log-enabled', s.log_enabled);
    s.log_level = activeSettingChoice('log-level-choice', s.log_level);
    s.log_retention_days = numericSetting('setting-log-retention', s.log_retention_days);
    s.log_write_delay_minutes = numericSetting('setting-log-delay', s.log_write_delay_minutes);
    s.log_flush_threshold = numericSetting('setting-log-threshold', s.log_flush_threshold);
    s.log_batch_size = numericSetting('setting-log-batch', s.log_batch_size);
    s.log_retry_count = numericSetting('setting-log-retries', s.log_retry_count);
    s.log_retry_backoff_ms = numericSetting('setting-log-backoff', s.log_retry_backoff_ms);
    s.log_task_lease_ms = numericSetting('setting-log-lease', s.log_task_lease_ms);
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
  const button = document.getElementById('settings-save');
  button.disabled = true;
  try {
    globalSettingsCache = await API.saveSystemSettings(s);
    applySystemUISettings(globalSettingsCache);
    Toast.success('全局设置已保存');
    paintGlobalSettings(document.getElementById('page-global-settings'));
  } catch (error) {
    Toast.error('保存失败：' + error.message);
  } finally {
    if (button.isConnected) button.disabled = false;
  }
}

async function renderTLSSettings() {
  const page = document.getElementById('page-settings-tls');
  if (!page) return;
  page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav('tls')}<main class="settings-content"><section class="settings-panel"><div class="settings-loading">正在读取 TLS 配置…</div></section></main></div>`;
  bindGlobalSettingsNav(page);
  try {
    const status = await API.panelCertificate();
    if (Router.current !== 'settings-tls') return;
    page.innerHTML = `
      <div class="settings-layout fade-up">
        ${globalSettingsNav('tls')}
        <main class="settings-content">
        <section class="settings-panel fade-up">
          <header><span>TLS</span><h2>TLS 设置</h2><b>${status.configured ? '已配置' : '未配置'}</b></header>
          <div class="global-settings-status" id="p-panel-certificate-status">${renderPanelCertificateStatus(status)}</div>
          <div class="form-group" style="margin-top:18px">
            <label>面板访问域名前缀</label>
            <input type="text" class="form-input" id="p-panel-prefix" maxlength="63" value="${esc(status.panel_prefix || '')}" placeholder="panel" autocomplete="off" autocapitalize="none" spellcheck="false">
            <div class="form-help">只需填写前缀，例如 <code>panel</code>，不必填写完整域名。</div>
          </div>
          <div class="form-group">
            <label>节点泛域名</label>
            <input type="text" class="form-input" id="p-wildcard-domain" maxlength="255" value="${esc(status.wildcard_domain || (status.route_domain ? `*.${status.route_domain}` : ''))}" placeholder="*.example.com" autocomplete="off" autocapitalize="none" spellcheck="false">
            <div class="form-help">仅使用泛域名申请证书，例如 <code>*.example.com</code>；请提前将泛域名解析到本机。</div>
          </div>
          <div class="form-group">
            <label>启用后的面板地址</label>
            <div class="form-help" id="p-panel-address-preview">${esc(panelHTTPSPreview(status.panel_domain || ''))}</div>
          </div>
          <div class="form-group">
            <label>面板监听端口</label>
            <input type="number" class="form-input" id="p-panel-listen-port" min="1" max="65535" step="1" value="${esc(String(status.listen_port || status.active_listen_port || 9090))}">
            <div class="form-help">修改端口后需要重启面板；Docker 请使用 host 网络，并在宿主机防火墙中放行新端口。</div>
          </div>
        </section>
        <section class="settings-panel fade-up">
          <header><span>ACME</span><h2>申请泛域名证书</h2><b>Cloudflare DNS</b></header>
          <div class="form-group"><label>ACME 邮箱</label><input type="email" class="form-input" id="p-acme-email" autocomplete="email" maxlength="254" value="${esc(status.acme_email || '')}" placeholder="admin@example.com"><div class="form-help">邮箱会直接显示在面板中，用于 ACME 账户与证书续签通知。</div></div>
          <div class="form-group"><label>DNS 服务商</label><select class="form-select" id="p-acme-provider"><option value="cloudflare">Cloudflare DNS</option></select></div>
          <div class="form-group"><label>DNS API Token</label><input type="text" class="form-input mono" id="p-acme-token" autocomplete="off" maxlength="512" value="${esc(status.dns_api_token || '')}" placeholder="Cloudflare DNS API Token"><div class="form-help">Token 会直接显示给已登录管理员；数据库中仍加密保存，并用于证书自动续签。</div></div>
          <label class="settings-check"><input type="checkbox" id="p-acme-staging" ${status.acme_staging ? 'checked' : ''}><span>ACME 测试环境</span></label>
          <div class="settings-save-bar tls-settings-actions">
            ${status.restart_required && ((status.configured && status.certificate_current) || (!status.configured && status.listen_port !== status.active_listen_port)) ? `<button class="telegram-btn primary" type="button" id="p-cert-restart">${status.configured ? '启用 HTTPS 并重启' : '重启应用'}</button>` : ''}
            <button class="telegram-btn" type="button" id="p-cert-save">保存设置</button>
            <button class="telegram-btn primary" type="button" id="p-cert-issue" ${status.available === false || status.issuing || !status.settings_configured ? 'disabled' : ''}>申请证书</button>
          </div>
        </section>
        </main>
      </div>`;
    bindGlobalSettingsNav(page);
    const get = id => document.getElementById(`p-${id}`);
    const refreshPreview = () => {
      const prefix = get('panel-prefix').value.trim().replace(/^\*\./, '');
      const wildcard = get('wildcard-domain').value.trim().replace(/^\*\./, '');
      const domain = prefix && wildcard ? `${prefix}.${wildcard}` : '';
      const port = Number(get('panel-listen-port').value) || 9090;
      get('panel-address-preview').textContent = domain ? `https://${domain}${port === 443 ? '' : `:${port}`}` : '—';
    };
    ['panel-prefix', 'wildcard-domain', 'panel-listen-port'].forEach(id => get(id).addEventListener('input', refreshPreview));
    const restartButton = get('cert-restart');
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
        restartButton.textContent = status.configured ? '启用 HTTPS 并重启' : '重启应用';
        Toast.error(error.message);
      }
    };
    const settingsPayload = () => ({
      panel_prefix: get('panel-prefix').value.trim(),
      wildcard_domain: get('wildcard-domain').value.trim(),
      listen_port: Number(get('panel-listen-port').value),
    });
    get('cert-save').onclick = async () => {
      const button = get('cert-save');
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
        await renderTLSSettings();
      } catch (error) {
        button.disabled = false;
        button.textContent = '保存设置';
        Toast.error(error.message);
      }
    };
    get('cert-issue').onclick = async () => {
      const button = get('cert-issue');
      const tokenInput = get('acme-token');
      const settingsPayloadValue = settingsPayload();
      const savedWildcard = String(status.wildcard_domain || '').toLowerCase().replace(/^\*\./, '');
      const formWildcard = settingsPayloadValue.wildcard_domain.toLowerCase().replace(/^\*\./, '');
      if (settingsPayloadValue.panel_prefix !== status.panel_prefix || formWildcard !== savedWildcard || settingsPayloadValue.listen_port !== Number(status.listen_port)) {
        Toast.error('请先点击“保存设置”，再申请证书');
        return;
      }
      const payload = {
        email: get('acme-email').value.trim(),
        dns_provider: get('acme-provider').value,
        dns_api_token: tokenInput.value.trim(),
        staging: get('acme-staging').checked,
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
        await renderTLSSettings();
      } catch (error) {
        button.disabled = false;
        button.textContent = '申请证书';
        Toast.error(error.message);
      }
    };
  } catch (error) {
    page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav('tls')}<main class="settings-content"><section class="settings-panel"><div class="settings-loading request-log-error">读取 TLS 状态失败：${esc(error.message)}</div></section></main></div>`;
    bindGlobalSettingsNav(page);
  }
}
