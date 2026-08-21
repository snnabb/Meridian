// Meridian API Client
let meridianTimezoneOffsetMinutes = 480;
let meridianTimezoneName = 'Asia/Shanghai';
let meridianTimezoneFormatter = null;
let meridianTimezoneNameExplicit = false;

function meridianTimezoneSupported(name) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: name }).format();
    return true;
  } catch (_) {
    return false;
  }
}

function meridianSetTimezoneName(value) {
  const name = String(value || '').trim();
  if (name && meridianTimezoneSupported(name)) {
    meridianTimezoneName = name;
    meridianTimezoneNameExplicit = true;
    meridianTimezoneFormatter = null;
  }
  return meridianTimezoneName;
}

function meridianGetTimezoneName() {
  return meridianTimezoneName;
}

function meridianSetTimezoneOffset(value) {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric >= -720 && numeric <= 840) {
    meridianTimezoneOffsetMinutes = Math.trunc(numeric);
    if (!meridianTimezoneNameExplicit) meridianTimezoneName = 'UTC' + (numeric < 0 ? '-' : '+') + String(Math.floor(Math.abs(numeric) / 60)).padStart(2, '0') + ':' + String(Math.abs(numeric) % 60).padStart(2, '0');
  }
  return meridianTimezoneOffsetMinutes;
}

function meridianGetTimezoneOffset() {
  return meridianTimezoneOffsetMinutes;
}

function meridianTimezoneLabel(offset) {
  const value = Number.isFinite(Number(offset)) ? Number(offset) : meridianTimezoneOffsetMinutes;
  const sign = value < 0 ? '-' : '+';
  const absolute = Math.abs(value);
  return `${meridianTimezoneName} (UTC${sign}${String(Math.floor(absolute / 60)).padStart(2, '0')}:${String(absolute % 60).padStart(2, '0')})`;
}

function meridianTimezoneParts(timestamp) {
  const value = Number(timestamp);
  const instant = new Date(Number.isFinite(value) ? value : Date.now());
  if (!meridianTimezoneFormatter) meridianTimezoneFormatter = new Intl.DateTimeFormat('en-CA-u-ca-gregory-nu-latn', { timeZone: meridianTimezoneName, calendar: 'gregory', numberingSystem: 'latn', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3, hourCycle: 'h23' });
  const parts = Object.create(null);
  for (const part of meridianTimezoneFormatter.formatToParts(instant)) if (part.type !== 'literal') parts[part.type] = part.value;
  return { year: Number(parts.year), month: Number(parts.month), day: Number(parts.day), hour: Number(parts.hour), minute: Number(parts.minute), second: Number(parts.second), millisecond: Number(parts.fractionalSecond || 0) };
}

function meridianTimezoneDate(timestamp) {
  const value = Number(timestamp);
  const instant = Number.isFinite(value) ? value : Date.now();
  if (meridianTimezoneNameExplicit && meridianTimezoneSupported(meridianTimezoneName)) {
    const parts = meridianTimezoneParts(instant);
    return new Date(Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second));
  }
  return new Date(instant + meridianTimezoneOffsetMinutes * 60000);
}

function meridianFormatDateTime(timestamp, includeSeconds = true) {
  const date = meridianTimezoneDate(timestamp);
  const pad = value => String(value).padStart(2, '0');
  const base = `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
  return includeSeconds ? `${base}:${pad(date.getUTCSeconds())}` : base;
}

function meridianFormatDate(timestamp) {
  const date = meridianTimezoneDate(timestamp);
  return `${date.getUTCFullYear()}/${date.getUTCMonth() + 1}/${date.getUTCDate()}`;
}

function meridianDateTimeLocalValue(dateOrTimestamp) {
  const timestamp = dateOrTimestamp instanceof Date ? dateOrTimestamp.getTime() : Number(dateOrTimestamp);
  const date = meridianTimezoneDate(Number.isFinite(timestamp) ? timestamp : Date.now());
  const pad = value => String(value).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}T${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
}

function meridianParseDateTimeLocal(value) {
  const match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/);
  if (!match) return NaN;
  return meridianParseTimezoneWallTime(Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5]), 0);
}

function meridianParseDateTimeText(value) {
  const normalized = String(value || '').trim().replace(' ', 'T');
  const match = normalized.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/);
  if (!match) return NaN;
  return meridianParseTimezoneWallTime(Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0));
}

function meridianParseTimezoneWallTime(year, month, day, hour, minute, second, millisecond = 0) {
  const wall = Date.UTC(year, month - 1, day, hour, minute, second, millisecond);
  if (!meridianTimezoneNameExplicit) return wall - meridianTimezoneOffsetMinutes * 60000;
  let candidate = wall - meridianTimezoneOffsetMinutes * 60000;
  for (let attempt = 0; attempt < 3; attempt++) {
    const parts = meridianTimezoneParts(candidate);
    const observedWall = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, parts.millisecond);
    candidate += wall - observedWall;
  }
  return candidate;
}

function meridianDateOnlyValue(dateOrTimestamp) {
  const timestamp = dateOrTimestamp instanceof Date ? dateOrTimestamp.getTime() : Number(dateOrTimestamp);
  const date = meridianTimezoneDate(Number.isFinite(timestamp) ? timestamp : Date.now());
  const pad = value => String(value).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

function meridianParseDateOnly(value, endOfDay = false) {
  const match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return NaN;
  return meridianParseTimezoneWallTime(Number(match[1]), Number(match[2]), Number(match[3]), endOfDay ? 23 : 0, endOfDay ? 59 : 0, endOfDay ? 59 : 0, endOfDay ? 999 : 0);
}

const API = {
  username: '',
  authenticated: false,

  setSession(data) {
    this.username = (data && data.username) || '';
    this.authenticated = true;
  },

  clearSession() {
    this.username = '';
    this.authenticated = false;
  },

  async request(method, path, body) {
    const opts = {
      method,
      credentials: 'same-origin',
      headers: {},
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }

    const res = await fetch(path, opts);
    if (res.status === 401 && path !== '/api/auth/login') {
      await this.logout();
      window.location.reload();
      // The session is gone and the page is navigating to the login screen:
      // stop this request's control flow right here. Parsing or rejecting the
      // stale 401 body would only let callers keep handling a response that
      // is no longer valid (same convention as the dashboard SSE handler).
      return;
    }
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error(res.statusText || 'Request failed');
    }
    if (!res.ok) {
      const error = new Error(data.error || 'Request failed');
      error.status = res.status;
      const bodyRetryAfter = Number(data.retry_after_seconds);
      const headerRetryAfter = Number(res.headers && typeof res.headers.get === 'function'
        ? res.headers.get('Retry-After')
        : 0);
      const retryAfterSeconds = Number.isFinite(bodyRetryAfter) && bodyRetryAfter > 0
        ? bodyRetryAfter
        : headerRetryAfter;
      if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
        error.retryAfterSeconds = Math.ceil(retryAfterSeconds);
      }
      throw error;
    }
    return data;
  },

  // Auth
  checkSetup() { return this.request('GET', '/api/auth/check'); },
  login(username, password) { return this.request('POST', '/api/auth/login', { username, password }); },
  setup(username, password, setupToken) {
    return this.request('POST', '/api/auth/setup', { username, password, setup_token: setupToken });
  },
  getAccount() { return this.request('GET', '/api/account'); },
  updateAccount(data) { return this.request('PUT', '/api/account', data); },

  // Dashboard
  dashboard() { return this.request('GET', '/api/dashboard'); },
  dashboardInsights() { return this.request('GET', '/api/dashboard-insights'); },
  dashboardTrends(siteId, range, customStart, customEnd) {
    const params = new URLSearchParams({ site_id: siteId || 'all', range: range || 'realtime' });
    if ((range || '').toLowerCase() === 'custom') {
      if (customStart) params.set('start', customStart);
      if (customEnd) params.set('end', customEnd);
    }
    return this.request('GET', '/api/dashboard-trends?' + params.toString());
  },
  getSystemSettings() { return this.request('GET', '/api/system-settings'); },
  saveSystemSettings(data) { return this.request('POST', '/api/system-settings', data); },

  // Sites
  ingressCapabilities() { return this.request('GET', '/api/ingress-capabilities'); },
  panelCertificate() { return this.request('GET', '/api/panel-certificate'); },
  savePanelSettings(data) { return this.request('POST', '/api/panel-settings', data); },
  requestPanelCertificate(data) { return this.request('POST', '/api/panel-certificate/issue', data); },
  restartSystem() { return this.request('POST', '/api/system/restart', {}); },
  async exportBackup(password, includeTLS) {
    const res = await fetch('/api/backup/export', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, include_tls: includeTLS === true }),
    });
    if (res.status === 401) {
      await this.logout();
      window.location.reload();
      return;
    }
    if (!res.ok) {
      let message = '创建备份失败';
      try { message = (await res.json()).error || message; } catch (_) {}
      throw new Error(message);
    }
    return {
      blob: await res.blob(),
      disposition: res.headers.get('Content-Disposition') || '',
    };
  },
  async restoreBackup(file, password, confirm) {
    const body = new FormData();
    body.append('backup', file);
    body.append('password', password);
    body.append('confirm', confirm);
    const res = await fetch('/api/backup/restore', {
      method: 'POST',
      credentials: 'same-origin',
      body,
    });
    if (res.status === 401) {
      await this.logout();
      window.location.reload();
      return;
    }
    let data;
    try { data = await res.json(); } catch (_) { throw new Error(res.statusText || '恢复失败'); }
    if (!res.ok) throw new Error(data.error || '恢复失败');
    return data;
  },
  listSites() { return this.request('GET', '/api/sites'); },
  createSite(data) { return this.request('POST', '/api/sites', data); },
  reorderSites(siteIds) { return this.request('PUT', '/api/sites/reorder', { site_ids: siteIds }); },
  updateSite(id, data) { return this.request('PUT', '/api/sites/' + id, data); },
  deleteSite(id) { return this.request('DELETE', '/api/sites/' + id); },
  toggleSite(id) { return this.request('POST', '/api/sites/' + id + '/toggle'); },
  diagSite(id) { return this.request('GET', '/api/sites/' + id + '/diag'); },
  testUpstream(targetURL) { return this.request('POST', '/api/upstream-test', { target_url: targetURL }); },

  // Traffic
  getTraffic(siteId, hours) { return this.request('GET', '/api/traffic/' + siteId + '?hours=' + (hours || 24)); },
  // Live-merged traffic page payload: { snapshot: SiteTraffic, logs: TrafficLog[] }.
  getTrafficSnapshot(siteId, hours) { return this.request('GET', '/api/traffic/' + siteId + '/snapshot?hours=' + (hours || 24)); },
	getTrafficTimeline(siteId, minutes) {
		return this.request('GET', '/api/traffic/' + encodeURIComponent(siteId) + '/timeline?minutes=' + (minutes || 1440));
	},

  // Request logs
  getRequestLogs(filters) {
    const params = new URLSearchParams();
    Object.entries(filters || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
    });
    const query = params.toString();
    return this.request('GET', '/api/request-logs' + (query ? '?' + query : ''));
  },
  clearRequestLogs() { return this.request('DELETE', '/api/request-logs'); },

  // Telegram daily report
  getTelegramReportSettings() { return this.request('GET', '/api/telegram-report'); },
  saveTelegramReportSettings(data) { return this.request('POST', '/api/telegram-report', data); },

  // Asset cache
  getAssetCache() { return this.request('GET', '/api/asset-cache'); },
  clearAssetCache() { return this.request('DELETE', '/api/asset-cache'); },

  // UA Profiles
  getProfiles() { return this.request('GET', '/api/ua-profiles'); },

  // Dynamic discovery
  getDynamicProfiles() { return this.request('GET', '/api/dynamic-profiles'); },
  getDynamicObservations(siteId) {
    return this.request('GET', '/api/sites/' + encodeURIComponent(siteId) + '/dynamic-observations');
  },
  deleteDynamicObservations(siteId) {
    return this.request('DELETE', '/api/sites/' + encodeURIComponent(siteId) + '/dynamic-observations');
  },

  async logout() {
    this.clearSession();
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
      });
    } catch (e) {
      // The local UI can still safely return to its logged-out state.
    }
  }
};

// The server validates administrator passwords by UTF-8 byte length. Keep the
// setup form on the same contract without allocating an encoded copy.
function utf8ByteLength(value) {
  let length = 0;
  for (const char of String(value)) {
    const codePoint = char.codePointAt(0);
    if (codePoint <= 0x7f) length += 1;
    else if (codePoint <= 0x7ff) length += 2;
    else if (codePoint <= 0xffff) length += 3;
    else length += 4;
  }
  return length;
}

function adminPasswordValidationError(password) {
  const length = utf8ByteLength(password);
  return length < 12 || length > 72 ? '管理员密码必须为 12-72 字节' : '';
}

// Shared HTML escaper. It lives in the first-loaded script that every page
// already depends on, so no page can render markup before escaping exists.
// Keep it a function declaration: pages reach it as a global.
function esc(str) {
  return String(str).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char]);
}

// Shared display-time contract. API payloads stay as epoch/UTC values; every
// page derives the same China Standard Time labels without consulting the
// browser's locale or local time zone.
const SHANGHAI_DATE_TIME_FORMATTER = new Intl.DateTimeFormat('en-CA-u-ca-gregory-nu-latn', {
  timeZone: 'Asia/Shanghai',
  calendar: 'gregory',
  numberingSystem: 'latn',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});

function formatShanghaiDateTimeParts(value) {
  if (!(value instanceof Date) && typeof value !== 'number' && typeof value !== 'string') return null;
  const timestamp = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) return null;

  const values = Object.create(null);
  for (const part of SHANGHAI_DATE_TIME_FORMATTER.formatToParts(timestamp)) {
    if (part.type !== 'literal') values[part.type] = part.value;
  }
  if (!/^\d{4}$/.test(values.year || '')
      || !/^\d{2}$/.test(values.month || '')
      || !/^\d{2}$/.test(values.day || '')
      || !/^\d{2}$/.test(values.hour || '')
      || !/^\d{2}$/.test(values.minute || '')) return null;
  return {
    date: `${values.year}-${values.month}-${values.day}`,
    time: `${values.hour}:${values.minute}`,
  };
}

function formatShanghaiDateTime(value) {
  const parts = formatShanghaiDateTimeParts(value);
  return parts ? `${parts.date} ${parts.time}` : '不可用';
}
