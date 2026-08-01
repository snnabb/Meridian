// Meridian API Client
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
    const data = await res.json();
    if (!res.ok) {
      if (res.status === 401 && path !== '/api/auth/login') {
        await this.logout();
        window.location.reload();
      }
      throw new Error(data.error || 'Request failed');
    }
    return data;
  },

  // Auth
  checkSetup() { return this.request('GET', '/api/auth/check'); },
  login(username, password) { return this.request('POST', '/api/auth/login', { username, password }); },
  setup(username, password, setupToken) {
    return this.request('POST', '/api/auth/setup', { username, password, setup_token: setupToken });
  },

  // Dashboard
  dashboard() { return this.request('GET', '/api/dashboard'); },

  // Sites
  listSites() { return this.request('GET', '/api/sites'); },
  createSite(data) { return this.request('POST', '/api/sites', data); },
  updateSite(id, data) { return this.request('PUT', '/api/sites/' + id, data); },
  deleteSite(id) { return this.request('DELETE', '/api/sites/' + id); },
  toggleSite(id) { return this.request('POST', '/api/sites/' + id + '/toggle'); },
  diagSite(id) { return this.request('GET', '/api/sites/' + id + '/diag'); },

  // Traffic
  getTraffic(siteId, hours) { return this.request('GET', '/api/traffic/' + siteId + '?hours=' + (hours || 24)); },

  // UA Profiles
  getProfiles() { return this.request('GET', '/api/ua-profiles'); },

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
