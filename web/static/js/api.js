// EmbyHub API Client
const API = {
  get token() { return localStorage.getItem('embyhub_token'); },
  set token(v) { v ? localStorage.setItem('embyhub_token', v) : localStorage.removeItem('embyhub_token'); },
  get username() { return localStorage.getItem('embyhub_user') || ''; },
  set username(v) { v ? localStorage.setItem('embyhub_user', v) : localStorage.removeItem('embyhub_user'); },

  async request(method, path, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (this.token) opts.headers['Authorization'] = 'Bearer ' + this.token;
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(path, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  },

  // Auth
  checkSetup() { return this.request('GET', '/api/auth/check'); },
  login(username, password) { return this.request('POST', '/api/auth/login', { username, password }); },
  setup(username, password) { return this.request('POST', '/api/auth/setup', { username, password }); },

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

  logout() {
    this.token = null;
    this.username = null;
  }
};
