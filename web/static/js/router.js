// SPA Hash Router
const Router = {
  routes: {},
  current: null,

  register(path, handler) { this.routes[path] = handler; },

  navigate(path) {
    location.hash = path;
  },

  resolve() {
    const hash = location.hash.slice(1) || 'dashboard';
    this.current = hash;

    // Update nav links
    document.querySelectorAll('.topnav-link').forEach(l => {
      l.classList.toggle('active', l.dataset.page === hash);
    });
    document.querySelectorAll('.mobile-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.page === hash);
    });

    // Show active page
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById('page-' + hash);
    if (target) target.classList.add('active');

    // Call handler
    const handler = this.routes[hash];
    if (handler) handler();
  },

  init() {
    window.addEventListener('hashchange', () => this.resolve());
  }
};
