const Router = {
  routes: Object.create(null),
  current: null,
  initialized: false,

  register(path, handler) {
    this.routes[path] = handler;
  },

  navigate(path) {
    location.hash = path;
  },

  resolve() {
    const hash = location.hash.slice(1) || 'dashboard';
    const previous = this.current;

    if (previous === 'dashboard' && hash !== 'dashboard' && typeof stopDashSSE === 'function') {
      stopDashSSE();
    }

    this.current = hash;

    document.querySelectorAll('.topnav-link').forEach(link => {
      link.classList.toggle('active', link.dataset.page === hash);
    });
    document.querySelectorAll('.mobile-tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.page === hash);
    });

    document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
    const target = document.getElementById('page-' + hash);
    if (target) target.classList.add('active');

    const handler = this.routes[hash];
    if (handler) handler();
  },

  init() {
    if (this.initialized) return;
    window.addEventListener('hashchange', () => this.resolve());
    this.initialized = true;
  }
};
