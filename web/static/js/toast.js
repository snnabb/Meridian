// Toast notification system
const Toast = {
  show(msg, type, duration) {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = 'toast ' + (type || 'info');
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => el.remove(), 300);
    }, duration || 3000);
  },
  success(msg) { this.show(msg, 'success'); },
  error(msg) { this.show(msg, 'error', 5000); },
  info(msg) { this.show(msg, 'info'); },
};
