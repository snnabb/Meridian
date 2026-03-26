// EmbyHub Main App
(function() {
  'use strict';

  const loginEl = document.getElementById('page-login');
  const shellEl = document.getElementById('app-shell');

  // ========= Modal helpers =========
  window.openModal = function() {
    document.getElementById('modal-overlay').classList.add('active');
  };

  window.closeModal = function() {
    document.getElementById('modal-overlay').classList.remove('active');
  };

  document.getElementById('modal-overlay').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });

  document.getElementById('modal-close').addEventListener('click', closeModal);

  // ========= Auth flow =========
  async function checkAuth() {
    if (API.token) {
      enterApp();
      return;
    }

    try {
      const res = await API.checkSetup();
      if (res.needs_setup) {
        showSetupMode();
      }
    } catch (e) {
      // Server not available, just show login
    }
  }

  function showSetupMode() {
    document.getElementById('btn-login').textContent = '注 册';
    document.getElementById('login-footer').innerHTML = '首次使用，请创建管理员账号';
    loginEl._isSetup = true;
  }

  // Login form
  document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const username = document.getElementById('inp-username').value.trim();
    const password = document.getElementById('inp-password').value;

    if (!username || !password) {
      Toast.error('请填写用户名和密码');
      return;
    }

    if (password.length < 6) {
      Toast.error('密码至少 6 位');
      return;
    }

    const btn = document.getElementById('btn-login');
    btn.disabled = true;
    btn.textContent = '处理中...';

    try {
      let res;
      if (loginEl._isSetup) {
        res = await API.setup(username, password);
        Toast.success('管理员创建成功！');
      } else {
        res = await API.login(username, password);
        Toast.success('欢迎回来, ' + res.username + '!');
      }
      API.token = res.token;
      API.username = res.username;
      enterApp();
    } catch (err) {
      Toast.error(err.message);
      btn.disabled = false;
      btn.textContent = loginEl._isSetup ? '注 册' : '登 录';
    }
  });

  // Register link
  document.getElementById('link-register').addEventListener('click', function(e) {
    e.preventDefault();
    showSetupMode();
  });

  function enterApp() {
    loginEl.classList.add('hidden');
    shellEl.classList.add('active');

    // Set avatar
    const avatar = document.getElementById('avatar-btn');
    avatar.textContent = (API.username || 'A')[0].toUpperCase();

    // Register routes
    Router.register('dashboard', renderDashboard);
    Router.register('sites', renderSites);
    Router.register('traffic', renderTraffic);
    Router.register('diagnostics', renderDiag);
    Router.init();

    // Initial navigation
    Router.resolve();

    // Auto refresh
    setInterval(() => {
      if (Router.current === 'dashboard') loadDashboardData();
    }, 15000);
  }

  // Logout
  document.getElementById('avatar-btn').addEventListener('click', function() {
    if (confirm('确认退出登录？')) {
      API.logout();
      loginEl.classList.remove('hidden');
      loginEl._isSetup = false;
      shellEl.classList.remove('active');
      document.getElementById('btn-login').textContent = '登 录';
      document.getElementById('btn-login').disabled = false;
      document.getElementById('login-footer').innerHTML = '首次使用？<a href="#" id="link-register">创建管理员账号</a>';
      document.getElementById('inp-password').value = '';
      Toast.info('已退出登录');
    }
  });

  // ========= Start =========
  checkAuth();

})();
