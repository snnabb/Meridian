(function() {
  'use strict';

  const loginEl = document.getElementById('page-login');
  const shellEl = document.getElementById('app-shell');
  const loginFormEl = document.getElementById('loginForm');
  const loginFooterEl = document.getElementById('login-footer');
  const loginButtonEl = document.getElementById('btn-login');
  const loginRateLimitEl = document.getElementById('login-rate-limit');
  const usernameInputEl = document.getElementById('inp-username');
  const usernameHelpEl = document.getElementById('admin-username-help');
  const passwordInputEl = document.getElementById('inp-password');
  const passwordHelpEl = document.getElementById('admin-password-help');
  const confirmPasswordGroupEl = document.getElementById('confirm-password-group');
  const confirmPasswordInputEl = document.getElementById('inp-confirm-password');
  const setupTokenGroupEl = document.getElementById('setup-token-group');
  const setupTokenInputEl = document.getElementById('inp-setup-token');
  const setupTokenToggleEl = document.getElementById('btn-toggle-setup-token');
  const authCheckStatusEl = document.getElementById('auth-check-status');
  const authCheckMessageEl = document.getElementById('auth-check-message');
  const authRetryButtonEl = document.getElementById('btn-auth-retry');
  let dashboardRefreshTimer = null;
  let appBootstrapped = false;
  let modalBackdropClosable = false;
  let modalPreviousFocus = null;
  let activeModalClass = '';
  let authMode = 'checking';
  let authSubmissionInFlight = false;
  let loginRetryTimer = null;
  let loginRetryDeadline = 0;
  let authStatus = {
    needs_setup: false,
    mode: 'single_admin',
    jwt_secret_ephemeral: false,
    setup_token_required: false,
  };

  function resetModalScroll() {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    const body = document.getElementById('modal-body');
    if (overlay) overlay.scrollTop = 0;
    if (modal) modal.scrollTop = 0;
    if (body) body.scrollTop = 0;
    document.getElementById('modal-body').scrollTop = 0;
  }

  window.openModal = function(options) {
    modalBackdropClosable = !!(options && options.closeOnBackdrop);
    modalPreviousFocus = document.activeElement;
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    if (modal) {
      if (activeModalClass) modal.classList.remove(activeModalClass);
      const requestedClass = String(options && options.modalClass || '').trim();
      activeModalClass = /^[A-Za-z][A-Za-z0-9_-]*$/.test(requestedClass) ? requestedClass : '';
      if (activeModalClass) modal.classList.add(activeModalClass);
    }
    resetModalScroll();
    overlay.classList.add('active');
    overlay.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    // Reset after layout as well: replacing modal content can restore the
    // previous scroll position in some browsers after the overlay is shown.
    if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(resetModalScroll);
    if (typeof window.setTimeout === 'function') window.setTimeout(resetModalScroll, 0);
  };

  window.closeModal = function() {
    modalBackdropClosable = false;
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    if (modal && activeModalClass) modal.classList.remove(activeModalClass);
    activeModalClass = '';
    overlay.classList.remove('active');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    if (modalPreviousFocus && modalPreviousFocus.isConnected) modalPreviousFocus.focus();
    modalPreviousFocus = null;
  };

  document.getElementById('modal-overlay').addEventListener('click', function(e) {
    if (e.target === this && modalBackdropClosable) closeModal();
  });

  document.getElementById('modal-close').addEventListener('click', closeModal);

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && document.getElementById('modal-overlay').classList.contains('active')) closeModal();
  });

  function setSetupTokenVisible(visible) {
    setupTokenInputEl.type = visible ? 'text' : 'password';
    setupTokenToggleEl.textContent = visible ? '隐藏' : '显示';
    setupTokenToggleEl.setAttribute('aria-pressed', visible ? 'true' : 'false');
    setupTokenToggleEl.setAttribute('aria-label', visible ? '隐藏初始化令牌' : '显示初始化令牌');
  }

  const sidebarToggleEl = document.getElementById('sidebar-toggle');
  const sidebarDrawerCloseEl = document.getElementById('sidebar-drawer-close');
  const sidebarStorageKey = 'meridian-sidebar-expanded';

  function storedSidebarExpanded() {
    try {
      if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) return false;
      return !!(window.localStorage && window.localStorage.getItem(sidebarStorageKey) === 'true');
    } catch (_) {
      return false;
    }
  }

  function setSidebarExpanded(expanded, persist) {
    expanded = !!expanded;
    if (shellEl && shellEl.classList) {
      if (typeof shellEl.classList.toggle === 'function') shellEl.classList.toggle('sidebar-expanded', expanded);
      else if (expanded && typeof shellEl.classList.add === 'function') shellEl.classList.add('sidebar-expanded');
      else if (!expanded && typeof shellEl.classList.remove === 'function') shellEl.classList.remove('sidebar-expanded');
    }
    if (sidebarToggleEl) {
      const label = expanded ? '折叠导航栏' : '展开导航栏';
      sidebarToggleEl.setAttribute('aria-expanded', String(expanded));
      sidebarToggleEl.setAttribute('aria-label', label);
      sidebarToggleEl.title = label;
    }
    if (persist) {
      try {
        if (window.localStorage) window.localStorage.setItem(sidebarStorageKey, String(expanded));
      } catch (_) {}
    }
  }

  setSidebarExpanded(storedSidebarExpanded(), false);
  if (sidebarToggleEl) {
    sidebarToggleEl.addEventListener('click', function() {
      setSidebarExpanded(!shellEl.classList.contains('sidebar-expanded'), true);
    });
  }
  if (sidebarDrawerCloseEl) sidebarDrawerCloseEl.addEventListener('click', () => setSidebarExpanded(false, true));

  const dismissMobileDrawer = () => {
    if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches && shellEl.classList.contains('sidebar-expanded')) {
      setSidebarExpanded(false, true);
    }
  };
  if (typeof document.querySelector === 'function') {
    document.querySelector('.main')?.addEventListener('click', dismissMobileDrawer);
    document.querySelector('.app-header')?.addEventListener('click', event => {
      if (!event.target.closest('#sidebar-toggle')) dismissMobileDrawer();
    });
  }

  if (typeof document.querySelectorAll === 'function') document.querySelectorAll('.sidebar a[href^="#"]').forEach(link => {
    link.addEventListener('click', function() {
      if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) {
        setSidebarExpanded(false, true);
      }
    });
  });

  function setAuthChecking() {
    stopLoginRetryCountdown();
    authMode = 'checking';
    loginFormEl.setAttribute('aria-busy', 'true');
    loginButtonEl.disabled = true;
    loginButtonEl.textContent = '正在检查...';
    if (authCheckStatusEl) {
      authCheckStatusEl.hidden = false;
      authCheckStatusEl.classList.remove('error');
      authCheckStatusEl.setAttribute('role', 'status');
    }
    if (authCheckMessageEl) authCheckMessageEl.textContent = '正在检查初始化状态...';
    if (authRetryButtonEl) {
      authRetryButtonEl.hidden = true;
      authRetryButtonEl.disabled = true;
    }
    if (loginFooterEl) loginFooterEl.hidden = true;
  }

  function revealAuthScreen() {
    if (document.body && document.body.classList) document.body.classList.remove('auth-checking');
  }

  function showAuthCheckError() {
    revealAuthScreen();
    authMode = 'error';
    loginFormEl.setAttribute('aria-busy', 'false');
    loginButtonEl.disabled = true;
    loginButtonEl.textContent = '状态检查失败';
    if (authCheckStatusEl) {
      authCheckStatusEl.hidden = false;
      authCheckStatusEl.classList.add('error');
      authCheckStatusEl.setAttribute('role', 'alert');
    }
    if (authCheckMessageEl) authCheckMessageEl.textContent = '初始化状态检查失败，无法确定应登录还是创建管理员。请确认服务可用后重试。';
    if (authRetryButtonEl) {
      authRetryButtonEl.hidden = false;
      authRetryButtonEl.disabled = false;
    }
    if (loginFooterEl) loginFooterEl.hidden = true;
  }

  async function checkAuth() {
    setAuthChecking();
    try {
      const res = await API.checkSetup();
      if (!res || typeof res.needs_setup !== 'boolean') {
        throw new Error('invalid auth check response');
      }
      authStatus = {
        needs_setup: res.needs_setup,
        mode: typeof res.mode === 'string' ? res.mode : 'single_admin',
        jwt_secret_ephemeral: !!res.jwt_secret_ephemeral,
      };
      if (res.needs_setup) {
        showSetupMode();
        return;
      }
      if (res.authenticated) {
        API.setSession(res);
        enterApp();
        return;
      }
      showLoginMode();
    } catch (e) {
      showAuthCheckError();
    }
  }

  function renderLoginFooter(isSetup) {
    const lines = [isSetup
      ? '当前为单管理员模式，请创建唯一的管理员账号。'
      : '当前为单管理员模式。'];

    if (authStatus.jwt_secret_ephemeral) {
      lines.push('<span class="login-note warn">当前未固定 JWT_SECRET，服务重启后需要重新登录。</span>');
    }

    return lines.join('');
  }

  function showSetupMode() {
    stopLoginRetryCountdown();
    revealAuthScreen();
    authMode = 'setup';
    loginFormEl.setAttribute('aria-busy', 'false');
    if (authCheckStatusEl) authCheckStatusEl.hidden = true;
    loginButtonEl.textContent = '创建管理员';
    loginButtonEl.disabled = false;
    loginFooterEl.innerHTML = renderLoginFooter(true);
    loginFooterEl.hidden = false;
    usernameHelpEl.hidden = false;
    usernameInputEl.setAttribute('aria-describedby', 'admin-username-help');
    passwordHelpEl.hidden = false;
    passwordInputEl.autocomplete = 'new-password';
    passwordInputEl.setAttribute('aria-describedby', 'admin-password-help');
    confirmPasswordGroupEl.hidden = false;
    confirmPasswordInputEl.required = true;
    setupTokenGroupEl.hidden = false;
    setupTokenInputEl.required = true;
    setSetupTokenVisible(false);
  }

  function showLoginMode() {
    stopLoginRetryCountdown();
    revealAuthScreen();
    authMode = 'login';
    loginFormEl.setAttribute('aria-busy', 'false');
    if (authCheckStatusEl) authCheckStatusEl.hidden = true;
    loginButtonEl.textContent = '登录';
    loginButtonEl.disabled = false;
    loginFooterEl.innerHTML = renderLoginFooter(false);
    loginFooterEl.hidden = false;
    if (usernameHelpEl) usernameHelpEl.hidden = true;
    if (usernameInputEl && typeof usernameInputEl.removeAttribute === 'function') usernameInputEl.removeAttribute('aria-describedby');
    if (passwordHelpEl) passwordHelpEl.hidden = true;
    if (passwordInputEl) {
      passwordInputEl.autocomplete = 'current-password';
      if (typeof passwordInputEl.removeAttribute === 'function') passwordInputEl.removeAttribute('aria-describedby');
    }
    if (confirmPasswordGroupEl) confirmPasswordGroupEl.hidden = true;
    if (confirmPasswordInputEl) {
      confirmPasswordInputEl.required = false;
      confirmPasswordInputEl.value = '';
    }
    if (setupTokenGroupEl) setupTokenGroupEl.hidden = true;
    if (setupTokenInputEl) {
      setupTokenInputEl.required = false;
      setupTokenInputEl.value = '';
    }
    if (setupTokenToggleEl) setSetupTokenVisible(false);
  }

  function setupUsernameValidationError(username) {
    const length = utf8ByteLength(username);
    return length < 1 || length > 64 ? '管理员用户名必须为 1-64 个 UTF-8 字节' : '';
  }

  if (authRetryButtonEl) authRetryButtonEl.addEventListener('click', checkAuth);
  if (setupTokenToggleEl) setupTokenToggleEl.addEventListener('click', function() {
    setSetupTokenVisible(setupTokenInputEl.type === 'password');
  });

  function startDashboardRefresh() {
    if (dashboardRefreshTimer) clearInterval(dashboardRefreshTimer);
    dashboardRefreshTimer = setInterval(() => {
      if (Router.current === 'dashboard') loadDashboardData();
    }, 15000);
  }

  function stopDashboardRefresh() {
    if (!dashboardRefreshTimer) return;
    clearInterval(dashboardRefreshTimer);
    dashboardRefreshTimer = null;
  }

  function teardownAppRuntime() {
    stopDashboardRefresh();
    if (typeof stopDashSSE === 'function') stopDashSSE();
    if (typeof stopTrafficRefresh === 'function') stopTrafficRefresh();
  }

  function loginErrorMessage(error) {
    const message = String(error && error.message || '登录失败');
    if (message.includes('too many login attempts') || message.includes('登录尝试次数过多')) {
      const seconds = Math.max(1, Number(error && error.retryAfterSeconds) || 60);
      return `登录尝试次数过多，请在 ${Math.ceil(seconds)} 秒后重试`;
    }
    if (message === 'invalid username or password' || message === '用户名或密码错误') return '用户名或密码错误';
    return message;
  }

  function stopLoginRetryCountdown() {
    if (loginRetryTimer !== null) clearInterval(loginRetryTimer);
    loginRetryTimer = null;
    loginRetryDeadline = 0;
    if (loginRateLimitEl) {
      loginRateLimitEl.hidden = true;
      loginRateLimitEl.textContent = '';
    }
  }

  function startLoginRetryCountdown(seconds) {
    stopLoginRetryCountdown();
    const waitSeconds = Math.max(1, Math.ceil(Number(seconds) || 60));
    loginRetryDeadline = Date.now() + waitSeconds * 1000;
    const update = () => {
      const remaining = Math.max(0, Math.ceil((loginRetryDeadline - Date.now()) / 1000));
      if (remaining === 0) {
        stopLoginRetryCountdown();
        if (authMode === 'login' && !authSubmissionInFlight) {
          loginButtonEl.disabled = false;
          loginButtonEl.textContent = '登录';
        }
        return;
      }
      loginButtonEl.disabled = true;
      loginButtonEl.textContent = `${remaining} 秒后重试`;
      if (loginRateLimitEl) {
        loginRateLimitEl.hidden = false;
        loginRateLimitEl.textContent = `密码错误次数过多，请在 ${remaining} 秒后重试。`;
      }
    };
    update();
    loginRetryTimer = setInterval(update, 1000);
  }

  loginFormEl.addEventListener('submit', async function(e) {
    e.preventDefault();
    if (authSubmissionInFlight) return;
    if (authMode !== 'setup' && authMode !== 'login') {
      Toast.error('初始化状态尚未确认，请先重试');
      return;
    }
    const submittingSetup = authMode === 'setup';

    const username = usernameInputEl.value.trim();
    const password = passwordInputEl.value;
    const confirmPassword = confirmPasswordInputEl.value;
    const setupToken = setupTokenInputEl.value.trim();

    if (!submittingSetup) {
      if (!username || !password) {
        Toast.error('请填写用户名和密码');
        return;
      }
    } else {
      const usernameError = setupUsernameValidationError(username);
      if (usernameError) {
        Toast.error(usernameError);
        return;
      }
      const passwordError = adminPasswordValidationError(password);
      if (passwordError) {
        Toast.error(passwordError);
        return;
      }
      if (password !== confirmPassword) {
        Toast.error('两次输入的密码不一致');
        return;
      }
      if (!setupToken) {
        Toast.error('请填写初始化令牌');
        return;
      }
    }

    authSubmissionInFlight = true;
    loginButtonEl.disabled = true;
    loginButtonEl.textContent = '处理中...';

    try {
      let res;
      if (submittingSetup) {
        res = await API.setup(username, password, setupToken);
        Toast.success('管理员创建成功');
      } else {
        res = await API.login(username, password);
        Toast.success('欢迎回来, ' + res.username + '!');
      }
      API.setSession(res);
      passwordInputEl.value = '';
      confirmPasswordInputEl.value = '';
      setupTokenInputEl.value = '';
      setSetupTokenVisible(false);
      enterApp();
    } catch (err) {
      Toast.error(loginErrorMessage(err));
      if (submittingSetup) {
        await checkAuth();
      } else if (err && err.status === 429) {
        startLoginRetryCountdown(err.retryAfterSeconds);
      } else {
        loginButtonEl.disabled = false;
        loginButtonEl.textContent = '登录';
      }
    } finally {
      authSubmissionInFlight = false;
    }
  });


  function enterApp() {
    stopLoginRetryCountdown();
    loginEl.classList.add('hidden');
    shellEl.classList.add('active');

    const avatar = document.getElementById('avatar-initial');
    if (avatar) avatar.textContent = (API.username || 'A')[0].toUpperCase();
    const username = document.getElementById('sidebar-username');
    if (username) username.textContent = API.username || '管理员';
    API.ingressCapabilities().then(capabilities => {
      if (!capabilities || !capabilities.app_version) return;
      ['sidebar-version'].forEach(id => {
        const version = document.getElementById(id);
        if (version) version.textContent = capabilities.app_version;
      });
    }).catch(() => {});

    if (!appBootstrapped) {
      Router.register('dashboard', renderDashboard);
      Router.register('sites', renderSites);
      Router.register('request-logs', renderRequestLogs);
      Router.register('telegram-report', renderTelegramReport);
      Router.register('settings-tls', renderTLSSettings);
      Router.register('global-settings', renderGlobalSettings);
      Router.register('backup-restore', renderBackupRestore);
      Router.register('account', renderAccount);
      if (typeof renderDiag === 'function') {
        Router.register('diagnostics', renderDiag);
      } else {
        console.error('renderDiag is not defined; diagnostics page script failed to load');
        Router.register('diagnostics', function() {
          var page = document.getElementById('page-diagnostics');
          if (page) {
            page.innerHTML = '<div class="diag-card diag-card-wide"><div class="diag-empty">诊断页面脚本加载失败，请强制刷新浏览器缓存后重试。</div></div>';
          }
        });
      }
      Router.init();
      loadAppliedSystemSettings();
      appBootstrapped = true;
    }

    Router.resolve();
    startDashboardRefresh();
    document.body.classList.remove('auth-checking');
  }

  async function logoutApp() {
    if (!confirm('确认退出登录？')) return;

    teardownAppRuntime();
    await API.logout();
    loginEl.classList.remove('hidden');
    shellEl.classList.remove('active');
    showLoginMode();
    document.getElementById('inp-password').value = '';
    Toast.info('已退出登录');
  }

  window.logoutMeridian = logoutApp;
  if (document.getElementById('avatar-btn')) document.getElementById('avatar-btn').addEventListener('click', function() {
    if (window.matchMedia && window.matchMedia('(max-width: 768px)').matches) {
      setSidebarExpanded(false, true);
    }
  });

  checkAuth();
})();
