// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', function () {
  // Initialize Lucide icons
  lucide.createIcons();

  // Password visibility toggle
  document.querySelectorAll('.input-toggle').forEach(function (button) {
    button.addEventListener('click', function () {
      var input = this.parentElement.querySelector('input');
      var eyeIcon = this.querySelector('[data-lucide="eye"]');
      var eyeOffIcon = this.querySelector('[data-lucide="eye-off"]');

      if (input.type === 'password') {
        input.type = 'text';
        if (eyeIcon) eyeIcon.style.display = 'none';
        if (eyeOffIcon) eyeOffIcon.style.display = 'block';
      } else {
        input.type = 'password';
        if (eyeIcon) eyeIcon.style.display = 'block';
        if (eyeOffIcon) eyeOffIcon.style.display = 'none';
      }
    });
  });

  // Form submission with spinner
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var button = form.querySelector('button[type="submit"]');
      if (button && !button.disabled) {
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span>Please wait...';
      }
    });
  });

  // Settings Panel
  var settingsBtn = document.getElementById('settingsBtn');
  var settingsPopover = document.getElementById('settingsPopover');
  var themeToggleIcon = document.getElementById('themeToggleIcon');

  if (settingsBtn && settingsPopover) {
    // Toggle popover
    settingsBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      settingsPopover.classList.toggle('open');
    });

    // Close popover when clicking outside
    document.addEventListener('click', function (e) {
      if (!settingsPopover.contains(e.target) && !settingsBtn.contains(e.target)) {
        settingsPopover.classList.remove('open');
      }
    });
  }

  // Theme handling
  function getStoredTheme() {
    return localStorage.getItem('theme') || 'system';
  }

  function setTheme(theme) {
    localStorage.setItem('theme', theme);
    applyTheme(theme);
    updateThemeButtons(theme);
  }

  function applyTheme() {
    // First check cookie (set by Next.js redirect)
    const cookieTheme = getCookie('theme');
    if (cookieTheme && !localStorage.getItem('theme')) {
      localStorage.setItem('theme', cookieTheme);
    }

    const savedTheme = localStorage.getItem('theme') || 'system';

    if (savedTheme === 'system') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', savedTheme);
    }

    updateThemeButtons();
  }

  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }

  function updateThemeButtons(theme) {
    document.querySelectorAll('.settings-option[data-theme]').forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-theme') === theme);
    });
  }

  // Quick toggle (header icon)
  if (themeToggleIcon) {
    themeToggleIcon.addEventListener('click', function () {
      var current = getStoredTheme();
      var isDark = current === 'dark' ||
        (current === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      setTheme(isDark ? 'light' : 'dark');
    });
  }

  // Theme option buttons
  document.querySelectorAll('.settings-option[data-theme]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      setTheme(this.getAttribute('data-theme'));
    });
  });

  // Apply stored theme on load
  var storedTheme = getStoredTheme();
  applyTheme(storedTheme);
  updateThemeButtons(storedTheme);
});