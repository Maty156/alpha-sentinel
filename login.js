// ============================================================
// ALPHA SENTINEL - sign-in page
// Served by AlphaSentinel.ps1. Kept in its own file because the server sends
// Content-Security-Policy: script-src 'self' (no inline script anywhere).
// ============================================================
'use strict';

(function () {
  var form = document.getElementById('loginForm');
  var btn = document.getElementById('loginBtn');
  var errBox = document.getElementById('loginError');
  var userEl = document.getElementById('username');
  var passEl = document.getElementById('password');

  function showError(message) {
    errBox.textContent = message;
    errBox.style.display = 'block';
  }

  function clearError() {
    errBox.textContent = '';
    errBox.style.display = 'none';
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    clearError();

    var username = (userEl.value || '').trim();
    var password = passEl.value || '';
    if (!username || !password) {
      showError('Enter your username and password.');
      return;
    }

    btn.disabled = true;
    var original = btn.textContent;
    btn.textContent = 'Signing in...';

    fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.ok) {
          // the session cookie is HttpOnly, so the browser - not this script -
          // is what carries it to the dashboard
          window.location.replace('/');
          return;
        }
        if (res.status === 429) {
          showError(data.error || 'Too many failed sign-in attempts from this address.');
        } else {
          showError(data.error || 'Incorrect username or password.');
        }
      });
    }).catch(function () {
      showError('Could not reach the server. Is AlphaSentinel running?');
    }).then(function () {
      btn.disabled = false;
      btn.textContent = original;
      passEl.value = '';
    });
  });
})();
