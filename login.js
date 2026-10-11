/* login.js - OWNER: the sign-in form. Posts to /api/login, shows the one generic
   message the backend returns, and forwards to the dashboard on success. */
(function () {
  'use strict';

  var form = document.getElementById('loginForm');
  var button = document.getElementById('loginButton');
  var errorBox = document.getElementById('loginError');

  function show(message) {
    errorBox.textContent = message;
    errorBox.classList.add('on');
  }

  function busy(on) {
    button.disabled = !!on;
    button.textContent = on ? 'Signing in...' : 'Sign in';
  }

  function logFail(err) {
    console.error('[sentinel:login] sign-in failed:', err && err.message ? err.message : err);
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    if (!username || !password) { show('Enter your username and password.'); return; }
    busy(true);
    fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (res.ok) { window.location.replace('/'); return; }
        var message = (data && data.error) ? data.error : 'Sign-in failed.';
        if (res.status === 429) { message = 'Too many attempts from this address. Try again in a few minutes.'; }
        show(message);
        busy(false);
      });
    }).catch(function (err) {
      logFail(err);
      show('Could not reach the monitor. Is it still running?');
      busy(false);
    });
  });
})();
