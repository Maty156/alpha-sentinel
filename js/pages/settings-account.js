/* pages/settings-account.js - OWNER: the Account tab - your own password, your
   sign-in name and your avatar chip. Passwords live only inside their input
   fields and are cleared the moment a submit settles; they are never put into
   the DOM anywhere else. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.settingsTabs = S.settingsTabs || {};

  var PALETTE = [
    { key: 'crimson', hex: '#d2103c' }, { key: 'ember', hex: '#ff8a3d' },
    { key: 'amber', hex: '#ffc247' },  { key: 'moss', hex: '#7bc47f' },
    { key: 'teal', hex: '#2ec4a6' },   { key: 'azure', hex: '#4d9fff' },
    { key: 'violet', hex: '#a06bff' }, { key: 'slate', hex: '#8fa3bd' }
  ];

  function field(labelText, input, hint) {
    var wrap = S.ui.el('div', { class: 'form-row' });
    var label = S.ui.el('label', { class: 'form-label', text: labelText });
    label.setAttribute('for', input.id);
    wrap.appendChild(label);
    wrap.appendChild(input);
    if (hint) { wrap.appendChild(S.ui.el('div', { class: 'form-hint', text: hint })); }
    var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
    wrap.appendChild(msg);
    wrap._msg = msg;
    return wrap;
  }

  function say(row, text, bad) {
    row._msg.textContent = text || '';
    row._msg.className = 'form-msg' + (bad ? ' form-msg-bad' : ' form-msg-ok');
  }

  function passwordInput(id, autocomplete) {
    var input = S.ui.el('input', { class: 'field', type: 'password', id: id, autocomplete: autocomplete });
    var toggle = S.ui.el('button', { class: 'btn btn-sm', type: 'button', text: 'show', 'aria-label': 'Show or hide the password' });
    toggle.addEventListener('click', function () {
      var showing = input.getAttribute('type') === 'text';
      input.setAttribute('type', showing ? 'password' : 'text');
      toggle.textContent = showing ? 'show' : 'hide';
    });
    var wrap = S.ui.el('div', { class: 'field-with-btn' }, [input, toggle]);
    wrap._input = input;
    return wrap;
  }

  function general(view, session) {
    var form = S.ui.el('form', { class: 'card-form', novalidate: 'novalidate' });
    var current = passwordInput('accCurrent', 'current-password');
    var next = passwordInput('accNew', 'new-password');
    var rowCurrent = field('Current password', current);
    var rowNew = field('New password', next, 'At least 12 characters, and not your username or your current password.');
    var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
    var submit = S.ui.el('button', { class: 'btn btn-primary', type: 'submit', text: 'Change password' });

    form.appendChild(rowCurrent);
    form.appendChild(rowNew);
    form.appendChild(msg);
    form.appendChild(S.ui.el('div', { class: 'form-actions' }, [submit]));
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      msg.textContent = '';
      var cv = current._input.value, nv = next._input.value;
      if (nv.length < 12) { say(rowNew, 'At least 12 characters.', true); return; }
      if (nv === cv) { say(rowNew, 'Must differ from the current password.', true); return; }
      submit.disabled = true;
      S.api.post('/api/account/password', { current: cv, new: nv }, 'settings-account').then(function (r) {
        msg.textContent = 'Password changed' + (r && r.sessionsEnded ? (' - ' + r.sessionsEnded + ' other session(s) signed out') : '') + '.';
        msg.className = 'form-msg form-msg-ok';
        current._input.value = ''; next._input.value = '';
        say(rowNew, ''); say(rowCurrent, '');
      }).catch(function (err) {
        msg.textContent = err && err.message ? err.message : 'Could not change the password.';
        msg.className = 'form-msg form-msg-bad';
      }).then(function () {
        submit.disabled = false;
      });
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Password' })]),
      S.ui.el('div', { class: 'card-body' }, [form])
    ]));
  }

  function usernameCard(view, session) {
    var form = S.ui.el('form', { class: 'card-form', novalidate: 'novalidate' });
    var input = S.ui.el('input', { class: 'field', type: 'text', id: 'accName', value: session && session.user ? session.user : '', autocomplete: 'username' });
    var pass = passwordInput('accNamePass', 'current-password');
    var rowName = field('New sign-in name', input, '3-32 characters: A-Z, a-z, 0-9, dot, underscore, hyphen.');
    var rowPass = field('Your password', pass);
    var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
    var submit = S.ui.el('button', { class: 'btn btn-primary', type: 'submit', text: 'Change name' });
    form.appendChild(rowName);
    form.appendChild(rowPass);
    form.appendChild(msg);
    form.appendChild(S.ui.el('div', { class: 'form-actions' }, [submit]));
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      msg.textContent = '';
      var nv = input.value.trim();
      if (!/^[A-Za-z0-9._-]{3,32}$/.test(nv)) { say(rowName, '3-32 characters of A-Z, a-z, 0-9, dot, underscore, hyphen.', true); return; }
      submit.disabled = true;
      S.api.post('/api/account/username', { password: pass._input.value, newName: nv }, 'settings-account').then(function () {
        msg.textContent = 'Name changed to ' + nv + '.';
        msg.className = 'form-msg form-msg-ok';
        pass._input.value = '';
        say(rowName, ''); say(rowPass, '');
        try { window.sessionStorage.removeItem('sentinel-settings-tab'); } catch (e) { }
        setTimeout(function () { window.location.reload(); }, 600);
      }).catch(function (err) {
        msg.textContent = err && err.message ? err.message : 'Could not change the name.';
        msg.className = 'form-msg form-msg-bad';
      }).then(function () { submit.disabled = false; });
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Sign-in name' })]),
      S.ui.el('div', { class: 'card-body' }, [form])
    ]));
  }

  function avatarCard(view, session) {
    var chosen = (session && session.avatarColor) || 'crimson';
    var currentInitials = (session && session.avatarInitials) || '';
    var form = S.ui.el('form', { class: 'card-form', novalidate: 'novalidate' });
    var input = S.ui.el('input', { class: 'field', type: 'text', id: 'accInitials', value: currentInitials, maxlength: '2', autocomplete: 'off' });
    var rowInit = field('Initials', input, '1-2 characters, A-Z or 0-9.');
    var swatches = S.ui.el('div', { class: 'swatch-row', role: 'radiogroup', 'aria-label': 'Avatar colour' });
    PALETTE.forEach(function (c) {
      var b = S.ui.el('button', {
        class: 'swatch' + (c.key === chosen ? ' on' : ''), type: 'button',
        'aria-label': 'Colour ' + c.key, 'data-color': c.key, title: c.key
      });
      b.style.backgroundColor = c.hex;
      b.addEventListener('click', function () {
        chosen = c.key;
        Array.prototype.forEach.call(swatches.children, function (x) { x.classList.remove('on'); });
        b.classList.add('on');
      });
      swatches.appendChild(b);
    });
    var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
    var submit = S.ui.el('button', { class: 'btn btn-primary', type: 'submit', text: 'Save avatar' });
    form.appendChild(rowInit);
    form.appendChild(S.ui.el('div', { class: 'form-row' }, [S.ui.el('div', { class: 'form-label', text: 'Colour' }), swatches]));
    form.appendChild(msg);
    form.appendChild(S.ui.el('div', { class: 'form-actions' }, [submit]));
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      msg.textContent = '';
      var iv = input.value.trim().toUpperCase();
      if (!/^[A-Z0-9]{1,2}$/.test(iv)) { say(rowInit, '1-2 characters, A-Z or 0-9.', true); return; }
      submit.disabled = true;
      S.api.post('/api/account/avatar', { color: chosen, initials: iv }, 'settings-account').then(function () {
        msg.textContent = 'Avatar saved.';
        msg.className = 'form-msg form-msg-ok';
        say(rowInit, '');
        if (S.topbarAvatar) { S.topbarAvatar(iv, chosen); }
      }).catch(function (err) {
        msg.textContent = err && err.message ? err.message : 'Could not save the avatar.';
        msg.className = 'form-msg form-msg-bad';
      }).then(function () { submit.disabled = false; });
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Avatar' })]),
      S.ui.el('div', { class: 'card-body' }, [form])
    ]));
  }

  S.settingsTabs.account = {
    render: function (view) {
      S.ui.clear(view);
      S.api.get('/api/session', 'settings-account').then(function (session) {
        general(view, session);
        usernameCard(view, session);
        avatarCard(view, session);
      }).catch(function (err) {
        view.appendChild(S.ui.error(err && err.message ? err.message : 'Could not load the account.'));
      });
    }
  };
})();
