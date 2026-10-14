/* pages/settings-users.js - OWNER: the Users tab - who can sign in to this
   dashboard. Creating, resetting and removing all require YOUR password again
   (re-auth): anyone at a keyboard left signed in must not be able to mint or
   destroy accounts silently. No password is ever kept in the DOM after a
   submit settles. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.settingsTabs = S.settingsTabs || {};

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

  function formMsg() {
    return S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
  }

  function paint(rows) {
    var view = document.getElementById('settingsBody');
    if (!view) { return; }
    S.ui.clear(view);
    var me = '';
    rows.forEach(function (r) { if (r.current) { me = r.name; } });

    /* ---- the list ---- */
    var tbody = S.ui.el('tbody');
    rows.forEach(function (r) {
      var actions = S.ui.el('td', { class: 'cell-actions' });
      var resetBtn = S.ui.el('button', { class: 'btn btn-sm', type: 'button', text: 'Reset password' });
      resetBtn.addEventListener('click', function () { openReset(r, load); });
      actions.appendChild(resetBtn);
      if (!r.current) {
        var removeBtn = S.ui.el('button', { class: 'btn btn-sm btn-danger', type: 'button', text: 'Remove' });
        removeBtn.addEventListener('click', function () { openRemove(r, load); });
        actions.appendChild(removeBtn);
      }
      tbody.appendChild(S.ui.el('tr', {}, [
        S.ui.el('td', { class: 'cell-strong', text: r.name + (r.current ? ' (you)' : '') }),
        S.ui.el('td', { text: S.ui.fmtDateTime(r.created) }),
        S.ui.el('td', { text: S.ui.fmtDateTime(r.updated) }),
        actions
      ]));
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [
        S.ui.el('h2', { text: 'Accounts' }),
        S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('span', { class: 'caption', text: rows.length + ' account(s)' })
      ]),
      S.ui.el('div', { class: 'card-body' }, [
        S.ui.el('table', { class: 'data' }, [
          S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Name', 'Created', 'Last changed', ''].map(function (h) { return S.ui.el('th', { text: h }); }))]),
          tbody
        ])
      ])
    ]));

    /* ---- create ---- */
    var form = S.ui.el('form', { class: 'card-form', novalidate: 'novalidate' });
    var name = S.ui.el('input', { class: 'field', type: 'text', id: 'uNewName', autocomplete: 'off' });
    var theirPass = passwordInput('uNewPass', 'new-password');
    var myPass = passwordInput('uMyPass', 'current-password');
    var rowName = S.ui.el('div', { class: 'form-row' }, [
      S.ui.el('label', { class: 'form-label', for: 'uNewName', text: 'Name' }), name,
      S.ui.el('div', { class: 'form-hint', text: '3-32 characters: A-Z, a-z, 0-9, dot, underscore, hyphen.' })
    ]);
    var rowTheir = S.ui.el('div', { class: 'form-row' }, [
      S.ui.el('label', { class: 'form-label', for: 'uNewPass', text: 'Their password' }), theirPass,
      S.ui.el('div', { class: 'form-hint', text: 'At least 12 characters.' })
    ]);
    var rowMine = S.ui.el('div', { class: 'form-row' }, [
      S.ui.el('label', { class: 'form-label', for: 'uMyPass', text: 'Your password' }), myPass
    ]);
    var msg = formMsg();
    var submit = S.ui.el('button', { class: 'btn btn-primary', type: 'submit', text: 'Create account' });
    form.appendChild(rowName); form.appendChild(rowTheir); form.appendChild(rowMine);
    form.appendChild(msg);
    form.appendChild(S.ui.el('div', { class: 'form-actions' }, [submit]));
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      msg.textContent = '';
      if (!/^[A-Za-z0-9._-]{3,32}$/.test(name.value.trim())) { msg.textContent = 'The name must be 3-32 characters of A-Z, a-z, 0-9, dot, underscore, hyphen.'; msg.className = 'form-msg form-msg-bad'; return; }
      if (theirPass._input.value.length < 12) { msg.textContent = 'Their password must be at least 12 characters.'; msg.className = 'form-msg form-msg-bad'; return; }
      submit.disabled = true;
      S.api.post('/api/users', { password: myPass._input.value, name: name.value.trim(), newPassword: theirPass._input.value }, 'settings-users').then(function (r) {
        msg.textContent = 'Account ' + (r && r.name ? r.name : name.value) + ' created.';
        msg.className = 'form-msg form-msg-ok';
        name.value = ''; theirPass._input.value = ''; myPass._input.value = '';
        load();
      }).catch(function (err) {
        msg.textContent = err && err.message ? err.message : 'Could not create the account.';
        msg.className = 'form-msg form-msg-bad';
      }).then(function () { submit.disabled = false; });
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Create an account' })]),
      S.ui.el('div', { class: 'card-body' }, [form])
    ]));

    /* ---- the confirm dialogs ---- */
    function openReset(row, done) {
      var dlg = S.ui.el('div', { class: 'confirm-backdrop', role: 'dialog', 'aria-modal': 'true' });
      var box = S.ui.el('div', { class: 'confirm-box' }, [
        S.ui.el('h2', { text: 'Reset the password for ' + row.name }),
        S.ui.el('p', { class: 'confirm-text', text: 'Their current sessions end when the password changes.' })
      ]);
      var theirs = passwordInput('uResetNew-' + row.name, 'new-password');
      var mine = passwordInput('uResetMine-' + row.name, 'current-password');
      var m2 = formMsg();
      var go = S.ui.el('button', { class: 'btn btn-primary', type: 'button', text: 'Reset password' });
      var cancel = S.ui.el('button', { class: 'btn', type: 'button', text: 'Cancel' });
      box.appendChild(S.ui.el('div', { class: 'form-row' }, [S.ui.el('div', { class: 'form-label', text: 'New password for ' + row.name }), theirs]));
      box.appendChild(S.ui.el('div', { class: 'form-row' }, [S.ui.el('div', { class: 'form-label', text: 'Your password' }), mine]));
      box.appendChild(m2);
      box.appendChild(S.ui.el('div', { class: 'form-actions' }, [go, cancel]));
      dlg.appendChild(box);
      document.body.appendChild(dlg);
      cancel.addEventListener('click', function () { theirs._input.value = ''; mine._input.value = ''; dlg.remove(); });
      dlg.addEventListener('click', function (ev) { if (ev.target === dlg) { theirs._input.value = ''; mine._input.value = ''; dlg.remove(); } });
      go.addEventListener('click', function () {
        m2.textContent = '';
        if (theirs._input.value.length < 12) { m2.textContent = 'At least 12 characters.'; m2.className = 'form-msg form-msg-bad'; return; }
        go.disabled = true;
        S.api.post('/api/users/' + encodeURIComponent(row.name) + '/reset',
          { password: mine._input.value, newPassword: theirs._input.value }, 'settings-users').then(function () {
          dlg.remove();
          if (S.toast) { S.toast('Password reset for ' + row.name + '.'); }
          done();
        }).catch(function (err) {
          m2.textContent = err && err.message ? err.message : 'Could not reset the password.';
          m2.className = 'form-msg form-msg-bad';
        }).then(function () { go.disabled = false; });
      });
    }

    function openRemove(row, done) {
      var dlg = S.ui.el('div', { class: 'confirm-backdrop', role: 'dialog', 'aria-modal': 'true' });
      var box = S.ui.el('div', { class: 'confirm-box' }, [
        S.ui.el('h2', { text: 'Remove ' + row.name }),
        S.ui.el('p', { class: 'confirm-text', text: 'The account is removed from sentinel-users.json and every session of it ends. This cannot sign you out.' })
      ]);
      var mine = passwordInput('uRemoveMine-' + row.name, 'current-password');
      var m2 = formMsg();
      var go = S.ui.el('button', { class: 'btn btn-danger', type: 'button', text: 'Remove account' });
      var cancel = S.ui.el('button', { class: 'btn', type: 'button', text: 'Cancel' });
      box.appendChild(S.ui.el('div', { class: 'form-row' }, [S.ui.el('div', { class: 'form-label', text: 'Your password' }), mine]));
      box.appendChild(m2);
      box.appendChild(S.ui.el('div', { class: 'form-actions' }, [go, cancel]));
      dlg.appendChild(box);
      document.body.appendChild(dlg);
      cancel.addEventListener('click', function () { mine._input.value = ''; dlg.remove(); });
      dlg.addEventListener('click', function (ev) { if (ev.target === dlg) { mine._input.value = ''; dlg.remove(); } });
      go.addEventListener('click', function () {
        m2.textContent = '';
        go.disabled = true;
        S.api.post('/api/users/' + encodeURIComponent(row.name) + '/remove', { password: mine._input.value }, 'settings-users').then(function () {
          dlg.remove();
          if (S.toast) { S.toast('Account ' + row.name + ' removed.'); }
          done();
        }).catch(function (err) {
          m2.textContent = err && err.message ? err.message : 'Could not remove the account.';
          m2.className = 'form-msg form-msg-bad';
        }).then(function () { go.disabled = false; });
      });
    }
  }

  function load() {
    return S.api.get('/api/users', 'settings-users').then(function (rows) {
      paint(Array.isArray(rows) ? rows : []);
    }).catch(function (err) {
      var view = document.getElementById('settingsBody');
      if (!view) { return; }
      S.ui.clear(view);
      view.appendChild(S.ui.error(err && err.message ? err.message : 'Could not load the accounts.'));
    });
  }

  S.settingsTabs.users = { render: function () { load(); } };
})();
