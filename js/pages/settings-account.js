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
    
    // Live avatar preview circle
    var chosenHex = (PALETTE.filter(function (x) { return x.key === chosen; })[0] || PALETTE[0]).hex;
    var preview = S.ui.el('div', { class: 'avatar-preview-lg', text: currentInitials ? currentInitials.toUpperCase() : '?' });
    preview.style.backgroundColor = chosenHex;
    var previewText = S.ui.el('div', {}, [
      S.ui.el('div', { style: 'font-weight:600;font-size:14px;color:var(--text)', text: 'Topbar Badge Preview' }),
      S.ui.el('div', { class: 'caption', text: 'Rendered in the console header menu' })
    ]);
    var previewBox = S.ui.el('div', { class: 'avatar-preview-box' }, [preview, previewText]);

    var input = S.ui.el('input', { class: 'field', type: 'text', id: 'accInitials', value: currentInitials, maxlength: '2', autocomplete: 'off' });
    input.addEventListener('input', function () {
      var txt = input.value.trim().toUpperCase();
      preview.textContent = txt || '?';
    });
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
        preview.style.backgroundColor = c.hex;
        Array.prototype.forEach.call(swatches.children, function (x) { x.classList.remove('on'); });
        b.classList.add('on');
      });
      swatches.appendChild(b);
    });
    var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
    var submit = S.ui.el('button', { class: 'btn btn-primary', type: 'submit', text: 'Save avatar' });
    
    form.appendChild(previewBox);
    form.appendChild(rowInit);
    form.appendChild(S.ui.el('div', { class: 'form-row' }, [S.ui.el('div', { class: 'form-label', text: 'Accent Colour' }), swatches]));
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
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Avatar & Identity' })]),
      S.ui.el('div', { class: 'card-body' }, [form])
    ]));
  }

  function securityCard(view, session) {
    var user = (session && session.user) || 'admin';
    var kv = S.ui.el('dl', { class: 'kv' }, [
      S.ui.el('dt', { text: 'Signed In User' }), S.ui.el('dd', { class: 'cell-strong', text: user }),
      S.ui.el('dt', { text: 'Authentication' }), S.ui.el('dd', { text: 'PBKDF2 (150,000 iterations, SHA-1)' }),
      S.ui.el('dt', { text: 'Session Lifetime' }), S.ui.el('dd', { text: '8 hours (30 min idle timeout)' }),
      S.ui.el('dt', { text: 'Cookie Protection' }), S.ui.el('dd', { text: 'HttpOnly; SameSite=Strict' }),
      S.ui.el('dt', { text: 'Brute-Force Guard' }), S.ui.el('dd', { text: '5 attempts / 5 mins (HTTP 429 block)' })
    ]);
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Session Security Posture' })]),
      S.ui.el('div', { class: 'card-body' }, [kv])
    ]));
  }

  function geminiKeyCard(view, session) {
    var form = S.ui.el('form', { class: 'card-form', novalidate: 'novalidate' });
    var keySet = false;
  
    // Check if key is already set
    S.api.get('/api/settings/gemini-key/status', 'settings-account').then(function (r) {
      keySet = r && r.keySet === true;
      renderForm(keySet);
    }).catch(function () {
      renderForm(false);
    });

    function renderForm(hasKey) {
      // Clear form
      S.ui.clear(form);
    
      var titleText = hasKey ? 'Gemini API Key (Configured)' : 'Gemini API Key';
      var subtitle = hasKey ? 'A valid key enables AI-powered answers in the Wolf bot assistant.' : 'Add a Gemini API key to enable AI-powered answers in the Wolf bot assistant.';
    
      form.appendChild(S.ui.el('div', { class: 'form-row' }, [
        S.ui.el('div', { class: 'form-label', text: titleText }),
        S.ui.el('div', { class: 'caption', text: subtitle })
      ]));
    
      if (hasKey) {
        var clearBtn = S.ui.el('button', { class: 'btn btn-danger', type: 'button', text: 'Clear Key' });
        clearBtn.addEventListener('click', function () {
          if (!confirm('Clear the Gemini API key? The bot will fall back to rule-based answers only.')) return;
          clearBtn.disabled = true;
          S.api.post('/api/settings/gemini-key/clear', {}, 'settings-account').then(function () {
            form.parentElement.parentElement.remove();
            renderForm(false);
          }).catch(function (err) {
            alert('Failed to clear key: ' + (err && err.message ? err.message : 'Unknown error'));
            clearBtn.disabled = false;
          });
        });
        form.appendChild(S.ui.el('div', { class: 'form-actions' }, [clearBtn]));
      } else {
        var input = S.ui.el('input', { 
          class: 'field', 
          type: 'password', 
          id: 'geminiKey', 
          autocomplete: 'new-password',
          placeholder: 'Enter your Gemini API key'
        });
        var rowKey = field('Gemini API Key', input, 'Get a free key at https://aistudio.google.com/apikey. The key is stored server-side only and never sent back to the browser.');
        var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
        var submit = S.ui.el('button', { class: 'btn btn-primary', type: 'submit', text: 'Save Key' });
      
        form.appendChild(rowKey);
        form.appendChild(msg);
        form.appendChild(S.ui.el('div', { class: 'form-actions' }, [submit]));
      
        form.addEventListener('submit', function (ev) {
          ev.preventDefault();
          msg.textContent = '';
          var key = input.value.trim();
          if (!key) { 
            msg.textContent = 'API key is required.'; 
            msg.className = 'form-msg form-msg-bad'; 
            return; 
          }
          submit.disabled = true;
          S.api.post('/api/settings/gemini-key', { apiKey: key }, 'settings-account').then(function () {
            msg.textContent = 'Gemini API key saved.';
            msg.className = 'form-msg form-msg-ok';
            input.value = '';
            // Re-render to show the key as set
            renderForm(true);
          }).catch(function (err) {
            msg.textContent = err && err.message ? err.message : 'Could not save the key.';
            msg.className = 'form-msg form-msg-bad';
          }).then(function () { submit.disabled = false; });
        });
      }
    }
  
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Wolf Bot AI Assistant' })]),
      S.ui.el('div', { class: 'card-body' }, [form])
    ]));
  }

  S.settingsTabs.account = {
    render: function (view) {
      S.ui.clear(view);
      S.api.get('/api/session', 'settings-account').then(function (session) {
        var grid = S.ui.el('div', { class: 'settings-layout' });
        var left = S.ui.el('div', { style: 'display:flex;flex-direction:column;gap:var(--s-4)' });
        var right = S.ui.el('div', { style: 'display:flex;flex-direction:column;gap:var(--s-4)' });
        general(left, session);
        usernameCard(left, session);
        avatarCard(right, session);
        securityCard(right, session);
        geminiKeyCard(right, session);
        grid.appendChild(left);
        grid.appendChild(right);
        view.appendChild(grid);
      }).catch(function (err) {
        view.appendChild(S.ui.error(err && err.message ? err.message : 'Could not load the account.'));
      });
    }
  };
})();
