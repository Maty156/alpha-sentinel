/* pages/settings-audit.js - OWNER: the Audit tab - what the Windows audit
   policy allows each detection family to see, and the three actions:
   preview (read-only diff), apply (asks for your password and lists the
   changes first) and restore (only backups this tool wrote). Nothing happens
   without the confirm step, and a non-elevated process is read-only. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.settingsTabs = S.settingsTabs || {};

  function stateBadge(state) {
    var kind = state === 'ok' ? 'pill-ok' : (state === 'blind' ? 'pill-bad' : 'pill-warn');
    var label = state === 'ok' ? 'Working' : (state === 'blind' ? 'Blind' : 'Unverified');
    return S.ui.pill(kind, label, state === 'ok' ? 'the subcategory is audited' : (state === 'blind' ? 'Windows is not writing these events' : 'the audit policy could not be read'));
  }

  function confirmDialog(title, lines, fields, onGo) {
    var dlg = S.ui.el('div', { class: 'confirm-backdrop', role: 'dialog', 'aria-modal': 'true' });
    var box = S.ui.el('div', { class: 'confirm-box confirm-wide' }, [S.ui.el('h2', { text: title })]);
    lines.forEach(function (t) { box.appendChild(S.ui.el('p', { class: 'confirm-text', text: t })); });
    var inputs = {};
    fields.forEach(function (f) {
      var input = S.ui.el('input', { class: 'field', type: 'password', autocomplete: 'current-password', id: 'audit-' + f.key });
      if (f.options) {
        input = S.ui.el('select', { class: 'field', id: 'audit-' + f.key });
        f.options.forEach(function (o) {
          var opt = S.ui.el('option', { text: o });
          opt.setAttribute('value', o);
          input.appendChild(opt);
        });
      }
      var row = S.ui.el('div', { class: 'form-row' }, [S.ui.el('label', { class: 'form-label', for: 'audit-' + f.key, text: f.label }), input]);
      box.appendChild(row);
      inputs[f.key] = input;
    });
    var msg = S.ui.el('div', { class: 'form-msg', 'aria-live': 'polite' });
    box.appendChild(msg);
    var go = S.ui.el('button', { class: 'btn btn-primary', type: 'button', text: fields.goLabel || 'Confirm' });
    var cancel = S.ui.el('button', { class: 'btn', type: 'button', text: 'Cancel' });
    box.appendChild(S.ui.el('div', { class: 'form-actions' }, [go, cancel]));
    dlg.appendChild(box);
    document.body.appendChild(dlg);
    cancel.addEventListener('click', function () {
      Object.keys(inputs).forEach(function (k) { inputs[k].value = ''; });
      dlg.remove();
    });
    dlg.addEventListener('click', function (ev) { if (ev.target === dlg) { Object.keys(inputs).forEach(function (k) { inputs[k].value = ''; }); dlg.remove(); } });
    go.addEventListener('click', function () {
      msg.textContent = '';
      go.disabled = true;
      onGo(inputs, function () {
        Object.keys(inputs).forEach(function (k) { inputs[k].value = ''; });
        dlg.remove();
      }, function (text) {
        msg.textContent = text || 'It did not work.';
        msg.className = 'form-msg form-msg-bad';
      }).then(function () { go.disabled = false; });
    });
  }

  function statPill(count, label, kind, icon) {
    return S.ui.el('div', { class: 'audit-stat-pill' }, [
      S.ui.el('div', { class: 'audit-stat-num audit-stat-' + kind, text: String(count) }),
      S.ui.el('div', { class: 'audit-stat-label', text: label })
    ]);
  }

  function paint(data) {
    var view = document.getElementById('settingsBody');
    if (!view) { return; }
    S.ui.clear(view);
    var elevated = !!(data && data.elevated);
    var rules = data.rules || [];

    /* ---- top HUD: stat pills ---- */
    var okCount     = rules.filter(function (r) { return r.state === 'ok'; }).length;
    var blindCount  = rules.filter(function (r) { return r.state === 'blind'; }).length;
    var unverCount  = rules.filter(function (r) { return r.state !== 'ok' && r.state !== 'blind'; }).length;

    view.appendChild(S.ui.el('div', { class: 'audit-hud' }, [
      statPill(okCount,    'Verified',   'ok'),
      statPill(blindCount, 'Blind',      'bad'),
      statPill(unverCount, 'Unverified', 'warn'),
      S.ui.el('div', { class: 'audit-hud-right' }, [
        elevated
          ? S.ui.el('span', { class: 'pill pill-ok', title: 'Can modify the audit policy' }, [S.ui.el('span', { class: 'dot' }), S.ui.el('span', { text: 'Elevated' })])
          : S.ui.el('span', { class: 'pill pill-warn', title: 'Read-only view — run as Administrator to change policy' }, [S.ui.el('span', { class: 'dot' }), S.ui.el('span', { text: 'Read-only' })])
      ])
    ]));

    if (!elevated) {
      view.appendChild(S.ui.el('div', { class: 'banner banner-info' }, [
        S.ui.el('span', { text: 'Run Sentinel as Administrator to change the audit policy - this view is read-only.' })
      ]));
    }

    var tbody = S.ui.el('tbody');
    rules.forEach(function (r) {
      tbody.appendChild(S.ui.el('tr', {}, [
        S.ui.el('td', { class: 'cell-strong', text: r.key }),
        S.ui.el('td', { text: r.subcategory || '-' }),
        S.ui.el('td', { text: r.need || '-' }),
        S.ui.el('td', {}, [stateBadge(r.state)])
      ]));
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [
        S.ui.el('h2', { text: 'Rule families and the audit policy' }),
        S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('span', { class: 'caption', text: rules.length + ' families' })
      ]),
      S.ui.el('div', { class: 'card-body' }, [
        S.ui.el('div', { class: 'table-wrap' }, [
          S.ui.el('table', { class: 'data' }, [
            S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Rule family', 'Subcategory', 'Needs', 'State'].map(function (h) { return S.ui.el('th', { text: h }); }))]),
            tbody
          ])
        ])
      ])
    ]));

    /* ---- action card ---- */
    var previewBtn = S.ui.el('button', { class: 'btn', type: 'button', text: 'Preview changes' });
    var applyBtn   = S.ui.el('button', { class: 'btn btn-primary', type: 'button', text: 'Apply policy' });
    var restoreBtn = S.ui.el('button', { class: 'btn', type: 'button', text: 'Restore a backup' });
    if (!elevated) {
      applyBtn.disabled  = true;
      restoreBtn.disabled = true;
      applyBtn.title  = 'Run Sentinel as Administrator to change the audit policy';
      restoreBtn.title = applyBtn.title;
    }
    var previewBox = S.ui.el('div', { class: 'audit-preview', 'aria-live': 'polite' });

    var actionsBody = S.ui.el('div', { class: 'card-body' }, [
      S.ui.el('div', { class: 'audit-action-grid' }, [
        S.ui.el('div', { class: 'audit-action-item' }, [
          S.ui.el('div', { class: 'audit-action-title', text: 'Preview' }),
          S.ui.el('div', { class: 'audit-action-desc', text: 'Show what subcategories would be changed without applying anything.' }),
          previewBtn
        ]),
        S.ui.el('div', { class: 'audit-action-item audit-action-item-primary' }, [
          S.ui.el('div', { class: 'audit-action-title', text: 'Apply policy' }),
          S.ui.el('div', { class: 'audit-action-desc', text: 'Enable the subcategories Sentinel needs. A backup is written first.' }),
          applyBtn
        ]),
        S.ui.el('div', { class: 'audit-action-item' }, [
          S.ui.el('div', { class: 'audit-action-title', text: 'Restore backup' }),
          S.ui.el('div', { class: 'audit-action-desc', text: 'Roll back to a policy snapshot written by Sentinel.' }),
          restoreBtn
        ])
      ]),
      previewBox
    ]);

    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Set the policy Sentinel needs' })]),
      actionsBody
    ]));


    function renderPreview(changes) {
      S.ui.clear(previewBox);
      if (!changes || !changes.length) {
        previewBox.appendChild(S.ui.el('p', { class: 'confirm-text', text: 'Nothing to change - every subcategory the rules need is already enabled.' }));
        return;
      }
      var tb = S.ui.el('tbody');
      changes.forEach(function (c) {
        tb.appendChild(S.ui.el('tr', {}, [
          S.ui.el('td', { class: 'cell-strong', text: c.subcategory }),
          S.ui.el('td', { text: c.before }),
          S.ui.el('td', { class: 'cell-strong', text: c.after }),
          S.ui.el('td', { class: 'cell-dim', text: (c.flags || []).join(', ') })
        ]));
      });
      previewBox.appendChild(S.ui.el('table', { class: 'data' }, [
        S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Subcategory', 'Before', 'After', 'Enables'].map(function (h) { return S.ui.el('th', { text: h }); }))]),
        tb
      ]));
    }

    previewBtn.addEventListener('click', function () {
      S.api.post('/api/audit/preview', {}, 'settings-audit').then(renderPreview).catch(function (err) {
        S.ui.clear(previewBox);
        previewBox.appendChild(S.ui.error(err && err.message ? err.message : 'Preview failed.'));
      });
    });

    applyBtn.addEventListener('click', function () {
      S.api.post('/api/audit/preview', {}, 'settings-audit').then(function (changes) {
        var lines = (!changes || !changes.length)
          ? ['Nothing to change - every subcategory is already enabled.']
          : changes.map(function (c) { return c.subcategory + ': ' + c.before + ' -> ' + c.after; });
        lines.push('A backup of the current policy is written before anything changes.');
        confirmDialog('Apply the audit policy changes?', lines, [
          { key: 'password', label: 'Your password' }
        ], function (inputs, close, fail) {
          return S.api.post('/api/audit/apply', { password: inputs.password.value }, 'settings-audit').then(function () {
            close();
            if (S.toast) { S.toast('Audit policy updated. Coverage re-checked.'); }
            load();
          }).catch(function (err) {
            fail(err && err.message ? err.message : 'Apply failed.');
          });
        });
      }).catch(function (err) {
        if (S.toast) { S.toast(err && err.message ? err.message : 'Preview failed.'); }
      });
    });

    restoreBtn.addEventListener('click', function () {
      var backups = (data.backups || []);
      if (!backups.length) {
        if (S.toast) { S.toast('No backups yet - apply a change first and one is written automatically.'); }
        return;
      }
      confirmDialog('Restore an audit-policy backup', ['Restoring overwrites the current policy with the backup.'], [
        { key: 'backup', label: 'Backup', options: backups },
        { key: 'password', label: 'Your password' }
      ], function (inputs, close, fail) {
        return S.api.post('/api/audit/restore', { password: inputs.password.value, backup: inputs.backup.value }, 'settings-audit').then(function () {
          close();
          if (S.toast) { S.toast('Policy restored from ' + inputs.backup.value + '.'); }
          load();
        }).catch(function (err) {
          fail(err && err.message ? err.message : 'Restore failed.');
        });
      });
    });
  }

  function load() {
    return S.api.get('/api/audit', 'settings-audit').then(paint).catch(function (err) {
      var view = document.getElementById('settingsBody');
      if (!view) { return; }
      S.ui.clear(view);
      view.appendChild(S.ui.error(err && err.message ? err.message : 'Could not load the audit state.'));
    });
  }

  S.settingsTabs.audit = { render: function () { load(); } };
})();
