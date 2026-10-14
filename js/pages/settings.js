/* pages/settings.js - OWNER: the Settings page shell. Four tabs: General (the
   read-only configuration, unchanged), Account (your own credentials + avatar),
   Users (who can sign in) and Audit (what the audit policy allows). Each tab is
   one file: settings.js (this shell) + settings-account.js + settings-users.js
   + settings-audit.js. Nothing here is rendered inline; every value goes
   through textContent. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  /* the active tab is remembered for the session so a refresh lands back on it */
  var active = 'general';
  var TABS = [
    { key: 'general', label: 'General', mod: 'general' },
    { key: 'account', label: 'Account', mod: 'account' },
    { key: 'users',   label: 'Users',   mod: 'users' },
    { key: 'audit',   label: 'Audit',   mod: 'audit' }
  ];

  function tabs() {
    var bar = S.ui.el('div', { class: 'chip-group', role: 'tablist', 'aria-label': 'Settings sections' });
    TABS.forEach(function (t) {
      bar.appendChild(S.ui.chip(t.label, active === t.key, function () {
        active = t.key;
        try { window.sessionStorage.setItem('sentinel-settings-tab', active); } catch (e) { }
        paint();
      }));
    });
    return bar;
  }

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'settings') { return; }
    S.ui.clear(view);
    view.appendChild(tabs());
    var body = S.ui.el('div', { id: 'settingsBody' });
    view.appendChild(body);
    var mod = S.settingsTabs && S.settingsTabs[active];
    if (mod && mod.render) {
      mod.render(body);
    } else {
      body.appendChild(S.ui.error('That tab has no content module.'));
    }
  }

  S.pages.settings = {
    title: 'Settings',
    subtitle: 'How this monitor is configured, your account, and who can sign in.',
    render: function () {
      try { var saved = window.sessionStorage.getItem('sentinel-settings-tab'); if (saved) { active = saved; } } catch (e) { }
      paint();
    },
    refresh: function () { paint(); },
    filter: function () { },
    repaint: paint
  };

  /* tab modules register themselves here when their files load */
  S.settingsTabs = S.settingsTabs || {};
  S.settingsRepaint = function () { paint(); };
})();
