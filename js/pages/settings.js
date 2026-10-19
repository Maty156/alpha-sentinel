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

  var TAB_ICONS = {
    general: '<svg class="tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>',
    account: '<svg class="tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="7" r="4"/><path d="M5.5 21a8.38 8.38 0 0113 0"/></svg>',
    users:   '<svg class="tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>',
    audit:   '<svg class="tab-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>'
  };

  function tabIcon(key) {
    var span = document.createElement('span');
    span.className = 'tab-icon-wrap';
    /* safe SVG literal without external user input */
    var parser = new DOMParser();
    var doc = parser.parseFromString(TAB_ICONS[key] || '', 'image/svg+xml');
    if (doc.documentElement) { span.appendChild(doc.documentElement); }
    return span;
  }

  function tabs() {
    var bar = S.ui.el('div', { class: 'settings-tabs-bar', role: 'tablist', 'aria-label': 'Settings sections' });
    TABS.forEach(function (t) {
      var isActive = active === t.key;
      var btn = S.ui.el('button', {
        class: 'settings-tab-btn' + (isActive ? ' active' : ''),
        type: 'button',
        role: 'tab',
        'aria-selected': isActive ? 'true' : 'false'
      }, [
        tabIcon(t.key),
        S.ui.el('span', { class: 'tab-text', text: t.label })
      ]);
      btn.addEventListener('click', function () {
        active = t.key;
        try { window.sessionStorage.setItem('sentinel-settings-tab', active); } catch (e) { }
        paint();
      });
      bar.appendChild(btn);
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
