/* pages/settings.js - OWNER: the Settings page. READ-ONLY: it renders /api/settings
   and offers nothing that changes the tool. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  function kv(pairs) {
    var dl = S.ui.el('dl', { class: 'kv' });
    pairs.forEach(function (p) {
      dl.appendChild(S.ui.el('dt', { text: p[0] }));
      dl.appendChild(S.ui.el('dd', { text: p[1] === null || p[1] === undefined || p[1] === '' ? '-' : String(p[1]) }));
    });
    return dl;
  }

  function card(title, node) {
    return S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: title })]),
      S.ui.el('div', { class: 'card-body' }, [node])
    ]);
  }

  function paint(s) {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'settings') { return; }
    S.ui.clear(view);

    var accounts = S.ui.el('ul', { class: 'timeline' }, (s.users || []).map(function (u) {
      return S.ui.el('li', {}, [
        S.ui.el('div', { text: u.user }),
        S.ui.el('div', { class: 't-time', text: 'created ' + S.ui.fmtDateTime(u.created) })
      ]);
    }));

    view.appendChild(S.ui.el('div', { class: 'banner banner-info' }, [
      S.ui.el('span', { text: 'Read-only: this page shows how the monitor is configured. Nothing here changes it.' })
    ]));
    view.appendChild(S.ui.el('div', { class: 'settings-grid' }, [
      card('Monitor', kv([
        ['Version', s.version],
        ['Poll interval', s.pollSeconds + ' s'],
        ['Listen on', s.bind + ':' + s.port],
        ['Users file', s.usersFileState],
        ['Demo data', s.demoData ? 'yes (-DemoData)' : 'no']
      ])),
      card('Sessions', kv([
        ['Session lifetime', s.sessionHours + ' h'],
        ['Idle timeout', s.idleMinutes + ' min']
      ])),
      card('Rate limits', kv([
        ['Failed sign-ins', s.rateLimit.maxLoginFailures + ' per ' + s.rateLimit.windowMinutes + ' min'],
        ['Then blocked for', s.rateLimit.blockMinutes + ' min'],
        ['Stalled bodies', s.rateLimit.maxBodyStalls + ' before the address is blocked'],
        ['Body read limit', s.rateLimit.bodyReadMs + ' ms'],
        ['Login body max', s.rateLimit.maxLoginBodyBytes + ' bytes'],
        ['Other body max', s.rateLimit.maxJsonBodyBytes + ' bytes']
      ])),
      card('Forwarding', kv([
        ['Enabled', s.forwarding.enabled ? 'yes' : 'no'],
        ['Destination host', s.forwarding.host],
        ['Key configured', s.forwarding.keyConfigured ? 'yes' : 'no']
      ])),
      card('Audit-policy preflight', kv([
        ['Readable', s.audit.readable ? 'yes' : 'no (not elevated / not Windows)'],
        ['Checked at', S.ui.fmtDateTime(s.audit.checkedAt)],
        ['Rule families', s.audit.rulesTotal],
        ['Blind', s.audit.blindCount],
        ['Unknown', s.audit.unknownCount]
      ])),
      card('Accounts', (s.users || []).length ? accounts : S.ui.empty('No accounts yet', 'Create one with New-SentinelAdmin.ps1'))
    ]));
  }

  function load() {
    return S.api.get('/api/settings', 'settings').then(paint).catch(function (err) {
      var view = document.getElementById('view');
      if (view && S.router.current() === 'settings') { S.ui.clear(view); view.appendChild(S.ui.error(err.message)); }
    });
  }

  S.pages.settings = {
    title: 'Settings',
    subtitle: 'How this monitor is configured (read-only).',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading settings...' })]));
      load();
    },
    refresh: function () { if (S.router.current() === 'settings') { load(); } },
    filter: function () { }
  };
})();
