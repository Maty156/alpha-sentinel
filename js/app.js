/* app.js - OWNER: boot. Confirms the session, wires the shell (logout, sidebar,
   top search, health pill, alert badge) and starts the router plus polling. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  var POLL_MS = 10000;

  /* The label says WHY: Blind (red) when families cannot fire, Unverified
     (amber) when the audit policy is unreadable, Catching up (amber) only when
     the poller is behind, Healthy (green) otherwise. Every reason that applies
     lands in the tooltip, worst first - the server orders them. */
  function healthPill(health) {
    var host = document.getElementById('healthPill');
    if (!host) { return; }
    S.ui.clear(host);
    var state = health && health.state ? health.state : 'ok';
    var reasons = (health && health.reasons) || [];
    var labels = [];
    reasons.forEach(function (r) { if (r && r.label) { labels.push(r.label + ' - ' + (r.detail || '')); } });
    var kind = 'pill-ok', label = 'Healthy', title = labels.length ? labels.join('; ') : 'polling normally';
    if (state === 'blind') {
      kind = 'pill-bad'; label = 'Blind';
    } else if (state === 'degraded') {
      kind = 'pill-warn';
      var codes = reasons.map(function (r) { return r.code; });
      if (codes.indexOf('unverified') >= 0) { label = 'Unverified'; }
      else if (codes.indexOf('catching-up') >= 0 || codes.indexOf('lag') >= 0) { label = 'Catching up'; }
      else { label = 'Degraded'; }
    }
    host.appendChild(S.ui.pill(kind, label, title));
  }

  function navBadge(overview) {
    var host = document.getElementById('alertCount');
    if (!host) { return; }
    var n = overview && overview.tiles ? overview.tiles.openAlerts : 0;
    host.textContent = n > 0 ? String(n) : '';
    host.hidden = !(n > 0);
    host.title = n + ' open alert(s)';
  }

  function demoPill(overview) {
    var host = document.getElementById('demoPill');
    if (!host) { return; }
    /* the marker appears only when the monitor was started with -DemoData: real
       numbers are never invented to fill a panel */
    if (overview && overview.demoData) {
      host.hidden = false;
      S.ui.clear(host);
      host.appendChild(S.ui.pill('pill-brand', 'DEMO DATA', 'started with -DemoData'));
    } else {
      host.hidden = true;
      S.ui.clear(host);
    }
  }

  function refreshOverview() {
    return S.api.get('/api/overview', 'overview').then(function (ov) {
      S.state.set('overview', ov);
      healthPill(ov.health);
      navBadge(ov);
      demoPill(ov);
      return ov;
    }).catch(function () { return null; });
  }

  /* the topbar avatar chip: initials + palette colour from the user record */
  var AVATAR_HEX = {
    crimson: '#d2103c', ember: '#ff8a3d', amber: '#ffc247', moss: '#7bc47f',
    teal: '#2ec4a6', azure: '#4d9fff', violet: '#a06bff', slate: '#8fa3bd'
  };
  function paintAvatar(initials, color) {
    var host = document.getElementById('userAvatar');
    if (!host) { return; }
    if (!initials) { host.hidden = true; host.textContent = ''; host.style.backgroundColor = ''; return; }
    host.hidden = false;
    host.textContent = String(initials).toUpperCase();
    host.style.backgroundColor = AVATAR_HEX[color] || AVATAR_HEX.slate;
  }
  S.topbarAvatar = paintAvatar;

  function wireShell() {
    var chip = document.getElementById('userChip');
    var drop = document.getElementById('userDropdown');
    if (chip && drop) {
      chip.addEventListener('click', function () {
        var open = !drop.hidden;
        drop.hidden = open;
        chip.setAttribute('aria-expanded', open ? 'false' : 'true');
      });
      document.addEventListener('click', function (ev) {
        if (drop.hidden) { return; }
        var menu = document.getElementById('userMenu');
        if (menu && !menu.contains(ev.target)) {
          drop.hidden = true;
          chip.setAttribute('aria-expanded', 'false');
        }
      });
    }
    var accountItem = document.getElementById('menuAccount');
    if (accountItem) {
      accountItem.addEventListener('click', function () {
        if (drop) { drop.hidden = true; }
        window.location.hash = '#/settings';
        /* land on the Account tab, not the last-viewed one */
        try { window.sessionStorage.setItem('sentinel-settings-tab', 'account'); } catch (e) { }
        if (S.router.current() === 'settings' && S.pages.settings.repaint) { S.pages.settings.repaint(); }
      });
    }
    var out = document.getElementById('logout');
    if (out) {
      out.addEventListener('click', function () {
        S.api.post('/api/logout', {}, 'shell').then(function () { window.location.replace('/'); },
          function () { window.location.replace('/'); });
      });
    }
    var toggle = document.getElementById('sidebarToggle');
    if (toggle) {
      toggle.addEventListener('click', function () {
        document.querySelector('.app').classList.toggle('collapsed');
      });
    }
    var search = document.getElementById('search');
    if (search) {
      /* the top box filters the table on the CURRENT page only - it never asks the
         backend for anything new */
      search.addEventListener('input', function () {
        var page = S.router.page();
        if (page && page.filter) { page.filter(search.value); }
      });
    }
  }

  function boot() {
    wireShell();
    if (S.pages.bot && S.pages.bot.mount) { S.pages.bot.mount(); }
    S.api.get('/api/session', 'boot').then(function (session) {
      var who = document.getElementById('whoami');
      if (who) { who.textContent = session && session.user ? session.user : 'signed in'; }
      paintAvatar(session && session.avatarInitials, session && session.avatarColor);
    }).catch(function () { /* a 401 already redirected */ });

    refreshOverview();
    S.router.start();
    S.poller.start(function () {
      refreshOverview();
      var page = S.router.page();
      if (page && page.refresh) { page.refresh(); }
    }, POLL_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
