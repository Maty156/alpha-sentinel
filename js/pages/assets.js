/* pages/assets.js - OWNER: the Assets page - Hosts / Accounts / IPs tabs, search,
   sortable tables, and the right drawer with the asset's detail, its open alerts
   (linked to the Alerts drawer) and its activity timeline. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  var KINDS = [
    { key: 'host', label: 'Hosts', nameKey: 'name', extra: 'users' },
    { key: 'account', label: 'Accounts', nameKey: 'name', extra: 'type' },
    { key: 'ip', label: 'IPs', nameKey: 'address', extra: 'internal' }
  ];
  var current = { kind: 'host', q: '', limit: 500 };
  var payload = { assets: [], count: 0, total: 0 };
  var sort = { key: 'alertCount', dir: -1 };
  var errorMsg = '';
  var openAsset = null;

  function fmtWhen(v) { return S.ui.fmtDateTime(v); }

  function sevCell(v) {
    if (!v) { return S.ui.el('td', { class: 'cell-mute', text: '-' }); }
    return S.ui.el('td', {}, [S.ui.sevBadge(v)]);
  }

  function nameOf(a) {
    return current.kind === 'ip' ? a.address : a.name;
  }

  function table() {
    var rows = payload.assets.slice();
    var dir = sort.dir;
    rows.sort(function (p, q) {
      var a = p[sort.key], b = q[sort.key];
      if (sort.key === 'lastSeen' || sort.key === 'firstSeen') { return String(b).localeCompare(String(a)) * dir * -1; }
      if (typeof a === 'boolean') { return ((a === dir > 0) ? -1 : 1); }
      return ((Number(a) || 0) - (Number(b) || 0)) * dir;
    });
    var cols = current.kind === 'ip'
      ? [['Address', 'address'], ['Accounts', null], ['Failed logons', 'failedLogons'], ['Last seen', 'lastSeen'], ['Alerts', 'alertCount'], ['Max severity', 'maxSeverity']]
      : [[current.kind === 'host' ? 'Host' : 'Account', 'name'], ['Users / type', null], ['Events', 'eventCount'], ['Last seen', 'lastSeen'], ['Alerts', 'alertCount'], ['Max severity', 'maxSeverity']];
    var thead = S.ui.el('thead', {}, [S.ui.el('tr', {}, cols.map(function (c) {
      var sortable = !!c[1];
      var th = S.ui.el('th', { class: sortable ? 'sortable' : '', text: c[0] + (sortable && sort.key === c[1] ? (dir > 0 ? ' \u25B2' : ' \u25BC') : '') });
      if (sortable) {
        th.addEventListener('click', function () {
          if (sort.key === c[1]) { dir = -dir; } else { sort = { key: c[1], dir: -1 }; }
          sort.dir = dir; paint();
        });
      }
      return th;
    }))]);
    var tbody = S.ui.el('tbody');
    rows.forEach(function (a) {
      var tr;
      if (current.kind === 'ip') {
        tr = S.ui.el('tr', {}, [
          S.ui.el('td', { class: 'mono cell-strong', text: a.address + (a.internal ? '' : ' (external)') }),
          S.ui.el('td', { class: 'cell-dim', text: (a.accounts || []).join(', ') || '-' }),
          S.ui.el('td', { class: 'num', text: String(a.failedLogons || 0) }),
          S.ui.el('td', { class: 'cell-mute', text: fmtWhen(a.lastSeen) }),
          S.ui.el('td', { class: 'num', text: String(a.alertCount || 0) }),
          sevCell(a.maxSeverity)
        ]);
      } else {
        var second = current.kind === 'host' ? (a.users || []).join(', ') : (a.type || '');
        tr = S.ui.el('tr', {}, [
          S.ui.el('td', { class: 'cell-strong', text: nameOf(a) }),
          S.ui.el('td', { class: 'cell-dim', text: second || '-' }),
          S.ui.el('td', { class: 'num', text: String(a.eventCount || 0) }),
          S.ui.el('td', { class: 'cell-mute', text: fmtWhen(a.lastSeen) }),
          S.ui.el('td', { class: 'num', text: String(a.alertCount || 0) }),
          sevCell(a.maxSeverity)
        ]);
      }
      tr.addEventListener('click', function () { openDrawer(a); });
      tbody.appendChild(tr);
    });
    return S.ui.el('table', { class: 'data' }, [thead, tbody]);
  }

  function drawerHost() {
    var d = document.getElementById('assetDrawer');
    if (d) { return d; }
    d = S.ui.el('aside', { id: 'assetDrawer', class: 'drawer', 'aria-label': 'asset details' });
    document.body.appendChild(d);
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeDrawer(); } });
    return d;
  }
  function closeDrawer() {
    var d = document.getElementById('assetDrawer');
    if (d) { d.classList.remove('open'); }
    var b = document.getElementById('backdrop');
    if (b) { b.hidden = true; }
    openAsset = null;
  }

  function detail(a) {
    var kv = S.ui.el('dl', { class: 'kv' });
    function row(k, v) { kv.appendChild(S.ui.el('dt', { text: k })); kv.appendChild(S.ui.el('dd', { text: v === undefined || v === null || v === '' ? '-' : String(v) })); }
    if (current.kind === 'host') {
      row('Host', a.name);
      row('First seen', fmtWhen(a.firstSeen)); row('Last seen', fmtWhen(a.lastSeen));
      row('Events / alerts', a.eventCount + ' / ' + a.alertCount);
      row('Max severity', a.maxSeverity || '-');
      row('Users', (a.users || []).join(', ')); row('Source IPs', (a.ips || []).join(', '));
      row('Open alerts', (a.openAlerts || []).join(', ') || 'none');
      row('Tactics', (a.tactics || []).join(', ') || '-');
    } else if (current.kind === 'account') {
      row('Account', a.name); row('Type', a.type);
      row('First seen', fmtWhen(a.firstSeen)); row('Last seen', fmtWhen(a.lastSeen));
      row('Hosts', (a.hosts || []).join(', ')); row('Source IPs', (a.ips || []).join(', '));
      row('Alerts', String(a.alertCount)); row('Max severity', a.maxSeverity || '-');
      row('Recent event IDs', (a.lastEventIds || []).join(', ') || '-');
      row('Flags', (a.flags || []).join('; ') || 'none');
    } else {
      row('Address', a.address); row('Internal', a.internal ? 'yes' : 'no');
      row('First seen', fmtWhen(a.firstSeen)); row('Last seen', fmtWhen(a.lastSeen));
      row('Failed logons', String(a.failedLogons));
      row('Accounts', (a.accounts || []).join(', ')); row('Hosts', (a.hosts || []).join(', '));
      row('Alerts', String(a.alertCount)); row('Max severity', a.maxSeverity || '-');
    }
    return kv;
  }

  function drawer(a) {
    var d = drawerHost();
    S.ui.clear(d);
    var head = S.ui.el('div', { class: 'drawer-head' }, [
      S.ui.el('div', { class: 'grow' }, [
        S.ui.el('div', { class: 'row' }, [S.ui.sevBadge(a.maxSeverity || 'Low')]),
        S.ui.el('h2', { style: 'margin-top:8px', text: nameOf(a) }),
        S.ui.el('div', { class: 'caption', text: current.kind + ' - last seen ' + fmtWhen(a.lastSeen) })
      ]),
      S.ui.el('button', { class: 'drawer-close', title: 'Close', text: '\u00D7' })
    ]);
    head.lastChild.addEventListener('click', closeDrawer);

    var body = S.ui.el('div', { class: 'drawer-body' });
    body.appendChild(detail(a));

    var links = S.ui.el('div', {}, [S.ui.el('h2', { text: 'Open alerts on this ' + current.kind })]);
    var ids = (current.kind === 'host') ? (a.openAlerts || []) : [];
    if (ids.length) {
      var ul = S.ui.el('ul', { class: 'timeline' });
      ids.forEach(function (id) {
        var li = S.ui.el('li', {});
        var link = S.ui.el('a', { href: '#/alerts', class: 'cell-strong', text: 'Alert #' + id + ' - open in Alerts' });
        link.addEventListener('click', function () {
          try { window.sessionStorage.setItem('sentinel-open-alert', String(id)); } catch (e) { }
        });
        li.appendChild(link);
        ul.appendChild(li);
      });
      links.appendChild(ul);
    } else {
      links.appendChild(S.ui.empty('No open alerts', 'Alerts for this asset would be linked here.'));
    }
    body.appendChild(links);

    var tl = S.ui.el('div', {}, [S.ui.el('h2', { text: 'Activity timeline' })]);
    var loading = S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading timeline...' })]);
    tl.appendChild(loading);
    body.appendChild(tl);

    d.appendChild(head); d.appendChild(body);
    d.classList.add('open');
    var b = document.getElementById('backdrop');
    if (!b) { b = S.ui.el('div', { id: 'backdrop', class: 'backdrop' }); document.body.appendChild(b); b.addEventListener('click', closeDrawer); }
    b.hidden = false;

    var idPart = current.kind === 'ip' ? a.address : a.name;
    S.api.get('/api/assets/' + current.kind + '/' + encodeURIComponent(idPart), 'assets').then(function (det) {
      S.ui.clear(tl);
      var events = det && det.timeline ? det.timeline : [];
      if (!events.length) { tl.appendChild(S.ui.empty('No events in the buffer', 'The ring buffer holds the last 300 events.')); return; }
      var ul = S.ui.el('ul', { class: 'timeline' });
      events.forEach(function (e) {
        ul.appendChild(S.ui.el('li', {}, [
          S.ui.el('div', { class: 't-time', text: S.ui.fmtDateTime(e.time) + ' - ' + e.summary }),
          S.ui.el('div', { class: 't-tactic', text: (e.channel || '') + (e.matchedRule ? (' - ' + e.matchedRule) : '') })
        ]));
      });
      tl.appendChild(ul);
    }).catch(function (err) {
      S.ui.clear(tl);
      tl.appendChild(S.ui.error(err.message));
    });
  }

  function openDrawer(a) { openAsset = a; drawer(a); }

  function tabs() {
    return S.ui.el('div', { class: 'chip-group' }, KINDS.map(function (k) {
      return S.ui.chip(k.label, current.kind === k.key, function () {
        current.kind = k.key; current.q = '';
        var s = document.getElementById('search'); if (s) { s.value = ''; }
        load();
      });
    }));
  }

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'assets') { return; }
    S.ui.clear(view);
    view.appendChild(tabs());
    var card = S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [
        S.ui.el('h2', { text: KINDS.filter(function (k) { return k.key === current.kind; })[0].label }),
        S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('span', { class: 'caption', text: payload.count + ' of ' + payload.total + (errorMsg ? ' - ' + errorMsg : '') })
      ]),
      S.ui.el('div', { class: 'card-body tight' }, [S.ui.el('div', { class: 'table-wrap' },
        payload.assets.length ? [table()] : [S.ui.empty('No assets match', 'Assets appear as events and alerts are observed.')]
      )])
    ]);
    view.appendChild(card);
    if (openAsset) { drawer(openAsset); }
  }

  function load() {
    return S.api.get('/api/assets' + S.api.qs({ kind: current.kind, q: current.q, limit: current.limit }), 'assets').then(function (p) {
      payload = p || payload; errorMsg = ''; paint();
    }).catch(function (err) {
      errorMsg = err && err.message ? err.message : 'request failed';
      var view = document.getElementById('view');
      if (view && S.router.current() === 'assets') { S.ui.clear(view); view.appendChild(S.ui.error(errorMsg)); }
    });
  }

  S.pages.assets = {
    title: 'Assets',
    subtitle: 'Hosts, accounts and addresses seen in the window - derived from observed events only.',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading assets...' })]));
      load();
    },
    refresh: function () { if (S.router.current() === 'assets') { load(); } },
    filter: function (q) { current.q = q || ''; load(); }
  };
})();
