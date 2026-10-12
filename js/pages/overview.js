/* pages/overview.js - OWNER: the Security Overview page. Tiles with deltas,
   coverage meter, severity bar, hourly sparkline, top tactics and the latest
   alerts + events. Every number comes from the API; nothing is invented. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  var lastAlerts = [];

  var TILES = [
    { key: 'openAlerts', label: 'Active Alerts', glyph: '!', attention: true },
    { key: 'critical', label: 'Critical', glyph: '\u25B2', sev: 'Critical', attention: true },
    { key: 'high', label: 'High', glyph: '\u25B2', sev: 'High', attention: true },
    { key: 'hostsSeen', label: 'Hosts Monitored', glyph: '\u25A6', attention: false },
    { key: 'coverage', label: 'Detection Coverage', glyph: '\u2713', coverage: true }
  ];

  /* An arrow for the direction plus the number, straight from
     /api/overview.deltas. The colour follows what the metric means: more alerts
     is attention (amber), more hosts is just coverage (teal), a fall is neither. */
  function deltaNode(value, risingIsAttention) {
    var v = Number(value) || 0;
    var arrow = v > 0 ? '\u25B2' : (v < 0 ? '\u25BC' : '\u2013');
    var cls = 'tile-delta neutral';
    if (v > 0) { cls = 'tile-delta ' + (risingIsAttention ? 'up' : 'good'); }
    else if (v < 0) { cls = 'tile-delta down'; }
    var node = S.ui.el('span', { class: cls, title: 'change against the previous hour' });
    node.appendChild(S.ui.el('span', { class: 'arrow', text: arrow }));
    node.appendChild(S.ui.el('span', { text: (v > 0 ? '+' + v : String(v)) }));
    return node;
  }

  function tile(cfg, ov) {
    var hourly = (ov.hourly || []).map(function (h) { return h.events; });
    var cov = ov.coverage || {};
    var value, delta = null, notes = [];
    if (cfg.coverage) {
      value = (cov.percent || 0) + '%';
      // coverage counts CONFIRMED families only, so an unreadable policy has to
      // be visible here rather than quietly counted as working
      if (Number(cov.rulesBlind) > 0) { notes.push(S.ui.el('span', { class: 'tile-note bad', text: cov.rulesBlind + ' blind' })); }
      if (Number(cov.rulesUnknown) > 0) { notes.push(S.ui.el('span', { class: 'tile-note warn', text: cov.rulesUnknown + ' unverified' })); }
      if (!notes.length) { notes.push(S.ui.el('span', { class: 'tile-note', text: 'all families verified' })); }
    } else {
      value = S.ui.fmtNum(ov.tiles ? ov.tiles[cfg.key] : 0);
      delta = deltaNode(ov.deltas ? ov.deltas[cfg.key] : 0, cfg.attention === true);
    }
    var icon = S.ui.el('span', { class: 'tile-icon', text: cfg.glyph });
    if (cfg.sev) { icon.classList.add('sev-' + cfg.sev); }
    var sparkHost = S.ui.el('div', { class: 'tile-spark' });
    if (hourly.length) {
      // one bucket still draws (a flat line and a baseline), not an empty box
      sparkHost.appendChild(S.ui.sparkline(hourly, { width: 88, height: 22, padY: 3, small: true, label: cfg.label + ' hourly events' }));
    }
    return S.ui.el('div', { class: 'tile' }, [
      S.ui.el('div', { class: 'tile-top' }, [icon, S.ui.el('span', { class: 'tile-label', text: cfg.label })]),
      S.ui.el('div', { class: 'tile-row' }, [S.ui.el('span', { class: 'tile-value', text: value }), delta]),
      S.ui.el('div', { class: 'row', style: 'gap:8px;min-height:16px' }, notes),
      S.ui.el('div', { class: 'tile-foot' }, [S.ui.el('span', { class: 'tile-delta neutral', text: 'last 24 h' }), sparkHost])
    ]);
  }

  function severityCard(ov) {
    var counts = ov.severityCounts || {};
    var total = 0;
    ['Critical', 'High', 'Medium', 'Low'].forEach(function (k) { total += Number(counts[k]) || 0; });
    var bar = S.ui.el('div', { class: 'sevbar' });
    var legend = S.ui.el('div', { class: 'legend' });
    ['Critical', 'High', 'Medium', 'Low'].forEach(function (k) {
      var n = Number(counts[k]) || 0;
      if (total > 0) { bar.appendChild(S.ui.el('span', { class: 's-' + k, style: 'width:' + ((n / total) * 100).toFixed(1) + '%' })); }
      legend.appendChild(S.ui.el('span', {}, [S.ui.el('i', { class: 's-' + k, style: 'background:var(--sev-' + k.toLowerCase() + ')' }), k + ' ' + n]));
    });
    return S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Alerts by severity' })]),
      S.ui.el('div', { class: 'card-body' }, [ bar, S.ui.el('div', { style: 'height:10px' }), legend ])
    ]);
  }

  function coverageCard(ov) {
    var c = ov.coverage || { percent: 0, rulesTotal: 0, rulesWorking: 0, rulesBlind: 0, blindRules: [] };
    var cls = c.rulesBlind > 0 ? 'bad' : '';
    var meter = S.ui.el('div', { class: 'meter ' + cls });
    meter.appendChild(S.ui.el('span', { style: 'width:' + c.percent + '%' }));
    var body = [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Detection Coverage' }), S.ui.el('span', { class: 'spacer grow' }),
        S.ui.el('a', { class: 'card-link', href: '#/rules', text: 'See all' })]),
      S.ui.el('div', { class: 'card-body' }, [
        S.ui.el('div', { class: 'coverage-head' }, [
          S.ui.el('span', { class: 'coverage-value ' + cls, text: c.percent + '%' }),
          S.ui.el('span', { class: 'caption', text: c.rulesWorking + ' of ' + c.rulesTotal + ' families can fire' })
        ]),
        meter
      ])
    ];
    if (c.rulesBlind > 0) {
      var banner = S.ui.el('div', { class: 'banner banner-warn', style: 'margin:0 16px 16px' });
      banner.appendChild(S.ui.el('span', { text: c.rulesBlind + ' rule famil' + (c.rulesBlind === 1 ? 'y is' : 'ies are') + ' blind - Windows is not writing their events. ' }));
      banner.appendChild(S.ui.el('a', { href: '#/rules', text: 'Why, and how to fix it' }));
      body.push(banner);
    }
    return S.ui.el('div', { class: 'card' }, body);
  }

  function hourlyCard(ov) {
    var hourly = ov.hourly || [];
    var card = S.ui.el('div', { class: 'card' });
    card.appendChild(S.ui.el('div', { class: 'card-head' }, [
      S.ui.el('h2', { text: 'Host Activity' }),
      S.ui.el('span', { class: 'caption', text: '24 hours' }),
      S.ui.el('span', { class: 'spacer grow' }),
      S.ui.el('span', { class: 'legend' }, [
        S.ui.el('span', {}, [S.ui.el('i', { style: 'background:var(--ok)' }), 'Events ' + S.ui.fmtNum(hourly.reduce(function (a, h) { return a + (h.events || 0); }, 0))])
      ])
    ]));
    var body = S.ui.el('div', { class: 'card-body' });
    if (!hourly.length) {
      body.appendChild(S.ui.empty('No hourly data yet', 'The chart fills as events are polled.'));
    } else {
      // area + line + baseline, so one or two buckets still read as a chart
      body.appendChild(S.ui.sparkline(hourly.map(function (h) { return h.events; }), { fill: true, label: 'events per hour' }));
      // label each hour at most ONCE (a short series used to print the same hour twice)
      var axis = S.ui.el('div', { class: 'legend', style: 'justify-content:space-between' });
      var n = hourly.length;
      var step = Math.max(1, Math.ceil(n / 6));
      for (var i = 0; i < n; i += step) {
        axis.appendChild(S.ui.el('span', { class: 'caption', text: hourly[i].hour }));
      }
      if (n > 1 && (n - 1) % step !== 0) {
        axis.appendChild(S.ui.el('span', { class: 'caption', text: hourly[n - 1].hour }));
      }
      body.appendChild(axis);
    }
    card.appendChild(body);
    return card;
  }

  function tacticsCard(ov) {
    var counts = ov.tacticCounts || {};
    var rows = Object.keys(counts).map(function (k) { return { name: k, n: Number(counts[k]) || 0 }; })
      .sort(function (a, b) { return b.n - a.n; }).slice(0, 7);
    var list = S.ui.el('ul', { class: 'tactic-list' });
    var max = rows.length ? rows[0].n : 1;
    if (!rows.length) {
      rows = [];
    }
    return S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Top MITRE tactics' })]),
      // the rows must live inside the <ul class="tactic-list">: bare <li> nodes
      // keep the browser's bullets and none of the leader/count styling
      S.ui.el('div', { class: 'card-body' }, rows.length ? [S.ui.el('ul', { class: 'tactic-list' },
        rows.map(function (r) {
          // "Tactic ............ count": no bullets, the number right-aligned
          return S.ui.el('li', { title: r.name + ' - ' + r.n + ' alert(s)' }, [
            S.ui.el('span', { class: 't-name', text: r.name }),
            S.ui.el('span', { class: 't-lead' }),
            S.ui.el('span', { class: 't-count', text: String(r.n) })
          ]);
        })
      )] : S.ui.empty('No alerts mapped yet', 'Tactics appear when a rule fires.'))
    ]);
  }

  function alertsTable(alerts, filterText) {
    // six rows, one line each: severity, title, host, account, time, status. The
    // description and the rest of the detail belong to the drawer on the Alerts page.
    var rows = alerts;
    if (filterText) {
      var q = filterText.toLowerCase();
      rows = alerts.filter(function (a) {
        return (String(a.Title) + ' ' + a.Host + ' ' + a.Account + ' ' + a.Severity).toLowerCase().indexOf(q) >= 0;
      });
    }
    rows = rows.slice(0, 6);
    var tbody = S.ui.el('tbody');
    rows.forEach(function (a) {
      var tr = S.ui.el('tr', {}, [
        S.ui.el('td', {}, [S.ui.sevBadge(a.Severity)]),
        S.ui.el('td', {}, [S.ui.el('span', { class: 'alert-title truncate', style: 'display:block', title: a.Title, text: a.Title })]),
        S.ui.el('td', { class: 'cell-dim', text: a.Host || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: a.Account || '-' }),
        S.ui.el('td', { class: 'cell-mute', text: S.ui.fmtAgo(a.Time) }),
        S.ui.el('td', {}, [S.ui.statusBadge(a.Status)])
      ]);
      tr.addEventListener('click', function () { window.location.hash = '#/alerts'; });
      tbody.appendChild(tr);
    });
    var table = S.ui.el('table', { class: 'data' }, [
      S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Severity', 'Detection', 'Host', 'Account', 'Time', 'Status'].map(function (h) {
        return S.ui.el('th', { text: h });
      }))]),
      tbody
    ]);
    var card = S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Recent Alerts' }), S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('a', { class: 'card-link', href: '#/alerts', text: 'View all \u2192' })]),
      S.ui.el('div', { class: 'card-body tight' }, [S.ui.el('div', { class: 'table-wrap' }, rows.length ? [table] : [S.ui.empty('No alerts', 'Nothing has fired yet - that is a good thing.')])])
    ]);
    return card;
  }

  function eventsCard(events) {
    var tbody = S.ui.el('tbody');
    events.slice(0, 6).forEach(function (e) {
      tbody.appendChild(S.ui.el('tr', {}, [
        S.ui.el('td', { class: 'cell-mute mono', text: S.ui.fmtTime(e.time) }),
        S.ui.el('td', {}, [S.ui.el('span', { class: 'cell-strong', text: e.summary })]),
        S.ui.el('td', { class: 'cell-dim', text: e.host || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: e.user || '-' }),
        S.ui.el('td', { class: 'cell-mute mono', text: e.matchedRule || ('event ' + e.eventId) })
      ]));
    });
    return S.ui.el('div', { class: 'card overview-latest' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Latest Events' }), S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('a', { class: 'card-link', href: '#/events', text: 'View all \u2192' })]),
      S.ui.el('div', { class: 'card-body tight' }, [S.ui.el('div', { class: 'table-wrap' }, events.length ? [S.ui.el('table', { class: 'data' }, [
        S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Time', 'Event', 'Host', 'Account', 'Rule'].map(function (h) { return S.ui.el('th', { text: h }); }))]),
        tbody
      ])] : [S.ui.empty('No events in the window', 'The ring buffer holds the last 300 events the poller saw.')])])
    ]);
  }

  var lastFilter = '';
  var lastData = null;

  function paint(view) {
    var ov = lastData.overview, alerts = lastData.alerts, events = lastData.events;
    S.ui.clear(view);
    if (!ov) { view.appendChild(S.ui.error(lastData.error || 'overview unavailable')); return; }
    var tiles = S.ui.el('div', { class: 'grid-tiles' }, TILES.map(function (t) { return tile(t, ov); }));
    var left = alertsTable(alerts || [], lastFilter);
    var right = S.ui.el('div', { style: 'display:flex;flex-direction:column;gap:12px' }, [coverageCard(ov), hourlyCard(ov), tacticsCard(ov)]);
    view.appendChild(tiles);
    view.appendChild(S.ui.el('div', { class: 'grid-2' }, [left, right]));
    view.appendChild(severityCard(ov));
    view.appendChild(eventsCard(events || []));
  }

  function load() {
    if (!lastData) { lastData = {}; }
    return Promise.all([
      S.api.get('/api/overview', 'overview'),
      S.api.get('/api/alerts?selfTest=0', 'overview'),
      S.api.get('/api/events?limit=6', 'overview')
    ]).then(function (out) {
      lastData.overview = out[0];
      lastData.alerts = (out[1] || []).slice().sort(function (a, b) { return String(b.Time).localeCompare(String(a.Time)); });
      lastData.events = out[2] && out[2].events ? out[2].events : [];
      var view = document.getElementById('view');
      if (view && S.router.current() === 'overview') { paint(view); }
    }).catch(function (err) {
      lastData.error = err && err.message ? err.message : 'request failed';
      var view = document.getElementById('view');
      if (view && S.router.current() === 'overview') { S.ui.clear(view); view.appendChild(S.ui.error(lastData.error)); }
    });
  }

  S.pages.overview = {
    title: 'Security Overview',
    subtitle: 'Monitor suspicious activity across your AD lab.',
    render: function (view) {
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading overview...' })]));
      load();
    },
    refresh: load,
    filter: function (q) {
      lastFilter = q || '';
      var view = document.getElementById('view');
      if (view && lastData && S.router.current() === 'overview') { paint(view); }
    }
  };
})();
