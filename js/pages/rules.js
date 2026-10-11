/* pages/rules.js - OWNER: the Detection Rules page. All 28 families with their
   audit-policy state: Working, or BLIND with the reason and the auditpol command
   that fixes it. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};
  var onlyBlind = false;
  var rules = [];
  var preflight = null;

  function fixFor(rule) {
    if (!preflight || !preflight.blind) { return ''; }
    var sub = String(rule.auditSubcategory || '').split(' + ')[0];
    for (var i = 0; i < preflight.blind.length; i++) {
      var b = preflight.blind[i];
      if (b.key === rule.key) {
        var need = String(b.need || 'Success').toLowerCase();
        return 'auditpol /set /subcategory:"' + sub + '" /' + need + ':enable';
      }
    }
    return '';
  }

  function stateBadge(r) {
    if (r.auditState === 'blind') {
      return S.ui.el('span', { class: 'badge rule-blind', text: 'BLIND' });
    }
    if (r.auditState === 'ok') { return S.ui.el('span', { class: 'badge rule-ok', text: 'Working' }); }
    if (r.auditState === 'n/a') { return S.ui.el('span', { class: 'badge rule-ok', text: 'Working', title: 'not gated by an audit-policy subcategory' }); }
    return S.ui.el('span', { class: 'badge', text: 'Working', title: 'audit policy could not be read - run elevated to confirm coverage' });
  }

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'rules') { return; }
    S.ui.clear(view);
    var rows = rules.filter(function (r) { return onlyBlind ? r.auditState === 'blind' : true; });
    var blindCount = rules.filter(function (r) { return r.auditState === 'blind'; }).length;
    if (blindCount > 0) {
      view.appendChild(S.ui.el('div', { class: 'banner banner-warn' }, [
        S.ui.el('span', { text: blindCount + ' famil' + (blindCount === 1 ? 'y is' : 'ies are') + ' blind: Windows is not writing their events, so no rule logic can help.' })
      ]));
    }
    var tbody = S.ui.el('tbody');
    rows.forEach(function (r) {
      var detail = S.ui.el('div', { text: r.description || '' });
      if (r.auditState === 'blind') {
        detail.appendChild(S.ui.el('div', { class: 'caption rule-blind', text: r.auditDetail || 'not auditing' }));
        var cmd = fixFor(r);
        if (cmd) { detail.appendChild(S.ui.el('code', { class: 'rule-fix', text: cmd })); }
      }
      tbody.appendChild(S.ui.el('tr', {}, [
        S.ui.el('td', {}, [stateBadge(r)]),
        S.ui.el('td', {}, [S.ui.el('div', { class: 'cell-strong', text: r.title }), detail]),
        S.ui.el('td', {}, [S.ui.sevBadge(r.severity)]),
        S.ui.el('td', { class: 'cell-dim mono', text: (r.eventIds || []).join(', ') }),
        S.ui.el('td', { class: 'cell-dim', text: r.mitre || '' }),
        S.ui.el('td', { class: 'cell-mute', text: r.category || '' }),
        S.ui.el('td', { class: 'num cell-mute', text: String(r.fired || 0) })
      ]));
    });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [
        S.ui.el('h2', { text: 'Detection rules' }),
        S.ui.el('span', { class: 'grow spacer' }),
        S.ui.chip('Only blind', onlyBlind, function () { onlyBlind = !onlyBlind; paint(); }),
        S.ui.el('span', { class: 'caption', text: rules.length + ' families' })
      ]),
      S.ui.el('div', { class: 'card-body tight' }, [S.ui.el('div', { class: 'table-wrap' }, [S.ui.el('table', { class: 'data' }, [
        S.ui.el('thead', {}, [S.ui.el('tr', {}, ['State', 'Rule', 'Severity', 'Event IDs', 'MITRE', 'Category', 'Fired'].map(function (h) { return S.ui.el('th', { text: h }); }))]),
        tbody
      ])])])
    ]));
  }

  function load() {
    return Promise.all([
      S.api.get('/api/rules', 'rules'),
      S.api.get('/api/preflight', 'rules').catch(function () { return null; })
    ]).then(function (out) {
      rules = (out[0] && out[0].rules) ? out[0].rules : [];
      preflight = out[1];
      paint();
    }).catch(function (err) {
      var view = document.getElementById('view');
      if (view && S.router.current() === 'rules') { S.ui.clear(view); view.appendChild(S.ui.error(err.message)); }
    });
  }

  S.pages.rules = {
    title: 'Detection Rules',
    subtitle: 'What this tool can see, and what Windows is not telling it.',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading rules...' })]));
      load();
    },
    refresh: function () { if (S.router.current() === 'rules') { load(); } },
    filter: function (q) {
      var needle = (q || '').toLowerCase();
      var view = document.getElementById('view');
      if (!view || S.router.current() !== 'rules' || !needle) { paint(); return; }
      var rows = rules.filter(function (r) {
        return ([r.title, r.key, r.mitre, r.category, (r.eventIds || []).join(' ')].join(' ').toLowerCase().indexOf(needle) >= 0);
      });
      var keep = rules; rules = rows; onlyBlind = false; paint(); rules = keep;
    }
  };
})();
