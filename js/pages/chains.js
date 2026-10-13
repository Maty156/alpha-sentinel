/* pages/chains.js - OWNER: the Attack Chains page - a list of chains on the left,
   and on the right a horizontal kill-chain strip (the 11 tactics) with the chain's
   alerts under each lit tactic. Inline SVG/CSS only, no libraries. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};
  var chains = [];
  var selected = null;
  var errorMsg = '';

  function strip(chain) {
    var all = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
               'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'];
    var host = S.ui.el('div', { class: 'chain-strip' });
    all.forEach(function (t) {
      var lit = (chain.tacticsInOrder || []).indexOf(t) >= 0;
      var cell = S.ui.el('div', { class: 'chain-cell' + (lit ? ' lit' : '') });
      cell.appendChild(S.ui.el('div', { class: 'chain-dot' }));
      cell.appendChild(S.ui.el('div', { class: 'chain-name', text: t }));
      if (lit) {
        var mine = (chain.alerts || []).filter(function (a) { return a.tactic === t; });
        var ul = S.ui.el('ul', { class: 'chain-alerts' });
        mine.forEach(function (a) {
          var li = S.ui.el('li', {});
          var link = S.ui.el('a', { class: 'sev sev-' + String(a.severity).replace(/\s+/g, ''), href: '#/alerts', text: a.title });
          link.addEventListener('click', function () {
            try { window.sessionStorage.setItem('sentinel-open-alert', String(a.id)); } catch (e) { }
          });
          li.appendChild(link);
          ul.appendChild(li);
        });
        cell.appendChild(ul);
      }
      host.appendChild(cell);
    });
    return host;
  }

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'chains') { return; }
    S.ui.clear(view);
    if (errorMsg) { view.appendChild(S.ui.error(errorMsg)); return; }
    if (!chains.length) {
      view.appendChild(S.ui.empty('No multi-step activity detected.', 'Chains appear when two or more open alerts share an account or a source IP within an hour.'));
      return;
    }
    var wrap = S.ui.el('div', { class: 'chains-layout' });
    var list = S.ui.el('div', { class: 'chains-list' });
    chains.forEach(function (c) {
      var item = S.ui.el('button', { class: 'chains-item' + (selected && selected.id === c.id ? ' on' : ''), type: 'button' });
      item.appendChild(S.ui.el('div', { class: 'row' }, [S.ui.sevBadge(c.maxSeverity), S.ui.el('span', { class: 'cell-strong grow', text: c.title })]));
      item.appendChild(S.ui.el('div', { class: 'caption', text: (c.alerts || []).length + ' alert(s) - ' + S.ui.fmtTime(c.firstSeen) + ' to ' + S.ui.fmtTime(c.lastSeen) }));
      item.addEventListener('click', function () { selected = c; paint(); });
      list.appendChild(item);
    });
    var right = S.ui.el('div', { class: 'chains-detail' });
    var c = selected || chains[0];
    var scroller = S.ui.el('div', { class: 'chains-scroller' });
    scroller.appendChild(strip(c));
    right.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [
        S.ui.el('h2', { text: c.title }),
        S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('span', { class: 'caption', text: 'kill-chain order, earliest tactic first' })
      ]),
      S.ui.el('div', { class: 'card-body' }, [scroller])
    ]));
    wrap.appendChild(list);
    wrap.appendChild(right);
    view.appendChild(wrap);
  }

  function load() {
    return S.api.get('/api/chains', 'chains').then(function (rows) {
      chains = Array.isArray(rows) ? rows : [];
      if (selected) {
        var again = chains.filter(function (c) { return c.id === selected.id; });
        selected = again.length ? again[0] : (chains[0] || null);
      } else { selected = chains[0] || null; }
      errorMsg = ''; paint();
    }).catch(function (err) {
      errorMsg = err && err.message ? err.message : 'request failed';
      var view = document.getElementById('view');
      if (view && S.router.current() === 'chains') { S.ui.clear(view); view.appendChild(S.ui.error(errorMsg)); }
    });
  }

  S.pages.chains = {
    title: 'Attack Chains',
    subtitle: 'Open alerts that share an entity within an hour - a kill-chain view.',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading chains...' })]));
      load();
    },
    refresh: function () { if (S.router.current() === 'chains') { load(); } },
    filter: function () { }
  };
})();
