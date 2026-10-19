/* pages/paths.js - OWNER: the Attack Paths graph page - BloodHound-style interactive Active Directory identity compromise graph and shortest path to Domain Admin. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  var selectedNode = null;
  var graphData = null;

  /* Default Active Directory Tiering Topology */
  function generateTopology(alerts) {
    var compromisedEntities = {};
    (alerts || []).forEach(function (a) {
      if (a.Account && a.Account !== '-') { compromisedEntities[a.Account.toLowerCase()] = true; }
      if (a.Host && a.Host !== '-') { compromisedEntities[a.Host.toLowerCase()] = true; }
    });

    var nodes = [
      { id: 'u1', name: 'jsmith', type: 'user', tier: 2, label: 'Standard User (Sales)', compromised: !!compromisedEntities['jsmith'] },
      { id: 'h1', name: 'WS-SALES-04', type: 'host', tier: 2, label: 'Workstation (Windows 11)', compromised: !!compromisedEntities['ws-sales-04'] },
      { id: 'u2', name: 'svc-backup', type: 'service', tier: 1, label: 'Service Account (Veeam)', compromised: !!compromisedEntities['svc-backup'] || !!compromisedEntities['kerberoasting'] },
      { id: 'h2', name: 'SRV-FILE-01', type: 'server', tier: 1, label: 'Member File Server', compromised: !!compromisedEntities['srv-file-01'] },
      { id: 'g1', name: 'Server Operators', type: 'group', tier: 1, label: 'AD Security Group', compromised: false },
      { id: 'u3', name: 'adm-da', type: 'admin', tier: 0, label: 'Delegated Administrator', compromised: !!compromisedEntities['adm-da'] },
      { id: 'g0', name: 'Domain Admins', type: 'group', tier: 0, label: 'Tier-0 Privileged Group', compromised: !!compromisedEntities['privilege_escalation'] },
      { id: 'dc', name: 'DC01.corp.local', type: 'dc', tier: 0, label: 'Primary Domain Controller', compromised: !!compromisedEntities['dc01'] || !!compromisedEntities['dcsync_replication'] }
    ];

    var edges = [
      { source: 'u1', target: 'h1', relation: 'HasSession', label: 'Logged On' },
      { source: 'h1', target: 'u2', relation: 'Kerberoast', label: 'Kerberoastable SPN' },
      { source: 'u2', target: 'g1', relation: 'MemberOf', label: 'Group Member' },
      { source: 'g1', target: 'h2', relation: 'AdminTo', label: 'Local Admin' },
      { source: 'h2', target: 'u3', relation: 'HasSession', label: 'Cached Credential' },
      { source: 'u3', target: 'g0', relation: 'MemberOf', label: 'Member of DA' },
      { source: 'g0', target: 'dc', relation: 'DCSync', label: 'Replication Rights (Tier 0)' }
    ];

    return { nodes: nodes, edges: edges };
  }

  function renderGraphSvg(data) {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 880 480');
    svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

    // Defs for arrows and glows
    var defs = document.createElementNS(ns, 'defs');
    var marker = document.createElementNS(ns, 'marker');
    marker.setAttribute('id', 'path-arrow');
    marker.setAttribute('viewBox', '0 0 10 10');
    marker.setAttribute('refX', '18');
    marker.setAttribute('refY', '5');
    marker.setAttribute('markerWidth', '6');
    marker.setAttribute('markerHeight', '6');
    marker.setAttribute('orient', 'auto-start-reverse');
    var markerPath = document.createElementNS(ns, 'path');
    markerPath.setAttribute('d', 'M 0 1 L 10 5 L 0 9 z');
    markerPath.setAttribute('fill', '#ff4d6d');
    marker.appendChild(markerPath);
    defs.appendChild(marker);
    svg.appendChild(defs);

    // Positions for nodes across columns (Tier 2 -> Tier 1 -> Tier 0)
    var coords = {
      'u1': { x: 70, y: 150 },
      'h1': { x: 190, y: 260 },
      'u2': { x: 330, y: 140 },
      'g1': { x: 460, y: 240 },
      'h2': { x: 570, y: 350 },
      'u3': { x: 670, y: 210 },
      'g0': { x: 770, y: 120 },
      'dc': { x: 800, y: 330 }
    };

    // Draw edges
    data.edges.forEach(function (e) {
      var s = coords[e.source];
      var t = coords[e.target];
      if (!s || !t) { return; }

      var line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', s.x);
      line.setAttribute('y1', s.y);
      line.setAttribute('x2', t.x);
      line.setAttribute('y2', t.y);
      line.setAttribute('stroke', '#ff4d6d');
      line.setAttribute('stroke-width', '2');
      line.setAttribute('stroke-dasharray', '5,4');
      line.setAttribute('marker-end', 'url(#path-arrow)');
      line.setAttribute('opacity', '0.75');
      svg.appendChild(line);

      // Label on edge
      var mx = (s.x + t.x) / 2;
      var my = (s.y + t.y) / 2 - 6;
      var txt = document.createElementNS(ns, 'text');
      txt.setAttribute('x', mx);
      txt.setAttribute('y', my);
      txt.setAttribute('fill', '#a9a2b4');
      txt.setAttribute('font-size', '10');
      txt.setAttribute('font-family', 'var(--font-mono)');
      txt.setAttribute('text-anchor', 'middle');
      txt.textContent = e.label;
      svg.appendChild(txt);
    });

    // Draw nodes
    data.nodes.forEach(function (n) {
      var pt = coords[n.id] || { x: 100, y: 100 };
      var g = document.createElementNS(ns, 'g');
      g.style.cursor = 'pointer';

      var circle = document.createElementNS(ns, 'circle');
      circle.setAttribute('cx', pt.x);
      circle.setAttribute('cy', pt.y);
      circle.setAttribute('r', n.type === 'dc' ? '24' : '18');
      
      var fillColor = n.tier === 0 ? '#ff4d6d' : (n.tier === 1 ? '#ff8a3d' : '#2ec4a6');
      circle.setAttribute('fill', '#1c1923');
      circle.setAttribute('stroke', n.compromised ? '#ff4d6d' : fillColor);
      circle.setAttribute('stroke-width', n.compromised ? '3.5' : '2');
      if (n.compromised) {
        circle.setAttribute('filter', 'drop-shadow(0 0 8px rgba(255, 77, 109, 0.8))');
      }

      var text = document.createElementNS(ns, 'text');
      text.setAttribute('x', pt.x);
      text.setAttribute('y', pt.y + 30);
      text.setAttribute('fill', '#ece9f1');
      text.setAttribute('font-size', '11');
      text.setAttribute('font-weight', '600');
      text.setAttribute('text-anchor', 'middle');
      text.textContent = n.name;

      var sub = document.createElementNS(ns, 'text');
      sub.setAttribute('x', pt.x);
      sub.setAttribute('y', pt.y + 42);
      sub.setAttribute('fill', '#837c95');
      sub.setAttribute('font-size', '9.5');
      sub.setAttribute('text-anchor', 'middle');
      sub.textContent = 'Tier ' + n.tier;

      g.appendChild(circle);
      g.appendChild(text);
      g.appendChild(sub);

      g.addEventListener('click', function () {
        selectedNode = n;
        paint();
      });

      svg.appendChild(g);
    });

    return svg;
  }

  function renderDetailCard(n) {
    if (!n) {
      return S.ui.el('div', { class: 'card paths-info-card' }, [
        S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Attack Path Inspector' })]),
        S.ui.el('div', { class: 'card-body' }, [
          S.ui.el('div', { class: 'state' }, [
            S.ui.el('div', { class: 'state-title', text: 'Select any Active Directory node' }),
            S.ui.el('div', { class: 'state-hint', text: 'Click an account, computer, or group in the graph to inspect compromise risk and ACL attack vectors.' })
          ])
        ])
      ]);
    }

    var tierCls = 'tier-' + n.tier;
    var badge = S.ui.el('span', { class: 'tier-tag ' + tierCls, text: 'Tier ' + n.tier });

    var kv = S.ui.el('dl', { class: 'kv' }, [
      S.ui.el('dt', { text: 'Identity' }), S.ui.el('dd', { text: n.name }),
      S.ui.el('dt', { text: 'Classification' }), S.ui.el('dd', { text: n.label }),
      S.ui.el('dt', { text: 'Tier Level' }), S.ui.el('dd', {}, [badge]),
      S.ui.el('dt', { text: 'Compromised' }), S.ui.el('dd', { text: n.compromised ? 'YES (Active Detection)' : 'No known alert' }),
      S.ui.el('dt', { text: 'Hops to Tier 0' }), S.ui.el('dd', { text: n.tier === 0 ? '0 (Target Domain Admin/DC)' : (n.tier === 1 ? '1-2 hops' : '3 hops') }),
      S.ui.el('dt', { text: 'Remediation' }), S.ui.el('dd', { text: n.tier === 0 ? 'Isolate domain controller, revoke Kerberos krbtgt ticket twice.' : 'Enforce credential tiering, disable NTLM & unconstrained delegation.' })
    ]);

    return S.ui.el('div', { class: 'card paths-info-card' }, [
      S.ui.el('div', { class: 'card-head' }, [
        S.ui.el('h2', { text: n.name }),
        S.ui.el('span', { class: 'grow spacer' }),
        badge
      ]),
      S.ui.el('div', { class: 'card-body' }, [kv])
    ]);
  }

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'paths') { return; }
    S.ui.clear(view);

    var alerts = S.state.get('alerts') || [];
    graphData = generateTopology(alerts);

    var stage = S.ui.el('div', { class: 'paths-stage' });
    stage.appendChild(renderGraphSvg(graphData));

    var legend = S.ui.el('div', { class: 'paths-legend-hud' }, [
      S.ui.el('span', { style: 'color:var(--sev-critical);font-weight:600', text: '\u25CF Tier 0 (Domain Admins & DC)' }),
      S.ui.el('span', { style: 'color:var(--sev-high);font-weight:600', text: '\u25CF Tier 1 (Servers & Priv Groups)' }),
      S.ui.el('span', { style: 'color:var(--ok);font-weight:600', text: '\u25CF Tier 2 (Workstations & Users)' })
    ]);
    stage.appendChild(legend);

    var hero = S.ui.el('div', { class: 'paths-hero' }, [
      stage,
      renderDetailCard(selectedNode || graphData.nodes[0])
    ]);

    var container = S.ui.el('div', { class: 'paths-layout' }, [
      S.ui.el('div', { class: 'banner banner-info' }, [
        S.ui.el('span', { text: 'Active Directory Identity Graph: Models shortest lateral movement and privilege escalation attack vectors targeting Tier-0 Domain Controllers.' })
      ]),
      hero
    ]);

    view.appendChild(container);
  }

  function load() {
    return S.api.get('/api/alerts', 'paths').then(function (rows) {
      if (Array.isArray(rows)) { S.state.set('alerts', rows); }
      paint();
    }).catch(function () {
      paint();
    });
  }

  S.pages.paths = {
    title: 'Attack Paths',
    subtitle: 'Graph Analysis of Active Directory Privilege Escalation Vectors to Domain Admin',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      load();
    },
    refresh: function () { if (S.router.current() === 'paths') { load(); } },
    filter: function () { }
  };
})();
