/* pages/events.js - OWNER: the Events page - the last 300 normalised events,
   newest first, with the filters the endpoint supports. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};
  var filters = { eventId: '', host: '', user: '', q: '', limit: 100 };
  var payload = { events: [], count: 0, total: 0, limit: 100 };
  var errorMsg = '';

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'events') { return; }
    S.ui.clear(view);

    function field(key, placeholder, width) {
      var input = S.ui.el('input', { class: 'field', type: 'text', placeholder: placeholder, value: filters[key], style: 'width:' + width + 'px' });
      input.addEventListener('change', function () { filters[key] = input.value.trim(); load(); });
      input.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { filters[key] = input.value.trim(); load(); } });
      return input;
    }
    var bar = S.ui.el('div', { class: 'filterbar' }, [
      field('eventId', 'event id (e.g. 4625)', 150),
      field('host', 'host (exact)', 140),
      field('user', 'user (exact)', 130),
      field('q', 'contains...', 150),
      S.ui.chip('Clear', false, function () { filters = { eventId: '', host: '', user: '', q: '', limit: 100 }; var s = document.getElementById('search'); if (s) { s.value = ''; } load(); })
    ]);

    var tbody = S.ui.el('tbody');
    payload.events.forEach(function (e) {
      tbody.appendChild(S.ui.el('tr', {}, [
        S.ui.el('td', { class: 'cell-mute mono', text: S.ui.fmtTime(e.time) }),
        S.ui.el('td', { class: 'cell-strong mono', text: e.eventId }),
        S.ui.el('td', { class: 'cell-dim', text: e.channel || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: e.host || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: e.user || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: e.sourceIp || '-' }),
        S.ui.el('td', { class: 'ev-summary', text: e.summary || '' }),
        S.ui.el('td', { class: 'cell-mute mono', text: e.matchedRule || '-' })
      ]));
    });

    var card = S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Events' }), S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('span', { class: 'caption', text: payload.count + ' of ' + payload.total + ' in the buffer (max 300)' })]),
      S.ui.el('div', { class: 'card-body tight' }, [S.ui.el('div', { class: 'table-wrap' },
        payload.events.length ? [S.ui.el('table', { class: 'data' }, [
          S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Time', 'ID', 'Channel', 'Host', 'User', 'Source IP', 'Summary', 'Rule'].map(function (h) { return S.ui.el('th', { text: h }); }))]),
          tbody
        ])] : [S.ui.empty('No events match', 'The buffer holds what the poller has seen since this process started.')])])
    ]);
    view.appendChild(bar);
    if (errorMsg) { view.appendChild(S.ui.el('div', { class: 'banner banner-warn', text: errorMsg })); }
    view.appendChild(card);
  }

  function load() {
    var params = { limit: filters.limit };
    ['eventId', 'host', 'user', 'q'].forEach(function (k) { params[k] = filters[k]; });
    return S.api.get('/api/events' + S.api.qs(params), 'events').then(function (p) {
      payload = p || payload;
      errorMsg = '';
      paint();
    }).catch(function (err) {
      errorMsg = err && err.message ? err.message : 'request failed';
      if (err && err.status === 400) { errorMsg = 'Filter rejected: ' + errorMsg; }
      var view = document.getElementById('view');
      if (view && S.router.current() === 'events') { paint(); }
    });
  }

  S.pages.events = {
    title: 'Events',
    subtitle: 'The last 300 normalised events the poller saw, newest first.',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading events...' })]));
      load();
    },
    refresh: function () { if (S.router.current() === 'events') { load(); } },
    filter: function (q) { filters.q = q || ''; load(); }
  };
})();
