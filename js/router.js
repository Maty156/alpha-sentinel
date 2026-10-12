/* router.js - OWNER: the hash router. #/overview #/alerts #/rules #/events
   #/settings; it renders the page module into <main id="view">, sets the title and
   moves the crimson active marker in the sidebar. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};

  var ROUTES = {
    '/overview': 'overview',
    '/alerts': 'alerts',
    '/assets': 'assets',
    '/rules': 'rules',
    '/events': 'events',
    '/settings': 'settings'
  };
  var current = null;

  function path() {
    var h = window.location.hash || '';
    var p = h.replace(/^#/, '');
    if (!p) { return '/overview'; }
    return ROUTES[p] ? p : '/overview';
  }

  function markActive(page) {
    var items = document.querySelectorAll('.nav-item[data-page]');
    Array.prototype.forEach.call(items, function (it) {
      it.classList.toggle('active', it.getAttribute('data-page') === page);
    });
  }

  function render() {
    var p = path();
    var name = ROUTES[p];
    var mod = S.pages && S.pages[name];
    var view = document.getElementById('view');
    if (!view || !mod) { return; }
    current = name;
    markActive(name);
    var titleEl = document.getElementById('pageTitle');
    var subEl = document.getElementById('pageSub');
    if (titleEl) { titleEl.textContent = mod.title || name; }
    if (subEl) { subEl.textContent = mod.subtitle || ''; }
    document.title = 'ALPHA Sentinel - ' + (mod.title || name);
    S.ui.clear(view);
    try {
      mod.render(view);
    } catch (err) {
      console.error('[sentinel:' + name + '] render failed:', err && err.message ? err.message : err);
      view.appendChild(S.ui.error(err && err.message ? err.message : 'render failed'));
    }
  }

  S.router = {
    start: function () {
      window.addEventListener('hashchange', render);
      if (!window.location.hash) { window.location.hash = '#/overview'; }
      render();
    },
    current: function () { return current; },
    /* the page currently on screen, so polling and the top search box can reach it */
    page: function () { return S.pages && ROUTES[current] ? S.pages[ROUTES[current]] : null; },
    render: render
  };
})();
