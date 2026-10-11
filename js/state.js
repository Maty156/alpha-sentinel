/* state.js - OWNER: the tiny shared store and the polling timer.
   The timer pauses while the tab is hidden (a dashboard left open overnight must
   not poll a DC forever) and refreshes immediately when the tab comes back. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};

  var data = {};
  var watchers = [];

  S.state = {
    set: function (key, value) {
      data[key] = value;
      watchers.forEach(function (w) { if (w.key === key || w.key === '*') { w.fn(value, key); } });
    },
    get: function (key) { return data[key]; },
    watch: function (key, fn) { watchers.push({ key: key, fn: fn }); }
  };

  var timer = null;
  var task = null;
  var intervalMs = 10000;

  function tick() {
    if (document.hidden) { return; }
    if (task) { task(); }
  }

  S.poller = {
    start: function (fn, ms) {
      task = fn;
      if (ms) { intervalMs = ms; }
      S.poller.stop();
      timer = window.setInterval(tick, intervalMs);
      document.addEventListener('visibilitychange', function () {
        if (!document.hidden) { tick(); }
      });
    },
    stop: function () { if (timer) { window.clearInterval(timer); timer = null; } },
    now: function () { tick(); }
  };
})();
