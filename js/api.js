/* api.js - OWNER: every call to the backend, and nothing else.
   All requests are same-origin with credentials, so the session cookie goes with
   them; a 401 sends the browser back to the sign-in page. One console.error path,
   tagged with the page that asked, so a failing page names itself in the console. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};

  function logFail(page, err) {
    console.error('[sentinel:' + (page || 'api') + '] request failed:', err && err.message ? err.message : err);
  }

  function request(method, path, body, page) {
    var opts = {
      method: method,
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    };
    if (body !== undefined && body !== null) {
      opts.headers['Content-Type'] = 'application/json';
      // never an empty body: a length-less POST is refused as a stalled request
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (res) {
      if (res.status === 401) {
        window.location.replace('/');
        return Promise.reject(new Error('not signed in'));
      }
      return res.text().then(function (text) {
        var data = null;
        if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
        if (!res.ok) {
          var err = new Error((data && data.error) ? data.error : ('HTTP ' + res.status));
          err.status = res.status;
          err.body = data;
          logFail(page, err);
          return Promise.reject(err);
        }
        return data;
      });
    }, function (err) {
      // a fetch the page itself aborted (navigation, tab close, an abort
      // controller) is not a failure: it must stay silent, or every link clicked
      // away from a mid-flight poll prints an error for a request nobody wanted
      if (err && (err.name === 'AbortError' || err.name === 'NavigationError')) { return Promise.reject(err); }
      logFail(page, err);
      return Promise.reject(err);
    });
  }

  S.api = {
    get: function (path, page) { return request('GET', path, null, page); },
    post: function (path, body, page) { return request('POST', path, body || {}, page); },
    /* builds '?a=1&b=2' from an object, skipping empty values and encoding both
       sides (a filter is data, never a fragment of the URL) */
    qs: function (params) {
      var parts = [];
      if (!params) { return ''; }
      Object.keys(params).forEach(function (k) {
        var v = params[k];
        if (v === undefined || v === null || v === '') { return; }
        parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(v)));
      });
      return parts.length ? ('?' + parts.join('&')) : '';
    }
  };
})();
