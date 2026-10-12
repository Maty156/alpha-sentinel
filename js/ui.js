/* ui.js - OWNER: DOM helpers, formatting, badges, sparklines and toasts.
   Every piece of dynamic text goes through textContent (or el()'s text argument),
   never through innerHTML, so an account name or a summary from the event log can
   never become markup. innerHTML is used for exactly one thing: clearing a node. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === undefined || v === null || v === false) { return; }
        if (k === 'text') { node.textContent = String(v); return; }
        if (k === 'class') { node.className = v; return; }
        if (k === 'html') { return; }                    /* deliberately ignored */
        if (k.indexOf('on') === 0) { return; }           /* no inline handlers, ever */
        node.setAttribute(k, String(v));
      });
    }
    append(node, children);
    return node;
  }

  function append(node, children) {
    if (children === undefined || children === null) { return node; }
    if (!Array.isArray(children)) { children = [children]; }
    children.forEach(function (c) {
      if (c === undefined || c === null || c === false) { return; }
      if (c instanceof Node) { node.appendChild(c); } else { node.appendChild(document.createTextNode(String(c))); }
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
    return node;
  }

  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function asDate(value) {
    if (!value) { return null; }
    var d = new Date(value);
    return isNaN(d.getTime()) ? null : d;
  }

  S.ui = {
    el: el,
    append: append,
    clear: clear,
    text: function (node, value) { node.textContent = value === null || value === undefined ? '' : String(value); return node; },

    fmtTime: function (v) {
      var d = asDate(v);
      if (!d) { return '-'; }
      return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    },
    fmtDateTime: function (v) {
      var d = asDate(v);
      if (!d) { return '-'; }
      return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    },
    fmtAgo: function (v) {
      var d = asDate(v);
      if (!d) { return '-'; }
      var s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
      if (s < 60) { return s + 's ago'; }
      if (s < 3600) { return Math.round(s / 60) + 'm ago'; }
      if (s < 86400) { return Math.round(s / 3600) + 'h ago'; }
      return Math.round(s / 86400) + 'd ago';
    },
    fmtNum: function (n) {
      if (n === null || n === undefined) { return '0'; }
      return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    sevBadge: function (sev) {
      var s = String(sev || 'Low');
      return el('span', { class: 'sev sev-' + s.replace(/\s+/g, '') }, [
        el('span', { class: 'sev-dot' }),
        el('span', { text: s })
      ]);
    },
    statusBadge: function (status) {
      var s = String(status || 'New');
      return el('span', { class: 'badge status-' + s.replace(/\s+/g, ''), text: s });
    },
    ackBadge: function (ack) {
      if (!ack) { return el('span', { class: 'badge', text: 'Not acked' }); }
      return el('span', { class: 'badge badge-ack', text: 'Acknowledged' });
    },
    pill: function (kind, label, title) {
      return el('span', { class: 'pill ' + (kind || ''), title: title || '' }, [
        el('span', { class: 'dot' }),
        el('span', { text: label })
      ]);
    },
    chip: function (label, on, onClick, title) {
      var c = el('button', { class: 'chip' + (on ? ' on' : ''), type: 'button', text: label, title: title || '' });
      if (onClick) { c.addEventListener('click', onClick); }
      return c;
    },

    empty: function (title, hint) {
      return el('div', { class: 'state' }, [
        el('div', { class: 'state-title', text: title || 'Nothing here yet' }),
        el('div', { class: 'state-hint', text: hint || '' })
      ]);
    },
    error: function (message) {
      return el('div', { class: 'state state-error' }, [
        el('div', { class: 'state-title', text: 'Could not load this' }),
        el('div', { class: 'state-hint', text: message || 'The request failed.' })
      ]);
    },

    toast: function (message, kind) {
      var host = document.getElementById('toasts');
      if (!host) { host = el('div', { id: 'toasts', class: 'toasts' }); document.body.appendChild(host); }
      var t = el('div', { class: 'toast ' + (kind || ''), text: message });
      host.appendChild(t);
      window.setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, 4200);
    },

    /* inline SVG sparkline - no chart library, no HTML string, no data in markup */
    sparkline: function (series, opts) {
      var o = opts || {};
      var w = o.width || 640, h = o.height || 130, padY = o.padY || 12;
      var ns = 'http://www.w3.org/2000/svg';
      var svg = document.createElementNS(ns, 'svg');
      svg.setAttribute('class', o.className2 || 'spark');
      svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
      svg.setAttribute('preserveAspectRatio', 'none');
      svg.setAttribute('role', 'img');
      svg.setAttribute('aria-label', o.label || 'hourly activity');
      if (o.small) { svg.setAttribute('class', 'spark spark-sm'); }
      var values = (series || []).map(function (v) { return Number(v) || 0; });
      var max = Math.max.apply(null, values.concat([1]));
      // one bucket must still draw: a flat line reads as "one hour of data",
      // an empty chart reads as "broken". Duplicate the single point.
      if (values.length === 1) { values = [values[0], values[0]]; }
      var n = Math.max(values.length, 2);
      var x = function (i) { return (i / (n - 1)) * w; };
      var y = function (v) { return h - padY - ((v / max) * (h - padY * 2)); };
      var base = h - padY;

      for (var g = 0; g < 3; g++) {
        var ln = document.createElementNS(ns, 'line');
        ln.setAttribute('class', 'grid-line');
        ln.setAttribute('x1', 0); ln.setAttribute('x2', w);
        var yy = padY + g * ((h - padY * 2) / 2);
        ln.setAttribute('y1', yy); ln.setAttribute('y2', yy);
        svg.appendChild(ln);
      }
      var d = '';
      for (var i = 0; i < values.length; i++) { d += (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ' ' + y(values[i]).toFixed(1) + ' '; }
      if (o.fill) {
        var area = document.createElementNS(ns, 'path');
        area.setAttribute('class', 'area-events');
        area.setAttribute('d', d + 'L' + x(values.length - 1).toFixed(1) + ' ' + base.toFixed(1) + ' L0 ' + base.toFixed(1) + ' Z');
        svg.appendChild(area);
      }
      var path = document.createElementNS(ns, 'path');
      path.setAttribute('class', o.className || 'line-events');
      path.setAttribute('d', d.trim());
      svg.appendChild(path);
      // a baseline, so a flat or single-bucket series still looks like a chart
      var baseline = document.createElementNS(ns, 'line');
      baseline.setAttribute('class', 'baseline');
      baseline.setAttribute('x1', 0); baseline.setAttribute('x2', w);
      baseline.setAttribute('y1', base.toFixed(1)); baseline.setAttribute('y2', base.toFixed(1));
      svg.appendChild(baseline);
      return svg;
    }
  };
})();
