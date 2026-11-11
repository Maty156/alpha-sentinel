/* wolf-store.js - OWNER: Wolf conversations. Several chats, kept in THIS browser only
   (localStorage), shared by the floating widget and the Wolf page. The last few turns
   of the active chat go to the server with every question so Wolf remembers context. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};

  var KEY = 'wolf-chats-v2';
  var MAX_CHATS = 30;
  var MAX_MSGS = 60;
  var listeners = [];
  var state = { active: null, chats: [] };
  var sending = {};

  function now() { return Date.now(); }
  function newId() { return 'c' + now().toString(36) + Math.random().toString(36).slice(2, 6); }

  function load() {
    var raw = null;
    try { raw = JSON.parse(window.localStorage.getItem(KEY) || 'null'); } catch (e) { raw = null; }
    if (raw && Array.isArray(raw.chats)) {
      state.chats = raw.chats.filter(function (c) { return c && typeof c.id === 'string' && Array.isArray(c.msgs); }).map(function (c) {
        c.msgs = c.msgs.filter(function (m) { return m && (m.who === 'user' || m.who === 'bot') && typeof m.text === 'string'; }).slice(-MAX_MSGS);
        c.title = typeof c.title === 'string' && c.title ? c.title : 'New chat';
        c.updated = c.updated || now();
        return c;
      }).slice(0, MAX_CHATS);
      state.active = raw.active;
    } else {
      // migrate the single conversation saved by the previous version
      var old = [];
      try { old = JSON.parse(window.localStorage.getItem('wolf-chat') || '[]'); } catch (e) { old = []; }
      if (Array.isArray(old) && old.length) {
        var first = old.filter(function (m) { return m && typeof m.text === 'string'; });
        if (first.length) { state.chats = [makeChat(first)]; }
      }
    }
    if (!state.chats.length) { state.chats = [makeChat([])]; }
    if (!state.chats.some(function (c) { return c.id === state.active; })) { state.active = state.chats[0].id; }
  }

  function titleFrom(msgs) {
    for (var i = 0; i < msgs.length; i++) {
      if (msgs[i].who === 'user') { var t = msgs[i].text.replace(/\s+/g, ' ').trim(); return t.length > 40 ? t.slice(0, 40) + '...' : t; }
    }
    return 'New chat';
  }
  function makeChat(msgs) { return { id: newId(), title: titleFrom(msgs), msgs: msgs, updated: now() }; }

  function save() {
    try { window.localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { }
  }
  function emit() { save(); listeners.forEach(function (fn) { try { fn(); } catch (e) { } }); }

  function get(id) { return state.chats.filter(function (c) { return c.id === id; })[0] || null; }

  var api = {
    greeting: "I'm Wolf, your AD sentinel assistant. Ask me about alerts, whether the detection rules are working (audit coverage), or what to do about an alert.",
    placeholder: 'Ask about alerts, rules, coverage...',
    subscribe: function (fn) { listeners.push(fn); return function () { listeners = listeners.filter(function (l) { return l !== fn; }); }; },
    chats: function () { return state.chats.slice().sort(function (a, b) { return b.updated - a.updated; }); },
    active: function () { return get(state.active); },
    activeId: function () { return state.active; },
    isSending: function (id) { return !!sending[id || state.active]; },
    select: function (id) { if (get(id)) { state.active = id; emit(); } },
    // an empty "New chat" is reused instead of piling up blank ones
    newChat: function () {
      var blank = state.chats.filter(function (c) { return c.msgs.length === 0; })[0];
      if (blank) { state.active = blank.id; blank.updated = now(); emit(); return blank; }
      var c = makeChat([]);
      state.chats.unshift(c);
      state.chats = state.chats.sort(function (a, b) { return b.updated - a.updated; }).slice(0, MAX_CHATS);
      state.active = c.id;
      emit();
      return c;
    },
    remove: function (id) {
      state.chats = state.chats.filter(function (c) { return c.id !== id; });
      if (!state.chats.length) { state.chats = [makeChat([])]; }
      if (!get(state.active)) { state.active = api.chats()[0].id; }
      emit();
    },
    clearAll: function () { state.chats = [makeChat([])]; state.active = state.chats[0].id; emit(); },
    // the greeting and connection errors are shown but never stored
    ask: function (question, extra) {
      var chat = api.active();
      var id = chat.id;
      if (!question || sending[id]) { return; }
      var prior = chat.msgs.slice(-6).map(function (m) { return { role: m.who === 'user' ? 'user' : 'assistant', text: m.text.slice(0, 500) }; });
      chat.msgs.push({ who: 'user', text: question });
      if (chat.msgs.length > MAX_MSGS) { chat.msgs = chat.msgs.slice(-MAX_MSGS); }
      chat.title = titleFrom(chat.msgs);
      chat.updated = now();
      sending[id] = true;
      emit();
      S.api.post('/api/bot/ask', { question: question, history: prior }, 'bot').then(function (data) {
        sending[id] = false;
        var c = get(id);
        if (c) {
          c.msgs.push({ who: 'bot', text: (data && data.answer) ? data.answer : "I'm not sure - try asking about alerts, rules or coverage." });
          c.updated = now();
        }
        emit();
        if (extra && extra.onAnswer) { extra.onAnswer(); }
      }).catch(function () {
        sending[id] = false;
        var c = get(id);
        if (c) { c.msgs.push({ who: 'bot', text: 'Connection error - try again in a moment.', transient: true }); }
        emit();
      });
    }
  };

  // transient messages (errors) are not persisted
  var rawSave = save;
  save = function () {
    var copy = { active: state.active, chats: state.chats.map(function (c) {
      return { id: c.id, title: c.title, updated: c.updated, msgs: c.msgs.filter(function (m) { return !m.transient; }) };
    }) };
    try { window.localStorage.setItem(KEY, JSON.stringify(copy)); } catch (e) { }
  };

  load();
  S.wolf = api;
})();
