/* pages/wolf.js - OWNER: the Wolf page. A full-size chat with a list of past chats
   and a "New chat" button. Shares its conversations with the floating widget
   through S.wolf (wolf-store.js). */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  var unsub = null;

  function render(view) {
    var el = S.ui.el;
    var side = el('div', { class: 'wolf-side' });
    var main = el('div', { class: 'wolf-main' });
    var msgs = el('div', { class: 'wolf-msgs', 'aria-live': 'polite' });
    var input = el('input', { class: 'wolf-input', type: 'text', placeholder: S.wolf.placeholder, autocomplete: 'off', 'aria-label': 'Message Wolf' });
    var send = el('button', { class: 'btn', type: 'button', text: 'Send' });
    var row = el('div', { class: 'wolf-inputrow' }, [input, send]);
    main.appendChild(msgs);
    main.appendChild(row);
    view.appendChild(el('div', { class: 'wolf-layout' }, [side, main]));

    function bubble(who, text) {
      return el('div', { class: 'wolf-row ' + (who === 'user' ? 'wolf-user' : 'wolf-bot') }, [el('div', { class: 'wolf-bubble', text: text })]);
    }

    var off = function () { };
    function paint() {
      if (!msgs.isConnected) { off(); return; }
      // sidebar
      S.ui.clear(side);
      var nb = el('button', { class: 'btn wolf-new', type: 'button', text: '+ New chat' });
      nb.addEventListener('click', function () { S.wolf.newChat(); input.focus(); });
      side.appendChild(nb);
      var list = el('div', { class: 'wolf-list' });
      var activeId = S.wolf.activeId();
      S.wolf.chats().forEach(function (c) {
        var item = el('div', { class: 'wolf-item' + (c.id === activeId ? ' active' : '') });
        var title = el('button', { class: 'wolf-title', type: 'button', text: c.title, title: c.title });
        title.addEventListener('click', function () { S.wolf.select(c.id); });
        var del = el('button', { class: 'wolf-del', type: 'button', text: '×', title: 'Delete this chat', 'aria-label': 'Delete chat ' + c.title });
        del.addEventListener('click', function (e) { e.stopPropagation(); S.wolf.remove(c.id); });
        item.appendChild(title);
        item.appendChild(del);
        list.appendChild(item);
      });
      side.appendChild(list);
      var hint = el('div', { class: 'wolf-hint', text: 'Chats are saved in this browser only.' });
      side.appendChild(hint);
      // messages
      S.ui.clear(msgs);
      var chat = S.wolf.active();
      if (!chat.msgs.length) { msgs.appendChild(bubble('bot', S.wolf.greeting)); }
      chat.msgs.forEach(function (m) { msgs.appendChild(bubble(m.who, m.text)); });
      if (S.wolf.isSending()) { msgs.appendChild(bubble('bot', '...')); }
      msgs.scrollTop = msgs.scrollHeight;
    }

    function submit() {
      var q = input.value.trim();
      if (!q || S.wolf.isSending()) { return; }
      input.value = '';
      S.wolf.ask(q);
    }
    send.addEventListener('click', submit);
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); submit(); } });

    off = S.wolf.subscribe(paint);
    paint();
    input.focus();
  }

  S.pages.wolf = {
    title: 'Wolf',
    subtitle: 'Ask about alerts, rules and audit coverage. Past chats are on the left.',
    render: render
  };
})();
