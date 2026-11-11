/* pages/bot.js - OWNER: the floating Wolf assistant.
   A small always-on widget, pinned bottom-right on every dashboard page -
   not a routed page. Answers natural-language questions about alerts,
   detection coverage, active detections, and triage using the dashboard's
   own API data. No external LLM needed - the backend reads from the live
   alert/rule state and answers from that (see /api/bot/ask).
*/
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  var mounted = false;
  var panelOpen = false;
  var sending = false;

  // ---- small DOM helper -------------------------------------------------
  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      if (k === 'style') { n.setAttribute('style', attrs[k]); }
      else if (k === 'class') { n.className = attrs[k]; }
      else if (k === 'text') { n.textContent = attrs[k]; }
      else { n.setAttribute(k, attrs[k]); }
    });
    (children || []).forEach(function (c) { if (c) { n.appendChild(c); } });
    return n;
  }

  // ---- build the floating toggle + panel once ---------------------------
  function mount() {
    if (mounted) { return; }
    mounted = true;

    var toggle = el('button', {
      id: 'sentinel-bot-toggle',
      type: 'button',
      title: 'Ask Wolf - AD security assistant',
      'aria-label': 'Open Wolf assistant',
      style: [
        'position:fixed', 'bottom:24px', 'right:24px', 'z-index:2000',
        'width:56px', 'height:56px', 'border-radius:50%',
        'display:flex', 'align-items:center', 'justify-content:center',
        'font-size:26px', 'line-height:1', 'cursor:pointer',
        'background:linear-gradient(145deg, var(--brand), var(--brand-dim))',
        'color:#fff', 'border:1px solid var(--line-2)',
        'box-shadow:0 10px 30px rgba(0,0,0,.55), 0 0 0 4px var(--brand-soft)',
        'transition:transform .15s ease, box-shadow .15s ease',
      ].join(';'),
    }, [document.createTextNode('🐺')]);
    toggle.addEventListener('mouseenter', function () { toggle.style.transform = 'scale(1.06)'; });
    toggle.addEventListener('mouseleave', function () { toggle.style.transform = 'scale(1)'; });
    toggle.addEventListener('click', function () { setOpen(!panelOpen); });

    var badge = el('span', {
      id: 'sentinel-bot-badge', style: [
        'position:fixed', 'bottom:66px', 'right:18px', 'z-index:2001',
        'background:var(--sev-critical)', 'color:#fff', 'font-size:10px',
        'font-weight:700', 'padding:1px 5px', 'border-radius:999px',
        'display:none', 'box-shadow:0 0 0 2px var(--bg-0)',
      ].join(';'), text: '1',
    });

    var panel = el('div', {
      id: 'sentinel-bot-panel', role: 'dialog', 'aria-label': 'Wolf assistant',
      style: [
        'position:fixed', 'bottom:90px', 'right:24px', 'z-index:2000',
        'width:340px', 'max-width:calc(100vw - 32px)', 'height:440px',
        'max-height:calc(100vh - 120px)', 'display:none', 'flex-direction:column',
        'background:var(--surface-glass)', 'backdrop-filter:blur(18px)',
        '-webkit-backdrop-filter:blur(18px)', 'border:1px solid var(--line)',
        'border-radius:var(--radius)', 'box-shadow:var(--shadow)',
        'overflow:hidden', 'font-family:var(--font)', 'font-size:13px',
      ].join(';'),
    });

    var header = el('div', {
      style: [
        'display:flex', 'align-items:center', 'justify-content:space-between',
        'padding:12px 14px', 'border-bottom:1px solid var(--line)',
        'background:var(--surface-card)',
      ].join(';'),
    }, [
      el('div', { style: 'display:flex;align-items:center;gap:8px;' }, [
        el('span', { style: 'font-size:18px;' , text: '🐺' }),
        el('div', {}, [
          el('div', { style: 'color:var(--text);font-weight:600;font-size:13px;', text: 'Wolf' }),
          el('div', { style: 'color:var(--text-mute);font-size:11px;', text: 'AD security assistant' }),
        ]),
      ]),
      el('button', {
        type: 'button', 'aria-label': 'New chat', title: 'Start a new chat', id: 'sentinel-bot-clear',
        style: 'background:none;border:none;color:var(--text-mute);font-size:12px;cursor:pointer;padding:4px;margin-left:auto;margin-right:2px',
      }, [document.createTextNode('+ New')]),
      el('button', {
        type: 'button', 'aria-label': 'Open Wolf page', title: 'Open the Wolf page (all chats)', id: 'sentinel-bot-open',
        style: 'background:none;border:none;color:var(--text-mute);font-size:12px;cursor:pointer;padding:4px;margin-right:2px',
      }, [document.createTextNode('All chats')]),
      el('button', {
        type: 'button', 'aria-label': 'Expand', title: 'Full screen', id: 'sentinel-bot-expand',
        style: 'background:none;border:none;color:var(--text-mute);font-size:16px;line-height:1;cursor:pointer;padding:4px;margin-right:4px',
      }, [document.createTextNode('\u2922')]),
      el('button', {
        type: 'button', 'aria-label': 'Close', title: 'Close',
        style: [
          'background:none', 'border:none', 'color:var(--text-mute)',
          'font-size:18px', 'line-height:1', 'cursor:pointer', 'padding:4px',
        ].join(';'),
        onclick: '',
      }, [document.createTextNode('×')]),
    ]);
    var expandBtn = header.querySelector('#sentinel-bot-expand');
    header.querySelector('#sentinel-bot-clear').addEventListener('click', function () { S.wolf.newChat(); });
    header.querySelector('#sentinel-bot-open').addEventListener('click', function () { setOpen(false); window.location.hash = '#/wolf'; });
    header.querySelector('button[aria-label="Close"]').addEventListener('click', function () { setOpen(false); });
    var big = false;
    function setBig(next) {
      big = next;
      if (big) {
        panel.style.width = 'min(1000px, calc(100vw - 32px))';
        panel.style.height = 'calc(100vh - 32px)';
        panel.style.maxHeight = 'calc(100vh - 32px)';
        panel.style.bottom = '16px'; panel.style.right = '16px';
        panel.style.fontSize = '15px';
        expandBtn.textContent = '\u2921'; expandBtn.title = 'Shrink';
      } else {
        panel.style.width = '340px'; panel.style.height = '440px';
        panel.style.maxHeight = 'calc(100vh - 120px)';
        panel.style.bottom = '90px'; panel.style.right = '24px';
        panel.style.fontSize = '13px';
        expandBtn.textContent = '\u2922'; expandBtn.title = 'Full screen';
      }
      try { window.localStorage.setItem('wolf-big', big ? '1' : '0'); } catch (e) { }
    }
    expandBtn.addEventListener('click', function () { setBig(!big); });
    try { if (window.localStorage.getItem('wolf-big') === '1') { setBig(true); } } catch (e) { }

    var chat = el('div', {
      class: 'sentinel-bot-chat', 'aria-live': 'polite',
      style: [
        'flex:1', 'overflow-y:auto', 'padding:12px 12px 4px',
        'display:flex', 'flex-direction:column', 'gap:8px',
        'background:transparent', 'font-size:inherit', 'color:var(--text)',
      ].join(';'),
    });

    var inputRow = el('div', {
      style: [
        'display:flex', 'gap:8px', 'padding:10px 12px', 'border-top:1px solid var(--line)',
        'background:var(--surface-card)',
      ].join(';'),
    });
    var input = el('input', {
      type: 'text', placeholder: S.wolf.placeholder,
      style: [
        'flex:1', 'min-width:0', 'padding:8px 10px', 'border-radius:var(--radius-sm)',
        'border:1px solid var(--line-2)', 'background:var(--bg-2)', 'color:var(--text)',
        'font-size:13px', 'outline:none',
      ].join(';'),
    });
    input.addEventListener('keypress', function (e) {
      if (e.key === 'Enter') { submit(); }
    });
    var sendBtn = el('button', {
      type: 'button', title: 'Send', 'aria-label': 'Send',
      style: [
        'width:36px', 'border-radius:var(--radius-sm)', 'border:none', 'cursor:pointer',
        'background:var(--brand)', 'color:#fff', 'font-size:15px',
      ].join(';'),
    }, [document.createTextNode('➤')]);
    sendBtn.addEventListener('click', submit);

    inputRow.appendChild(input);
    inputRow.appendChild(sendBtn);

    panel.appendChild(header);
    panel.appendChild(chat);
    panel.appendChild(inputRow);

    document.body.appendChild(toggle);
    document.body.appendChild(badge);
    document.body.appendChild(panel);

    function syncRoute() {
      var onPage = (window.location.hash === '#/wolf');
      toggle.style.display = onPage ? 'none' : 'flex';
      if (onPage) { setOpen(false); badge.style.display = 'none'; }
    }
    window.addEventListener('hashchange', syncRoute);
    syncRoute();

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && panelOpen) { setOpen(false); }
    });

    function submit() {
      var q = input.value.trim();
      if (!q || sending) { return; }
      input.value = '';
      ask(q);
    }

    function setOpen(next) {
      panelOpen = next;
      panel.style.display = next ? 'flex' : 'none';
      if (next) {
        badge.style.display = 'none';
        input.focus();
      }
    }

    function greet() {
      appendBubble('bot', S.wolf.greeting);
    }

    function appendBubble(who, text) {
      var isUser = who === 'user';
      var row = el('div', { style: 'display:flex;' + (isUser ? 'justify-content:flex-end;' : 'justify-content:flex-start;') });
      var bubble = el('div', {
        style: [
          'max-width:84%','font-size:inherit', 'padding:8px 10px', 'border-radius:12px',
          'line-height:1.4', 'white-space:pre-wrap', 'word-break:break-word',
          isUser
            ? 'background:var(--brand);color:#fff;border-bottom-right-radius:3px;'
            : 'background:var(--bg-2);color:var(--text);border:1px solid var(--line);border-bottom-left-radius:3px;',
        ].join(';'),
        text: text,
      });
      row.appendChild(bubble);
      chat.appendChild(row);
      chat.scrollTop = chat.scrollHeight;
    }

    function appendTyping() {
      var row = el('div', { id: 'sentinel-bot-typing', style: 'display:flex;justify-content:flex-start;' });
      var bubble = el('div', {
        style: [
          'padding:8px 10px', 'border-radius:12px', 'border-bottom-left-radius:3px',
          'background:var(--bg-2)', 'color:var(--text-mute)', 'border:1px solid var(--line)',
          'font-size:13px',
        ].join(';'),
        text: '…',
      });
      row.appendChild(bubble);
      chat.appendChild(row);
      chat.scrollTop = chat.scrollHeight;
    }

    function removeTyping() {
      var t = document.getElementById('sentinel-bot-typing');
      if (t) { t.remove(); }
    }

    function ask(question) {
      S.wolf.ask(question, { onAnswer: function () { if (!panelOpen) { badge.style.display = 'flex'; } } });
    }

    // paint the active chat from the shared store (also reacts to the Wolf page)
    function paint() {
      S.ui.clear(chat);
      var c = S.wolf.active();
      if (!c.msgs.length) { greet(); }
      c.msgs.forEach(function (m) { appendBubble(m.who, m.text); });
      if (S.wolf.isSending()) { appendTyping(); }
      chat.scrollTop = chat.scrollHeight;
    }
    S.wolf.subscribe(paint);
    paint();
  }

  S.pages.bot = { mount: mount };
})();
