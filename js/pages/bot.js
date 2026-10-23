/* pages/bot.js - OWNER: the floating Wolf bot / AI assistant.
   Answers natural-language questions about alerts, detection coverage,
   active detections, and triage using the dashboard's own API data.
   No external LLM needed — reads from /api/overview, /api/status,
   /api/alerts, /api/rules, /api/assets.
*/
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  // ---- bot state -------------------------------------------------------
  var botSocket = null;        // could be SSE later; for now use polling
  var pollInterval = null;
  var lastBotAnswer = '';

  // ---- render the bot UI into the page -------------------------------
  function renderBotUI() {
    // Remove any previous bot DOM if re-rendering
    var existing = document.getElementById('sentinel-bot');
    if (existing) { existing.remove(); }

    // Floating toggle button (bottom-right)
    var toggle = document.createElement('div');
    toggle.id = 'sentinel-bot-toggle';
    toggle.innerHTML = '🐺 Wolf';
    toggle.title = 'Open Wolf bot';
    Object.assign(toggle.style, {
      position: 'fixed',
      bottom: '24px',
      right: '24px',
      zIndex: '9999',
      background: '#dc2626',
      color: 'white',
      width: '64px',
      height: '64px',
      borderRadius: '50%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: '1.8rem',
      cursor: 'pointer',
      boxShadow: '0 4px 12px rgba(0,0,0,.15)',
      userSelect: 'none',
    });
    toggle.onclick = function () {
      var panel = document.getElementById('sentinel-bot-panel');
      if (panel) {
        panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
      } else {
        openBotPanel();
      }
    };
    document.body.appendChild(toggle);

    // Panel (initially hidden)
    var panel = document.createElement('div');
    panel.id = 'sentinel-bot-panel';
    panel.style.display = 'none';
    Object.assign(panel.style, {
      position: 'fixed',
      bottom: '96px',
      right: '24px',
      width: '320px',
      maxHeight: '400px',
      background: 'white',
      borderRadius: '8px',
      boxShadow: '0 4px 20px rgba(0,0,0,.15)',
      overflow: 'hidden',
      fontFamily: 'system-ui, sans-serif',
      zIndex: '9998',
    });

    // Header
    var ph = document.createElement('div');
    ph.style = 'padding: 12px 16px; background: #f1f5f9; border-bottom: 1px solid #e2e8f0;';
    ph.innerHTML = '<h4 style="margin:0; font-size:1rem;">🐺 Wolf — AD Assistant</h4>';
    panel.appendChild(ph);

    // Close button
    var closeBtn = document.createElement('button');
    closeBtn.style = 'margin:-12px -16px -8px; padding: 4px 8px; float: right; background: none; border: none; font-size: 1.2rem;';
    closeBtn.innerHTML = '×';
    closeBtn.onclick = function () { panel.style.display = 'none'; };
    ph.appendChild(closeBtn);

    // Chat area
    var chat = document.createElement('div');
    chat.style = 'height: 260px; overflow-y: auto; padding: 12px; background: #f8fafc; font-size: 0.95rem;';
    chat.setAttribute('aria-live', 'polite');
    panel.appendChild(chat);

    // Input area
    var inputGroup = document.createElement('div');
    inputGroup.style = 'padding: 8px 16px; border-top: 1px solid #e2e8f0; display: flex; gap: 8px;';
    var input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Ask Wolf... (try: "how many critical alerts?", "show attack chains", "what is kerberoasting")';
    input.style = 'flex: 1; padding: 6px 8px; border: 1px solid #cbd5e0; border-radius: 6px; outline: none;';
    input.onkeypress = function (e) {
      if (e.key === 'Enter' && input.value.trim()) {
        sendBotQuery(input.value.trim());
        input.value = '';
      }
    };
    inputGroup.appendChild(input);

    var sendBtn = document.createElement('button');
    sendBtn.innerHTML = '▶';
    sendBtn.style = 'padding: 0 12px; background: #2563eb; color: white; border: none; border-radius: 6px; font-size: 0.85rem;';
    sendBtn.onclick = function () {
      if (input.value.trim()) {
        sendBotQuery(input.value.trim());
        input.value = '';
      }
    };
    inputGroup.appendChild(sendBtn);

    panel.appendChild(inputGroup);
    document.body.appendChild(panel);

    // Handle escape to close
    document.onkeydown = function (e) {
      if (e.key === 'Escape' && panel.style.display !== 'none') {
        panel.style.display = 'none';
      }
    };
  }

  // ---- send a query to the backend -------------------------------------
  function sendBotQuery(query) {
    // Immediately show the user's question in the chat
    appendChatLine('You', query);

    fetch('/api/bot/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: query }),
    })
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        if (data.error) {
          appendChatLine('Wolf', 'Hmm, I had trouble with that. ' + data.error);
        } else if (data.answer) {
          appendChatLine('Wolf', data.answer);
        } else {
          appendChatLine('Wolf', "I'm not sure — try asking about alerts, rules, coverage, or attack chains.");
        }
      })
      .catch(function () {
        appendChatLine('Wolf', 'Connection error — are you signed in?');
      });
  }

  function appendChatLine(sender, text) {
    var chat = document.querySelector('#sentinel-bot-panel .chat-area');
    if (!chat) return;
    var line = document.createElement('div');
    line.style = 'margin: 6px 0;';
    var strong = document.createElement('strong');
    strong.textContent = sender + ': ';
    strong.style.fontWeight = 'bold';
    line.appendChild(strong);
    line.appendChild(document.createTextNode(text));
    chat.appendChild(line);
    // auto-scroll
    chat.scrollTop = chat.scrollHeight;
  }

  // ---- initial load: populate some quick answers ----------------------
  function bootstrapQuickAnswers() {
    // When the panel opens, we can prefetch a little data so the first answer is fast
    Promise.all([
      S.api.get('/api/overview'),
      S.api.get('/api/status'),
    ]).then(function (out) {
      // stored for use in answers if user asks before first fetch completes
      window.__botOverview = out[0];
      window.__botStatus = out[1];
    }).catch(function () {});
  }

  // ---- router: make sure /bot path works -------------------------------
  function ensureBotRoute() {
    // The router already handles hash routes; the bot panel is a floating UI
    // that sits on top of whatever page is active. No new route needed.
  }

  // ---- page render ----------------------------------------------------
  function render() {
    renderBotUI();
    bootstrapQuickAnswers();
  }

  S.pages.bot = {
    title: 'Wolf — AD Assistant',
    subtitle: 'Ask me about alerts, detection coverage, rules, and attack chains',
    render: render,
  };
})();