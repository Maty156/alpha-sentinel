// ============================================================
// ALPHA SENTINEL v2 — Embedded Web Dashboard
// Served by AlphaSentinel.ps1 on http://0.0.0.0:8443 (or -Port).
// Pure vanilla HTML/CSS/JS — no CDN, works on an isolated DC.
// ============================================================
'use strict';

const SEV_COLORS = { Critical: '#e8483f', High: '#d6883a', Medium: '#e8c93a', Low: '#4ade80' };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

let alerts = [];
// selfTest: 'hide' (default) | 'only' | 'all' - synthetic [SELF-TEST] rows are
// demo data, so they are kept out of the tiles and the table unless asked for
let filters = { severity: 'all', status: 'all', q: '', selfTest: 'hide' };
let autoRefresh = true;
// ack state lives on the SERVER (persisted in sentinel-history.csv, survives
// restarts and is shared across every browser) — no browser-side copy

function esc(str) {
  const div = document.createElement('div');
  div.textContent = String(str == null ? '' : str);
  return div.innerHTML;
}
function escAttr(str) { return esc(str).replace(/"/g, '&quot;'); }

// MITRE technique reference URL from a catalog string like
// "T1110.003 - Brute Force: Password Spraying" → attack.mitre.org/techniques/T1110/003/
function mitreUrl(technique) {
  if (!technique) return null;
  const match = String(technique).match(/T\d{4}(?:\.\d{3})?/);
  if (!match) return null;
  const id = match[0];
  const [base, sub] = id.split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// The server protects every /api route with a session cookie. The cookie is
// HttpOnly and same-origin, so the browser attaches it automatically and this
// script never handles any credential.
async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) {
    // session expired (8h absolute, 30 min idle) or was never established
    window.location.replace('/');
    throw new Error('Not signed in.');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ---------- stats ----------
function renderStats() {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  let open = 0, ackCount = 0;
  const base = alerts.filter(a => !a.selfTest);
  base.forEach(a => {
    if (counts[a.severity] != null) counts[a.severity]++;
    if (a.acknowledged) ackCount++; else open++;
  });
  const set = (id, val) => { document.getElementById(id).textContent = val; };
  set('statCritical', counts.Critical);
  set('statHigh', counts.High);
  set('statMedium', counts.Medium);
  set('statLow', counts.Low);
  set('statOpen', open);
  set('statAck', ackCount);
  document.getElementById('statTotal').textContent = base.length;
  const selfTestCount = alerts.length - base.length;
  const tile = document.getElementById('statTotalLabel');
  if (tile) tile.textContent = selfTestCount > 0 ? `Total (${selfTestCount} self-test hidden)` : 'Total';
}

// ---------- alert table ----------
function visibleAlerts() {
  let list = [...alerts];
  if (filters.selfTest === 'hide') list = list.filter(a => !a.selfTest);
  else if (filters.selfTest === 'only') list = list.filter(a => a.selfTest);
  if (filters.severity !== 'all') list = list.filter(a => a.severity === filters.severity);
  if (filters.status !== 'all') {
    list = list.filter(a => (filters.status === 'acknowledged') ? !!a.acknowledged : !a.acknowledged);
  }
  if (filters.q) {
    const q = filters.q.toLowerCase();
    list = list.filter(a =>
      `${a.title} ${a.rule || ''} ${a.mitre || ''} ${a.account || ''} ${a.host || ''} ${a.description || ''}`
        .toLowerCase().includes(q));
  }
  list.sort((a, b) => {
    const t = new Date(b.time || 0) - new Date(a.time || 0);
    if (t !== 0) return t;
    return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
  });
  return list;
}

function renderTable() {
  const tbody = document.getElementById('alertRows');
  const list = visibleAlerts();
  const emptyEl = document.getElementById('tableEmpty');
  if (!list.length) {
    tbody.innerHTML = '';
    emptyEl.style.display = 'flex';
    document.getElementById('filterInfo').textContent = alerts.length
      ? `${alerts.length} alerts match your filters.` : '';
    return;
  }
  emptyEl.style.display = 'none';
  document.getElementById('filterInfo').textContent = `${list.length} of ${alerts.length} alerts`;
  tbody.innerHTML = list.map(a => {
    const isAck = !!a.acknowledged;
    const status = a.status || 'New';
    const statusPill = status !== 'New'
      ? ` <span class="status-pill ${status.toLowerCase().replace(/\s+/g, '-')}">${esc(status)}</span>`
      : '';
    return `
      <tr data-id="${escAttr(String(a.id))}" class="${isAck ? 'row-ack' : ''}">
        <td class="cell-time">${fmtTime(a.time)}</td>
        <td><span class="sev-badge" style="background:${SEV_COLORS[a.severity] || '#888'}22; color:${SEV_COLORS[a.severity] || '#ccc'}; border-color:${SEV_COLORS[a.severity] || '#888'}55;">${esc(a.severity || 'Unknown')}</span></td>
        <td class="cell-title">${esc(a.title)}${isAck ? ' <span class="ack-tag">ACK</span>' : ''}${statusPill}${a.selfTest ? ' <span class="selftest-tag">SELF-TEST</span>' : ''}</td>
        <td class="cell-mono">${esc(a.account || '—')}</td>
        <td class="cell-mono">${esc(a.host || '—')}</td>
        <td class="cell-mono">${esc(a.mitre || '—')}</td>
        <td><button type="button" class="row-ack-btn" data-ack="${escAttr(String(a.id))}">${isAck ? 'Unack' : 'Ack'}</button></td>
      </tr>`;
  }).join('');

  tbody.querySelectorAll('tr[data-id]').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('.row-ack-btn')) return;
      tbody.querySelectorAll('tr').forEach(r => r.classList.remove('row-selected'));
      row.classList.add('row-selected');
      const a = alerts.find(x => String(x.id) === String(row.dataset.id));
      if (a) renderDetail(a);
    });
  });
  tbody.querySelectorAll('[data-ack]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.ack;
      const a = alerts.find(x => String(x.id) === String(id));
      if (!a) return;
      try {
        if (a.acknowledged) {
          await api(`/alerts/${id}/unack`, { method: 'POST' });
        } else {
          await api(`/alerts/${id}/ack`, { method: 'POST' });
        }
        await refresh(true);
      } catch (err) { showToast(err.message, 'error'); }
    });
  });
}

function renderDetail(a) {
  const el = document.getElementById('detailBody');
  document.getElementById('detailEmpty').style.display = 'none';
  el.style.display = 'block';

  const url = mitreUrl(a.mitre);
  const mitreCell = url
    ? `<a class="mitre-link" href="${url}" target="_blank" rel="noopener noreferrer">${esc(a.mitre)}</a>`
    : esc(a.mitre || '—');

  el.innerHTML = `
    <div class="detail-head">
      <span class="sev-badge sev-lg" style="background:${SEV_COLORS[a.severity] || '#888'}22; color:${SEV_COLORS[a.severity] || '#ccc'}; border-color:${SEV_COLORS[a.severity] || '#888'}55;">${esc(a.severity || 'Unknown')}</span>
      <span class="detail-time">${fmtDate(a.time)}</span>
    </div>
    <h3>${esc(a.title)}</h3>
    <div class="detail-grid">
      <div><label>MITRE ATT&amp;CK</label><span class="cell-mono">${mitreCell}</span></div>
      <div><label>Rule</label><span class="cell-mono">${esc(a.rule || '—')}</span></div>
      <div><label>Event ID</label><span class="cell-mono">${esc(a.eventId || '—')}</span></div>
      <div><label>Host</label><span class="cell-mono">${esc(a.host || '—')}</span></div>
      <div><label>Account</label><span class="cell-mono">${esc(a.account || '—')}</span></div>
      <div><label>Source IP</label><span class="cell-mono">${esc(a.sourceIp || '—')}</span></div>
    </div>
    <label class="detail-label">What happened</label>
    <p class="detail-desc">${esc(a.description || 'No description.')}</p>
    <label class="detail-label">Remediation</label>
    <p class="detail-rem">${esc(a.remediation || 'No remediation guidance for this rule.')}</p>

    <label class="detail-label">Investigation</label>
    <div class="triage-row">
      <select id="detailStatus">
        ${['New', 'Investigating', 'Resolved', 'False Positive'].map(s => `<option value="${s}"${a.status === s ? ' selected' : ''}>${s}</option>`).join('')}
      </select>
      <button type="button" class="btn" id="detailSaveBtn">Save triage</button>
      <span class="saved-flag" id="detailSaved" style="display:none;">saved &#10003;</span>
    </div>
    <textarea class="triage-notes" id="detailNotes" placeholder="Investigation notes — what you checked, what you found, what you did. Saved to sentinel-history.csv.">${esc(a.notes || '')}</textarea>
  `;

  document.getElementById('detailSaveBtn').addEventListener('click', async () => {
    const status = document.getElementById('detailStatus').value;
    const notes = document.getElementById('detailNotes').value;
    const btn = document.getElementById('detailSaveBtn');
    btn.disabled = true;
    try {
      await api(`/alerts/${a.id}/status`, { method: 'POST', body: JSON.stringify({ status, notes }) });
      // `a` is the same object held in `alerts`, so the row re-renders with the
      // new triage state without a round trip
      a.status = status;
      a.notes = notes;
      renderTable();
      const flag = document.getElementById('detailSaved');
      flag.style.display = 'inline';
      setTimeout(() => { flag.style.display = 'none'; }, 2500);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });
}

// ---------- toast ----------
let toastTimer = null;
function showToast(message, kind = 'info') {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = `toast show toast-${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 3500);
}

// ---------- data refresh ----------
async function refresh(silent = false) {
  try {
    const data = await api('/alerts');
    const prevCount = alerts.length;
    // server returns a BARE ARRAY of alerts with PascalCase keys
    alerts = (Array.isArray(data) ? data : (data.alerts || [])).map(a => ({
      id: a.Id, time: a.Time, severity: a.Severity, title: a.Title,
      rule: a.Rule, mitre: a.Mitre, remediation: a.Remediation,
      description: a.Description, host: a.Host, account: a.Account,
      sourceIp: a.SourceIp, eventId: a.EventId, acknowledged: !!a.Acknowledged,
      status: a.Status || 'New', notes: a.Notes || '',
      selfTest: !!a.SelfTest,
    }));
    renderStats();
    renderTable();
    document.getElementById('lastCheck').textContent = `Last checked ${new Date().toLocaleTimeString()}`;
    if (!silent && alerts.length > prevCount) {
      showToast(`${alerts.length - prevCount} new alert${alerts.length - prevCount > 1 ? 's' : ''}`, 'success');
    }
  } catch (err) {
    if (!silent) showToast(`Failed to refresh: ${err.message}`, 'error');
    document.getElementById('lastCheck').textContent = `Refresh failed — retrying…`;
  }
}

// ---------- detection coverage ----------
// Renders the rule catalog straight from the monitor (GET /api/rules), so the
// dashboard shows what the engine actually detects — not a hardcoded list in
// the HTML that can drift away from the rules in the script.
let rules = [];
let ruleFilters = { severity: 'all', q: '', firedOnly: false };
let coverageLoaded = false;

// A family whose audit subcategory is switched off is the "quietly never
// fires" case: show it in the coverage table instead of leaving it looking
// healthy next to the rules that work.
function auditBadge(r) {
  if (r.auditState === 'blind') return ` <span class="audit-pill blind" title="${escAttr(r.auditDetail || 'events not being written - audit policy is off')}">BLIND</span>`;
  if (r.auditState === 'unknown') return ` <span class="audit-pill unknown" title="${escAttr(r.auditDetail || 'audit policy could not be read - run as Administrator')}">?</span>`;
  return '';
}

function renderCoverage() {
  const tbody = document.getElementById('ruleRows');
  const list = rules.filter(r => {
    if (ruleFilters.severity !== 'all' && r.severity !== ruleFilters.severity) return false;
    if (ruleFilters.firedOnly && !(r.fired > 0)) return false;
    if (ruleFilters.q) {
      const q = ruleFilters.q.toLowerCase();
      const hay = `${r.title} ${r.key} ${r.mitre} ${r.category} ${(r.eventIds || []).join(' ')} ${r.description || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="cell-mono" style="padding:24px;text-align:center;">No rule families match your filter.</td></tr>';
    document.getElementById('ruleInfo').textContent = '';
    return;
  }

  document.getElementById('ruleInfo').textContent = `${list.length} of ${rules.length} rule families shown`;
  tbody.innerHTML = list.map(r => {
    const color = SEV_COLORS[r.severity] || '#888';
    const meta = `${(r.eventIds || []).join(', ')} · dedupe ${r.dedupeMinutes}m`;
    return `
      <tr style="cursor:default;">
        <td>
          <span class="cov-rule">${esc(r.title)}${auditBadge(r)}</span>
          <span class="cov-key">${esc(r.key)} — ${esc(meta)}</span>
        </td>
        <td><span class="sev-badge" style="background:${color}22; color:${color}; border-color:${color}55;">${esc(r.severity)}</span></td>
        <td class="cell-mono">${esc((r.eventIds || []).join(', '))}</td>
        <td class="cov-mitre">${esc(r.mitre)}</td>
        <td class="cov-cat">${esc(r.category)}</td>
        <td><span class="fired-tag ${r.fired > 0 ? 'hit' : ''}">${r.fired > 0 ? `${r.fired}×` : '—'}</span></td>
      </tr>`;
  }).join('');
}

async function loadCoverage() {
  try {
    const data = await api('/rules');
    rules = data.rules || [];
    const blind = data.auditBlind || 0;
    document.getElementById('coverageSummary').textContent =
      `${data.total} rule families · ${data.firedTotal} fired · ${(data.monitoredEventIds || []).length} event IDs monitored` +
      (blind > 0 ? ` · ${blind} BLIND (audit policy off)` : '');
    coverageLoaded = true;
    renderCoverage();
  } catch (err) {
    document.getElementById('coverageSummary').textContent = `could not load rule catalog — ${err.message}`;
  }
  // audit-policy preflight: which families this host is not even logging
  try {
    preflight = await api('/preflight');
    renderPreflight();
  } catch (err) { preflight = null; renderPreflight(); }
}

// ---------- audit-policy preflight ----------
// The panel that answers "why is this rule not firing?" before you go hunting a
// bug in the rule: Windows only writes an event if its Advanced Audit
// subcategory is enabled.
let preflight = null;

function renderPreflight() {
  const banner = document.getElementById('auditBanner');
  const body = document.getElementById('auditBannerBody');
  if (!banner || !body) return;
  if (!preflight) { banner.style.display = 'none'; return; }
  if (!preflight.readable) {
    banner.className = 'audit-banner warn';
    body.innerHTML = '<strong>Audit policy could not be read.</strong> Run Sentinel as Administrator ' +
      'to check whether each rule family is actually being logged on this host.';
  } else if (preflight.blindCount > 0) {
    banner.className = 'audit-banner danger';
    const items = (preflight.blind || []).map(b =>
      `<li><span class="cell-mono">${esc(b.key)}</span> needs <em>${esc(b.need)}</em> on "${esc(b.subcategory)}"</li>`).join('');
    const fixes = (preflight.fix || []).map(f => `<code>${esc(f)}</code>`).join('<br>');
    body.innerHTML = `<strong>${preflight.blindCount} of ${preflight.rulesTotal} rule families are blind on this host.</strong>
      Windows is not writing the events they need, so they cannot fire whatever the rule says:
      <ul class="audit-list">${items}</ul>
      <div class="detail-label">Run these as Administrator to enable them</div>
      <div class="audit-fix">${fixes}</div>`;
  } else {
    banner.className = 'audit-banner ok';
    body.innerHTML = `<strong>Audit policy covers every rule family.</strong> ${preflight.okCount} policy-gated families can fire; ${preflight.naCount} are not gated by audit policy.`;
  }
  banner.style.display = 'block';
}

// ---------- wire up ----------
// ---------- session ----------
async function loadSession() {
  try {
    const data = await api('/session');
    const el = document.getElementById('sessionUser');
    if (el) el.innerHTML = 'signed in as <strong>' + esc(data.user) + '</strong>';
  } catch (err) {
    // api() already redirected to the sign-in page on 401
  }
}

// ---------- tool health: poll lag and error counters ----------
// "lag" is how far behind the OLDEST log channel is. If it climbs, Sentinel is
// not keeping up and detections are the thing that suffers, so it is shown
// rather than buried in an endpoint.
let healthState = null;

// Same rule as the server's Get-CatchUpState. An IDLE monitor carries lag by
// design - it polls every `pollSeconds`, and the watermark is deliberately
// backdated 5s for overlap - so the old two-second lag test reported a perfectly
// healthy idle system as "catching up" forever. Real catch-up means the server had to
// defer events, or the lag has passed two whole poll intervals plus the overlap.
// The server sends the verdict; the fallback mirrors the formula for an older
// payload.
function catchUpThreshold(health) {
  const poll = health.pollSeconds || 15;
  return (poll * 2) + 5;
}

function isCatchingUp(health) {
  if (typeof health.catchingUp === 'boolean') return health.catchingUp;
  return (health.lagSeconds || 0) > catchUpThreshold(health);
}

function renderHealth() {
  const pill = document.getElementById('healthPill');
  if (!pill || !healthState) return;
  const lag = healthState.lagSeconds || 0;
  const evalErrors = healthState.evalErrors || 0;
  const pollErrors = healthState.pollErrors || 0;
  const catchingUp = isCatchingUp(healthState);
  const parts = [];
  if (catchingUp) parts.push(`catching up: ${lag}s behind`);
  if (evalErrors > 0) parts.push(`${evalErrors} event(s) skipped (malformed)`);
  if (pollErrors > 0) parts.push(`${pollErrors} failed log read(s)`);
  if (!parts.length) {
    pill.textContent = 'up to date';
    pill.className = 'health-pill ok';
  } else {
    pill.textContent = parts.join(' - ');
    pill.className = 'health-pill ' + ((lag > 120 || pollErrors > 0) ? 'danger' : 'warn');
  }
  pill.style.display = 'inline-flex';
  pill.title = `oldest channel ${lag}s behind (catching up past ${catchUpThreshold(healthState)}s`
    + `${healthState.lastPollCapped ? ', or any deferred poll' : ''}) - `
    + `evalErrors ${evalErrors} - pollErrors ${pollErrors}`;
}

async function refreshHealth() {
  try {
    // /api/status, not /api/health: the health probe now answers only
    // {"ok":true} so an unauthenticated caller learns nothing but that the port
    // is open. The counters live on the authenticated status route.
    healthState = await api('/status');
    renderHealth();
  } catch (err) {
    // best effort: the alert feed is what matters
  }
}

function updateSelfTestToggle() {
  const btn = document.getElementById('selfTestToggle');
  if (!btn) return;
  btn.textContent = filters.selfTest === 'hide' ? 'Self-test: hidden'
    : (filters.selfTest === 'all' ? 'Self-test: shown' : 'Self-test: only');
  btn.classList.toggle('active', filters.selfTest !== 'hide');
}

document.addEventListener('DOMContentLoaded', () => {
  updateSelfTestToggle();
  document.querySelectorAll('[data-sev-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      filters.severity = btn.dataset.sevFilter;
      document.querySelectorAll('[data-sev-filter]').forEach(b => b.classList.toggle('active', b === btn));
      renderTable();
    });
  });

  document.getElementById('statusFilter').addEventListener('change', e => {
    filters.status = e.target.value;
    renderTable();
  });
  document.getElementById('searchInput').addEventListener('input', e => {
    filters.q = e.target.value.trim();
    renderTable();
  });

  document.getElementById('exportBtn').addEventListener('click', () => {
    window.location.href = '/api/export.csv';
  });

  document.getElementById('autoRefreshToggle').addEventListener('change', e => {
    autoRefresh = e.target.checked;
  });
  document.getElementById('refreshBtn').addEventListener('click', () => { refresh(false); refreshHealth(); });

  document.getElementById('logoutBtn').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Signing out...';
    try { await api('/logout', { method: 'POST' }); } catch (err) { /* already gone */ }
    window.location.replace('/');
  });

  // ---- self-test: fire one synthetic event per rule family ----
  document.getElementById('selfTestBtn').addEventListener('click', async e => {
    const btn = e.currentTarget;
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = 'Running…';
    try {
      const result = await api('/self-test', { method: 'POST' });
      filters.selfTest = 'all';
      updateSelfTestToggle();
      await refresh(true);
      await loadCoverage();
      showToast(`Self-test: ${result.alertsFired} alerts fired across ${result.rulesExercised} of ${result.ruleFamiliesTotal} rule families (tagged SELF-TEST, excluded from coverage counts and exports)`, 'success');
    } catch (err) {
      showToast(`Self-test failed — ${err.message}`, 'error');
    } finally {
      btn.innerHTML = original;
      btn.disabled = false;
    }
  });

  document.getElementById('coverageExportBtn').addEventListener('click', () => {
    window.location.href = '/api/coverage.csv';
  });

  // ---- self-test rows: hide / only / all ----
  document.getElementById('selfTestToggle').addEventListener('click', () => {
    filters.selfTest = filters.selfTest === 'hide' ? 'all' : (filters.selfTest === 'all' ? 'only' : 'hide');
    updateSelfTestToggle();
    renderStats();
    renderTable();
  });

  document.getElementById('preflightRefreshBtn').addEventListener('click', async e => {
    const btn = e.currentTarget;
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Checking...';
    try {
      preflight = await api('/preflight/refresh', { method: 'POST' });
      renderPreflight();
      const data = await api('/rules');
      rules = data.rules || [];
      renderCoverage();
      const blind = (preflight && preflight.blindCount) || 0;
      showToast(blind > 0 ? `Audit policy re-checked - ${blind} rule families are blind` : 'Audit policy re-checked - full coverage', blind > 0 ? 'error' : 'success');
    } catch (err) {
      showToast(`Audit check failed - ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });

  // ---- detection coverage panel ----
  document.getElementById('coverageBar').addEventListener('click', () => {
    const open = document.getElementById('coverageBody').classList.toggle('open');
    document.getElementById('coverageBar').classList.toggle('open', open);
    if (open && !coverageLoaded) loadCoverage();
  });
  document.getElementById('coverageBar').classList.add('open');
  document.getElementById('coverageBody').classList.add('open');

  document.querySelectorAll('[data-rule-sev]').forEach(btn => {
    btn.addEventListener('click', () => {
      ruleFilters.severity = btn.dataset.ruleSev;
      document.querySelectorAll('[data-rule-sev]').forEach(b => b.classList.toggle('active', b === btn));
      renderCoverage();
    });
  });
  document.getElementById('ruleFiredToggle').addEventListener('click', e => {
    ruleFilters.firedOnly = !ruleFilters.firedOnly;
    e.target.classList.toggle('active', ruleFilters.firedOnly);
    renderCoverage();
  });
  document.getElementById('ruleSearch').addEventListener('input', e => {
    ruleFilters.q = e.target.value.trim();
    renderCoverage();
  });

  setInterval(() => {
    if (autoRefresh) { refresh(true); refreshHealth(); }
  }, 10000);
  loadSession();
  refresh(false);
  refreshHealth();
  loadCoverage();
});
