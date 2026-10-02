// ============================================================
// ALPHA SENTINEL v2 — Embedded Web Dashboard
// Served by AlphaSentinel.ps1 on http://0.0.0.0:8443 (or -Port).
// Pure vanilla HTML/CSS/JS — no CDN, works on an isolated DC.
// ============================================================
'use strict';

const SEV_COLORS = { Critical: '#e8483f', High: '#d6883a', Medium: '#e8c93a', Low: '#4ade80' };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

let alerts = [];
let filters = { severity: 'all', status: 'all', q: '' };
let autoRefresh = true;
// ack state lives on the SERVER (persisted in sentinel-history.csv, survives
// restarts and is shared across every browser) — no browser-side copy

function esc(str) {
  const div = document.createElement('div');
  div.textContent = String(str == null ? '' : str);
  return div.innerHTML;
}
function escAttr(str) { return esc(str).replace(/"/g, '"'); }

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

async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ---------- stats ----------
function renderStats() {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  let open = 0, ackCount = 0;
  alerts.forEach(a => {
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
  document.getElementById('statTotal').textContent = alerts.length;
}

// ---------- alert table ----------
function visibleAlerts() {
  let list = [...alerts];
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
    return `
      <tr data-id="${escAttr(String(a.id))}" class="${isAck ? 'row-ack' : ''}">
        <td class="cell-time">${fmtTime(a.time)}</td>
        <td><span class="sev-badge" style="background:${SEV_COLORS[a.severity] || '#888'}22; color:${SEV_COLORS[a.severity] || '#ccc'}; border-color:${SEV_COLORS[a.severity] || '#888'}55;">${esc(a.severity || 'Unknown')}</span></td>
        <td class="cell-title">${esc(a.title)}${isAck ? ' <span class="ack-tag">ACK</span>' : ''}</td>
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
  el.innerHTML = `
    <div class="detail-head">
      <span class="sev-badge sev-lg" style="background:${SEV_COLORS[a.severity] || '#888'}22; color:${SEV_COLORS[a.severity] || '#ccc'}; border-color:${SEV_COLORS[a.severity] || '#888'}55;">${esc(a.severity || 'Unknown')}</span>
      <span class="detail-time">${fmtDate(a.time)}</span>
    </div>
    <h3>${esc(a.title)}</h3>
    <div class="detail-grid">
      <div><label>MITRE ATT&CK</label><span class="cell-mono">${esc(a.mitre || '—')}</span></div>
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
  `;
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
    }));
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

// ---------- wire up ----------
document.addEventListener('DOMContentLoaded', () => {
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
  document.getElementById('refreshBtn').addEventListener('click', () => refresh(false));

  setInterval(() => { if (autoRefresh) refresh(true); }, 10000);
  refresh(false);
});
