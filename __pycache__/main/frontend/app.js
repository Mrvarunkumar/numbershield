/**
 * NumberShield — Privacy Command Center
 * Frontend application logic
 */

/* ── Utilities ────────────────────────────────────────────────────── */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const PAGE_TITLES = {
  overview:  'Privacy Overview',
  exposure:  'Exposure Tracker',
  discovery: 'Exposure Discovery',
  consent:   'Consent Manager',
  requests:  'Privacy Requests',
  audit:     'Audit History',
};

const state = {
  services: [], consents: [], exposures: [],
  requests: [], audit: [], draft: null,
};

let toastTimer;

/* ── API helper ──────────────────────────────────────────────────── */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

/* ── String helpers ──────────────────────────────────────────────── */
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtDate(v) {
  try { return new Date(v).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); }
  catch { return v || '—'; }
}

function initials(name) {
  return (name || '?').split(/\s+/).map(x => x[0] || '').join('').slice(0, 2).toUpperCase();
}

/* ── Toast ───────────────────────────────────────────────────────── */
function toast(msg, duration = 3400) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), duration);
}

/* ── Navigation ──────────────────────────────────────────────────── */
function showView(name) {
  if (!PAGE_TITLES[name]) return;
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === name));
  $('#page-title').textContent = PAGE_TITLES[name];
  $('#bc-current').textContent = name.toUpperCase();
  $('#sidebar').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (name === 'audit') renderAudit();
}

/* ── Load all data ───────────────────────────────────────────────── */
async function loadAll() {
  const [summary, services, consents, exposure, requests, audit] = await Promise.all([
    api('/api/summary'),
    api('/api/services'),
    api('/api/consents'),
    api('/api/exposure'),
    api('/api/requests'),
    api('/api/audit'),
  ]);
  Object.assign(state, { services, consents, exposures: exposure.items, requests, audit });
  renderSummary(summary);
  renderRecentTable();
  renderConsents();
  renderExposure(exposure);
  populateServiceSelect();
  renderRequests();
  renderAudit();
}

/* ── Overview / Summary ──────────────────────────────────────────── */
function renderSummary(s) {
  $('#kv-services').textContent  = s.services_tracked;
  $('#kv-consents').textContent  = s.active_consents;
  $('#kv-exposure').textContent  = s.exposure_count;
  $('#kv-requests').textContent  = s.draft_requests;
  $('#kv-exposure-detail').textContent =
    `${s.high_severity || 0} high · ${s.medium_severity || 0} medium · ${s.low_severity || 0} low`;

  // Gauge
  $('#gauge-score').textContent = s.risk_score;
  const deg = s.risk_score * 3.6;
  const col = s.risk_score >= 60 ? 'var(--red)' : s.risk_score >= 30 ? 'var(--amber)' : 'var(--green)';
  $('#gauge').style.background = `conic-gradient(${col} ${deg}deg, #1e3250 ${deg}deg)`;
  $('#gauge-score').style.color = col;

  const badge = $('#risk-label-badge');
  badge.textContent = s.risk_label;
  badge.style.background = s.risk_score >= 60 ? 'var(--red-dim)' : s.risk_score >= 30 ? 'var(--amber-dim)' : 'var(--green-dim)';
  badge.style.color = col;
  badge.style.borderColor = col + '50';

  $('#risk-text').textContent =
    `${s.exposure_count} recorded signal(s) contribute to this demo score. ` + s.score_note;
}

function svcCell(name, note) {
  return `<div class="svc-cell">
    <div class="svc-avatar">${esc(initials(name))}</div>
    <div>
      <div class="svc-name">${esc(name)}</div>
      <div class="svc-note">${esc(note || 'Synthetic demo record')}</div>
    </div>
  </div>`;
}

function statusChip(s) {
  return `<span class="status-chip chip-${esc(s)}">${esc(s)}</span>`;
}

function renderRecentTable() {
  $('#recent-tbody').innerHTML = state.consents.slice(0, 4).map(c => `
    <tr>
      <td>${svcCell(c.service_name, c.note)}</td>
      <td>${esc(c.category)}</td>
      <td>${statusChip(c.status)}</td>
      <td><span style="color:var(--text-muted);font-size:10px">Manual record</span></td>
    </tr>`).join('');
}

/* ── Exposure Tracker ────────────────────────────────────────────── */
function renderExposure(data) {
  const { items, risk_score, risk_label, risk_color, disclaimer } = data;

  $('#exposure-summary-bar').innerHTML = `
    <div style="flex:1">
      <div style="font-size:13px;font-weight:700;color:var(--text)">${esc(risk_label)} Exposure Indicator</div>
      <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${esc(disclaimer)}</div>
    </div>
    <div style="display:flex;align-items:center;gap:14px;flex-shrink:0">
      <div style="font-size:28px;font-weight:800;color:${esc(risk_color || 'var(--amber)')}">${risk_score}</div>
      <div style="font-size:10px;color:var(--text-muted)">/ 100<br>risk score</div>
    </div>`;

  if (!items.length) {
    $('#exposure-grid').innerHTML = `<div class="empty-state" style="grid-column:1/-1">
      <div class="empty-icon">⚡</div><p>No exposure records found.</p></div>`;
    return;
  }

  $('#exposure-grid').innerHTML = items.map(e => `
    <article class="exposure-card">
      <div class="exposure-card-header">
        <span class="svc-label">${esc(e.service_name)}</span>
        <span class="sev-chip sev-${esc(e.severity)}">${esc(e.severity)}</span>
      </div>
      <h3>${esc(e.exposure_type)}</h3>
      <p>${esc(e.evidence)}</p>
      <div class="exposure-meta">Recorded ${esc(fmtDate(e.created_at))}</div>
    </article>`).join('');
}

/* ── Consent Manager ─────────────────────────────────────────────── */
function renderConsents() {
  $('#consent-count-badge').textContent = `${state.consents.length} services`;
  $('#consent-tbody').innerHTML = state.consents.map(c => `
    <tr>
      <td>${svcCell(c.service_name, c.note)}</td>
      <td>${esc(c.category)}</td>
      <td>${statusChip(c.status)}</td>
      <td style="color:var(--text-muted);font-size:11px">${esc(fmtDate(c.updated_at))}</td>
      <td>
        <select class="select-status" data-consent-id="${c.id}"
          aria-label="Change consent status for ${esc(c.service_name)}">
          ${['allowed','denied','withdrawn'].map(v =>
            `<option value="${v}"${v === c.status ? ' selected' : ''}>${
              v === 'allowed' ? 'Allow' : v === 'denied' ? 'Deny' : 'Withdraw'
            }</option>`).join('')}
        </select>
      </td>
    </tr>`).join('');
}

async function changeConsent(id, status) {
  try {
    const r = await api(`/api/consents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
    await loadAll();
    showView('consent');
    toast(r.message);
  } catch (e) {
    toast(e.message);
    await loadAll();
  }
}

/* ── Privacy Requests ────────────────────────────────────────────── */
function populateServiceSelect() {
  $('#svc-choice').innerHTML = state.services
    .map(s => `<option value="${s.id}">${esc(s.name)}</option>`)
    .join('');
}

const REQ_TYPE_LABEL = {
  deletion:           'Data Erasure',
  consent_withdrawal: 'Consent Withdrawal',
  access:             'Access Request (DSAR)',
};

function renderRequests() {
  const list = $('#request-list');
  if (!state.requests.length) {
    list.innerHTML = `<div class="panel" style="text-align:center;color:var(--text-muted);padding:30px">
      <div style="font-size:24px;margin-bottom:8px;opacity:.3">▤</div>
      <p>No requests yet. Create a draft above.</p>
    </div>`;
    return;
  }
  list.innerHTML = state.requests.map(r => `
    <div class="request-card">
      <div>
        <h3>${esc(r.service_name)} · ${esc(REQ_TYPE_LABEL[r.request_type] || r.request_type)}</h3>
        <p>Ref <strong>${esc(r.reference)}</strong> · ${esc(fmtDate(r.created_at))}</p>
        <div style="margin-top:6px;display:flex;align-items:center;gap:8px">
          ${statusChip(r.status)}
          <span style="font-size:10px;color:var(--text-muted)">Draft only — not submitted</span>
        </div>
      </div>
      <button class="btn-preview" data-preview-id="${r.id}">Preview draft →</button>
    </div>`).join('');
}

function openModal(r) {
  state.draft = r;
  $('#modal-meta').textContent = `${r.service_name} · ${r.reference} · Draft only`;
  $('#modal-draft').textContent = r.draft_text;
  $('#modal').classList.remove('hidden');
  $('#modal-draft').focus();
}
function closeModal() { $('#modal').classList.add('hidden'); }

/* ── Audit ───────────────────────────────────────────────────────── */
const AUDIT_ICONS = {
  consent_updated:          '◉',
  privacy_request_drafted:  '▤',
  request_status_updated:   '✓',
};

function renderAudit() {
  const list = $('#audit-list');
  if (!state.audit.length) {
    list.innerHTML = `<div style="text-align:center;padding:30px;color:var(--text-muted)">
      <div style="font-size:24px;opacity:.3;margin-bottom:8px">⟲</div>
      <p>No actions recorded yet. Consent changes and request drafts will appear here.</p>
    </div>`;
    return;
  }
  list.innerHTML = state.audit.map(a => {
    const d = typeof a.details === 'object' ? a.details : {};
    let detail = '';
    if (a.action === 'consent_updated') {
      detail = `${d.service || 'Service'}: ${d.from || '—'} → ${d.to || '—'}`;
    } else if (a.action === 'privacy_request_drafted') {
      detail = `${REQ_TYPE_LABEL[d.type] || d.type || 'Privacy'} request for ${d.service || 'service'} (${d.reference || 'ref'})`;
    } else if (a.action === 'request_status_updated') {
      detail = `Status changed: ${d.from || '—'} → ${d.to || '—'}`;
    } else {
      detail = JSON.stringify(d);
    }
    return `<div class="audit-item">
      <div class="audit-icon">${AUDIT_ICONS[a.action] || '◈'}</div>
      <div class="audit-body">
        <strong>${esc(a.action.replaceAll('_', ' '))}</strong>
        <p>${esc(detail)}</p>
        <span class="audit-time">${esc(fmtDate(a.created_at))} · ${esc(a.entity_type)} #${a.entity_id}</span>
      </div>
    </div>`;
  }).join('');
}

/* ── Discovery ───────────────────────────────────────────────────── */
const CONF_LABEL = configured =>
  configured ? 'Configured · ready when authorised' : 'Not configured · no query will be sent';

async function loadDiscoveryStatus() {
  try {
    const s = await api('/api/discovery/status');
    $('#gmail-state').textContent   = s.gmail.connected ? 'Connected · read-only Gmail access' : CONF_LABEL(s.gmail.configured);
    $('#web-state').textContent     = CONF_LABEL(s.public_web.configured);
    $('#breach-state').textContent  = CONF_LABEL(s.breach.configured);
    $('#btn-connect-gmail').disabled    = !s.gmail.configured;
    $('#btn-disconnect-gmail').disabled = !s.gmail.connected;
    $('#disc-status').innerHTML = `
      <div style="display:grid;gap:6px">
        <div><strong style="color:var(--text)">Gmail</strong> — ${esc(s.gmail.connected ? 'Connected (read-only)' : s.gmail.configured ? 'Configured, not connected' : 'Not configured')}</div>
        <div><strong style="color:var(--text)">Public Web</strong> — ${esc(s.public_web.configured ? 'Configured' : 'Not configured')}</div>
        <div><strong style="color:var(--text)">Breach Catalogue</strong> — ${esc(s.breach.configured ? 'Configured' : 'Not configured')}</div>
        <div style="margin-top:6px;padding-top:6px;border-top:1px solid var(--panel-border);color:var(--text-dim)">${esc(s.privacy)}</div>
      </div>`;
  } catch (e) {
    $('#disc-status').textContent = `Could not load integration status: ${e.message}`;
  }
}

function confidenceClass(c) {
  return c === 'high' ? 'sev-high' : c === 'medium' ? 'sev-medium' : 'sev-low';
}

function renderDiscoveryResults(d) {
  $('#result-count-badge').textContent = `${d.result_count} finding${d.result_count === 1 ? '' : 's'}`;

  // Errors
  $('#disc-errors').innerHTML = (d.errors || []).map(e => `
    <div class="discovery-error">
      <strong>${esc(e.source)} · ${esc(e.status.replaceAll('_', ' '))}</strong>
      <p>${esc(e.message)}</p>
    </div>`).join('');

  // Results
  const resultsEl = $('#disc-results');
  if (!d.results.length) {
    resultsEl.innerHTML = `<div class="empty-state">
      <div class="empty-icon">⌕</div>
      <p>No confirmed matches returned by configured sources.<br>
      That does not prove there is no exposure.</p>
    </div>`;
  } else {
    resultsEl.innerHTML = d.results.map(r => `
      <article class="finding-card">
        <div class="finding-top">
          <span class="badge badge-info">${esc(r.source)}</span>
          <span class="sev-chip ${confidenceClass(r.confidence)}">${esc(r.confidence)} confidence</span>
        </div>
        <h4>${esc(r.title)}</h4>
        <p class="finding-source">${esc(r.publisher || 'Source not specified')}${r.date ? ` · ${esc(r.date)}` : ''}</p>
        <p>${esc(r.evidence || 'No excerpt available')}</p>
        ${r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">Open original source ↗</a>` : ''}
        <details>
          <summary>Evidence provenance &amp; confidence rationale</summary>
          <p style="margin-top:8px">${esc(r.provenance)}</p>
          <p>${esc(r.confidence_reason)}</p>
        </details>
      </article>`).join('');
  }

  // Limitations
  const limEl = $('#disc-limits');
  limEl.classList.remove('hidden');
  limEl.innerHTML = `<strong>Limitations</strong>` +
    d.limitations.map(x => `<p>· ${esc(x)}</p>`).join('') +
    `<p style="margin-top:8px;color:var(--text-dim);font-size:9px">Run completed ${esc(fmtDate(d.generated_at))}. ${esc(d.persistence)}</p>`;
}

/* ── Event delegation ────────────────────────────────────────────── */
document.addEventListener('click', e => {
  const navBtn  = e.target.closest('[data-view]');
  const gotoBtn = e.target.closest('[data-goto]');
  const prevBtn = e.target.closest('[data-preview-id]');
  if (navBtn)  { showView(navBtn.dataset.view); return; }
  if (gotoBtn) { showView(gotoBtn.dataset.goto); return; }
  if (prevBtn) {
    const r = state.requests.find(x => String(x.id) === prevBtn.dataset.previewId);
    if (r) openModal(r);
  }
});

document.addEventListener('change', e => {
  const sel = e.target.closest('[data-consent-id]');
  if (sel) changeConsent(Number(sel.dataset.consentId), sel.value);
});

/* ── Exposure filter ─────────────────────────────────────────────── */
$('#sev-filter').addEventListener('change', async () => {
  const sev = $('#sev-filter').value;
  const data = await api(`/api/exposure${sev ? '?severity=' + sev : ''}`).catch(e => { toast(e.message); return null; });
  if (data) renderExposure(data);
});

/* ── Request form ────────────────────────────────────────────────── */
$('#request-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = $('#btn-create-request');
  btn.disabled = true;
  btn.textContent = 'Generating…';
  try {
    const r = await api('/api/requests', {
      method: 'POST',
      body: JSON.stringify({
        service_id:   Number($('#svc-choice').value),
        request_type: $('#req-type').value,
      }),
    });
    await loadAll();
    openModal(r);
    toast(r.message);
  } catch (err) {
    toast(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '✦ Generate Request Draft';
  }
});

/* ── Reset ───────────────────────────────────────────────────────── */
$('#btn-reset').addEventListener('click', async () => {
  if (!confirm('Reset all demo data to the initial synthetic state?')) return;
  try {
    await api('/api/demo/reset', { method: 'POST', body: '{}' });
    await loadAll();
    showView('overview');
    toast('Synthetic demo data restored.');
  } catch (e) { toast(e.message); }
});

/* ── Audit refresh ───────────────────────────────────────────────── */
$('#btn-refresh-audit').addEventListener('click', async () => {
  try {
    state.audit = await api('/api/audit');
    renderAudit();
    toast('Audit log refreshed.');
  } catch (e) { toast(e.message); }
});

/* ── Notice bar ──────────────────────────────────────────────────── */
$('#notice-close').addEventListener('click', () => $('#notice-bar').remove());

/* ── Hamburger menu ──────────────────────────────────────────────── */
$('#hamburger').addEventListener('click', () => {
  const sidebar = $('#sidebar');
  sidebar.classList.toggle('open');
  $('#hamburger').setAttribute('aria-expanded', String(sidebar.classList.contains('open')));
});
document.addEventListener('click', e => {
  if (!e.target.closest('#sidebar') && !e.target.closest('#hamburger')) {
    $('#sidebar').classList.remove('open');
  }
});

/* ── Modal ───────────────────────────────────────────────────────── */
$('#modal-close').addEventListener('click', closeModal);
$('#btn-close-modal').addEventListener('click', closeModal);
$('#modal').addEventListener('click', e => { if (e.target === $('#modal')) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

$('#btn-copy-draft').addEventListener('click', async () => {
  if (!state.draft) return;
  try {
    await navigator.clipboard.writeText(state.draft.draft_text);
    toast('Draft copied to clipboard. Review carefully before sending via an official channel.');
  } catch {
    const t = document.createElement('textarea');
    t.value = state.draft.draft_text;
    document.body.appendChild(t);
    t.select();
    const ok = document.execCommand('copy');
    t.remove();
    toast(ok ? 'Draft copied.' : 'Clipboard blocked; select and copy the text manually.');
  }
});

/* ── Discovery controls ──────────────────────────────────────────── */
$('#btn-connect-gmail').addEventListener('click', () => {
  if (!$('#discovery-consent').checked) {
    toast('Please confirm the consent notice before connecting Gmail.');
    return;
  }
  window.location.href = '/api/discovery/gmail/connect';
});

$('#btn-disconnect-gmail').addEventListener('click', async () => {
  try {
    const r = await api('/api/discovery/gmail/disconnect', { method: 'POST', body: '{}' });
    toast(r.message);
    await loadDiscoveryStatus();
  } catch (e) { toast(e.message); }
});

$('#btn-run-discovery').addEventListener('click', async () => {
  const payload = {
    consent_confirmed: $('#discovery-consent').checked,
    use_gmail:         $('#src-gmail').checked,
    use_public_web:    $('#src-web').checked,
    use_breach_check:  $('#src-breach').checked,
    phone_number:      $('#disc-phone').value.trim() || null,
    email_address:     $('#disc-email').value.trim() || null,
  };
  if (!payload.consent_confirmed) { toast('Please confirm consent before running checks.'); return; }
  if (!(payload.use_gmail || payload.use_public_web || payload.use_breach_check)) {
    toast('Select at least one source.'); return;
  }
  const btn = $('#btn-run-discovery');
  btn.disabled = true;
  btn.textContent = 'Searching selected sources…';
  try {
    const d = await api('/api/discovery/run', { method: 'POST', body: JSON.stringify(payload) });
    renderDiscoveryResults(d);
    toast(`Discovery complete: ${d.result_count} finding(s). Review confidence and limitations.`);
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '⌕ Run Selected Checks';
    await loadDiscoveryStatus();
  }
});

/* ── Handle Gmail OAuth redirect ─────────────────────────────────── */
if (new URLSearchParams(location.search).get('gmail') === 'connected') {
  history.replaceState({}, '', location.pathname + '#discovery');
  showView('discovery');
  toast('Gmail connected for read-only discovery.');
}

/* ── Bootstrap ───────────────────────────────────────────────────── */
loadAll().catch(e => toast(`Could not load dashboard: ${e.message}. Is the API server running?`));
loadDiscoveryStatus();
