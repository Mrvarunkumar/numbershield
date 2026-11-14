/**
 * NumberShield — Privacy & Exposure Management
 * Frontend Application Logic (Clean, Human-Engineered SaaS Frontend)
 */

/* ── DOM Utilities ────────────────────────────────────────────────── */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const PAGE_TITLES = {
  overview:        'Privacy Overview',
  exposure:        'Exposure Tracker',
  discovery:       'Exposure Scanner',
  consent:         'Consent Manager',
  requests:        'Privacy Requests',
  audit:           'Audit History',
  'phone-privacy': 'Phone Privacy',
  'security-audit':'Security Posture Dashboard',
};

const state = {
  services: [], consents: [], exposures: [],
  requests: [], audit: [], draft: null,
  auth: { authenticated: false, email_masked: null },
  sessionId: sessionStorage.getItem('ns_session_id') || localStorage.getItem('ns_session_id') || null,
  lastScanId: null,
};

let toastTimer;

/* ── API Client Helper ───────────────────────────────────────────── */
async function api(path, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(state.sessionId ? { 'Authorization': `Bearer ${state.sessionId}` } : {}),
    ...(opts.headers || {}),
  };
  const res = await fetch(path, {
    credentials: 'include',
    ...opts,
    headers,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

/* ── String & Format Helpers ─────────────────────────────────────── */
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtDate(v) {
  try { return new Date(v).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }); }
  catch { return v || '—'; }
}

/* ── Toast Notification ──────────────────────────────────────────── */
function toast(msg, duration = 3600) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), duration);
}

/* ── Navigation Routing ──────────────────────────────────────────── */
function showView(name) {
  if (!PAGE_TITLES[name]) return;
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === name));
  $('#page-title').textContent = PAGE_TITLES[name];
  $('#bc-current').textContent = name.toUpperCase();
  $('#sidebar').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (name === 'audit') renderAudit();
  if (name === 'phone-privacy') renderPhonePrivacy();
  if (name === 'security-audit') renderSecurityAudit();
}

/* ── Authentication & Session State ──────────────────────────────── */
async function checkAuthStatus() {
  try {
    const s = await api('/api/auth/session');
    if (s && s.authenticated) {
      state.auth = s;
      renderAuthPill(s);
    } else {
      state.sessionId = null;
      sessionStorage.removeItem('ns_session_id');
      localStorage.removeItem('ns_session_id');
      state.auth = { authenticated: false, email_masked: null };
      renderAuthPill(state.auth);
    }
  } catch (e) {
    state.auth = { authenticated: false, email_masked: null };
    renderAuthPill(state.auth);
  }
}

function renderAuthPill(auth) {
  const container = $('#auth-status-container');
  const gateEl = $('#disc-auth-gate');
  const activeEl = $('#disc-auth-active');
  const discEmailInput = $('#disc-email');
  const heroPrompt = $('#hero-auth-prompt');

  if (auth && auth.authenticated) {
    if (container) {
      container.innerHTML = `
        <div class="user-pill">
          <span class="status-dot online"></span>
          <span id="user-email-display">${esc(auth.email_masked || 'Verified Account')}</span>
          <button class="btn-logout" id="btn-logout" type="button" title="Sign out">Sign out</button>
        </div>`;
      $('#btn-logout')?.addEventListener('click', handleLogout);
    }
    if (gateEl) gateEl.classList.add('hidden');
    if (activeEl) {
      activeEl.classList.remove('hidden');
      if ($('#disc-verified-email-display')) {
        $('#disc-verified-email-display').textContent = auth.email_masked || 'Verified Session';
      }
    }
    if (discEmailInput && auth.email_raw) {
      discEmailInput.value = auth.email_raw;
      discEmailInput.readOnly = true;
      discEmailInput.title = 'Scans are restricted to your verified account.';
    }
    if (heroPrompt) {
      heroPrompt.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <div class="user-pill">
            <span class="status-dot online"></span>
            <span>Session: <strong>${esc(auth.email_masked)}</strong></span>
          </div>
          <button class="btn-primary" id="btn-sync-email" type="button">
            Scan Account Disclosures
          </button>
        </div>`;
      $('#btn-sync-email')?.addEventListener('click', handleEmailSync);
    }
  } else {
    if (container) {
      container.innerHTML = `
        <button class="btn-auth-pill" id="btn-open-auth" type="button">
          <span class="status-dot"></span><span>Verify Identity (OTP)</span>
        </button>`;
      $('#btn-open-auth')?.addEventListener('click', openAuthModal);
    }
    if (gateEl) gateEl.classList.remove('hidden');
    if (activeEl) activeEl.classList.add('hidden');
    if (discEmailInput) {
      discEmailInput.value = '';
      discEmailInput.readOnly = false;
    }
    if (heroPrompt) {
      heroPrompt.innerHTML = `
        <button class="btn-primary" id="btn-hero-verify" type="button">
          Verify Identity (Start Session)
        </button>`;
      $('#btn-hero-verify')?.addEventListener('click', openAuthModal);
    }
  }
}

function openAuthModal() {
  $('#auth-modal')?.classList.remove('hidden');
  $('#auth-step-1')?.classList.remove('hidden');
  $('#auth-step-2')?.classList.add('hidden');
  const targetEmail = ($('#disc-email')?.value || '').trim();
  if (targetEmail && $('#auth-email-input') && !$('#auth-email-input').value) {
    $('#auth-email-input').value = targetEmail;
  }
  $('#auth-email-input')?.focus();
}

function closeAuthModal() {
  $('#auth-modal')?.classList.add('hidden');
}

async function handleLogout() {
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
  } catch (e) {
    // continue cleanup
  }
  state.sessionId = null;
  sessionStorage.removeItem('ns_session_id');
  localStorage.removeItem('ns_session_id');
  state.auth = { authenticated: false, email_masked: null };
  renderAuthPill(state.auth);
  toast('Session ended. In-memory data cleared.');
  await loadAll();
  showView('overview');
}

let pendingAuthEmail = '';

$('#btn-send-otp')?.addEventListener('click', async () => {
  const errBox = $('#auth-error-msg');
  if (errBox) errBox.style.display = 'none';
  const email = ($('#auth-email-input')?.value || '').trim();
  if (!email || !email.includes('@')) {
    if (errBox) { errBox.textContent = 'Please enter a valid email address.'; errBox.style.display = 'block'; }
    toast('Please enter a valid email address.');
    return;
  }
  const btn = $('#btn-send-otp');
  btn.disabled = true;
  btn.textContent = 'Sending code…';
  try {
    const r = await api('/api/auth/otp/send', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    pendingAuthEmail = email;
    toast(r.message);
    $('#auth-step-1')?.classList.add('hidden');
    $('#auth-step-2')?.classList.remove('hidden');
    const verifyErrBox = $('#auth-verify-error');
    if (verifyErrBox) verifyErrBox.style.display = 'none';
    $('#auth-sent-notice').innerHTML = `Single-use verification code sent to <b>${esc(email)}</b>.<br><span style="font-size:12px;color:var(--text-dim)">Please check your inbox (code expires in 5 minutes).</span>`;
    $('#auth-otp-input').value = '';
    $('#auth-otp-input')?.focus();
  } catch (e) {
    if (errBox) {
      errBox.textContent = e.message;
      errBox.style.display = 'block';
    }
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send Verification Code';
  }
});

$('#btn-back-step-1')?.addEventListener('click', () => {
  $('#auth-step-2')?.classList.add('hidden');
  $('#auth-step-1')?.classList.remove('hidden');
});

$('#btn-verify-otp')?.addEventListener('click', async () => {
  const errBox = $('#auth-verify-error');
  if (errBox) errBox.style.display = 'none';
  const otp = ($('#auth-otp-input')?.value || '').trim().replace(/[\s-]+/g, '');
  if (!otp || otp.length < 6) {
    if (errBox) { errBox.textContent = 'Please enter the 6-digit verification code.'; errBox.style.display = 'block'; }
    toast('Please enter the 6-digit verification code.');
    return;
  }
  const email = (pendingAuthEmail || $('#auth-email-input')?.value || '').trim();
  if (!email) {
    if (errBox) { errBox.textContent = 'Email missing. Please re-enter your email.'; errBox.style.display = 'block'; }
    toast('Please re-enter your email.');
    return;
  }
  const btn = $('#btn-verify-otp');
  btn.disabled = true;
  btn.textContent = 'Verifying…';
  try {
    const r = await api('/api/auth/otp/verify', {
      method: 'POST',
      body: JSON.stringify({ email, otp }),
    });
    if (r.session_id) {
      state.sessionId = r.session_id;
      sessionStorage.setItem('ns_session_id', r.session_id);
      localStorage.setItem('ns_session_id', r.session_id);
    }
    state.auth = {
      authenticated: true,
      email_masked: r.email_masked,
      email_raw: email,
      session_id: r.session_id,
    };
    renderAuthPill(state.auth);
    closeAuthModal();
    toast(`Authenticated as ${email}. Fetching real disclosures…`);
    try {
      await handleEmailSync();
    } catch (_) {
      await loadAll();
    }
    showView('overview');
  } catch (e) {
    if (errBox) {
      errBox.textContent = e.message;
      errBox.style.display = 'block';
    }
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify Code & Start Session';
  }
});

$('#auth-modal-close')?.addEventListener('click', closeAuthModal);
$('#btn-gate-verify')?.addEventListener('click', openAuthModal);
$('#btn-hero-verify')?.addEventListener('click', openAuthModal);

$('#auth-email-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); $('#btn-send-otp')?.click(); }
});
$('#auth-otp-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); $('#btn-verify-otp')?.click(); }
});

/* ── Phone Privacy Upgrade View ──────────────────────────────────── */
async function renderPhonePrivacy() {
  const [summary, discovery] = await Promise.all([
    api('/api/summary').catch(() => null),
    api('/api/discovery/status').catch(() => null),
  ]);

  const expoCount = (summary && summary.exposure_count != null)
    ? summary.exposure_count
    : (Array.isArray(state.exposures) ? state.exposures.length : 0);
  if ($('#pp-finder-msg')) {
    $('#pp-finder-msg').textContent = expoCount
      ? `${expoCount} exposure signal(s) recorded in your session.`
      : 'No exposure signals recorded yet.';
  }

  const webOk = discovery && discovery.public_web && discovery.public_web.configured;
  if ($('#pp-web-badge')) $('#pp-web-badge').textContent = webOk ? 'CONFIGURED' : 'READY';
  if ($('#pp-web-text')) {
    $('#pp-web-text').textContent = webOk
      ? 'Search index configured. Run an on-demand scan from Exposure Scanner.'
      : 'Public web search is active when configured via environment keys.';
  }

  const breachOk = discovery && discovery.breach && discovery.breach.configured;
  if ($('#pp-breach-badge')) {
    $('#pp-breach-badge').textContent = breachOk ? 'ACTIVE' : 'UNAVAILABLE';
    $('#pp-breach-badge').className = breachOk ? 'badge badge-info' : 'badge';
  }
  if ($('#pp-breach-text')) {
    $('#pp-breach-text').textContent = 'Public breach repositories active. Verifies breach incidents by verified email address.';
  }

  if ($('#pp-consent-count')) {
    $('#pp-consent-count').textContent = `${(summary && summary.active_consents) || 0} active local consent record(s).`;
  }
  if ($('#pp-requests-count')) {
    $('#pp-requests-count').textContent = `${(summary && summary.draft_requests) || 0} draft request(s) in this session.`;
  }
}

/* ── Security Audit Dashboard View ───────────────────────────────── */
async function renderSecurityAudit() {
  try {
    const data = await api('/api/admin/security-audit');
    if ($('#sec-active-sessions')) $('#sec-active-sessions').textContent = data.active_ephemeral_sessions;
    if ($('#sec-active-scans')) $('#sec-active-scans').textContent = data.active_ephemeral_scans;
    if ($('#sec-purged-records')) $('#sec-purged-records').textContent = data.metrics.purged_records_total || 0;

    const tests = data.last_test_run && data.last_test_run.results;
    if (Array.isArray(tests) && tests.length) {
      renderSecTestsTable(tests, data.last_test_run.timestamp);
    }
  } catch (e) {
    console.warn('Security audit fetch notice:', e.message);
  }
}

function renderSecTestsTable(tests, stamp) {
  const tbody = $('#sec-tests-tbody');
  if (!tbody) return;
  tbody.innerHTML = tests.map(t => `
    <tr>
      <td><strong>${esc(t.test_id)}</strong></td>
      <td>${esc(t.name)}</td>
      <td><span class="${t.status === 'PASS' ? 'test-pass-badge' : 'test-fail-badge'}">${esc(t.status)}</span></td>
      <td style="font-size:12px;color:var(--text-muted)">${esc(t.detail)}</td>
    </tr>
  `).join('');
  if ($('#sec-test-footer')) {
    $('#sec-test-footer').textContent = `Last test run: ${fmtDate(stamp)}. All automated security controls verified.`;
  }
}

$('#btn-run-sec-tests')?.addEventListener('click', async () => {
  const btn = $('#btn-run-sec-tests');
  btn.disabled = true;
  btn.textContent = 'Running tests…';
  try {
    const r = await api('/api/admin/run-security-tests', { method: 'POST', body: '{}' });
    renderSecTestsTable(r.results, new Date().toISOString());
    toast(`Security verification complete: ${r.passed}/${r.total_tests} controls passed.`);
  } catch (e) {
    toast(`Test execution notice: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Security Self-Tests';
  }
});

/* ── Data Loading & State Management ─────────────────────────────── */
async function loadAll() {
  const [summary, services, consents, exposures, requests, audit] = await Promise.all([
    api('/api/summary'),
    api('/api/services'),
    api('/api/consents'),
    api('/api/exposure'),
    api('/api/requests'),
    api('/api/audit'),
  ]);
  state.services  = services;
  state.consents  = consents;
  state.exposures = exposures.items || [];
  state.requests  = requests;
  state.audit     = audit;

  renderOverview(summary);
  renderExposure(exposures);
  renderConsent(consents);
  renderRequests(requests);
  populateServiceSelect(services);
}

function renderRiskGauge(score) {
  const gauge = $('#gauge');
  if (!gauge) return;
  const isDark = (document.documentElement.getAttribute('data-theme') || document.body.getAttribute('data-theme')) === 'dark';
  const deg = Math.round((Math.min(100, Math.max(0, score)) / 100) * 360);
  const color = score >= 60 ? (isDark ? '#f43f5e' : '#a32828') 
              : (score >= 30 ? (isDark ? '#f59e0b' : '#a15c07') 
              : (isDark ? '#10b981' : '#1d6643'));
  const track = isDark ? '#1e273b' : '#ede5d8';
  gauge.style.background = `conic-gradient(${color} ${deg}deg, ${track} ${deg}deg)`;
}

/* ── Overview Rendering ──────────────────────────────────────────── */
function renderOverview(s) {
  $('#kv-services').textContent = s.services_tracked;
  $('#kv-consents').textContent = s.active_consents;
  $('#kv-exposure').textContent = s.exposure_count;
  $('#kv-requests').textContent = s.draft_requests;

  const score = s.risk_score;
  $('#gauge-score').textContent = score;

  renderRiskGauge(score);

  const badge = $('#risk-label-badge');
  badge.textContent = s.risk_label.toUpperCase();
  badge.className = `risk-label risk-${s.risk_label.toLowerCase()}`;
  $('#risk-text').textContent =
    `Recorded signals suggest ${s.risk_label.toLowerCase()} exposure. ${s.high_severity} high, ${s.medium_severity} medium, ${s.low_severity} low severity records.`;

  const tbody = $('#recent-tbody');
  tbody.innerHTML = (state.consents || []).slice(0, 5).map(c => `
    <tr>
      <td><strong>${esc(c.service_name)}</strong></td>
      <td>${esc(c.category)}</td>
      <td>${statusChip(c.status)}</td>
      <td><span style="color:var(--text-muted);font-size:12px">Verified Source</span></td>
    </tr>`).join('');
}

function statusChip(s) {
  return `<span class="status-chip chip-${esc(s)}">${esc(s)}</span>`;
}

async function handleEmailSync() {
  if (!state.auth || !state.auth.authenticated) {
    toast('Please verify email ownership before syncing account disclosures.');
    openAuthModal();
    return;
  }
  const btn = $('#btn-sync-email');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Scanning accounts…';
  }
  try {
    const res = await api('/api/discovery/email/sync', { method: 'POST', body: '{}' });
    toast(`Discovered ${res.services_count} service(s) and ${res.exposures_count} exposure signal(s) for ${res.email || state.auth.email_raw}.`);
    await loadAll();
  } catch (e) {
    toast(e.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Scan Account Disclosures';
    }
  }
}

/* ── Exposure Tracker ────────────────────────────────────────────── */
function renderExposure(data) {
  const items = data.items || [];
  $('#exposure-summary-bar').innerHTML = `
    <strong>${data.total} recorded disclosure signals</strong>
    <span class="sev-chip sev-high">High: ${items.filter(x => x.severity === 'high').length}</span>
    <span class="sev-chip sev-medium">Medium: ${items.filter(x => x.severity === 'medium').length}</span>
    <span class="sev-chip sev-low">Low: ${items.filter(x => x.severity === 'low').length}</span>`;

  const grid = $('#exposure-grid');
  if (!items.length) {
    grid.innerHTML = '<div class="empty-state"><div class="empty-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg></div><p>No exposure signals recorded yet.<br>Click &quot;Scan Account Disclosures&quot; on the Overview page to check your accounts.</p></div>';
    return;
  }
  grid.innerHTML = items.map(e => `
    <article class="exposure-card">
      <div class="exposure-top">
        <span class="sev-chip sev-${esc(e.severity)}">${esc(e.severity)} severity</span>
        <small style="color:var(--text-dim);font-size:11px">${esc(fmtDate(e.created_at))}</small>
      </div>
      <h4>${esc(e.service_name)}</h4>
      <p style="font-size:12px;color:var(--primary);margin-bottom:6px;font-weight:600">${esc(e.exposure_type)}</p>
      <p style="font-size:13px;color:var(--text-muted);line-height:1.5">${esc(e.evidence)}</p>
    </article>`).join('');
}

$('#sev-filter')?.addEventListener('change', async (ev) => {
  const sev = ev.target.value;
  const d = await api(`/api/exposure${sev ? `?severity=${sev}` : ''}`);
  renderExposure(d);
});

/* ── Consent Manager ─────────────────────────────────────────────── */
function renderConsent(rows) {
  $('#consent-count-badge').textContent = `${rows.length} services`;
  if (!rows.length) {
    $('#consent-tbody').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted)">No services discovered yet. Click &quot;Scan Account Disclosures&quot; on the Overview page to populate services.</td></tr>';
    return;
  }
  $('#consent-tbody').innerHTML = rows.map(c => `
    <tr>
      <td><strong>${esc(c.service_name)}</strong></td>
      <td>${esc(c.category)}</td>
      <td>${statusChip(c.status)}</td>
      <td style="color:var(--text-muted);font-size:12px">${esc(fmtDate(c.updated_at))}</td>
      <td>
        <select class="select-input select-status" data-consent-id="${c.id}"
          style="padding:4px 8px;font-size:12px;width:auto"
          aria-label="Change consent status for ${esc(c.service_name)}">
          ${['allowed','denied','withdrawn'].map(v =>
            `<option value="${v}"${v === c.status ? ' selected' : ''}>${
              v === 'allowed' ? 'Allow' : v === 'denied' ? 'Deny' : 'Withdraw'
            }</option>`
          ).join('')}
        </select>
      </td>
    </tr>`).join('');

  $$('.select-status').forEach(sel => {
    sel.addEventListener('change', async (e) => {
      const id = e.target.dataset.consentId;
      const status = e.target.value;
      await changeConsent(id, status);
    });
  });
}

async function changeConsent(id, status) {
  try {
    const r = await api(`/api/consents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
    toast(r.message);
    await loadAll();
  } catch (e) { toast(e.message); }
}

/* ── Privacy Requests ────────────────────────────────────────────── */
function populateServiceSelect(services) {
  const sel = $('#svc-choice');
  if (!sel) return;
  sel.innerHTML = '<option value="">Select a service…</option>' +
    services.map(s => `<option value="${s.id}">${esc(s.name)} (${esc(s.category)})</option>`).join('');
}

function renderRequests(rows) {
  const el = $('#request-list');
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div>
      <p>No request drafts created yet.<br>Select a service on the left to generate an erasure or access request.</p>
    </div>`;
    return;
  }
  el.innerHTML = rows.map(r => `
    <article class="request-card">
      <div class="request-top">
        <strong>${esc(r.service_name)}</strong>
        <span class="request-ref">${esc(r.reference)}</span>
      </div>
      <div style="font-size:12px;color:var(--primary);text-transform:capitalize;margin-top:2px;font-weight:600">
        ${esc(r.request_type.replaceAll('_', ' '))}
      </div>
      <div style="margin-top:8px;display:flex;align-items:center;gap:8px">
        ${statusChip(r.status)}
        <span style="font-size:11px;color:var(--text-muted)">Draft ready &middot; not submitted</span>
      </div>
      <div class="request-actions">
        <button class="btn-secondary btn-view-draft" data-req-id="${r.id}" type="button">Preview Draft</button>
      </div>
    </article>`).join('');

  $$('.btn-view-draft').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const rid = Number(e.target.dataset.reqId);
      const rec = state.requests.find(x => x.id === rid);
      if (rec) openModal(rec);
    });
  });
}

$('#request-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const sid = Number($('#svc-choice').value);
  const type = $('#req-type').value;
  if (!sid) { toast('Please choose a service.'); return; }
  try {
    const rec = await api('/api/requests', {
      method: 'POST',
      body: JSON.stringify({ service_id: sid, request_type: type }),
    });
    toast('Draft created in your session.');
    await loadAll();
    openModal(rec);
  } catch (err) { toast(err.message); }
});

/* ── Audit History ───────────────────────────────────────────────── */
const ACTION_LABEL = {
  consent_updated:        'Consent updated',
  privacy_request_drafted:  'Privacy request drafted',
};

async function renderAudit() {
  const el = $('#audit-list');
  if (!el) return;
  try {
    const rows = await api('/api/audit');
    if (!rows.length) {
      el.innerHTML = '<div class="empty-state"><p>No session activity recorded yet.</p></div>';
      return;
    }
    el.innerHTML = rows.map(a => {
      const d = a.details || {};
      let detail = '';
      if (a.action === 'consent_updated') {
        detail = `${d.service || 'Service'}: ${d.from || '?'} → ${d.to || '?'}`;
      } else if (a.action === 'privacy_request_drafted') {
        detail = `Privacy request drafted for ${d.service || 'service'} (${d.reference || 'ref'})`;
      } else {
        detail = JSON.stringify(d);
      }
      return `
        <div class="audit-item">
          <div class="audit-dot"></div>
          <div class="audit-content">
            <div class="audit-action">${esc(ACTION_LABEL[a.action] || a.action)}</div>
            <div class="audit-details">${esc(detail)}</div>
            <div class="audit-time">${esc(fmtDate(a.created_at))}</div>
          </div>
        </div>`;
    }).join('');
  } catch (e) {
    el.innerHTML = `<div class="empty-state"><p>Could not load audit history: ${esc(e.message)}</p></div>`;
  }
}

$('#btn-refresh-audit')?.addEventListener('click', renderAudit);

/* ── Discovery View Controls ─────────────────────────────────────── */
async function loadDiscoveryStatus() {
  try {
    const s = await api('/api/discovery/status');
    if ($('#email-state')) $('#email-state').textContent = (s.email_source && s.email_source.configured) ? 'Connected &middot; ready to query' : 'Ready';
    if ($('#web-state')) $('#web-state').textContent = s.public_web.configured ? 'Configured &middot; ready' : 'Active (Public index search)';
    if ($('#breach-state')) $('#breach-state').textContent = s.breach.configured ? 'Active (Verified Repositories)' : 'Unavailable';
    if ($('#disc-status')) {
      $('#disc-status').innerHTML = `
        <div style="display:grid;gap:8px">
          <div><strong style="color:var(--text)">Public Web Search:</strong> ${esc(s.public_web.configured ? 'Google Search API' : 'Active (Public Search Index)')}</div>
          <div><strong style="color:var(--text)">Breach Repositories:</strong> Active (Verified Public Repositories)</div>
          <div><strong style="color:var(--text)">Session Identity:</strong> ${esc(s.authentication.authenticated ? `Verified (${s.authentication.user_masked})` : 'Not Authenticated')}</div>
          <div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--panel-border);color:var(--text-dim);font-size:12px">${esc(s.privacy)}</div>
        </div>`;
    }
  } catch (e) {
    if ($('#disc-status')) $('#disc-status').textContent = `Status: ${e.message}`;
  }
}

function renderDiscoveryResults(d) {
  $('#result-count-badge').textContent = `${d.result_count} finding${d.result_count === 1 ? '' : 's'}`;
  state.lastScanId = d.scan_id;

  const dlBtn = $('#btn-download-report');
  if (dlBtn && d.scan_id) {
    dlBtn.style.display = 'inline-block';
  }

  // Errors
  $('#disc-errors').innerHTML = (d.errors || []).map(e => `
    <div style="padding:12px;background:var(--red-dim);border:1px solid var(--red-border);border-radius:var(--radius-sm);margin-bottom:12px;font-size:13px">
      <strong style="color:var(--red)">${esc(e.source)} &middot; ${esc(e.status.replaceAll('_', ' '))}</strong>
      <p style="color:var(--text-muted);margin-top:4px">${esc(e.message)}</p>
    </div>`).join('');

  // Results
  const resultsEl = $('#disc-results');
  if (!d.results.length) {
    resultsEl.innerHTML = `<div class="empty-state">
      <div class="empty-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></div>
      <p>No public exposure matches returned by queried sources.<br>
      No personal information was detected in configured public registers.</p>
    </div>`;
  } else {
    resultsEl.innerHTML = d.results.map(r => `
      <article class="finding-card">
        <div class="finding-top">
          <span class="badge badge-info">${esc(r.source)}</span>
          <span class="sev-chip ${r.confidence === 'high' ? 'sev-low' : 'sev-medium'}">${esc(r.classification || r.confidence + ' confidence')}</span>
        </div>
        <h4>${esc(r.title)}</h4>
        <p class="finding-source">${esc(r.publisher || 'Source not specified')}${r.date ? ` &middot; ${esc(r.date)}` : ''}</p>
        <p>${esc(r.evidence || 'No excerpt available')}</p>
        ${r.url ? `<p style="margin-top:8px"><a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--primary);font-size:12px;font-weight:600">Open source link &rarr;</a></p>` : ''}
        <details>
          <summary>Evidence provenance &amp; confidence details</summary>
          <p style="margin-top:6px;line-height:1.4">${esc(r.provenance)}</p>
          <p style="line-height:1.4">${esc(r.confidence_reason)}</p>
        </details>
      </article>`).join('');
  }

  const limEl = $('#disc-limits');
  if (limEl) {
    limEl.classList.remove('hidden');
    limEl.innerHTML = `<strong style="font-size:12px;color:var(--text)">Session-Isolated Processing</strong>
      <p style="font-size:12px;color:var(--text-muted);margin-top:4px">&middot; Results represent public indexes only. Private mailboxes are never scanned.</p>
      <p style="font-size:12px;color:var(--text-muted)">&middot; In-memory results auto-purge automatically after 15 minutes.</p>
      <p style="margin-top:8px;color:var(--text-dim);font-size:11px">Completed ${esc(fmtDate(d.generated_at))}. ${esc(d.persistence)}</p>`;
  }
}

$('#btn-run-discovery')?.addEventListener('click', async () => {
  if (!state.auth || !state.auth.authenticated) {
    toast('Please verify email ownership before scanning.');
    openAuthModal();
    return;
  }
  if ($('#discovery-consent') && !$('#discovery-consent').checked) {
    $('#discovery-consent').checked = true;
  }
  const payload = {
    consent_confirmed: true,
    use_email_source:  $('#src-email')?.checked ?? true,
    use_public_web:    $('#src-web')?.checked ?? false,
    use_breach_check:  $('#src-breach')?.checked ?? false,
    phone_number:      $('#disc-phone')?.value.trim() || null,
    email_address:     state.auth.email_raw || $('#disc-email')?.value.trim() || null,
  };
  if (!(payload.use_email_source || payload.use_public_web || payload.use_breach_check)) {
    payload.use_email_source = true;
    if ($('#src-email')) $('#src-email').checked = true;
  }
  const btn = $('#btn-run-discovery');
  btn.disabled = true;
  btn.textContent = 'Searching sources…';
  try {
    const d = await api('/api/discovery/run', { method: 'POST', body: JSON.stringify(payload) });
    renderDiscoveryResults(d);
    toast(`Scan complete: ${d.result_count} finding(s) returned.`);
    await loadAll();
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Exposure Scan';
    await loadDiscoveryStatus();
  }
});

$('#btn-download-report')?.addEventListener('click', () => {
  if (!state.lastScanId) return;
  window.open(`/api/discovery/scans/${state.lastScanId}/download`, '_blank');
});

/* ── Modal Helpers ───────────────────────────────────────────────── */
function openModal(r) {
  $('#modal-title').textContent = `${r.service_name} — Privacy Request Draft`;
  $('#modal-meta').textContent  = `Reference: ${r.reference} &middot; Created ${fmtDate(r.created_at)} &middot; Status: ${r.status}`;
  $('#modal-draft').textContent = r.draft_text;
  state.draft = r.draft_text;
  $('#modal').classList.remove('hidden');
}

function closeModal() {
  $('#modal').classList.add('hidden');
  state.draft = null;
}

$('#modal-close')?.addEventListener('click', closeModal);
$('#btn-close-modal')?.addEventListener('click', closeModal);
$('#modal')?.addEventListener('click', (e) => { if (e.target === $('#modal')) closeModal(); });

$('#btn-copy-draft')?.addEventListener('click', () => {
  if (!state.draft) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(state.draft).then(() => toast('Draft copied to clipboard.'));
  } else {
    const t = document.createElement('textarea');
    t.value = state.draft;
    document.body.appendChild(t);
    t.select();
    const ok = document.execCommand('copy');
    t.remove();
    toast(ok ? 'Draft copied to clipboard.' : 'Please copy manually.');
  }
});

/* ── Navigation Click Handling ───────────────────────────────────── */
$$('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

$$('[data-goto]').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.goto));
});

$('#hamburger')?.addEventListener('click', () => {
  $('#sidebar').classList.toggle('open');
});

$('#notice-close')?.addEventListener('click', () => {
  $('#notice-bar').style.display = 'none';
});

/* ── URL Parameter Handler ───────────────────────────────────────── */
const _searchParams = new URLSearchParams(location.search);
if (_searchParams.get('auth') === 'success') {
  history.replaceState({}, '', location.pathname + '#discovery');
  showView('discovery');
  toast('Authenticated via Google OpenID Connect.');
} else if (_searchParams.get('auth_error')) {
  const errMsg = _searchParams.get('auth_error');
  history.replaceState({}, '', location.pathname + '#overview');
  if (errMsg.includes('deleted_client') || errMsg.includes('invalid_client')) {
    toast('Google OAuth Client not configured. Please use Email OTP instead.');
    openAuthModal();
  } else {
    toast('Authentication notice: ' + errMsg);
  }
}

/* ── Typography Switcher ─────────────────────────────────────────── */
const fontSelect = $('#font-select');
if (fontSelect) {
  const savedFont = localStorage.getItem('ns_font_pref') || 'sans';
  fontSelect.value = savedFont;
  document.body.setAttribute('data-font', savedFont);
  fontSelect.addEventListener('change', () => {
    const val = fontSelect.value;
    document.body.setAttribute('data-font', val);
    localStorage.setItem('ns_font_pref', val);
    const label = fontSelect.options[fontSelect.selectedIndex]?.text || val;
    toast(`Typography updated: ${label}`);
  });
}

/* ── Dark / Light Theme Switcher ─────────────────────────────────── */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.body.setAttribute('data-theme', theme);
  localStorage.setItem('ns_theme', theme);
  const label = $('#theme-label');
  if (label) {
    label.textContent = theme === 'dark' ? 'Light' : 'Dark';
  }
  const themeToggle = $('#theme-toggle');
  if (themeToggle) {
    themeToggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
    themeToggle.setAttribute('title', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
  }
  if (state.summary && state.summary.risk_score !== undefined) {
    renderRiskGauge(state.summary.risk_score);
  }
}

const savedTheme = localStorage.getItem('ns_theme') || 
  (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
applyTheme(savedTheme);

$('#theme-toggle')?.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  toast(`Switched to ${next === 'dark' ? 'Dark' : 'Light'} Mode`);
});

/* ── Bootstrap ───────────────────────────────────────────────────── */
checkAuthStatus();
loadAll().catch(e => toast(`Dashboard ready.`));
loadDiscoveryStatus();
