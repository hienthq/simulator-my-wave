#!/usr/bin/env node
/**
 * Emplx SSO Mock Server
 * ─────────────────────
 * Simulates the Emplx OAuth 2.0 provider for local integration testing.
 *
 * HOW IT WORKS
 * ────────────
 * The mock server impersonates the Emplx provider. Point the HRF app at it
 * via the `external_partner_integration` DB row (see configuration below).
 *
 * ENDPOINTS SERVED
 * ─────────────────
 *   GET  /                        →  Dashboard (auto-refreshes every 3 s)
 *   POST /oauth/authorize         →  Auto-redirect with code (uses active scenario — no page shown)
 *   POST /oauth/deny              →  Redirect with error=access_denied
 *   POST /oauth/token             →  Token exchange (called by HRF BE)
 *   GET  /:version/scrt/user/self →  User info (called by HRF BE)
 *   POST /api/set-scenario        →  Set the active scenario (dashboard form)
 *   POST /api/reset               →  Clear all sessions + log
 *   GET  /api/sessions            →  JSON list of active sessions
 *   GET  /api/simulate            →  IdP-initiated login — redirect to HRF callback
 *
 * USAGE
 * ─────
 *   node tools/emplx-mock-server.js
 *   PORT=4444 node tools/emplx-mock-server.js
 *
 * DB CONFIGURATION (external_partner_integration WHERE partnerName='emplx')
 * ─────────────────────────────────────────────────────────────────────────
 *   providerBaseUrl  = http://localhost:3333
 *   clientId         = mock-client-id
 *   clientSecret     = mock-client-secret
 *   apiVersion       = v1
 */
'use strict';

const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3333', 10);

// ─── In-memory state ──────────────────────────────────────────────────────────

/** @type {Map<string, {scenario: string, data: object, tokenFail: boolean, userInfoFail: boolean, usedAt?: string}>} */
const sessions = new Map();

/** @type {Array<{time: string, method: string, path: string, status: number, note: string}>} */
const requestLog = [];

/**
 * Active scenario used when HRF redirects to GET /oauth/authorize.
 * Set via POST /api/set-scenario from the dashboard.
 */
let activeScenario = 'new-superadmin';
let activeCustomData = null;
let activeTokenFail = false;
let activeUserInfoFail = false;

// ─── Scenario presets ─────────────────────────────────────────────────────────
//
// UUID strategy:
//   new-superadmin  → uuid = "emplx-uuid-sa-001"
//   existing-user   → same uuid ("emplx-uuid-sa-001")
//
// This means: run "new-superadmin" first to create the external_entity_mapping
// in HRF DB, then run "existing-user" to verify the fast-return (no polling) path.

const PRESETS = {
  'new-superadmin': {
    label: 'New SuperAdmin (full provisioning)',
    description:
      'isSuperAdmin=true — HRF creates role, user, employee, org structure. Returns queueId and polls until completed.',
    tokenFail: false,
    userInfoFail: false,
    data: {
      results: {
        userProfile: {
          companyUuid: 'leader-dinh-hai',
          userUuid: 'emplx-uuid-sa-001',
          userName: 'JOHN.ADMIN',
          identificationNo: 'emplxuser-sa',
          effectiveDate: '2024-01-01',
          pwdExpiryDate: '9999-12-31 23:59:59',
          disableDate: null,
          isSuperAdmin: true,
        },
        employeeProfile: {
          adminDeptAccess: [],
          employeeNo: 'EMP001',
          designation: 'SYSTEM ADMINISTRATOR',
          firstName: 'John',
          lastName: 'Admin',
          displayName: 'John Admin',
          idNew: '',
          idOld: '',
          birthDate: '1990-01-15',
          gender: 'Male',
          race: '',
          religion: '',
          nationality: 'Thailand',
          maritalStatus: 'Single',
          streetAddress1: '',
          streetAddress2: '',
          streetAddress3: '',
          postalCode: '10100',
          city: 'Bangkok',
          state: 'Bangkok',
          country: { countryName: 'Thailand', countryShortname: 'TH' },
          emailAddr: 'john.admin1@demo-company.com',
          cellPhone: '+66812345678',
          homePhone: '',
          officePhone: '',
          faxNo: '',
          hireDate: '2024-01-01',
          rehireDate: null,
          resignDate: null,
          photo: '',
          createdDate: '2024-01-01 00:00:00',
          createdBy: 1,
          modifiedDate: '2024-01-01 00:00:00',
          modifiedBy: 1,
          disableDate: null,
          location: 'Bangkok',
          probationPeriod: '3',
          confirmed: 1,
          resignReason: '',
          healthStatus: 1,
          taxGroupCategory: '',
          taxableFlag: 1,
          resignReason1: null,
          probationEndDate: '2024-04-01',
          adjustedHireDate: null,
          confirmationDate: '2024-04-02',
          nickname: '',
          personalEmail: null,
          residenceType: '',
          residenceCountryOfBirth: null,
          residenceEffectiveDate: null,
          personalId: null,
          employeeUuid: 'emp-uuid-sa-001',
          retirementDate: null,
          cellPhoneCountryCode: null,
          officePhoneCountryCode: null,
          homePhoneCountryCode: null,
          faxNoCountryCode: null,
          deptName: 'Management',
        },
        additionalAddress: [],
      },
    },
  },

  'new-employee': {
    label: 'New Employee (ESS-only)',
    description:
      'isSuperAdmin=false — HRF creates employee record only (ESS user, no asp_net_users entry). Polling required.',
    tokenFail: false,
    userInfoFail: false,
    data: {
      results: {
        userProfile: {
          companyUuid: 'leader-dinh-hai',
          userUuid: 'emplx-uuid-emp-001',
          userName: 'JANE.EMPLOYEE',
          identificationNo: 'emplxuser-emp',
          effectiveDate: '2024-03-01',
          pwdExpiryDate: '9999-12-31 23:59:59',
          disableDate: null,
          isSuperAdmin: false,
        },
        employeeProfile: {
          adminDeptAccess: [],
          employeeNo: 'EMP002',
          designation: 'HR OFFICER',
          firstName: 'Jane',
          lastName: 'Employee',
          displayName: 'Jane Employee',
          idNew: '',
          idOld: '',
          birthDate: '1995-06-20',
          gender: 'Female',
          race: '',
          religion: '',
          nationality: 'Thailand',
          maritalStatus: 'Single',
          streetAddress1: '',
          streetAddress2: '',
          streetAddress3: '',
          postalCode: '10110',
          city: 'Bangkok',
          state: 'Bangkok',
          country: { countryName: 'Thailand', countryShortname: 'TH' },
          emailAddr: 'jane.employee@demo-company.com',
          cellPhone: '+66898765432',
          homePhone: '',
          officePhone: '',
          faxNo: '',
          hireDate: '2024-03-01',
          rehireDate: null,
          resignDate: null,
          photo: '',
          createdDate: '2024-03-01 00:00:00',
          createdBy: 1,
          modifiedDate: '2024-03-01 00:00:00',
          modifiedBy: 1,
          disableDate: null,
          location: 'Bangkok',
          probationPeriod: '3',
          confirmed: 0,
          resignReason: '',
          healthStatus: 1,
          taxGroupCategory: '',
          taxableFlag: 1,
          resignReason1: null,
          probationEndDate: '2024-06-01',
          adjustedHireDate: null,
          confirmationDate: null,
          nickname: '',
          personalEmail: null,
          residenceType: '',
          residenceCountryOfBirth: null,
          residenceEffectiveDate: null,
          personalId: null,
          employeeUuid: 'emp-uuid-emp-001',
          retirementDate: null,
          cellPhoneCountryCode: null,
          officePhoneCountryCode: null,
          homePhoneCountryCode: null,
          faxNoCountryCode: null,
          deptName: 'Human Resource',
        },
        additionalAddress: [],
      },
    },
  },

  'existing-user': {
    label: 'Existing User (fast-return)',
    description:
      'UUID matches existing external_entity_mapping row — HRF returns token immediately, no polling. Use after "new-superadmin" has run once.',
    tokenFail: false,
    userInfoFail: false,
    data: {
      results: {
        userProfile: {
          companyUuid: 'leader-dinh-hai',
          userUuid: 'emplx-uuid-sa-001', // Same UUID as new-superadmin
          userName: 'JOHN.ADMIN',
          identificationNo: 'emplxuser-sa',
          effectiveDate: '2024-01-01',
          pwdExpiryDate: '9999-12-31 23:59:59',
          disableDate: null,
          isSuperAdmin: true,
        },
        employeeProfile: {
          adminDeptAccess: [],
          employeeNo: 'EMP001',
          designation: 'SYSTEM ADMINISTRATOR',
          firstName: 'John',
          lastName: 'Admin',
          displayName: 'John Admin',
          idNew: '',
          idOld: '',
          birthDate: '1990-01-15',
          gender: 'Male',
          nationality: 'Thailand',
          emailAddr: 'john.admin@demo-company.com',
          cellPhone: '+66812345678',
          hireDate: '2024-01-01',
          rehireDate: null,
          resignDate: null,
          photo: '',
          disableDate: null,
          location: 'Bangkok',
          confirmed: 1,
          employeeUuid: 'emp-uuid-sa-001',
          retirementDate: null,
          deptName: 'Management',
        },
        additionalAddress: [],
      },
    },
  },

  'token-fail': {
    label: 'Token Exchange Failure',
    description:
      'POST /oauth/token returns HTTP 500. HRF BE throws TOKEN_EXCHANGE_FAILED (HTTP 502).',
    tokenFail: true,
    userInfoFail: false,
    data: {
      results: {
        userProfile: {
          companyUuid: 'leader-dinh-hai',
          userUuid: 'emplx-uuid-tokenfail',
          isSuperAdmin: false,
        },
        employeeProfile: {},
        additionalAddress: [],
      },
    },
  },

  'userinfo-fail': {
    label: 'User Info Failure',
    description:
      'GET /scrt/user/self returns HTTP 500. HRF BE throws PROVIDER_API_FAILED (HTTP 502). Token exchange succeeds.',
    tokenFail: false,
    userInfoFail: true,
    data: {
      results: {
        userProfile: {
          companyUuid: 'leader-dinh-hai',
          userUuid: 'emplx-uuid-userinfofail',
          isSuperAdmin: false,
        },
        employeeProfile: {},
        additionalAddress: [],
      },
    },
  },

  custom: {
    label: 'Custom Data',
    description:
      'Edit the JSON below to define any user profile. Can also simulate failures.',
    tokenFail: false,
    userInfoFail: false,
    data: {
      results: {
        userProfile: {
          companyUuid: 'leader-dinh-hai',
          userUuid: 'custom-user-uuid-change-me',
          userName: 'CUSTOM.USER',
          identificationNo: 'emplxuser-custom',
          effectiveDate: '2025-01-01',
          pwdExpiryDate: '9999-12-31 23:59:59',
          disableDate: null,
          isSuperAdmin: true,
        },
        employeeProfile: {
          adminDeptAccess: [],
          employeeNo: 'EMP999',
          designation: 'ENGINEER',
          firstName: 'Custom',
          lastName: 'User',
          displayName: 'Custom User',
          idNew: '',
          idOld: '',
          birthDate: '1988-05-10',
          gender: 'Male',
          race: '',
          religion: '',
          nationality: 'Thailand',
          maritalStatus: 'Single',
          streetAddress1: '',
          streetAddress2: '',
          streetAddress3: '',
          postalCode: '',
          city: 'Bangkok',
          state: 'Bangkok',
          country: { countryName: 'Thailand', countryShortname: 'TH' },
          emailAddr: 'custom@example.com',
          cellPhone: '+66800000000',
          homePhone: '',
          officePhone: '',
          faxNo: '',
          hireDate: '2025-01-01',
          rehireDate: null,
          resignDate: null,
          photo: '',
          createdDate: '2025-01-01 00:00:00',
          createdBy: 1,
          modifiedDate: '2025-01-01 00:00:00',
          modifiedBy: 1,
          disableDate: null,
          location: 'Bangkok',
          probationPeriod: '3',
          confirmed: 1,
          resignReason: '',
          healthStatus: 1,
          taxGroupCategory: '',
          taxableFlag: 1,
          resignReason1: null,
          probationEndDate: '2025-04-01',
          adjustedHireDate: null,
          confirmationDate: '2025-04-02',
          nickname: '',
          personalEmail: null,
          residenceType: '',
          residenceCountryOfBirth: null,
          residenceEffectiveDate: null,
          personalId: null,
          employeeUuid: 'emp-uuid-custom-change-me',
          retirementDate: null,
          cellPhoneCountryCode: null,
          officePhoneCountryCode: null,
          homePhoneCountryCode: null,
          faxNoCountryCode: null,
          deptName: 'Engineering',
        },
        additionalAddress: [],
      },
    },
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateCode() {
  return crypto.randomBytes(16).toString('hex');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function logRequest(method, path, status, note = '') {
  requestLog.unshift({
    time: new Date().toISOString(),
    method,
    path,
    status,
    note,
  });
  if (requestLog.length > 100) requestLog.pop();
  const icon = status >= 500 ? '✗' : status >= 400 ? '!' : '✓';
  console.log(
    `  ${icon} ${method.padEnd(5)} ${String(status)} ${path}${note ? `  ← ${note}` : ''}`,
  );
}

function jsonResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(JSON.stringify(data, null, 2));
}

function htmlResponse(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Authorization page HTML ──────────────────────────────────────────────────

function renderAuthPage(params) {
  const { client_id = '', redirect_uri = '', state = '' } = params;
  let redirectDomain = '';
  try {
    redirectDomain = new URL(redirect_uri).origin;
  } catch {
    redirectDomain = redirect_uri;
  }

  const presetsJson = JSON.stringify(PRESETS).replace(
    /<\/script>/gi,
    '<\\/script>',
  );

  const scenarioCards = Object.entries(PRESETS)
    .map(
      ([key, preset], i) => `
    <label class="s-card${i === 0 ? ' selected' : ''}" for="s-${key}" onclick="selectScenario('${key}')">
      <input type="radio" name="scenario" id="s-${key}" value="${key}"${i === 0 ? ' checked' : ''}>
      <div>
        <div class="s-label">${escapeHtml(preset.label)}</div>
        <div class="s-desc">${escapeHtml(preset.description)}</div>
      </div>
    </label>`,
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emplx Authorization — Mock Server</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.badge{background:#fbbf24;color:#78350f;font-size:11px;font-weight:700;padding:2px 8px;border-radius:12px;text-transform:uppercase;letter-spacing:.5px;display:inline-block;margin-bottom:10px}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.12);padding:36px;width:100%;max-width:560px}
.logos{display:flex;align-items:center;gap:14px;margin-bottom:24px}
.logo{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;color:#fff;letter-spacing:-1px}
.logo-ex{background:linear-gradient(135deg,#6B4FBB,#9333EA)}
.logo-hrf{background:linear-gradient(135deg,#2563EB,#3B82F6)}
.arrow{color:#9ca3af;font-size:22px}
h1{font-size:20px;font-weight:700;color:#111827;margin-bottom:6px}
.sub{font-size:14px;color:#6b7280;margin-bottom:20px}
.sub strong{color:#374151}
.meta{display:flex;align-items:center;gap:8px;padding:9px 12px;background:#f9fafb;border-radius:8px;margin-bottom:6px;font-size:13px}
.meta-key{color:#6b7280;font-weight:500;min-width:80px}
.meta-val{color:#111827;font-family:monospace;font-size:12px;word-break:break-all}
.sec-title{font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.5px;margin:20px 0 8px}
.s-card{display:flex;align-items:flex-start;gap:10px;padding:11px 13px;border:2px solid #e5e7eb;border-radius:10px;margin-bottom:6px;cursor:pointer;transition:border-color .12s,background .12s}
.s-card.selected,.s-card:has(input:checked){border-color:#7C3AED;background:#faf5ff}
.s-card input{margin-top:3px;accent-color:#7C3AED;flex-shrink:0}
.s-label{font-size:13px;font-weight:600;color:#111827}
.s-desc{font-size:12px;color:#6b7280;margin-top:2px;line-height:1.4}
.custom-section{display:none;margin-top:10px}
.custom-section textarea{width:100%;font-family:'Menlo','Monaco',monospace;font-size:12px;border:1px solid #d1d5db;border-radius:8px;padding:10px;height:240px;resize:vertical;outline:none;color:#1f2937;line-height:1.5}
.custom-section textarea:focus{border-color:#7C3AED;box-shadow:0 0 0 3px rgba(124,58,237,.1)}
.fail-checks{display:flex;gap:16px;margin-top:10px}
.fail-checks label{display:flex;align-items:center;gap:6px;font-size:13px;color:#374151;cursor:pointer}
.fail-checks input{accent-color:#DC2626}
.btn{display:block;width:100%;padding:13px;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;border:none;transition:background .12s;margin-top:10px}
.btn-auth{background:#7C3AED;color:#fff}
.btn-auth:hover{background:#6D28D9}
.btn-deny{background:#f3f4f6;color:#6b7280;font-size:13px;padding:10px;margin-top:6px}
.btn-deny:hover{background:#e5e7eb}
.footer{margin-top:14px;text-align:center;font-size:12px;color:#9ca3af}
.footer a{color:#7C3AED;text-decoration:none}
</style>
</head>
<body>
<div class="card">
  <span class="badge">Mock Server — Test Mode</span>
  <div class="logos">
    <div class="logo logo-ex">EX</div>
    <div class="arrow">&#8594;</div>
    <div class="logo logo-hrf">HRF</div>
  </div>
  <h1>Authorize Access</h1>
  <p class="sub">Application <strong>${escapeHtml(client_id)}</strong> is requesting access to your Emplx account.</p>
  <div class="meta"><span class="meta-key">Client ID</span><span class="meta-val">${escapeHtml(client_id)}</span></div>
  <div class="meta"><span class="meta-key">Redirect to</span><span class="meta-val">${escapeHtml(redirectDomain)}</span></div>

  <form method="POST" action="/oauth/authorize" id="authForm">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
    <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
    <input type="hidden" name="state" value="${escapeHtml(state)}">
    <input type="hidden" id="scenarioHidden" name="scenario" value="new-superadmin">
    <input type="hidden" id="customDataHidden" name="custom_data">
    <input type="hidden" id="customTokenFail" name="custom_token_fail" value="0">
    <input type="hidden" id="customUserInfoFail" name="custom_user_info_fail" value="0">

    <div class="sec-title">Select Test Scenario</div>
    ${scenarioCards}

    <div class="custom-section" id="customSection">
      <div class="sec-title" style="margin-top:12px">User Data JSON</div>
      <textarea id="customTextarea" spellcheck="false"></textarea>
      <div class="fail-checks">
        <label><input type="checkbox" id="chkTokenFail" onchange="syncChecks()"> Simulate token fail</label>
        <label><input type="checkbox" id="chkUserInfoFail" onchange="syncChecks()"> Simulate user info fail</label>
      </div>
    </div>

    <button type="submit" class="btn btn-auth" onclick="return prepareSubmit()">Authorize Access &#8594;</button>
  </form>
  <form method="POST" action="/oauth/deny">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
    <input type="hidden" name="state" value="${escapeHtml(state)}">
    <button type="submit" class="btn btn-deny">Deny / Cancel</button>
  </form>
</div>
<div class="footer">
  <a href="/" target="_blank">Mock Server Dashboard</a> &middot; Port ${PORT}
</div>
<script>
const PRESETS = ${presetsJson};
function selectScenario(key) {
  document.getElementById('scenarioHidden').value = key;
  document.querySelectorAll('.s-card').forEach(el => el.classList.remove('selected'));
  const card = document.getElementById('s-' + key);
  if (card) card.closest('.s-card').classList.add('selected');
  const isCustom = key === 'custom';
  document.getElementById('customSection').style.display = isCustom ? 'block' : 'none';
  if (isCustom && PRESETS[key]) {
    document.getElementById('customTextarea').value = JSON.stringify(PRESETS[key].data, null, 2);
  }
}
function syncChecks() {
  document.getElementById('customTokenFail').value = document.getElementById('chkTokenFail').checked ? '1' : '0';
  document.getElementById('customUserInfoFail').value = document.getElementById('chkUserInfoFail').checked ? '1' : '0';
}
function prepareSubmit() {
  const key = document.getElementById('scenarioHidden').value;
  if (key === 'custom') {
    try {
      JSON.parse(document.getElementById('customTextarea').value);
      document.getElementById('customDataHidden').value = document.getElementById('customTextarea').value;
    } catch(e) {
      alert('Invalid JSON: ' + e.message);
      return false;
    }
  }
  return true;
}
selectScenario('new-superadmin');
</script>
</body>
</html>`;
}

// ─── Dashboard HTML ───────────────────────────────────────────────────────────

function renderDashboard() {
  const sessionsHtml =
    sessions.size === 0
      ? '<p class="empty">No active sessions</p>'
      : Array.from(sessions.entries())
          .map(([code, s]) => {
            const preset = PRESETS[s.scenario];
            const flags = [];
            if (s.tokenFail)
              flags.push('<span class="flag flag-err">token-fail</span>');
            if (s.userInfoFail)
              flags.push('<span class="flag flag-err">userinfo-fail</span>');
            return `<div class="session">
          <div class="sess-code">code: ${code.slice(0, 10)}…</div>
          <div class="sess-label">${escapeHtml(preset ? preset.label : s.scenario)} ${flags.join('')}</div>
          <div class="sess-uuid">uuid: ${escapeHtml(String((s.data && s.data.results && s.data.results.userProfile && s.data.results.userProfile.userUuid) || 'N/A'))}</div>
          <div class="sess-meta">${s.usedAt ? `<span class="used">Token exchanged ${s.usedAt.slice(11, 19)}</span>` : '<span class="unused">Awaiting token exchange</span>'}</div>
        </div>`;
          })
          .join('');

  const scenarioOptions = Object.entries(PRESETS)
    .map(([key, p]) => `<option value="${key}">${escapeHtml(p.label)}</option>`)
    .join('');

  const activePreset = PRESETS[activeScenario] || PRESETS['new-superadmin'];
  const activeScenarioCards = Object.entries(PRESETS)
    .map(
      ([key, p]) => `
      <label class="s-opt${key === activeScenario ? ' active-sel' : ''}" for="as-${key}" onclick="selectActive('${key}')">
        <input type="radio" name="active_scenario" id="as-${key}" value="${key}"${key === activeScenario ? ' checked' : ''}>
        <div>
          <div class="s-opt-label">${escapeHtml(p.label)}</div>
          <div class="s-opt-desc">${escapeHtml(p.description)}</div>
        </div>
      </label>`,
    )
    .join('');

  const logHtml =
    requestLog
      .slice(0, 30)
      .map(r => {
        const cls = r.status >= 500 ? 'err' : r.status >= 400 ? 'warn' : 'ok';
        return `<div class="log-row">
      <span class="log-time">${r.time.slice(11, 19)}</span>
      <span class="log-meth log-${r.method}">${r.method}</span>
      <span class="log-path">${escapeHtml(r.path)}</span>
      <span class="log-stat log-${cls}">${r.status}</span>
      ${r.note ? `<span class="log-note">${escapeHtml(r.note)}</span>` : ''}
    </div>`;
      })
      .join('') || '<p class="empty">No requests yet</p>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emplx Mock Server</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:24px}
h1{font-size:22px;font-weight:700;color:#f8fafc;margin-bottom:2px}
.sub{font-size:13px;color:#64748b;margin-bottom:24px}
.badge{background:#fbbf24;color:#78350f;font-size:11px;font-weight:700;padding:2px 8px;border-radius:12px;text-transform:uppercase;margin-right:10px;vertical-align:middle}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
@media(max-width:860px){.grid{grid-template-columns:1fr}}
.card{background:#1e293b;border-radius:12px;padding:20px}
.card h2{font-size:12px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px}
.cfg-row{display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid #0f172a;font-size:13px}
.cfg-key{color:#64748b;min-width:120px;font-weight:500;flex-shrink:0}
.cfg-val{color:#7dd3fc;font-family:monospace;word-break:break-all}
.ep{background:#0f172a;border-radius:8px;padding:9px 12px;margin-bottom:6px;font-size:12px}
.ep-meth{font-weight:700;margin-right:8px;font-family:monospace}
.ep-GET{color:#34d399}.ep-POST{color:#60a5fa}
.ep-path{color:#e2e8f0;font-family:monospace}
.ep-desc{color:#64748b;margin-top:3px;font-family:sans-serif}
.session{background:#0f172a;border-radius:8px;padding:11px;margin-bottom:8px;font-size:12px}
.sess-code{color:#64748b;font-family:monospace}
.sess-label{color:#e2e8f0;font-weight:600;margin:4px 0 2px}
.sess-uuid{color:#64748b;font-family:monospace}
.sess-meta{margin-top:4px}
.used{color:#f59e0b}.unused{color:#34d399}
.flag{display:inline-block;font-size:10px;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:4px}
.flag-err{background:#7f1d1d;color:#fca5a5}
.log-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #1e293b;font-size:12px}
.log-time{color:#64748b;font-family:monospace;min-width:65px;flex-shrink:0}
.log-meth{font-weight:700;min-width:38px;font-family:monospace;flex-shrink:0}
.log-GET{color:#34d399}.log-POST{color:#60a5fa}
.log-path{color:#e2e8f0;font-family:monospace;flex:1;word-break:break-all}
.log-stat{font-weight:700;font-family:monospace;min-width:32px;flex-shrink:0}
.log-ok{color:#34d399}.log-warn{color:#f59e0b}.log-err{color:#f87171}
.log-note{color:#94a3b8;font-style:italic;font-size:11px;flex-shrink:0}
.empty{color:#475569;font-size:13px;text-align:center;padding:16px}
.btn-reset{background:#7f1d1d;color:#fca5a5;border:none;border-radius:6px;padding:5px 10px;font-size:11px;font-weight:700;cursor:pointer;float:right}
.btn-reset:hover{background:#991b1b}
.note-box{background:#172033;border-left:3px solid #7C3AED;border-radius:6px;padding:12px 14px;font-size:12px;color:#94a3b8;margin-top:12px;line-height:1.6}
.note-box strong{color:#c4b5fd}
.hdr{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.refresh{font-size:11px;color:#475569;text-align:right;margin-bottom:6px}
.sim-label{font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}
.sim-input{width:100%;background:#0f172a;border:1px solid #334155;border-radius:7px;padding:8px 10px;color:#e2e8f0;font-family:monospace;font-size:12px;outline:none}
.sim-input:focus{border-color:#7C3AED}
.sim-select{width:100%;background:#0f172a;border:1px solid #334155;border-radius:7px;padding:8px 10px;color:#e2e8f0;font-size:13px;outline:none;cursor:pointer}
.sim-select:focus{border-color:#7C3AED}
.sim-row{margin-bottom:12px}
.btn-sim{width:100%;margin-top:4px;padding:11px;background:#7C3AED;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;letter-spacing:.2px}
.btn-sim:hover{background:#6D28D9}
.sim-hint{font-size:11px;color:#475569;margin-top:8px;line-height:1.5}
.active-badge{display:inline-block;background:#1e3a5f;color:#7dd3fc;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;font-family:monospace;margin-left:8px;vertical-align:middle}
.active-scenario-name{font-size:15px;font-weight:700;color:#f8fafc;margin-bottom:2px}
.active-scenario-desc{font-size:12px;color:#64748b;margin-bottom:14px;line-height:1.5}
.s-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px}
@media(max-width:600px){.s-grid{grid-template-columns:1fr}}
.s-opt{display:flex;align-items:flex-start;gap:8px;padding:9px 11px;border:2px solid #334155;border-radius:8px;cursor:pointer;transition:border-color .12s,background .12s;font-size:12px}
.s-opt.active-sel,.s-opt:has(input:checked){border-color:#7C3AED;background:#1e1535}
.s-opt input{margin-top:2px;accent-color:#7C3AED;flex-shrink:0}
.s-opt-label{font-weight:600;color:#e2e8f0;margin-bottom:2px}
.s-opt-desc{color:#64748b;line-height:1.35}
.btn-set{width:100%;margin-top:6px;padding:10px;background:#7C3AED;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer}
.btn-set:hover{background:#6D28D9}
.custom-area{display:none;margin-top:8px}
.custom-area textarea{width:100%;font-family:'Menlo','Monaco',monospace;font-size:11px;border:1px solid #334155;border-radius:7px;padding:8px;height:180px;resize:vertical;outline:none;color:#e2e8f0;line-height:1.4;background:#0f172a}
.custom-area textarea:focus{border-color:#7C3AED}
.fail-row{display:flex;gap:16px;margin-top:8px}
.fail-row label{display:flex;align-items:center;gap:5px;font-size:12px;color:#94a3b8;cursor:pointer}
.fail-row input{accent-color:#DC2626}
</style>
</head>
<body>
<div class="hdr">
  <span class="badge">Mock</span>
  <h1>Emplx SSO Mock Server</h1>
</div>
<p class="sub">Simulates the Emplx OAuth 2.0 provider &middot; Port ${PORT}</p>

<div class="grid">
  <div class="card">
    <h2>DB Configuration (external_partner_integration)</h2>
    <div class="cfg-row"><span class="cfg-key">partnerName</span><span class="cfg-val">emplx</span></div>
    <div class="cfg-row"><span class="cfg-key">providerBaseUrl</span><span class="cfg-val">http://localhost:${PORT}</span></div>
    <div class="cfg-row"><span class="cfg-key">clientId</span><span class="cfg-val">mock-client-id</span></div>
    <div class="cfg-row"><span class="cfg-key">clientSecret</span><span class="cfg-val">mock-client-secret</span></div>
    <div class="cfg-row"><span class="cfg-key">apiVersion</span><span class="cfg-val">v1</span></div>
    <div class="note-box">
      <strong>Tip — Existing User test:</strong><br>
      1. Run <strong>new-superadmin</strong> login once (creates external_entity_mapping in HRF DB).<br>
      2. Then run <strong>existing-user</strong> (same UUID <code>emplx-uuid-sa-001</code>) — HRF returns token immediately, no polling.
    </div>
  </div>

  <div class="card">
    <h2>Endpoints</h2>
    <div class="ep"><span class="ep-meth ep-POST">POST</span><span class="ep-path">/oauth/authorize</span><div class="ep-desc">Auto-redirects to HRF callback using the active scenario — no page shown</div></div>
    <div class="ep"><span class="ep-meth ep-POST">POST</span><span class="ep-path">/oauth/token</span><div class="ep-desc">Token exchange called by HRF BE (grant_type=authorization_code)</div></div>
    <div class="ep"><span class="ep-meth ep-GET">GET</span><span class="ep-path">/:version/scrt/user/self</span><div class="ep-desc">User info called by HRF BE (Bearer token auth)</div></div>
    <div class="ep"><span class="ep-meth ep-POST">POST</span><span class="ep-path">/api/set-scenario</span><div class="ep-desc">Set the active scenario used by GET /oauth/authorize</div></div>
    <div class="ep"><span class="ep-meth ep-GET">GET</span><span class="ep-path">/api/sessions</span><div class="ep-desc">JSON list of active mock sessions</div></div>
    <div class="ep"><span class="ep-meth ep-GET">GET</span><span class="ep-path">/api/simulate</span><div class="ep-desc">IdP-initiated login — generates code &amp; redirects to redirect_uri directly</div></div>
  </div>
</div>

<div class="card" style="margin-bottom:18px">
  <h2>Active Scenario <span class="active-badge">${escapeHtml(activeScenario)}</span></h2>
  <div class="active-scenario-name">${escapeHtml(activePreset.label)}</div>
  <div class="active-scenario-desc">${escapeHtml(activePreset.description)}</div>
  <form method="POST" action="/api/set-scenario" id="setScenarioForm">
    <input type="hidden" id="asHidden" name="scenario" value="${escapeHtml(activeScenario)}">
    <input type="hidden" id="asCustomData" name="custom_data" value="">
    <input type="hidden" id="asTokenFail" name="token_fail" value="${activeTokenFail ? '1' : '0'}">
    <input type="hidden" id="asUserInfoFail" name="user_info_fail" value="${activeUserInfoFail ? '1' : '0'}">
    <div class="s-grid">
      ${activeScenarioCards}
    </div>
    <div class="custom-area" id="asCustomArea">
      <div class="sim-label" style="margin-bottom:5px">Custom User Data JSON</div>
      <textarea id="asCustomTextarea" spellcheck="false">${activeScenario === 'custom' && activeCustomData ? escapeHtml(JSON.stringify(activeCustomData, null, 2)) : ''}</textarea>
      <div class="fail-row">
        <label><input type="checkbox" id="asChkToken" onchange="syncAsChecks()"${activeTokenFail ? ' checked' : ''}> Simulate token fail</label>
        <label><input type="checkbox" id="asChkUserInfo" onchange="syncAsChecks()"${activeUserInfoFail ? ' checked' : ''}> Simulate user info fail</label>
      </div>
    </div>
    <button type="submit" class="btn-set" onclick="return prepareAsSubmit()">Set Active Scenario</button>
  </form>
  <p class="sim-hint" style="margin-top:10px">
    This scenario is used automatically when HRF redirects to <code>GET /oauth/authorize</code>.
    No browser interaction needed — the server generates a code and bounces straight back to HRF's callback.
  </p>
</div>

<div class="card" style="margin-bottom:18px">
  <h2>Simulate Login from Emplx &#8594; HRF</h2>
  <p style="font-size:12px;color:#64748b;margin-bottom:14px;line-height:1.5">
    Simulates a user already logged into Emplx clicking <strong style="color:#c4b5fd">"Connect to HRF"</strong>.
    Generates an auth code and redirects straight to HRF's callback URL — no need to start the flow from HRF.
  </p>
  <form method="GET" action="/api/simulate">
    <div class="sim-row">
      <div class="sim-label">HRF Redirect URL</div>
      <input class="sim-input" type="text" name="redirect_uri"
        placeholder="https://dev.hrforte.com/auth/emplx-sso/callback"
        value="https://dev.hrforte.com/auth?provider=emplx">
    </div>
    <div class="sim-row">
      <div class="sim-label">Scenario</div>
      <select class="sim-select" name="scenario">${scenarioOptions}</select>
    </div>
    <div class="sim-row">
      <div class="sim-label">State (optional)</div>
      <input class="sim-input" type="text" name="state" placeholder="leave blank to auto-generate">
    </div>
    <button class="btn-sim" type="submit">Simulate Login &#8594;</button>
    <p class="sim-hint">This will redirect your browser to HRF's callback with <code>?code=…&state=…</code>, exactly as if Emplx had redirected after user consent.</p>
  </form>
</div>

<div class="grid">
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h2 style="margin:0">Active Sessions (${sessions.size})</h2>
      <form method="POST" action="/api/reset" style="display:inline">
        <button class="btn-reset" type="submit">Clear All</button>
      </form>
    </div>
    ${sessionsHtml}
  </div>

  <div class="card">
    <h2>Request Log</h2>
    ${logHtml}
  </div>
</div>
<script>
const AS_PRESETS = ${JSON.stringify(PRESETS).replace(/<\/script>/gi, '<\\/script>')};
function selectActive(key) {
  document.getElementById('asHidden').value = key;
  document.querySelectorAll('.s-opt').forEach(el => el.classList.remove('active-sel'));
  const lbl = document.getElementById('as-' + key);
  if (lbl) lbl.closest('.s-opt').classList.add('active-sel');
  const isCustom = key === 'custom';
  document.getElementById('asCustomArea').style.display = isCustom ? 'block' : 'none';
  if (isCustom && AS_PRESETS[key] && !document.getElementById('asCustomTextarea').value) {
    document.getElementById('asCustomTextarea').value = JSON.stringify(AS_PRESETS[key].data, null, 2);
  }
}
function syncAsChecks() {
  document.getElementById('asTokenFail').value = document.getElementById('asChkToken').checked ? '1' : '0';
  document.getElementById('asUserInfoFail').value = document.getElementById('asChkUserInfo').checked ? '1' : '0';
}
function prepareAsSubmit() {
  const key = document.getElementById('asHidden').value;
  if (key === 'custom') {
    try {
      JSON.parse(document.getElementById('asCustomTextarea').value);
      document.getElementById('asCustomData').value = document.getElementById('asCustomTextarea').value;
    } catch(e) {
      alert('Invalid JSON: ' + e.message);
      return false;
    }
  }
  return true;
}
// Show custom area on load if currently active
(function() {
  const cur = document.getElementById('asHidden').value;
  if (cur === 'custom') document.getElementById('asCustomArea').style.display = 'block';
})();
</script>
</body>
</html>`;
}

// ─── Request router ───────────────────────────────────────────────────────────

async function handleRequest(req, res) {
  const rawUrl = req.url || '/';
  const urlObj = new URL(rawUrl, `http://localhost:${PORT}`);
  const path = urlObj.pathname;
  const method = req.method || 'GET';

  // CORS pre-flight
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── Dashboard ──────────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/') {
    logRequest('GET', '/', 200, 'dashboard');
    htmlResponse(res, renderDashboard());
    return;
  }

  // ── GET|POST /oauth/authorize — auto-redirect using the active scenario ─────
  // HRF redirects the browser here (GET with query params) or posts directly.
  // We immediately generate a code and bounce back — no page shown.
  // Change the active scenario via the dashboard (POST /api/set-scenario).
  if ((method === 'GET' || method === 'POST') && path === '/oauth/authorize') {
    // Params are always in the query string — the FE submits a POST form whose
    // action URL already contains redirect_uri, state, etc. (no form fields).
    const params = Object.fromEntries(urlObj.searchParams.entries());
    const redirectUri = params.redirect_uri || '';
    const state = params.state || '';

    let sessionData;
    if (activeScenario === 'custom' && activeCustomData) {
      sessionData = {
        scenario: 'custom',
        data: activeCustomData,
        tokenFail: activeTokenFail,
        userInfoFail: activeUserInfoFail,
      };
    } else {
      const preset = PRESETS[activeScenario] || PRESETS['new-superadmin'];
      sessionData = {
        scenario: activeScenario,
        data: preset.data,
        tokenFail: preset.tokenFail,
        userInfoFail: preset.userInfoFail,
      };
    }

    if (!redirectUri) {
      logRequest(method, '/oauth/authorize', 400, 'Missing redirect_uri');
      jsonResponse(res, 400, { error: 'redirect_uri is required', params });
      return;
    }

    const code = generateCode();
    sessions.set(code, sessionData);

    const sep = redirectUri.includes('?') ? '&' : '?';
    const statePart = state ? `&state=${encodeURIComponent(state)}` : '';
    const callbackUrl = `${redirectUri}${sep}code=${code}${statePart}`;
    logRequest(
      method,
      '/oauth/authorize',
      302,
      `auto-redirect scenario=${activeScenario} code=${code.slice(0, 8)}… → ${callbackUrl.slice(0, 60)}…`,
    );
    redirect(res, callbackUrl);
    return;
  }

  // ── POST /oauth/deny ───────────────────────────────────────────────────────
  if (method === 'POST' && path === '/oauth/deny') {
    const body = await readBody(req);
    const form = new URLSearchParams(body);
    const redirectUri = form.get('redirect_uri') || '';
    const state = form.get('state') || '';
    logRequest('POST', '/oauth/deny', 302, 'User denied access');
    const sep = redirectUri.includes('?') ? '&' : '?';
    const statePart = state ? `&state=${encodeURIComponent(state)}` : '';
    redirect(
      res,
      `${redirectUri}${sep}error=access_denied&error_description=User+denied+access${statePart}`,
    );
    return;
  }

  // ── POST /oauth/token — token exchange ─────────────────────────────────────
  if (method === 'POST' && path === '/oauth/token') {
    const body = await readBody(req);
    let params;
    try {
      params = JSON.parse(body);
    } catch {
      params = Object.fromEntries(new URLSearchParams(body));
    }

    const code = String(params.code || '');
    const session = code ? sessions.get(code) : undefined;

    if (!session) {
      logRequest(
        'POST',
        '/oauth/token',
        400,
        `Unknown code: ${code.slice(0, 8) || '(empty)'}`,
      );
      jsonResponse(res, 400, {
        error: 'invalid_grant',
        error_description: 'Authorization code not found or expired',
      });
      return;
    }

    if (session.tokenFail) {
      logRequest(
        'POST',
        '/oauth/token',
        500,
        `Simulated failure (scenario=${session.scenario})`,
      );
      jsonResponse(res, 500, {
        error: 'server_error',
        error_description: 'Simulated token exchange failure',
      });
      return;
    }

    // Use code as access_token — simplifies /self lookup
    session.usedAt = new Date().toISOString();
    sessions.set(code, session);

    logRequest('POST', '/oauth/token', 200, `scenario=${session.scenario}`);
    jsonResponse(res, 200, {
      access_token: code,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read',
    });
    return;
  }

  // ── GET /:version/scrt/user/self — user info ───────────────────────────────
  // Matches /v1/scrt/user/self, /v2/scrt/user/self, etc.
  if (method === 'GET' && /^\/[^/]+\/scrt\/user\/self$/.test(path)) {
    const authHeader = req.headers['authorization'] || '';
    const accessToken = authHeader.replace(/^Bearer\s+/i, '').trim();
    const session = accessToken ? sessions.get(accessToken) : undefined;

    if (!session) {
      logRequest('GET', path, 401, 'Unknown or missing Bearer token');
      jsonResponse(res, 401, {
        error: 'invalid_token',
        error_description: 'Access token not found or expired',
      });
      return;
    }

    if (session.userInfoFail) {
      logRequest(
        'GET',
        path,
        500,
        `Simulated failure (scenario=${session.scenario})`,
      );
      jsonResponse(res, 500, {
        error: 'server_error',
        error_description: 'Simulated user info failure',
      });
      return;
    }

    logRequest(
      'GET',
      path,
      200,
      `uuid=${session.data && session.data.results && session.data.results.userProfile && session.data.results.userProfile.userUuid}, isSuperAdmin=${session.data && session.data.results && session.data.results.userProfile && session.data.results.userProfile.isSuperAdmin}`,
    );
    jsonResponse(res, 200, session.data);
    return;
  }

  // ── GET /api/simulate — IdP-initiated login (no HRF redirect needed) ───────
  // Generates a code for the chosen scenario and bounces the browser directly
  // to HRF's callback URL, simulating Emplx initiating the SSO flow.
  if (method === 'GET' && path === '/api/simulate') {
    const redirectUri = urlObj.searchParams.get('redirect_uri') || '';
    const scenario = urlObj.searchParams.get('scenario') || 'new-superadmin';
    const state =
      urlObj.searchParams.get('state') || crypto.randomBytes(8).toString('hex');

    if (!redirectUri) {
      logRequest('GET', '/api/simulate', 400, 'Missing redirect_uri');
      jsonResponse(res, 400, { error: 'redirect_uri is required' });
      return;
    }

    const preset = PRESETS[scenario];
    if (!preset) {
      logRequest('GET', '/api/simulate', 400, `Unknown scenario: ${scenario}`);
      jsonResponse(res, 400, { error: `Unknown scenario: ${scenario}` });
      return;
    }

    const code = generateCode();
    sessions.set(code, {
      scenario,
      data: preset.data,
      tokenFail: preset.tokenFail,
      userInfoFail: preset.userInfoFail,
    });

    const sep = redirectUri.includes('?') ? '&' : '?';
    const callbackUrl = `${redirectUri}${sep}code=${code}&state=${encodeURIComponent(state)}`;
    logRequest(
      'GET',
      '/api/simulate',
      302,
      `IdP-init scenario=${scenario} code=${code.slice(0, 8)}… → ${callbackUrl.slice(0, 60)}…`,
    );
    redirect(res, callbackUrl);
    return;
  }

  // ── POST /api/set-scenario — update active scenario used by GET /oauth/authorize
  if (method === 'POST' && path === '/api/set-scenario') {
    const body = await readBody(req);
    const form = new URLSearchParams(body);
    const scenario = form.get('scenario') || 'new-superadmin';

    if (scenario === 'custom') {
      const customDataRaw = form.get('custom_data') || '';
      try {
        activeCustomData = JSON.parse(customDataRaw);
      } catch (e) {
        logRequest('POST', '/api/set-scenario', 400, `Bad JSON: ${e.message}`);
        jsonResponse(res, 400, { error: `Invalid JSON: ${e.message}` });
        return;
      }
      activeTokenFail = form.get('token_fail') === '1';
      activeUserInfoFail = form.get('user_info_fail') === '1';
    } else if (!PRESETS[scenario]) {
      logRequest(
        'POST',
        '/api/set-scenario',
        400,
        `Unknown scenario: ${scenario}`,
      );
      jsonResponse(res, 400, { error: `Unknown scenario: ${scenario}` });
      return;
    }

    activeScenario = scenario;
    logRequest('POST', '/api/set-scenario', 302, `active → ${scenario}`);
    redirect(res, '/');
    return;
  }

  // ── POST /api/reset ────────────────────────────────────────────────────────
  if (method === 'POST' && path === '/api/reset') {
    const count = sessions.size;
    sessions.clear();
    requestLog.length = 0;
    logRequest('POST', '/api/reset', 302, `Cleared ${count} session(s)`);
    redirect(res, '/');
    return;
  }

  // ── GET /api/sessions ──────────────────────────────────────────────────────
  if (method === 'GET' && path === '/api/sessions') {
    logRequest('GET', '/api/sessions', 200);
    jsonResponse(
      res,
      200,
      Array.from(sessions.entries()).map(([code, s]) => ({
        code: code.slice(0, 10) + '…',
        scenario: s.scenario,
        uuid:
          s.data &&
          s.data.results &&
          s.data.results.userProfile &&
          s.data.results.userProfile.userUuid,
        tokenFail: s.tokenFail,
        userInfoFail: s.userInfoFail,
        usedAt: s.usedAt || null,
      })),
    );
    return;
  }

  // ── 404 ───────────────────────────────────────────────────────────────────
  logRequest(method, path, 404, 'Not found');
  jsonResponse(res, 404, {
    error: 'not_found',
    path,
    hint: 'See dashboard at http://localhost:' + PORT,
  });
}

// ─── Start server ─────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (err) {
    console.error('[UNHANDLED ERROR]', err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'internal_server_error',
          message: err.message,
        }),
      );
    }
  }
});

server.listen(PORT, () => {
  console.log(`
┌─────────────────────────────────────────────────────┐
│         Emplx SSO Mock Server — Running             │
├─────────────────────────────────────────────────────┤
│  Dashboard   →  http://localhost:${PORT}/              │
│  Authorize  →  http://localhost:${PORT}/oauth/authorize │
├─────────────────────────────────────────────────────┤
│  DB: external_partner_integration (partnerName=emplx)│
│    providerBaseUrl  = http://localhost:${PORT}         │
│    clientId         = mock-client-id                │
│    clientSecret     = mock-client-secret            │
│    apiVersion       = v1                            │
├─────────────────────────────────────────────────────┤
│  Scenarios available:                               │
│    new-superadmin   Full provisioning + polling     │
│    new-employee     ESS-only + polling              │
│    existing-user    Immediate token (no polling)    │
│    token-fail       Simulate TOKEN_EXCHANGE_FAILED  │
│    userinfo-fail    Simulate PROVIDER_API_FAILED    │
│    custom           Edit JSON freely                │
└─────────────────────────────────────────────────────┘
`);
});
