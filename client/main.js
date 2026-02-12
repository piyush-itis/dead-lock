/**
 * Deadlock - Password Manager
 * Zero-knowledge: All encryption/decryption happens in the browser
 */

// Web Crypto API (crypto.subtle) requires a secure context (HTTPS or localhost).
// HTTP over LAN (e.g. http://10.x.x.x:5173) is NOT secure, so crypto.subtle is undefined.
if (!window.crypto?.subtle) {
  document.body.innerHTML = `
    <div class="secure-context-error" style="
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 24px;
      font-family: 'DM Sans', sans-serif;
      text-align: center;
      background: #0d1117;
      color: #c9d1d9;
    ">
      <h1 style="font-size: 1.5rem; margin-bottom: 1rem;">🔒 Secure context required</h1>
      <p style="max-width: 420px; line-height: 1.6; margin-bottom: 1.5rem;">
        Encryption only works over HTTPS or localhost. You're likely on HTTP from another device (e.g. phone).
      </p>
      <p style="max-width: 420px; line-height: 1.6; margin-bottom: 1rem; color: #8b949e;">
        <strong>To use on your phone:</strong> Run <code style="background:#21262d;padding:2px 6px;border-radius:4px">npx ngrok http 5173</code> in a terminal, then open the <strong>https://</strong> URL on your phone.
      </p>
      <p style="font-size: 0.9rem; color: #6e7681;">
        Or use the app on this computer at <a href="http://localhost:5173" style="color:#58a6ff">localhost:5173</a>.
      </p>
    </div>
  `;
  throw new Error('Secure context required');
}

import { WORDLIST } from './wordlist.js';
import {
  generateMasterKey,
  generatePassword,
  setupNewUser,
  setupNewUserEmail,
  deriveFromMaster,
  deriveFromPassword,
  encryptVault,
  decryptVault,
  computeLoginHash,
  passwordStrength,
  checkPasswordBreach,
} from './crypto.js';

const API = '/api';

let state = {
  userId: null,
  salt: null,
  authHash: null,
  key: null,
  entries: [],
};

function $(sel, parent = document) {
  return parent.querySelector(sel);
}

function $$(sel, parent = document) {
  return parent.querySelectorAll(sel);
}

function uuid() {
  return crypto.randomUUID();
}

async function apiRegister(salt, loginHash, authHash) {
  const res = await fetch(`${API}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ salt, loginHash, authHash }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Registration failed');
  }
  return res.json();
}

async function apiLogin(loginHash) {
  const res = await fetch(`${API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ loginHash }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Invalid credentials');
  }
  return res.json();
}

async function apiGetVault(userId, authHash) {
  const res = await fetch(`${API}/vault`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, authHash }),
  });
  if (!res.ok) throw new Error('Failed to load vault');
  return res.json();
}

async function apiSaveVault(userId, authHash, encryptedData) {
  const res = await fetch(`${API}/vault`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, authHash, encryptedData }),
  });
  if (!res.ok) throw new Error('Failed to save vault');
  return res.json();
}

async function saveVault() {
  const payload = JSON.stringify({ entries: state.entries });
  const encrypted = await encryptVault(payload, state.key);
  await apiSaveVault(state.userId, state.authHash, encrypted);
}

function renderWelcome() {
  return `
    <div class="screen active" id="welcome">
      <div class="brand">
        <img src="/logo.png" alt="Deadlock" class="brand-logo" />
        
        <p class="brand-tagline">Zero-knowledge password manager. Your data is encrypted before it leaves your device.</p>
      </div>
      <div class="auth-card">
        <span class="auth-label">Create account</span>
        <div class="auth-buttons">
          <button class="btn-primary" data-action="generate">Master key</button>
          <button class="btn-outline" data-action="signup-email">Email & password</button>
        </div>
        <div class="auth-divider"><span>or</span></div>
        <span class="auth-label">Sign in</span>
        <div class="auth-buttons">
          <button class="btn-primary" data-action="login">Master key</button>
          <button class="btn-outline" data-action="login-email">Email & password</button>
        </div>
      </div>
    </div>
  `;
}

function renderGenerate() {
  const phrase = generateMasterKey(WORDLIST);
  return `
    <div class="screen active" id="generate">
      <h1>Your master key</h1>
      <p class="screen-desc">Write this down and store it safely. You cannot recover your account without it.</p>
      <div class="phrase-box" id="phraseBox">${phrase}</div>
      <button class="btn-secondary" id="copyPhrase" style="width: 100%;">Copy to clipboard</button>
      <div class="copy-hint" id="copyHint">Copied</div>
      <div class="warning">
        <strong>Warning:</strong> If you lose this key, all your passwords will be permanently unrecoverable. No one can help you — not even us.
      </div>
      <div class="actions">
        <button class="btn-secondary" data-action="back">Back</button>
        <button class="btn-primary" id="confirmGenerate" data-phrase="${escapeAttr(phrase)}">Create account</button>
      </div>
    </div>
  `;
}

function renderLogin() {
  const boxes = Array.from({ length: 12 }, (_, i) => 
    `<input type="text" class="phrase-word" data-idx="${i}" placeholder="${i + 1}" autocomplete="off" />`
  ).join('');
  return `
    <div class="screen active" id="login">
      <h1>Sign in with master key</h1>
      <p class="screen-desc">Enter or paste your 12-word recovery phrase</p>
      <label>Master key</label>
      <div class="phrase-grid" id="loginPhraseGrid">${boxes}</div>
      <div class="actions">
        <button class="btn-secondary" data-action="back">Back</button>
        <button class="btn-primary" id="doLogin">Sign in</button>
      </div>
    </div>
  `;
}

function renderSignupEmail() {
  return `
    <div class="screen active" id="signup-email">
      <h1>Create account</h1>
      <p class="screen-desc">Use a strong password. No recovery if forgotten.</p>
      <label for="signupEmail">Email</label>
      <input type="email" id="signupEmail" placeholder="you@example.com" autocomplete="email" />
      <label for="signupPassword">Password (min 8 characters)</label>
      <input type="password" id="signupPassword" placeholder="••••••••" autocomplete="new-password" />
      <div class="password-feedback" id="signupPasswordFeedback">
        <div class="strength-row">
          <span class="strength-label">Strength</span>
          <span class="strength-value" id="signupStrengthValue">—</span>
        </div>
        <div class="strength-bar">
          <div class="strength-fill" id="signupStrengthFill"></div>
        </div>
        <div class="breach-status" id="signupBreachStatus"></div>
      </div>
      <label for="signupConfirm">Confirm password</label>
      <input type="password" id="signupConfirm" placeholder="••••••••" autocomplete="new-password" />
      <div class="actions">
        <button class="btn-secondary" data-action="back">Back</button>
        <button class="btn-primary" id="doSignupEmail">Create account</button>
      </div>
    </div>
  `;
}

function renderLoginEmail() {
  return `
    <div class="screen active" id="login-email">
      <h1>Sign in</h1>
      <p class="screen-desc">Enter your email and password</p>
      <label for="loginEmail">Email</label>
      <input type="email" id="loginEmail" placeholder="you@example.com" autocomplete="email" />
      <label for="loginPassword">Password</label>
      <input type="password" id="loginPassword" placeholder="••••••••" autocomplete="current-password" />
      <div class="actions">
        <button class="btn-secondary" data-action="back">Back</button>
        <button class="btn-primary" id="doLoginEmail">Sign in</button>
      </div>
    </div>
  `;
}

function renderVault() {
  const oldEntries = state.entries.filter((e) => {
    const days = getPasswordAge(e.updatedAt);
    return days !== null && days >= PWD_AGE_DAYS_WARN;
  });
  const entriesHtml = state.entries.length
    ? state.entries
        .map(
          (e) => {
            const name = e.website || 'Unnamed';
            const initial = name.charAt(0).toUpperCase();
            const days = getPasswordAge(e.updatedAt);
            const ageStatus = getPasswordAgeStatus(days);
            const ageClass = ageStatus.status === 'urgent' ? 'age-urgent' : ageStatus.status === 'warn' ? 'age-warn' : '';
            return `
        <div class="entry ${ageClass}" data-id="${e.id}">
          <div class="entry-avatar">${initial}</div>
          <div class="entry-info">
            <div class="entry-name">${escapeHtml(name)}</div>
            <div class="entry-meta">${escapeHtml(e.username || '')}</div>
            <div class="entry-age" title="${escapeAttr(ageStatus.message)}">${formatPasswordAge(days)}</div>
          </div>
          <div class="entry-actions">
            <button class="btn-icon" data-copy data-id="${e.id}" title="Copy password">Copy</button>
            <button class="btn-icon" data-edit data-id="${e.id}" title="Edit">Edit</button>
            <button class="btn-icon btn-icon-danger" data-delete data-id="${e.id}" title="Delete">Delete</button>
          </div>
        </div>
      `;
          }
        )
        .join('')
    : '<div class="empty-state">No passwords yet.<br>Add your first one to get started.</div>';

  const ageAlertHtml = oldEntries.length > 0 ? `
      <div class="age-alert">
        <span class="age-alert-icon">⏰</span>
        <span>${oldEntries.length} password${oldEntries.length === 1 ? '' : 's'} over 90 days old — consider changing soon</span>
      </div>
  ` : '';

  return `
    <div class="screen active" id="vault">
      <div class="lockr-header">
        <div class="lockr-title">
          <h1>Lockr</h1>
          <span class="lockr-count">${state.entries.length} ${state.entries.length === 1 ? 'password' : 'passwords'}</span>
        </div>
        <button class="btn-ghost" data-action="logout">Log out</button>
      </div>
      ${ageAlertHtml}
      <div class="entry-list">${entriesHtml}</div>
      <button class="btn-primary btn-add" id="addEntry">
        <span class="btn-add-icon">+</span>
        Add password
      </button>
    </div>
  `;
}

function renderEntryModal(entry = null) {
  const isEdit = !!entry;
  const days = entry ? getPasswordAge(entry.updatedAt) : null;
  const ageStatus = getPasswordAgeStatus(days);
  const ageInfoHtml = isEdit ? `
        <div class="modal-age-info">
          <span class="modal-age-label">Last changed:</span> ${formatPasswordAge(days)}
          <span class="modal-age-hint">${ageStatus.message}</span>
        </div>
  ` : '';
  return `
    <div class="modal-overlay" id="entryModal">
      <div class="modal">
        <h2 class="modal-title">${isEdit ? 'Edit' : 'Add'} password</h2>
        ${ageInfoHtml}
        <label for="modalWebsite">Website / App / Service</label>
        <input type="text" id="modalWebsite" placeholder="example.com" value="${escapeAttr(entry?.website || '')}" />
        <label for="modalUsername">Username / Email</label>
        <input type="text" id="modalUsername" placeholder="user@example.com" value="${escapeAttr(entry?.username || '')}" />
        <label for="modalPassword">Password</label>
        <div class="password-field-row">
          <input type="password" id="modalPassword" placeholder="••••••••" value="${escapeAttr(entry?.password || '')}" autocomplete="off" />
          <button type="button" class="btn-secondary" id="generatePasswordBtn" title="Generate strong password">Suggest</button>
        </div>
        <div class="password-feedback">
          <div class="strength-row">
            <span class="strength-label">Strength</span>
            <span class="strength-value" id="modalStrengthValue">—</span>
          </div>
          <div class="strength-bar">
            <div class="strength-fill" id="modalStrengthFill"></div>
          </div>
          <div class="breach-status" id="modalBreachStatus"></div>
        </div>
        <div class="footer-actions">
          <button class="btn-secondary" data-modal-cancel>Cancel</button>
          <button class="btn-primary" data-modal-save data-id="${entry?.id || ''}">${isEdit ? 'Save' : 'Add'}</button>
        </div>
      </div>
    </div>
  `;
}

const PWD_AGE_DAYS_WARN = 90;
const PWD_AGE_DAYS_URGENT = 180;

function getPasswordAge(updatedAt) {
  if (!updatedAt) return null;
  const ts = typeof updatedAt === 'number' ? updatedAt : parseInt(updatedAt, 10);
  if (isNaN(ts)) return null;
  return Math.floor((Date.now() - ts) / (24 * 60 * 60 * 1000));
}

function formatPasswordAge(days) {
  if (days === null || days === undefined) return 'Unknown';
  if (days === 0) return 'Today';
  if (days === 1) return '1 day ago';
  if (days < 30) return `${days} days ago`;
  if (days < 60) return `${Math.floor(days / 30)} month ago`;
  if (days < 365) return `${Math.floor(days / 30)} months ago`;
  const y = Math.floor(days / 365);
  return y === 1 ? '1 year ago' : `${y} years ago`;
}

function getPasswordAgeStatus(days) {
  if (days === null || days === undefined) return { status: 'unknown', message: 'Change recommended every 90 days' };
  if (days < PWD_AGE_DAYS_WARN) return { status: 'ok', message: `Change within ${PWD_AGE_DAYS_WARN - days} days` };
  if (days < PWD_AGE_DAYS_URGENT) return { status: 'warn', message: `Overdue by ${days - PWD_AGE_DAYS_WARN} days — change soon` };
  return { status: 'urgent', message: `Overdue by ${days - PWD_AGE_DAYS_URGENT}+ days — change now` };
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function escapeAttr(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

function bindWelcome() {
  $('[data-action="generate"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderGenerate();
    bindGenerate();
  });
  $('[data-action="signup-email"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderSignupEmail();
    bindSignupEmail();
  });
  $('[data-action="login"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderLogin();
    bindLogin();
  });
  $('[data-action="login-email"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderLoginEmail();
    bindLoginEmail();
  });
}

function bindGenerate() {
  $('[data-action="back"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderWelcome();
    bindWelcome();
  });

  $('#copyPhrase')?.addEventListener('click', async () => {
    const phrase = $('#phraseBox')?.textContent;
    await navigator.clipboard.writeText(phrase);
    $('#copyHint')?.classList.add('visible');
    setTimeout(() => $('#copyHint')?.classList.remove('visible'), 1500);
  });

  $('#confirmGenerate')?.addEventListener('click', async () => {
    const phrase = $('#confirmGenerate')?.dataset.phrase;
    if (!phrase) return;
    const btn = $('#confirmGenerate');
    btn.disabled = true;
    btn.textContent = 'Creating...';
    try {
      const { salt, loginHash, authHash } = await setupNewUser(phrase);
      const { userId } = await apiRegister(salt, loginHash, authHash);
      const { key } = await deriveFromMaster(phrase, salt);
      state = { userId, salt, authHash, key, entries: [] };
      await saveVault();
      $('#app').innerHTML = renderVault();
      bindVault();
    } catch (e) {
      alert(e.message || 'Failed to create account');
      btn.disabled = false;
      btn.textContent = 'Create account';
    }
  });
}

function bindSignupEmail() {
  $('[data-action="back"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderWelcome();
    bindWelcome();
  });

  const signupPwd = $('#signupPassword');
  let signupBreachTimer = null;
  if (signupPwd) {
    const updateStrength = (pwd) => {
      const v = $('#signupStrengthValue');
      const f = $('#signupStrengthFill');
      const b = $('#signupBreachStatus');
      if (!v || !f) return;
      const strength = passwordStrength(pwd);
      v.textContent = pwd.length ? `${strength}%` : '—';
      f.style.width = `${strength}%`;
      f.className = 'strength-fill ' + (strength < 40 ? 'weak' : strength < 70 ? 'medium' : 'strong');
      if (!pwd || pwd.length < 4) {
        if (b) { b.textContent = ''; b.className = 'breach-status'; }
        return;
      }
      if (b) { b.textContent = 'Checking…'; b.className = 'breach-status breach-checking'; }
    };
    const runBreach = async (pwd) => {
      const b = $('#signupBreachStatus');
      if (!b || !pwd || pwd.length < 4) return;
      const r = await checkPasswordBreach(pwd);
      if (!b.parentElement) return;
      b.className = 'breach-status';
      if (r.error) {
        b.textContent = 'Unable to check breach status';
        b.classList.add('breach-error');
      } else if (r.breached) {
        b.textContent = `⚠️ Found in ${r.count?.toLocaleString() || 'a'} data breach${r.count !== 1 ? 'es' : ''}. Use a different password.`;
        b.classList.add('breach-found');
      } else {
        b.textContent = '✓ No known breaches';
        b.classList.add('breach-safe');
      }
    };
    signupPwd.addEventListener('input', () => {
      const pwd = signupPwd.value;
      updateStrength(pwd);
      clearTimeout(signupBreachTimer);
      if (pwd.length >= 4) signupBreachTimer = setTimeout(() => runBreach(pwd), 600);
      else {
        const b = $('#signupBreachStatus');
        if (b) { b.textContent = ''; b.className = 'breach-status'; }
      }
    });
  }

  $('#doSignupEmail')?.addEventListener('click', async () => {
    const email = $('#signupEmail')?.value?.trim().toLowerCase();
    const password = $('#signupPassword')?.value;
    const confirm = $('#signupConfirm')?.value;

    if (!email || !password) {
      alert('Please enter email and password');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      alert('Please enter a valid email address');
      return;
    }
    if (password.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }
    if (password !== confirm) {
      alert('Passwords do not match');
      return;
    }

    const btn = $('#doSignupEmail');
    btn.disabled = true;
    btn.textContent = 'Creating...';
    try {
      const { salt, loginHash, authHash } = await setupNewUserEmail(email, password);
      const { userId } = await apiRegister(salt, loginHash, authHash);
      const { key } = await deriveFromPassword(password, salt);
      state = { userId, salt, authHash, key, entries: [] };
      await saveVault();
      $('#app').innerHTML = renderVault();
      bindVault();
    } catch (e) {
      alert(e.message || 'Failed to create account');
      btn.disabled = false;
      btn.textContent = 'Create account';
    }
  });
}

function bindLoginEmail() {
  $('[data-action="back"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderWelcome();
    bindWelcome();
  });

  $('#doLoginEmail')?.addEventListener('click', async () => {
    const email = $('#loginEmail')?.value?.trim().toLowerCase();
    const password = $('#loginPassword')?.value;

    if (!email || !password) {
      alert('Please enter email and password');
      return;
    }

    const btn = $('#doLoginEmail');
    btn.disabled = true;
    btn.textContent = 'Signing in...';
    try {
      const loginHash = await computeLoginHash(email);
      const { userId, salt } = await apiLogin(loginHash);
      const { key, authHash } = await deriveFromPassword(password, salt);
      state = { userId, salt, authHash, key, entries: [] };
      const { encryptedData } = await apiGetVault(userId, authHash);
      if (encryptedData) {
        const raw = await decryptVault(encryptedData, key);
        const parsed = JSON.parse(raw);
        state.entries = (parsed.entries || []).map((e) => ({
          ...e,
          updatedAt: e.updatedAt ?? e.createdAt,
        }));
      }
      $('#app').innerHTML = renderVault();
      bindVault();
    } catch (e) {
      alert(e.message || 'Sign in failed');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  });
}

function bindLogin() {
  $('[data-action="back"]')?.addEventListener('click', () => {
    $('#app').innerHTML = renderWelcome();
    bindWelcome();
  });

  const grid = $('#loginPhraseGrid');
  if (grid) {
    const inputs = grid.querySelectorAll('.phrase-word');
    inputs.forEach((input, idx) => {
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData?.getData('text') || '').trim();
        const words = pasted.split(/\s+/).filter(Boolean);
        if (words.length >= 12) {
          words.slice(0, 12).forEach((w, i) => {
            inputs[i].value = w;
          });
        } else if (words.length > 0) {
          words.forEach((w, i) => {
            if (idx + i < 12) inputs[idx + i].value = w;
          });
        }
      });
      input.addEventListener('keydown', (e) => {
        if (e.key === ' ' || e.key === 'ArrowRight') {
          e.preventDefault();
          if (idx < 11) inputs[idx + 1].focus();
        }
        if (e.key === 'ArrowLeft' && idx > 0) inputs[idx - 1].focus();
        if (e.key === 'Backspace' && !input.value && idx > 0) {
          e.preventDefault();
          inputs[idx - 1].focus();
          inputs[idx - 1].value = '';
        }
      });
      input.addEventListener('input', (e) => {
        const val = input.value;
        if (val.includes(' ')) {
          const parts = val.split(/\s+/).filter(Boolean);
          input.value = parts[0] || '';
          parts.slice(1).forEach((w, i) => {
            if (idx + 1 + i < 12) inputs[idx + 1 + i].value = w;
          });
          const nextIdx = Math.min(idx + parts.length, 11);
          inputs[nextIdx].focus();
        }
      });
    });
  }

  $('#doLogin')?.addEventListener('click', async () => {
    const words = Array.from($$('.phrase-word', $('#login'))).map((i) => i.value.trim()).filter(Boolean);
    const phrase = words.join(' ');
    if (words.length !== 12) {
      alert('Master key must be exactly 12 words');
      return;
    }
    const btn = $('#doLogin');
    btn.disabled = true;
    btn.textContent = 'Signing in...';
    try {
      const loginHash = await computeLoginHash(phrase);
      const { userId, salt } = await apiLogin(loginHash);
      const { key, authHash } = await deriveFromMaster(phrase, salt);
      state = { userId, salt, authHash, key, entries: [] };
      const { encryptedData } = await apiGetVault(userId, authHash);
      if (encryptedData) {
        const raw = await decryptVault(encryptedData, key);
        const parsed = JSON.parse(raw);
        state.entries = (parsed.entries || []).map((e) => ({
          ...e,
          updatedAt: e.updatedAt ?? e.createdAt,
        }));
      }
      $('#app').innerHTML = renderVault();
      bindVault();
    } catch (e) {
      alert(e.message || 'Sign in failed');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  });
}

function bindVault() {
  $('[data-action="logout"]')?.addEventListener('click', () => {
    state = { userId: null, salt: null, authHash: null, key: null, entries: [] };
    $('#app').innerHTML = renderWelcome();
    bindWelcome();
  });

  $('#addEntry')?.addEventListener('click', () => {
    document.body.insertAdjacentHTML('beforeend', renderEntryModal());
    bindEntryModal(null);
  });

  $('#app').addEventListener('click', async (e) => {
    const id = e.target?.dataset?.id;
    if (e.target?.hasAttribute('data-copy') && id) {
      const entry = state.entries.find((x) => x.id === id);
      if (entry?.password) {
        try {
          await navigator.clipboard.writeText(entry.password);
          const btn = e.target;
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        } catch (err) {
          alert('Could not copy. Try selecting the password manually.');
        }
      }
      return;
    }
    if (e.target?.hasAttribute('data-edit') && id) {
      const entry = state.entries.find((x) => x.id === id);
      if (entry) {
        document.body.insertAdjacentHTML('beforeend', renderEntryModal(entry));
        bindEntryModal(entry);
      }
      return;
    }
    if (e.target?.hasAttribute('data-delete') && id) {
      state.entries = state.entries.filter((x) => x.id !== id);
      saveVault().then(() => {
        $('#app').innerHTML = renderVault();
        bindVault();
      });
    }
  });
}

function bindEntryModal(entry) {
  const modal = $('#entryModal');
  if (!modal) return;

  const cancel = () => {
    modal.remove();
  };

  modal.querySelector('[data-modal-cancel]')?.addEventListener('click', cancel);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) cancel();
  });

  const pwdInput = $('#modalPassword', modal);
  let breachTimer = null;

  const updatePasswordFeedback = (password) => {
    const strengthVal = $('#modalStrengthValue', modal);
    const strengthFill = $('#modalStrengthFill', modal);
    const breachStatus = $('#modalBreachStatus', modal);
    if (!strengthVal || !strengthFill || !breachStatus) return;

    const strength = passwordStrength(password);
    strengthVal.textContent = password.length ? `${strength}%` : '—';
    strengthFill.style.width = `${strength}%`;
    strengthFill.className = 'strength-fill ' + (strength < 40 ? 'weak' : strength < 70 ? 'medium' : 'strong');

    if (!password || password.length < 4) {
      breachStatus.textContent = '';
      breachStatus.className = 'breach-status';
      return;
    }
    breachStatus.textContent = 'Checking…';
    breachStatus.className = 'breach-status breach-checking';
  };

  const runBreachCheck = async (password) => {
    const breachStatus = $('#modalBreachStatus', modal);
    if (!breachStatus || !password || password.length < 4) return;
    const result = await checkPasswordBreach(password);
    if (!breachStatus.parentElement) return;
    breachStatus.className = 'breach-status';
    if (result.error) {
      breachStatus.textContent = 'Unable to check breach status';
      breachStatus.classList.add('breach-error');
    } else if (result.breached) {
      breachStatus.textContent = `⚠️ Found in ${result.count?.toLocaleString() || 'a'} data breach${result.count !== 1 ? 'es' : ''}. Use a different password.`;
      breachStatus.classList.add('breach-found');
    } else {
      breachStatus.textContent = '✓ No known breaches';
      breachStatus.classList.add('breach-safe');
    }
  };

  pwdInput?.addEventListener('input', () => {
    const pwd = pwdInput.value;
    updatePasswordFeedback(pwd);
    clearTimeout(breachTimer);
    if (pwd.length >= 4) {
      breachTimer = setTimeout(() => runBreachCheck(pwd), 600);
    } else {
      const breachStatus = $('#modalBreachStatus', modal);
      if (breachStatus) {
        breachStatus.textContent = '';
        breachStatus.className = 'breach-status';
      }
    }
  });

  if (entry?.password) {
    updatePasswordFeedback(entry.password);
    runBreachCheck(entry.password);
  } else {
    updatePasswordFeedback('');
  }

  $('#generatePasswordBtn', modal)?.addEventListener('click', () => {
    if (pwdInput) {
      pwdInput.value = generatePassword();
      pwdInput.dispatchEvent(new Event('input', { bubbles: true }));
      pwdInput.type = 'text';
      setTimeout(() => { pwdInput.type = 'password'; }, 2000);
    }
  });

  modal.querySelector('[data-modal-save]')?.addEventListener('click', async () => {
    const website = $('#modalWebsite', modal)?.value?.trim() || 'Unnamed';
    const username = $('#modalUsername', modal)?.value?.trim() || '';
    const password = $('#modalPassword', modal)?.value || '';
    const id = modal.querySelector('[data-modal-save]')?.dataset?.id;

    const now = Date.now();
    if (entry && id) {
      const idx = state.entries.findIndex((x) => x.id === id);
      if (idx >= 0) {
        state.entries[idx] = { ...state.entries[idx], website, username, password, updatedAt: now };
      }
    } else {
      state.entries.push({ id: uuid(), website, username, password, updatedAt: now });
    }
    modal.remove();
    await saveVault();
    $('#app').innerHTML = renderVault();
    bindVault();
  });
}

// Init
$('#app').innerHTML = renderWelcome();
bindWelcome();
