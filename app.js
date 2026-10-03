/**
 * app.js — Main application logic
 *
 * Responsibilities:
 *  - Screen routing (loading → setup → unlock → vault)
 *  - Setup wizard (3-step first-run flow)
 *  - Full unlock + quick-unlock (PIN/pattern session cache)
 *  - Vault CRUD (add, edit, delete entries)
 *  - Auto-save to GitHub after every change
 *  - Auto-lock on tab visibility loss / idle
 *  - Keyboard shortcuts
 *  - Password generator modal
 *
 * Dependencies (loaded before this script):
 *   crypto.js  → window.Crypto
 *   github.js  → window.GitHub
 *   ui.js      → Toast, Clipboard, PatternLock, PinInput, showModal, hideModal, uuid, escapeHtml, favicon, timeAgo
 */

'use strict';

// ─── Application State ────────────────────────────────────────────────────────

const state = {
  // Current active screen id
  screen: 'loading',

  // Decrypted vault data (null when locked)
  vault: null,

  // AES-256-GCM CryptoKey (null when locked)
  vaultKey: null,

  // Uint8Array — PBKDF2 salt embedded in vault.enc (stays constant for this vault)
  vaultSalt: null,

  // GitHub file SHA — needed for PUT (update) commits
  // Stored in sessionStorage so it survives lock/unlock within the same tab
  vaultSha: null,

  // localStorage config (non-sensitive)
  config: null,

  // Temporary state during setup wizard
  setup: {
    masterPw:    null,
    quickType:   'pin',    // 'pin' | 'pattern'
    quickSecret: null,
  },

  // Currently editing entry id (null = creating new)
  editingId: null,

  // Search filter string
  searchQuery: '',
};

// ─── Screen Management ────────────────────────────────────────────────────────

function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const el = document.getElementById(`screen-${name}`);
  if (el) el.classList.add('active');
  state.screen = name;
}

function setLoadingMsg(msg) {
  document.getElementById('loading-msg').textContent = msg;
}

// ─── Config (localStorage) ────────────────────────────────────────────────────
// Stores: github_owner, github_repo, github_path, quick_unlock_type
// Nothing sensitive — the vault URL is not secret.

const CONFIG_KEY = 'vault_config';

function loadConfig() {
  try {
    const raw = localStorage.getItem(CONFIG_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function saveConfig(config) {
  localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
  state.config = config;
}

function clearConfig() {
  localStorage.removeItem(CONFIG_KEY);
  state.config = null;
}

// ─── Session Storage Helpers ──────────────────────────────────────────────────

function sessionGet(key)        { return sessionStorage.getItem(key); }
function sessionSet(key, value) { sessionStorage.setItem(key, value); }
function sessionClear()         { sessionStorage.clear(); }

// ─── Initialisation ───────────────────────────────────────────────────────────

async function init() {
  showScreen('loading');
  setLoadingMsg('Checking configuration…');
  initPasswordToggles();
  initKeyboardShortcuts();

  const config = loadConfig();

  if (!config) {
    // First run — show setup wizard
    showScreen('setup');
    initSetupWizard();
    return;
  }

  state.config = config;

  // Try to fetch the vault blob from GitHub
  try {
    setLoadingMsg('Fetching encrypted vault…');
    const { blob, sha } = await GitHub.fetchVault(
      config.github_owner,
      config.github_repo,
      config.github_path || 'vault.enc'
    );

    // Store in memory and session
    state.vaultBlob = blob;
    sessionSet('vault_sha', sha);
    state.vaultSha  = sha;

    // Check if session has a wrapped key → offer quick unlock
    const wrappedKey = sessionGet('wrapped_key');

    showScreen('unlock');
    if (wrappedKey) {
      showQuickOnlyUnlock(config.quick_unlock_type);
    } else {
      showFullUnlock(config.quick_unlock_type);
    }

  } catch (err) {
    if (err.message === 'NOT_FOUND') {
      // vault.enc missing → assume stale config, re-run setup
      clearConfig();
      showScreen('setup');
      initSetupWizard();
    } else {
      setLoadingMsg(`⚠ Error: ${err.message}`);
    }
  }
}

// ─── Setup Wizard ─────────────────────────────────────────────────────────────

let setupPinInput    = null;
let setupPatternLock = null;

function initSetupWizard() {
  let currentStep = 1;

  // ── Step dot helpers ──
  function setStepDot(step) {
    document.querySelectorAll('.step-dot').forEach((d, i) => {
      d.classList.remove('active', 'done');
      if (i + 1 < step)  d.classList.add('done');
      if (i + 1 === step) d.classList.add('active');
    });
  }

  function goToStep(n) {
    document.querySelectorAll('.setup-step').forEach(s => s.classList.add('hidden'));
    const target = document.getElementById(`setup-step-${n}`);
    if (target) target.classList.remove('hidden');
    setStepDot(n);
    currentStep = n;
  }

  // ── Step 1: Master Password ──────────────────────────────────────────────

  const pwInput    = document.getElementById('setup-master-pw');
  const pwConfirm  = document.getElementById('setup-master-pw-confirm');
  const strengthBar  = document.getElementById('pw-strength-bar');
  const strengthLabel = document.getElementById('pw-strength-label');

  pwInput.addEventListener('input', () => {
    const { score, label } = Crypto.passwordStrength(pwInput.value);
    strengthBar.dataset.score = score;
    strengthBar.style.width   = score ? `${score * 25}%` : '0%';
    const colors = ['', '#ff4757', '#ffa502', '#ffec5c', '#2ed573'];
    strengthBar.style.background = colors[score] || '';
    strengthLabel.textContent     = label;
  });

  document.getElementById('setup-step1-next').addEventListener('click', () => {
    const pw  = pwInput.value;
    const cpw = pwConfirm.value;
    const err = document.getElementById('setup-step1-error');

    if (pw.length < 8) {
      showErr(err, 'Password must be at least 8 characters.');
      return;
    }
    if (pw !== cpw) {
      showErr(err, 'Passwords do not match.');
      return;
    }

    state.setup.masterPw = pw;
    err.classList.add('hidden');
    goToStep(2);
    initStep2();
  });

  // ── Step 2: Quick Unlock ─────────────────────────────────────────────────

  function initStep2() {
    const toggleBtns  = document.querySelectorAll('#quick-type-toggle .toggle-opt');
    const pinWrap     = document.getElementById('setup-pin-wrap');
    const patternWrap = document.getElementById('setup-pattern-wrap');
    const nextBtn     = document.getElementById('setup-step2-next');

    function setType(type) {
      state.setup.quickType   = type;
      state.setup.quickSecret = null;
      nextBtn.classList.add('hidden');

      toggleBtns.forEach(b => b.classList.toggle('active', b.dataset.type === type));

      if (type === 'pin') {
        pinWrap.classList.remove('hidden');
        patternWrap.classList.add('hidden');
        if (!setupPinInput) {
          setupPinInput = new PinInput({
            displayId:  'setup-pin-display',
            numpadId:   'setup-numpad',
            onComplete: pin => {
              state.setup.quickSecret = pin;
              nextBtn.classList.remove('hidden');
            },
          });
        } else {
          setupPinInput.reset();
        }
      } else {
        patternWrap.classList.remove('hidden');
        pinWrap.classList.add('hidden');
        if (!setupPatternLock) {
          setupPatternLock = new PatternLock(
            document.getElementById('setup-pattern-canvas'),
            {
              onChange: pattern => {
                if (pattern.length >= 4) {
                  state.setup.quickSecret = pattern.join('-');
                  nextBtn.classList.remove('hidden');
                } else {
                  state.setup.quickSecret = null;
                  nextBtn.classList.add('hidden');
                }
              },
            }
          );
        } else {
          setupPatternLock.reset();
        }
      }
    }

    toggleBtns.forEach(b => b.addEventListener('click', () => setType(b.dataset.type)));
    setType('pin');

    document.getElementById('setup-pattern-reset').addEventListener('click', () => {
      setupPatternLock?.reset();
    });

    document.getElementById('setup-step2-next').addEventListener('click', () => {
      if (!state.setup.quickSecret) return;
      goToStep(3);
    });
  }

  // ── Step 3: GitHub ───────────────────────────────────────────────────────

  document.getElementById('setup-step3-next').addEventListener('click', async () => {
    const owner  = document.getElementById('setup-gh-owner').value.trim();
    const repo   = document.getElementById('setup-gh-repo').value.trim();
    const pat    = document.getElementById('setup-gh-pat').value.trim();
    const errEl  = document.getElementById('setup-step3-error');
    const btn    = document.getElementById('setup-step3-next');

    if (!owner || !repo || !pat) {
      showErr(errEl, 'Please fill in all fields.');
      return;
    }

    errEl.classList.add('hidden');
    btn.classList.add('btn-loading');
    btn.disabled = true;

    try {
      // 1. Validate PAT + repo access
      await GitHub.validateAccess(owner, repo, pat);

      // 2. Check if vault.enc already exists
      const { exists, sha: existingSha } = await GitHub.checkVaultExists(owner, repo, 'vault.enc', pat);
      if (exists) {
        // Vault already exists — this is a new device connecting to an existing vault.
        // Try to decrypt it with the credentials entered in this wizard.
        const { masterPw, quickType, quickSecret } = state.setup;
        const masterSecret = masterPw + '\x00' + quickSecret;

        let blob, sha, data, key, salt;
        try {
          ({ blob, sha } = await GitHub.fetchVault(owner, repo, 'vault.enc', pat));
        } catch {
          showErr(errEl, 'Found an existing vault but could not fetch it. Check your network and try again.');
          return;
        }

        try {
          ({ data, key, salt } = await Crypto.decryptVault(blob, masterSecret));
        } catch {
          showErr(errEl,
            'A vault already exists in this repo but the master password or PIN/pattern is incorrect. ' +
            'Use the same credentials you chose when you first created the vault.'
          );
          return;
        }

        // ✅ Credentials match — connect this device to the existing vault
        const config = {
          github_owner:      owner,
          github_repo:       repo,
          github_path:       'vault.enc',
          quick_unlock_type: quickType,
          pin_length:        quickType === 'pin' ? quickSecret.length : null,
        };
        saveConfig(config);

        state.vault     = data;
        state.vaultKey  = key;
        state.vaultSalt = salt;
        state.vaultBlob = blob;
        state.vaultSha  = sha;
        sessionSet('vault_sha', sha);

        await cacheKeyForQuickUnlock(key, quickSecret);

        // Show success step with a "connected" message, then open vault
        document.querySelector('#setup-step-4 h2').textContent = 'Vault connected';
        document.querySelector('#setup-step-4 .hint').textContent =
          'This device is now connected to your existing vault.';
        goToStep(4);
        return;
      }

      // 3. Build the initial vault object
      const { masterPw, quickType, quickSecret } = state.setup;
      const masterSecret = masterPw + '\x00' + quickSecret;

      const initialVaultData = {
        version: 1,
        github_pat: pat,
        entries:    [],
        created_at: new Date().toISOString(),
      };

      // 4. Encrypt
      const { blob, key, salt } = await Crypto.createVault(masterSecret, initialVaultData);

      // 5. Commit vault.enc to GitHub
      const newSha = await GitHub.commitVault({
        content: blob,
        sha:     null,       // new file
        owner, repo,
        path:    'vault.enc',
        token:   pat,
      });

      // 6. Save config to localStorage
      const config = {
        github_owner:       owner,
        github_repo:        repo,
        github_path:        'vault.enc',
        quick_unlock_type:  quickType,
        // Store exact PIN length so unlock screen waits for the right number of digits
        pin_length: quickType === 'pin' ? quickSecret.length : null,
      };
      saveConfig(config);

      // 7. Load vault into state for immediate use
      state.vault     = initialVaultData;
      state.vaultKey  = key;
      state.vaultSalt = salt;
      state.vaultBlob = blob;
      state.vaultSha  = newSha;
      sessionSet('vault_sha', newSha);

      // 8. Wrap key for session quick-unlock
      await cacheKeyForQuickUnlock(key, quickSecret);

      goToStep(4);

    } catch (err) {
      let msg = err.message;
      if (msg === 'NOT_FOUND')   msg = 'Repository not found. Check the owner and repo name.';
      if (msg === 'UNAUTHORIZED') msg = 'Invalid token. Make sure the PAT has not expired.';
      if (msg === 'FORBIDDEN')   msg = 'Token does not have write access to this repo.';
      showErr(errEl, msg);
    } finally {
      btn.classList.remove('btn-loading');
      btn.disabled = false;
    }
  });

  // ── Step 4: Done ─────────────────────────────────────────────────────────

  document.getElementById('setup-done-btn').addEventListener('click', () => {
    showScreen('vault');
    renderVaultList();
  });
}

// ─── Unlock ───────────────────────────────────────────────────────────────────

// PIN/pattern input instances re-used across unlock modes
let unlockPinFull      = null;
let unlockPatternFull  = null;
let unlockPinQuick     = null;
let unlockPatternQuick = null;

/** Show full unlock (master password + quick secret) */
function showFullUnlock(quickType) {
  document.getElementById('unlock-full').classList.remove('hidden');
  document.getElementById('unlock-quick-only').classList.add('hidden');
  document.getElementById('unlock-error').classList.add('hidden');

  const wrap = document.getElementById('unlock-quick-input-wrap');
  wrap.innerHTML = '';

  if (quickType === 'pin') {
    const display = document.createElement('div');
    display.className = 'pin-dots';
    display.id        = 'unlock-pin-display';
    const numpad = document.createElement('div');
    numpad.className = 'numpad';
    numpad.id        = 'unlock-numpad';
    wrap.appendChild(display);
    wrap.appendChild(numpad);
    const pinLen = state.config?.pin_length || 8;
    unlockPinFull = new PinInput({ displayId: 'unlock-pin-display', numpadId: 'unlock-numpad', minLen: 4, maxLen: pinLen });
  } else {
    const label = document.createElement('p');
    label.className   = 'hint small';
    label.textContent = 'Draw your pattern';
    const canvas = document.createElement('canvas');
    canvas.id     = 'unlock-pattern-canvas';
    canvas.width  = 220;
    canvas.height = 220;
    wrap.appendChild(label);
    wrap.appendChild(canvas);
    unlockPatternFull = new PatternLock(canvas);
  }

  // Unlock button
  document.getElementById('unlock-btn').onclick = () => handleFullUnlock(quickType);

  // Enter key on password field
  document.getElementById('unlock-master-pw').onkeydown = e => {
    if (e.key === 'Enter') handleFullUnlock(quickType);
  };

  document.getElementById('unlock-master-pw').focus();
}

/** Show quick-only unlock (session has wrapped key — PIN/pattern only) */
function showQuickOnlyUnlock(quickType) {
  document.getElementById('unlock-full').classList.add('hidden');
  document.getElementById('unlock-quick-only').classList.remove('hidden');
  document.getElementById('unlock-quick-error').classList.add('hidden');

  const wrap = document.getElementById('unlock-quick-only-input-wrap');
  wrap.innerHTML = '';

  if (quickType === 'pin') {
    const pinLen = state.config?.pin_length || 8; // default 8 if old setup didn't save length

    const display = document.createElement('div');
    display.className = 'pin-dots';
    display.id        = 'unlock-quick-pin-display';

    const numpad = document.createElement('div');
    numpad.className = 'numpad';
    numpad.id        = 'unlock-quick-numpad';

    // Explicit unlock button — no more auto-submit confusion
    const unlockBtn = document.createElement('button');
    unlockBtn.className   = 'btn-primary';
    unlockBtn.textContent = 'Unlock';
    unlockBtn.style.marginTop = '4px';
    unlockBtn.onclick = () => handleQuickUnlock(unlockPinQuick.getPin());

    const center = document.createElement('div');
    center.style.display       = 'flex';
    center.style.flexDirection = 'column';
    center.style.alignItems    = 'center';
    center.style.gap           = '12px';
    center.style.width         = '100%';
    center.appendChild(display);
    center.appendChild(numpad);
    center.appendChild(unlockBtn);
    wrap.appendChild(center);

    unlockPinQuick = new PinInput({
      displayId: 'unlock-quick-pin-display',
      numpadId:  'unlock-quick-numpad',
      minLen:    4,        // minimum to enable button
      maxLen:    pinLen,   // how many dots to show
      // No onComplete — user taps the Unlock button explicitly
    });
  } else {
    const canvas = document.createElement('canvas');
    canvas.id     = 'unlock-quick-pattern-canvas';
    canvas.width  = 220;
    canvas.height = 220;
    wrap.appendChild(canvas);
    unlockPatternQuick = new PatternLock(canvas, {
      onChange: pattern => {
        if (pattern.length >= 4) handleQuickUnlock(pattern.join('-'));
      },
    });
  }

  document.getElementById('unlock-use-master-btn').onclick = () => {
    sessionClear(); // discard wrapped key — force full unlock
    showFullUnlock(quickType);
    document.getElementById('unlock-full').classList.remove('hidden');
    document.getElementById('unlock-quick-only').classList.add('hidden');
  };
}

async function handleFullUnlock(quickType) {
  const masterPw = document.getElementById('unlock-master-pw').value;
  const quickSecret = quickType === 'pin'
    ? unlockPinFull?.getPin()
    : unlockPatternFull?.getSecret();

  const errEl = document.getElementById('unlock-error');

  if (!masterPw) { showErr(errEl, 'Enter your master password.'); return; }
  if (!quickSecret || quickSecret === '' || quickSecret === '0' || quickSecret.split('-').length < 4 && quickType === 'pattern') {
    showErr(errEl, `Enter your ${quickType === 'pin' ? 'PIN' : 'pattern'}.`);
    return;
  }

  const btn = document.getElementById('unlock-btn');
  btn.classList.add('btn-loading');
  btn.disabled = true;

  try {
    const masterSecret = masterPw + '\x00' + quickSecret;
    const { data, key, salt } = await Crypto.decryptVault(state.vaultBlob, masterSecret);

    state.vault     = data;
    state.vaultKey  = key;
    state.vaultSalt = salt;
    state.vaultSha  = sessionGet('vault_sha');

    await cacheKeyForQuickUnlock(key, quickSecret);

    showScreen('vault');
    renderVaultList();

  } catch (err) {
    const msg = err.message === 'DECRYPT_FAILED'
      ? 'Wrong password or PIN/pattern. Please try again.'
      : err.message;
    showErr(errEl, msg);
    unlockPinFull?.reset();
    unlockPatternFull?.reset();
    document.getElementById('unlock-master-pw').value = '';
    document.getElementById('unlock-master-pw').focus();
  } finally {
    btn.classList.remove('btn-loading');
    btn.disabled = false;
  }
}

async function handleQuickUnlock(quickSecret) {
  const errEl      = document.getElementById('unlock-quick-error');
  const wrappedKey = sessionGet('wrapped_key');
  if (!wrappedKey) {
    // Session expired — fall back to full unlock
    showFullUnlock(state.config.quick_unlock_type);
    return;
  }

  // Use the blob cached at lock time (or in-memory from initial fetch)
  const blob = state.vaultBlob || sessionGet('vault_blob');
  if (!blob) {
    // No blob at all — fall back to full unlock (will re-fetch)
    showFullUnlock(state.config.quick_unlock_type);
    return;
  }

  try {
    const key = await Crypto.unwrapKey(wrappedKey, quickSecret);

    // Decode blob and decrypt with the unwrapped key
    const bytes = Uint8Array.from(atob(blob), c => c.charCodeAt(0));
    const salt  = bytes.slice(0, 16);
    const iv    = bytes.slice(16, 28);
    const ct    = bytes.slice(28);
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    const data  = JSON.parse(new TextDecoder().decode(ptBuf));

    state.vault     = data;
    state.vaultKey  = key;
    state.vaultSalt = salt;
    state.vaultBlob = blob;
    state.vaultSha  = sessionGet('vault_sha');

    showScreen('vault');
    renderVaultList();

  } catch {
    showErr(errEl, 'Wrong PIN/pattern. Try again.');
    unlockPinQuick?.reset();
    unlockPatternQuick?.flashError?.();
    unlockPatternQuick?.reset();
  }
}

/** Wrap the vault key with the quick secret and cache in sessionStorage */
async function cacheKeyForQuickUnlock(key, quickSecret) {
  try {
    const wrapped = await Crypto.wrapKey(key, quickSecret);
    sessionSet('wrapped_key', wrapped);
  } catch { /* non-critical */ }
}

// ─── Lock Vault ───────────────────────────────────────────────────────────────

function lockVault() {
  // Clear sensitive state from memory
  state.vault     = null;
  state.vaultKey  = null;
  state.vaultSalt = null;

  // Persist the latest blob in sessionStorage so quick-unlock
  // can decrypt without a network round-trip.
  if (state.vaultBlob) {
    sessionSet('vault_blob', state.vaultBlob);
  }

  const quickType = state.config?.quick_unlock_type || 'pin';
  showScreen('unlock');

  const wrappedKey = sessionGet('wrapped_key');
  if (wrappedKey) {
    showQuickOnlyUnlock(quickType);
  } else {
    showFullUnlock(quickType);
  }
}

// ─── Vault CRUD ───────────────────────────────────────────────────────────────

function renderVaultList() {
  const container = document.getElementById('vault-list');
  const q         = state.searchQuery.toLowerCase().trim();
  const entries   = state.vault?.entries || [];

  const filtered = q
    ? entries.filter(e =>
        e.name.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        (e.url || '').toLowerCase().includes(q)
      )
    : entries;

  // Sort: most recently updated first
  const sorted = [...filtered].sort((a, b) =>
    new Date(b.updated_at) - new Date(a.updated_at)
  );

  if (sorted.length === 0) {
    container.innerHTML = `
      <div class="vault-empty">
        <div class="vault-empty-icon">
          <svg width="32" height="32" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" opacity=".3">
            ${q
              ? '<circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/>'
              : '<circle cx="6" cy="6.5" r="3.5"/><path d="M9 9l5 5M12 12l-1.5 1.5"/>'}
          </svg>
        </div>
        <h3>${q ? `No results for "${escapeHtml(q)}"` : 'Your vault is empty'}</h3>
        <p>${q ? 'Try a different search.' : 'Press + to add your first password.'}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  // SVG icon strings reused in each card
  const svgCopy = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M2 11V2h9"/></svg>`;
  const svgEdit = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="m11 2 3 3-8 8H3v-3l8-8z"/></svg>`;

  sorted.forEach(entry => {
    const card = document.createElement('div');
    card.className = 'entry-card';
    card.dataset.id = entry.id;

    // Icon: favicon if URL available, else first letter of name
    const fav    = entry.url ? favicon(entry.url) : null;
    const letter = escapeHtml((entry.name || '?')[0].toUpperCase());

    const iconContent = fav
      ? `<img src="${fav}" alt="" onerror="this.style.display='none';this.nextSibling.style.display='flex'">`
        + `<span style="display:none;align-items:center;justify-content:center;width:100%;height:100%">${letter}</span>`
      : letter;

    card.innerHTML = `
      <div class="entry-icon">${iconContent}</div>
      <div class="entry-info">
        <div class="entry-name">${escapeHtml(entry.name)}</div>
        <div class="entry-username">${escapeHtml(entry.username)}</div>
      </div>
      <div class="entry-actions">
        <button class="btn-icon" data-action="copy" data-id="${entry.id}" title="Copy password">${svgCopy}</button>
        <button class="btn-icon" data-action="edit" data-id="${entry.id}" title="Edit">${svgEdit}</button>
      </div>
    `;

    card.addEventListener('click', e => {
      if (e.target.closest('[data-action]')) return;
      openEditModal(entry.id);
    });

    container.appendChild(card);
  });

  container.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const { action, id } = btn.dataset;
      if (action === 'copy') copyPassword(id);
      if (action === 'edit') openEditModal(id);
    });
  });
}

function findEntry(id) {
  return state.vault.entries.find(e => e.id === id);
}

async function copyPassword(entryId) {
  const entry = findEntry(entryId);
  if (!entry) return;
  await Clipboard.copy(entry.password, `Password for ${entry.name} copied!`);
}

// ─── Add / Edit Modal ─────────────────────────────────────────────────────────

function openAddModal() {
  state.editingId = null;

  document.getElementById('modal-entry-title').textContent = 'Add Password';
  document.getElementById('entry-name').value     = '';
  document.getElementById('entry-url').value      = '';
  document.getElementById('entry-username').value = '';
  document.getElementById('entry-password').value = '';
  document.getElementById('entry-notes').value    = '';
  document.getElementById('modal-entry-delete').classList.add('hidden');

  showModal('modal-entry');
  document.getElementById('entry-name').focus();
}

function openEditModal(id) {
  const entry = findEntry(id);
  if (!entry) return;
  state.editingId = id;

  document.getElementById('modal-entry-title').textContent = 'Edit Password';
  document.getElementById('entry-name').value     = entry.name;
  document.getElementById('entry-url').value      = entry.url      || '';
  document.getElementById('entry-username').value = entry.username;
  document.getElementById('entry-password').value = entry.password;
  document.getElementById('entry-notes').value    = entry.notes    || '';
  document.getElementById('modal-entry-delete').classList.remove('hidden');

  showModal('modal-entry');
}

async function saveEntry() {
  const name     = document.getElementById('entry-name').value.trim();
  const url      = document.getElementById('entry-url').value.trim();
  const username = document.getElementById('entry-username').value.trim();
  const password = document.getElementById('entry-password').value;
  const notes    = document.getElementById('entry-notes').value.trim();

  if (!name || !username || !password) {
    Toast.error('Name, username, and password are required.');
    return;
  }

  const now = new Date().toISOString();

  if (state.editingId) {
    // Update existing
    const idx = state.vault.entries.findIndex(e => e.id === state.editingId);
    if (idx !== -1) {
      state.vault.entries[idx] = {
        ...state.vault.entries[idx],
        name, url, username, password, notes,
        updated_at: now,
      };
    }
  } else {
    // Create new
    state.vault.entries.push({
      id:         uuid(),
      name, url, username, password, notes,
      created_at: now,
      updated_at: now,
    });
  }

  hideModal('modal-entry');
  renderVaultList();
  await saveVault();
}

async function deleteEntry() {
  if (!state.editingId) return;
  if (!confirm('Delete this entry? This cannot be undone.')) return;

  state.vault.entries = state.vault.entries.filter(e => e.id !== state.editingId);
  hideModal('modal-entry');
  renderVaultList();
  await saveVault();
}

// ─── GitHub Save ──────────────────────────────────────────────────────────────

async function saveVault() {
  setSyncStatus('⏳ Saving…');

  try {
    // Re-encrypt the vault (same key + salt, fresh IV)
    const blob = await Crypto.encryptVault(state.vault, state.vaultKey, state.vaultSalt);

    // Commit to GitHub
    const newSha = await GitHub.commitVault({
      content: blob,
      sha:     state.vaultSha,
      owner:   state.config.github_owner,
      repo:    state.config.github_repo,
      path:    state.config.github_path || 'vault.enc',
      token:   state.vault.github_pat,
    });

    state.vaultSha  = newSha;
    state.vaultBlob = blob;
    sessionSet('vault_sha', newSha);

    setSyncStatus('✓ Saved to GitHub');
    setTimeout(() => setSyncStatus(''), 4000);

  } catch (err) {
    setSyncStatus(`⚠ Save failed: ${err.message}`);
    Toast.error(`Save failed: ${err.message}`);
  }
}

function setSyncStatus(msg) {
  document.getElementById('sync-status').textContent = msg;
}

// ─── Password Generator Modal ─────────────────────────────────────────────────

function openGeneratorModal() {
  regeneratePassword();
  showModal('modal-generator');
}

function getGenOpts() {
  return {
    length:  parseInt(document.getElementById('gen-length').value, 10),
    upper:   document.getElementById('gen-upper').checked,
    lower:   document.getElementById('gen-lower').checked,
    digits:  document.getElementById('gen-digits').checked,
    symbols: document.getElementById('gen-symbols').checked,
  };
}

function regeneratePassword() {
  const { length, upper, lower, digits, symbols } = getGenOpts();
  const pw = Crypto.generatePassword(length, { upper, lower, digits, symbols });
  document.getElementById('gen-pw-output').textContent = pw;
}

// ─── Event Wiring ─────────────────────────────────────────────────────────────

function initEventListeners() {

  // ── Vault screen ──────────────────────────────────────────────────────────
  document.getElementById('vault-add-btn').addEventListener('click', openAddModal);
  document.getElementById('vault-gen-btn').addEventListener('click', openGeneratorModal);
  document.getElementById('vault-lock-btn').addEventListener('click', lockVault);

  document.getElementById('vault-search').addEventListener('input', e => {
    state.searchQuery = e.target.value;
    renderVaultList();
  });

  // ── Entry modal ───────────────────────────────────────────────────────────
  document.getElementById('modal-entry-close').addEventListener('click',  () => hideModal('modal-entry'));
  document.getElementById('modal-entry-cancel').addEventListener('click', () => hideModal('modal-entry'));
  document.getElementById('modal-entry-save').addEventListener('click',   saveEntry);
  document.getElementById('modal-entry-delete').addEventListener('click', deleteEntry);

  // Inline generate button inside entry modal
  document.getElementById('entry-gen-btn').addEventListener('click', () => {
    const pw = Crypto.generatePassword(20);
    document.getElementById('entry-password').value = pw;
    document.getElementById('entry-password').type  = 'text';
    Toast.info('Generated password filled in.');
  });

  // ── Generator modal ───────────────────────────────────────────────────────
  document.getElementById('modal-gen-close').addEventListener('click', () => hideModal('modal-generator'));
  document.getElementById('gen-refresh-btn').addEventListener('click', regeneratePassword);
  document.getElementById('gen-copy-btn').addEventListener('click', () => {
    const pw = document.getElementById('gen-pw-output').textContent;
    Clipboard.copy(pw, 'Password copied!');
  });
  document.getElementById('gen-length').addEventListener('input', e => {
    document.getElementById('gen-length-label').textContent = e.target.value;
    regeneratePassword();
  });
  ['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', regeneratePassword);
  });

  // ── Import ────────────────────────────────────────────────────────────────
  // Clicking the import button opens the OS file picker (no file ever uploads)
  document.getElementById('vault-import-btn').addEventListener('click', () => {
    document.getElementById('csv-file-input').click();
  });

  document.getElementById('csv-file-input').addEventListener('change', async e => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      await handleCsvSelected(file);
    } finally {
      // Always clear the input so the same file can be re-selected if needed
      e.target.value = '';
    }
  });

  // ── Import modal ──────────────────────────────────────────────────────────
  document.getElementById('modal-import-close').addEventListener('click',  () => hideModal('modal-import'));
  document.getElementById('modal-import-cancel').addEventListener('click', () => hideModal('modal-import'));
  document.getElementById('modal-import-confirm').addEventListener('click', confirmImport);
}

// ─── Keyboard Shortcuts ───────────────────────────────────────────────────────

function initKeyboardShortcuts() {
  document.addEventListener('keydown', e => {
    if (state.screen !== 'vault') return;
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    switch (e.key.toLowerCase()) {
      case 'a': openAddModal();                                      break;
      case 'g': openGeneratorModal();                                break;
      case 'i': document.getElementById('csv-file-input').click();  break;
      case 'l': lockVault();                                         break;
    }
  });

  // Close modals with Escape
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      ['modal-entry', 'modal-generator', 'modal-import'].forEach(id => {
        const m = document.getElementById(id);
        if (m && m.classList.contains('visible')) hideModal(id);
      });
    }
  });
}

// ─── Auto-Lock on Tab Hidden ──────────────────────────────────────────────────

document.addEventListener('visibilitychange', () => {
  if (document.hidden && state.screen === 'vault') {
    lockVault();
  }
});

// ─── Utility ──────────────────────────────────────────────────────────────────

function showErr(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  init();
});

// ─── CSV Import ───────────────────────────────────────────────────────────────
//
// Supports the Google Password Manager export format:
//   name,url,username,password[,note]
//
// Also handles Bitwarden and most other managers that export a similar CSV.
// The file is read entirely in browser memory and never sent anywhere.

/** Holds parsed entries waiting for the user to confirm import. */
let _pendingImport = [];

/**
 * Called when a CSV file is selected.
 * Reads it in memory, parses it, shows the preview modal.
 * @param {File} file
 */
async function handleCsvSelected(file) {
  let text;
  try {
    text = await file.text();
  } catch {
    Toast.error('Could not read the file.');
    return;
  }

  let parsed;
  try {
    parsed = parseGoogleCsv(text);
  } catch (err) {
    Toast.error(err.message);
    return;
  }

  if (parsed.length === 0) {
    Toast.error('No passwords found in the CSV file.');
    return;
  }

  // Separate new entries from duplicates (same url + username already in vault)
  const existing = state.vault?.entries || [];
  const dupes    = new Set(existing.map(e => `${e.url}|${e.username}`));

  const newEntries = parsed.filter(e => !dupes.has(`${e.url}|${e.username}`));
  const dupCount   = parsed.length - newEntries.length;

  _pendingImport = newEntries;

  // ── Build preview ─────────────────────────────────────────────────────────
  document.getElementById('import-found-msg').textContent =
    `Found ${parsed.length} password${parsed.length !== 1 ? 's' : ''} — ${newEntries.length} new will be imported.`;

  document.getElementById('import-dup-msg').textContent =
    dupCount > 0 ? `${dupCount} already exist in your vault and will be skipped.` : '';

  const confirmBtn = document.getElementById('modal-import-confirm');
  confirmBtn.textContent = `Import ${newEntries.length} password${newEntries.length !== 1 ? 's' : ''}`;
  confirmBtn.disabled    = newEntries.length === 0;

  // Render scrollable preview list
  const list = document.getElementById('import-preview-list');
  list.innerHTML = '';

  const allToShow = parsed.map(e => ({ ...e, isNew: !dupes.has(`${e.url}|${e.username}`) }));

  allToShow.forEach(entry => {
    const row = document.createElement('div');
    row.style.cssText = `
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 9px 12px;
      border-bottom: 1px solid var(--line);
    `;

    const letter = (entry.name || '?')[0].toUpperCase();
    row.innerHTML = `
      <div style="
        width: 26px; height: 26px; border-radius: 4px;
        background: var(--bg-2); border: 1px solid var(--line2);
        display: flex; align-items: center; justify-content: center;
        font-size: 11px; font-weight: 600; color: var(--t2);
        flex-shrink: 0;
      ">${escapeHtml(letter)}</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:13px;font-weight:500;color:${entry.isNew ? 'var(--t1)' : 'var(--t3)'};
                    white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
          ${escapeHtml(entry.name)}
        </div>
        <div style="font-size:12px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
          ${escapeHtml(entry.username)}
        </div>
      </div>
      ${!entry.isNew ? `<span style="font-size:11px;color:var(--t3);flex-shrink:0">skip</span>` : ''}
    `;
    list.appendChild(row);
  });

  showModal('modal-import');
}

/**
 * Called when the user clicks "Import N passwords" in the preview modal.
 */
async function confirmImport() {
  if (_pendingImport.length === 0) return;

  const btn = document.getElementById('modal-import-confirm');
  btn.classList.add('btn-loading');
  btn.disabled = true;

  const now = new Date().toISOString();
  const newEntries = _pendingImport.map(e => ({
    id:         uuid(),
    name:       e.name,
    url:        e.url,
    username:   e.username,
    password:   e.password,
    notes:      e.notes || '',
    created_at: now,
    updated_at: now,
  }));

  state.vault.entries.push(...newEntries);
  _pendingImport = [];

  hideModal('modal-import');
  renderVaultList();
  Toast.success(`Imported ${newEntries.length} password${newEntries.length !== 1 ? 's' : ''}.`);

  await saveVault();

  btn.classList.remove('btn-loading');
  btn.disabled = false;
}

// ─── CSV Parser ───────────────────────────────────────────────────────────────

/**
 * Parse Google Password Manager CSV export.
 *
 * Google's format (columns may vary slightly):
 *   name,url,username,password[,note]
 *
 * @param {string} text  raw CSV text
 * @returns {{ name, url, username, password, notes }[]}
 * @throws if the file doesn't look like a password CSV
 */
function parseGoogleCsv(text) {
  // Normalise line endings
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim().split('\n');

  if (lines.length < 2) throw new Error('CSV file appears to be empty.');

  const headers = parseCsvLine(lines[0]).map(h => h.toLowerCase().trim());

  // Find required columns — Google uses these exact names
  const col = name => headers.indexOf(name);

  const nameCol     = col('name');
  const urlCol      = col('url');
  const usernameCol = col('username');
  const passwordCol = col('password');
  const noteCol     = col('note');

  if (usernameCol === -1 || passwordCol === -1) {
    throw new Error(
      'This doesn\'t look like a Google password export. ' +
      'Make sure you exported from passwords.google.com and the file has username and password columns.'
    );
  }

  const entries = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const cols = parseCsvLine(line);

    const rawUrl  = cols[urlCol]      || '';
    const rawName = cols[nameCol]     || '';
    const username = cols[usernameCol] || '';
    const password = cols[passwordCol] || '';

    // Derive a display name: prefer the name column, fall back to hostname
    let name = rawName;
    if (!name && rawUrl) {
      try { name = new URL(rawUrl).hostname.replace(/^www\./, ''); } catch {}
    }
    if (!name) name = 'Unknown';

    entries.push({
      name,
      url:   rawUrl,
      username,
      password,
      notes: noteCol >= 0 ? (cols[noteCol] || '') : '',
    });
  }

  return entries;
}

/**
 * Parse a single CSV line, handling quoted fields and escaped quotes ("").
 * @param {string} line
 * @returns {string[]}
 */
function parseCsvLine(line) {
  const result   = [];
  let   current  = '';
  let   inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch   = line[i];
    const next = line[i + 1];

    if (ch === '"') {
      if (inQuotes && next === '"') {
        // Escaped quote inside quoted field
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }

  result.push(current);
  return result;
}
