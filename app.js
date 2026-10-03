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

  // Temporary in-memory master secret (masterPw + \x00 + quickSecret)
  // Wiped immediately upon lock
  masterSecret: null,

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

  // Active vault tab ('passwords' | 'journal' | 'docs')
  activeTab: 'passwords',

  // Currently editing journal note id (null = creating new)
  editingNoteId: null,

  // Journal search filter string
  journalSearchQuery: '',

  // Currently editing doc id (null = creating new)
  editingDocId: null,

  // Docs search filter string
  docSearchQuery: '',

  // Docs category filter ('all' | 'identity' | 'signature' | 'other')
  docCategoryFilter: 'all',

  // Stable doc ID during creation
  currentDocId: null,

  // Flag to prevent auto-lock when system file picker or camera dialog is active
  isPickingFile: false,

  // Temporary list of attached files in doc modal
  currentDocDraftFiles: [],

  // Cards & Banks state
  cardsSearchQuery: '',
  cardCategoryFilter: 'all',
  editingCardId: null,
  selectedCardTheme: 'card-theme-black',
  cardMode: 'card', // 'card' | 'bank'
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

// ─── URL Auto-Detection ───────────────────────────────────────────────────────

function detectRepoFromUrl() {
  const params = new URLSearchParams(window.location.search);
  let owner = params.get('owner');
  let repo  = params.get('repo');
  if (!owner && repo && repo.includes('/')) {
    [owner, repo] = repo.split('/');
  }

  if (!owner && !repo && window.location.hash) {
    const hash = window.location.hash.replace(/^#/, '');
    if (hash.includes('=')) {
      const hashParams = new URLSearchParams(hash);
      owner = hashParams.get('owner');
      repo  = hashParams.get('repo');
    } else if (hash.includes('/')) {
      const parts = hash.split('/').filter(Boolean);
      if (parts.length >= 2) {
        owner = parts[0];
        repo  = parts[1];
      }
    }
  }

  // Check if hosted on GitHub Pages: https://<owner>.github.io/<repo>/
  if (!owner && window.location.hostname.endsWith('.github.io')) {
    owner = window.location.hostname.replace('.github.io', '');
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    if (pathParts.length > 0) {
      repo = pathParts[0];
    }
  }

  if (owner && repo) {
    return {
      github_owner: owner,
      github_repo: repo,
      github_path: 'vault.enc',
      quick_unlock_type: 'pin',
      pin_length: 4,
    };
  }
  return null;
}

function showUnlockScreen() {
  const config = state.config;
  const wrappedKey = sessionGet('wrapped_key');

  const repoLabel = document.getElementById('unlock-repo-label');
  if (repoLabel && config?.github_owner && config?.github_repo) {
    repoLabel.textContent = `${config.github_owner} / ${config.github_repo}`;
    repoLabel.style.display = 'block';
  }

  showScreen('unlock');

  const bioEnrolled = typeof Biometrics !== 'undefined' && Biometrics.isEnrolled();
  const quickBioBtn = document.getElementById('unlock-quick-bio-btn');
  const fullBioBtn  = document.getElementById('unlock-full-bio-btn');

  if (quickBioBtn) quickBioBtn.classList.toggle('hidden', !bioEnrolled);
  if (fullBioBtn)  fullBioBtn.classList.toggle('hidden', !bioEnrolled);

  if (wrappedKey) {
    showQuickOnlyUnlock(config?.quick_unlock_type || 'pin');
  } else {
    showFullUnlock(config?.quick_unlock_type || 'pin');
  }

  // If biometrics is enrolled, prompt for Face ID / Fingerprint automatically
  if (bioEnrolled) {
    setTimeout(() => {
      // Only auto-trigger if still on unlock screen
      if (state.screen === 'unlock') {
        triggerBiometricUnlock();
      }
    }, 350);
  }
}

// ─── Initialisation ───────────────────────────────────────────────────────────

async function init() {
  showScreen('loading');
  setLoadingMsg('Checking configuration…');
  initPasswordToggles();
  initKeyboardShortcuts();

  let config = loadConfig();

  // If no config found locally, try to auto-detect repository from URL / GitHub Pages
  if (!config) {
    const detected = detectRepoFromUrl();
    if (detected) {
      setLoadingMsg(`Checking repository (${detected.github_owner}/${detected.github_repo})…`);
      try {
        const { blob, sha } = await GitHub.fetchVault(
          detected.github_owner,
          detected.github_repo,
          detected.github_path || 'vault.enc'
        );

        // Found an existing vault! Set config, store blob & sha
        config = detected;
        saveConfig(config);
        state.vaultBlob = blob;
        sessionSet('vault_sha', sha);
        state.vaultSha = sha;
      } catch (err) {
        console.log('No existing vault found in detected repo:', err);
      }
    }
  }

  if (!config) {
    // No saved or detected config — show setup wizard
    showScreen('setup');
    initSetupWizard();
    return;
  }

  state.config = config;

  if (state.vaultBlob) {
    showUnlockScreen();
    return;
  }

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

    showUnlockScreen();

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

  // ── Mode Toggle: Create New vs Connect Existing ──
  const modeCreateBtn  = document.getElementById('mode-create-btn');
  const modeConnectBtn = document.getElementById('mode-connect-btn');
  const connectStep    = document.getElementById('setup-connect-step');
  const stepDots       = document.getElementById('setup-step-dots');
  const setupTitle     = document.getElementById('setup-title');

  function setSetupMode(mode) {
    if (mode === 'connect') {
      modeCreateBtn?.classList.remove('active');
      modeConnectBtn?.classList.add('active');
      document.querySelectorAll('.setup-step').forEach(s => s.classList.add('hidden'));
      connectStep?.classList.remove('hidden');
      stepDots?.classList.add('hidden');
      if (setupTitle) setupTitle.textContent = 'Connect Vault';

      const detected = detectRepoFromUrl();
      if (detected) {
        const ownerInput = document.getElementById('connect-gh-owner');
        const repoInput  = document.getElementById('connect-gh-repo');
        if (ownerInput && !ownerInput.value) ownerInput.value = detected.github_owner;
        if (repoInput && !repoInput.value)   repoInput.value  = detected.github_repo;
      }
    } else {
      modeCreateBtn?.classList.add('active');
      modeConnectBtn?.classList.remove('active');
      connectStep?.classList.add('hidden');
      stepDots?.classList.remove('hidden');
      if (setupTitle) setupTitle.textContent = 'Set up Vault';
      goToStep(1);
    }
  }

  modeCreateBtn?.addEventListener('click', () => setSetupMode('create'));
  modeConnectBtn?.addEventListener('click', () => setSetupMode('connect'));

  // Connect Existing Vault button handler
  document.getElementById('connect-step-btn')?.addEventListener('click', async () => {
    const owner = document.getElementById('connect-gh-owner').value.trim();
    const repo  = document.getElementById('connect-gh-repo').value.trim();
    const pat   = document.getElementById('connect-gh-pat').value.trim() || null;
    const errEl = document.getElementById('connect-step-error');
    const btn   = document.getElementById('connect-step-btn');

    if (!owner || !repo) {
      showErr(errEl, 'Please enter both GitHub username and repository name.');
      return;
    }

    errEl.classList.add('hidden');
    btn.classList.add('btn-loading');
    btn.disabled = true;

    try {
      const { blob, sha } = await GitHub.fetchVault(owner, repo, 'vault.enc', pat);

      const config = {
        github_owner: owner,
        github_repo:  repo,
        github_path:  'vault.enc',
        quick_unlock_type: 'pin',
        pin_length:   4,
      };
      saveConfig(config);
      state.config    = config;
      state.vaultBlob = blob;
      state.vaultSha  = sha;
      sessionSet('vault_sha', sha);

      showUnlockScreen();
    } catch (err) {
      let msg = 'Could not find vault.enc in this repository.';
      if (err.message === 'NOT_FOUND')   msg = 'Repository or vault.enc not found. Check username and repo.';
      if (err.message === 'UNAUTHORIZED' || err.message === 'FORBIDDEN') msg = 'Repository is private. Please enter a valid PAT.';
      showErr(errEl, msg);
    } finally {
      btn.classList.remove('btn-loading');
      btn.disabled = false;
    }
  });

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
        if (state.vault && !state.vault.notes) state.vault.notes = [];
        if (state.vault && !state.vault.docs)  state.vault.docs  = [];
        if (state.vault && !state.vault.cards) state.vault.cards = [];
        state.vaultKey     = key;
        state.vaultSalt    = salt;
        state.masterSecret = masterSecret;
        state.vaultBlob    = blob;
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
        notes:      [],
        docs:       [],
        cards:      [],
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
      state.vault        = initialVaultData;
      state.vaultKey     = key;
      state.vaultSalt    = salt;
      state.masterSecret = masterSecret;
      state.vaultBlob    = blob;
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

function renderActiveTab() {
  switchVaultTab(state.activeTab || 'passwords');
}

  document.getElementById('setup-done-btn').addEventListener('click', () => {
    showScreen('vault');
    renderActiveTab();
  });
}

// ─── Unlock ───────────────────────────────────────────────────────────────────

// PIN/pattern input instances re-used across unlock modes
let unlockPinFull      = null;
let unlockPatternFull  = null;
let unlockPinQuick     = null;
let unlockPatternQuick = null;

let currentUnlockType = 'pin';

/** Show full unlock (master password + quick secret) */
function showFullUnlock(quickType) {
  currentUnlockType = quickType || 'pin';
  document.getElementById('unlock-full').classList.remove('hidden');
  document.getElementById('unlock-quick-only').classList.add('hidden');
  document.getElementById('unlock-error').classList.add('hidden');

  renderFullUnlockQuickInput(currentUnlockType);

  // Unlock button
  document.getElementById('unlock-btn').onclick = () => handleFullUnlock(currentUnlockType);

  // Enter key on password field
  document.getElementById('unlock-master-pw').onkeydown = e => {
    if (e.key === 'Enter') handleFullUnlock(currentUnlockType);
  };

  // Switch repository / disconnect button
  const switchVaultBtn = document.getElementById('unlock-switch-vault-btn');
  if (switchVaultBtn) {
    switchVaultBtn.onclick = () => {
      if (confirm('Disconnect this repository and switch vault?')) {
        clearConfig();
        sessionClear();
        state.vaultBlob = null;
        showScreen('setup');
        initSetupWizard();
      }
    };
  }

  document.getElementById('unlock-master-pw').focus();
}

function renderFullUnlockQuickInput(type) {
  const wrap = document.getElementById('unlock-quick-input-wrap');
  wrap.innerHTML = '';

  if (type === 'pin') {
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

  const toggleBtn = document.getElementById('unlock-type-toggle-btn');
  if (toggleBtn) {
    toggleBtn.textContent = type === 'pin' ? 'Using pattern? Switch to pattern' : 'Using PIN? Switch to PIN';
    toggleBtn.onclick = () => {
      currentUnlockType = type === 'pin' ? 'pattern' : 'pin';
      renderFullUnlockQuickInput(currentUnlockType);
      document.getElementById('unlock-btn').onclick = () => handleFullUnlock(currentUnlockType);
    };
  }
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
  if (!quickSecret || quickSecret === '' || quickSecret === '0' || (quickType === 'pattern' && quickSecret.split('-').length < 4)) {
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
    if (state.vault && !state.vault.notes) state.vault.notes = [];
    if (state.vault && !state.vault.docs)  state.vault.docs  = [];
    if (state.vault && !state.vault.cards) state.vault.cards = [];
    state.vaultKey     = key;
    state.vaultSalt    = salt;
    state.vaultSha     = sessionGet('vault_sha');
    state.masterSecret = masterSecret;

    // Persist quick unlock preferences in config
    if (state.config) {
      state.config.quick_unlock_type = quickType;
      state.config.pin_length = quickType === 'pin' ? quickSecret.length : null;
      saveConfig(state.config);
    }

    await cacheKeyForQuickUnlock(key, quickSecret);

    showScreen('vault');
    renderActiveTab();

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
    if (state.vault && !state.vault.notes) state.vault.notes = [];
    if (state.vault && !state.vault.docs)  state.vault.docs  = [];
    if (state.vault && !state.vault.cards) state.vault.cards = [];
    state.vaultKey  = key;
    state.vaultSalt = salt;
    state.vaultBlob = blob;
    state.vaultSha  = sessionGet('vault_sha');

    showScreen('vault');
    renderActiveTab();

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
  stopTotpTicker();

  // Hide all modals so orphaned dialogs don't stay visible on locked screen
  ['modal-entry', 'modal-generator', 'modal-import', 'modal-doc', 'modal-doc-viewer', 'modal-settings', 'modal-card'].forEach(id => {
    hideModal(id);
  });

  // Clear sensitive state from memory
  state.vault        = null;
  state.vaultKey     = null;
  state.vaultSalt    = null;
  state.masterSecret = null;

  // Persist the latest blob in sessionStorage so quick-unlock
  // can decrypt without a network round-trip.
  if (state.vaultBlob) {
    sessionSet('vault_blob', state.vaultBlob);
  }

  showUnlockScreen();
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

  // Update count badge & bottom nav badge
  const countBadge = document.getElementById('vault-count-badge');
  if (countBadge) {
    const total = entries.length;
    const shown = sorted.length;
    countBadge.textContent = q ? `${shown} of ${total}` : `${total} item${total !== 1 ? 's' : ''}`;
  }
  updateNavBadges();

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
  const svgCopy   = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M2 11V2h9"/></svg>`;
  const svgEdit   = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m11 2 3 3-8 8H3v-3l8-8z"/></svg>`;
  const svgShield = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.5l6 2.5v4.5c0 4-3 6.5-6 7.5-3-1-6-3.5-6-7.5V4l6-2.5z"/><path d="M5.5 8l2 2 3.5-3.5"/></svg>`;

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

    let cleanDomain = '';
    if (entry.url) {
      try {
        cleanDomain = new URL(entry.url.startsWith('http') ? entry.url : `https://${entry.url}`).hostname.replace(/^www\./, '');
      } catch {
        cleanDomain = entry.url;
      }
    }

    const domainDisplay = cleanDomain ? `<span class="entry-url">${escapeHtml(cleanDomain)}</span>` : '';

    let totpHtml = '';
    let totpActionBtn = '';
    if (entry.totp) {
      totpHtml = `
        <div class="entry-totp-row">
          <button type="button" class="entry-totp-chip" data-action="copy-totp" data-id="${entry.id}" title="Click to copy 2FA code">
            <svg class="totp-chip-icon" viewBox="0 0 16 16"><use href="#ic-shield-check"/></svg>
            <span class="totp-chip-label">2FA</span>
            <span class="totp-chip-code" data-totp-code="${entry.id}">--- ---</span>
            <span class="totp-chip-timer">
              <svg class="totp-ring-svg" viewBox="0 0 20 20">
                <circle class="totp-ring-bg" cx="10" cy="10" r="7"/>
                <circle class="totp-ring-progress" cx="10" cy="10" r="7" data-totp-ring="${entry.id}"/>
              </svg>
              <span class="totp-chip-sec" data-totp-sec="${entry.id}">--s</span>
            </span>
          </button>
        </div>
      `;
      totpActionBtn = `<button class="btn-icon" data-action="copy-totp" data-id="${entry.id}" title="Copy 2FA code" aria-label="Copy 2FA code" style="color:#22c55e">${svgShield}</button>`;
    }

    card.innerHTML = `
      <div class="entry-icon">${iconContent}</div>
      <div class="entry-info">
        <div class="entry-name-row">
          <span class="entry-name">${escapeHtml(entry.name)}</span>
          ${domainDisplay}
        </div>
        <div class="entry-username">${escapeHtml(entry.username)}</div>
        ${totpHtml}
      </div>
      <div class="entry-actions">
        ${totpActionBtn}
        <button class="btn-icon" data-action="copy" data-id="${entry.id}" title="Copy password" aria-label="Copy password">${svgCopy}</button>
        <button class="btn-icon" data-action="edit" data-id="${entry.id}" title="Edit" aria-label="Edit entry">${svgEdit}</button>
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
      if (action === 'copy') copyPassword(id, btn);
      if (action === 'copy-totp') copyTotp(id, btn);
      if (action === 'edit') openEditModal(id);
    });
  });

  updateAllVisibleTotp();
  startTotpTicker();
}

function findEntry(id) {
  return state.vault?.entries?.find(e => e.id === id);
}

async function copyPassword(entryId, btnElement = null) {
  const entry = findEntry(entryId);
  if (!entry) return;
  await Clipboard.copy(entry.password, `Password for ${entry.name} copied!`);

  // Instant checkmark micro-interaction
  if (btnElement) {
    const origHtml = btnElement.innerHTML;
    btnElement.innerHTML = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8l4.5 4.5L14 4"/></svg>`;
    btnElement.style.color = '#22c55e';
    setTimeout(() => {
      btnElement.innerHTML = origHtml;
      btnElement.style.color = '';
    }, 1500);
  }
}

// ─── TOTP Ticker & Actions ───────────────────────────────────────────────────

let totpTickerInterval = null;

function startTotpTicker() {
  if (totpTickerInterval) clearInterval(totpTickerInterval);
  updateAllVisibleTotp();
  totpTickerInterval = setInterval(updateAllVisibleTotp, 1000);
}

function stopTotpTicker() {
  if (totpTickerInterval) {
    clearInterval(totpTickerInterval);
    totpTickerInterval = null;
  }
}

async function updateAllVisibleTotp() {
  if (!state.vaultKey || state.screen !== 'vault' || state.activeTab !== 'passwords') {
    return;
  }

  const chips = document.querySelectorAll('.entry-totp-chip');
  for (const chip of chips) {
    const id = chip.dataset.id;
    const entry = findEntry(id);
    if (!entry || !entry.totp) continue;

    const parsed = Crypto.parseTotpSecret(entry.totp);
    if (!parsed) continue;

    const rem = Crypto.getTotpRemainingSeconds(parsed.period);
    const codeElem = chip.querySelector('[data-totp-code]');
    const secElem  = chip.querySelector('[data-totp-sec]');
    const ringElem = chip.querySelector('[data-totp-ring]');

    if (secElem) secElem.textContent = `${rem}s`;
    if (ringElem) {
      const circ = 43.98;
      const offset = circ * (1 - rem / parsed.period);
      ringElem.style.strokeDashoffset = offset;
    }

    if (rem <= 5) {
      chip.classList.add('totp-expiring');
    } else {
      chip.classList.remove('totp-expiring');
    }

    // Refresh code on step change or initial placeholder
    const currentStep = Math.floor(Math.floor(Date.now() / 1000) / parsed.period);
    if (codeElem && (codeElem.dataset.step !== String(currentStep) || codeElem.textContent.includes('-'))) {
      const code = await Crypto.generateTOTP(entry.totp);
      if (code && codeElem) {
        codeElem.textContent = Crypto.formatTotpCode(code);
        codeElem.dataset.step = String(currentStep);
        codeElem.dataset.raw = code;
      }
    }
  }

  // Update modal preview if open
  updateTotpPreview();
}

async function copyTotp(entryId, btnElement = null) {
  const entry = findEntry(entryId);
  if (!entry || !entry.totp) return;

  try {
    const code = await Crypto.generateTOTP(entry.totp);
    if (!code) {
      Toast.error('Invalid 2FA secret key');
      return;
    }

    const rem = Crypto.getTotpRemainingSeconds();
    await Clipboard.copy(code, `2FA Code for ${entry.name} copied! (${rem}s left)`);

    // Micro-interaction
    if (btnElement) {
      if (btnElement.classList.contains('entry-totp-chip')) {
        const origBg = btnElement.style.background;
        const origBorder = btnElement.style.borderColor;
        btnElement.style.background = 'rgba(34, 197, 94, 0.28)';
        btnElement.style.borderColor = '#22c55e';
        setTimeout(() => {
          btnElement.style.background = origBg;
          btnElement.style.borderColor = origBorder;
        }, 1200);
      } else {
        const origHtml = btnElement.innerHTML;
        btnElement.innerHTML = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 8l4.5 4.5L14 4"/></svg>`;
        btnElement.style.color = '#22c55e';
        setTimeout(() => {
          btnElement.innerHTML = origHtml;
          btnElement.style.color = '';
        }, 1500);
      }
    }
  } catch {
    Toast.error('Could not generate 2FA code.');
  }
}

async function updateTotpPreview() {
  const modal = document.getElementById('modal-entry');
  if (!modal || modal.classList.contains('hidden')) return;

  const input = document.getElementById('entry-totp');
  const previewBox = document.getElementById('entry-totp-preview');
  if (!input || !previewBox) return;

  const val = input.value.trim();
  if (!val) {
    previewBox.classList.add('hidden');
    return;
  }

  const parsed = Crypto.parseTotpSecret(val);
  if (!parsed) {
    previewBox.classList.add('hidden');
    return;
  }

  try {
    const code = await Crypto.generateTOTP(val);
    if (!code) {
      previewBox.classList.add('hidden');
      return;
    }

    const rem = Crypto.getTotpRemainingSeconds(parsed.period);
    const codeElem = document.getElementById('totp-preview-code');
    const secElem  = document.getElementById('totp-preview-sec');
    const ringElem = document.getElementById('totp-preview-ring');

    if (codeElem) codeElem.textContent = Crypto.formatTotpCode(code);
    if (secElem) secElem.textContent = `${rem}s`;
    if (ringElem) {
      const circ = 43.98;
      const offset = circ * (1 - rem / parsed.period);
      ringElem.style.strokeDashoffset = offset;
      if (rem <= 5) {
        ringElem.style.stroke = '#f59e0b';
      } else {
        ringElem.style.stroke = '#22c55e';
      }
    }
    previewBox.classList.remove('hidden');
  } catch {
    previewBox.classList.add('hidden');
  }
}

// ─── Add / Edit Modal ─────────────────────────────────────────────────────────

function openAddModal() {
  state.editingId = null;

  document.getElementById('modal-entry-title').textContent = 'Add Password';
  document.getElementById('entry-name').value     = '';
  document.getElementById('entry-url').value      = '';
  document.getElementById('entry-username').value = '';
  document.getElementById('entry-password').value = '';
  document.getElementById('entry-totp').value     = '';
  document.getElementById('entry-notes').value    = '';
  document.getElementById('entry-totp-preview').classList.add('hidden');
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
  document.getElementById('entry-totp').value     = entry.totp     || '';
  document.getElementById('entry-notes').value    = entry.notes    || '';
  document.getElementById('modal-entry-delete').classList.remove('hidden');

  updateTotpPreview();
  showModal('modal-entry');
}

async function saveEntry() {
  const name     = document.getElementById('entry-name').value.trim();
  const url      = document.getElementById('entry-url').value.trim();
  const username = document.getElementById('entry-username').value.trim();
  const password = document.getElementById('entry-password').value;
  const totp     = document.getElementById('entry-totp').value.trim();
  const notes    = document.getElementById('entry-notes').value.trim();

  if (!name || !username || !password) {
    Toast.error('Name, username, and password are required.');
    return;
  }

  if (totp) {
    const parsed = Crypto.parseTotpSecret(totp);
    if (!parsed) {
      if (!confirm('The entered 2FA secret does not look like a valid Base32 key or otpauth:// URI.\n\nDo you want to save it anyway?')) {
        return;
      }
    }
  }

  const now = new Date().toISOString();

  if (state.editingId) {
    // Update existing
    const idx = state.vault.entries.findIndex(e => e.id === state.editingId);
    if (idx !== -1) {
      state.vault.entries[idx] = {
        ...state.vault.entries[idx],
        name, url, username, password, totp, notes,
        updated_at: now,
      };
    }
  } else {
    // Create new
    state.vault.entries.push({
      id:         uuid(),
      name, url, username, password, totp, notes,
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

// ─── Journal & Notes (Mi Notes style) ─────────────────────────────────────────

function switchVaultTab(tab) {
  state.activeTab = tab;

  // Sync active classes across all tab buttons (both desktop top pills and mobile bottom bar)
  document.querySelectorAll('.vault-nav-tab, .vault-bottom-tab').forEach(el => {
    const tabName = el.getAttribute('data-tab');
    if (tabName === tab || el.id === `tab-${tab}-btn` || el.id === `bottom-tab-${tab}`) {
      el.classList.add('active');
    } else {
      el.classList.remove('active');
    }
  });

  const pwView    = document.getElementById('vault-view-passwords');
  const cardsView = document.getElementById('vault-view-cards');
  const jrnView   = document.getElementById('vault-view-journal');
  const docsView  = document.getElementById('vault-view-docs');
  const fab       = document.getElementById('vault-fab-btn');

  pwView?.classList.add('hidden');
  cardsView?.classList.add('hidden');
  jrnView?.classList.add('hidden');
  docsView?.classList.add('hidden');

  fab?.classList.remove('fab-journal', 'fab-docs', 'fab-cards');

  const brandTitle = document.getElementById('vault-brand-title');
  const brandIcon  = document.getElementById('vault-brand-icon');

  if (tab === 'journal') {
    stopTotpTicker();
    jrnView?.classList.remove('hidden');
    fab?.classList.add('fab-journal');
    if (brandTitle) brandTitle.textContent = 'Journal';
    if (brandIcon) brandIcon.innerHTML = `<svg class="ic" style="color:#f59e0b"><use href="#ic-note"/></svg>`;
    renderJournalList();
    const grid = document.getElementById('journal-grid');
    if (grid) grid.scrollTop = 0;
  } else if (tab === 'cards') {
    stopTotpTicker();
    cardsView?.classList.remove('hidden');
    fab?.classList.add('fab-cards');
    if (brandTitle) brandTitle.textContent = 'Cards & Banks';
    if (brandIcon) brandIcon.innerHTML = `<svg class="ic" style="color:#a855f7"><use href="#ic-credit-card"/></svg>`;
    renderCardsList();
    const grid = document.getElementById('cards-grid');
    if (grid) grid.scrollTop = 0;
  } else if (tab === 'docs') {
    stopTotpTicker();
    docsView?.classList.remove('hidden');
    fab?.classList.add('fab-docs');
    if (brandTitle) brandTitle.textContent = 'Docs';
    if (brandIcon) brandIcon.innerHTML = `<svg class="ic" style="color:#38bdf8"><use href="#ic-id-card"/></svg>`;
    renderDocsList();
    const grid = document.getElementById('docs-grid');
    if (grid) grid.scrollTop = 0;
  } else {
    pwView?.classList.remove('hidden');
    if (brandTitle) brandTitle.textContent = 'Passwords';
    if (brandIcon) brandIcon.innerHTML = `<svg class="ic"><use href="#ic-key"/></svg>`;
    renderVaultList();
    const list = document.getElementById('vault-list');
    if (list) list.scrollTop = 0;
  }

  updateNavBadges();
}

function updateNavBadges() {
  const pwCount   = state.vault?.entries?.length || 0;
  const cardCount = state.vault?.cards?.length   || 0;
  const docCount  = state.vault?.docs?.length    || 0;
  const jrnCount  = state.vault?.notes?.length   || 0;

  const updateBadge = (id, count) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (count > 0) {
      el.textContent = count > 99 ? '99+' : count;
      el.style.display = 'inline-flex';
    } else {
      el.style.display = 'none';
    }
  };

  updateBadge('bottom-badge-passwords', pwCount);
  updateBadge('bottom-badge-cards',     cardCount);
  updateBadge('bottom-badge-docs',      docCount);
  updateBadge('bottom-badge-journal',   jrnCount);
}

function formatJournalCardDate(isoString) {
  if (!isoString) return '';
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return '';
  const now = new Date();
  const isSameYear = d.getFullYear() === now.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  if (isSameYear) {
    return `${month}/${day}`;
  } else {
    return `${month}/${day}/${d.getFullYear()}`;
  }
}

function formatNoteEditorDate(isoString) {
  const d = isoString ? new Date(isoString) : new Date();
  if (isNaN(d.getTime())) return 'Today';
  const opts = { month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true };
  return d.toLocaleDateString(undefined, opts);
}

function updateNoteCharCount() {
  const title = document.getElementById('note-title-input')?.value || '';
  const content = document.getElementById('note-content-input')?.value || '';
  const total = (title + content).length;
  const countEl = document.getElementById('note-char-count');
  if (countEl) {
    countEl.textContent = `${total} character${total === 1 ? '' : 's'}`;
  }
}

function renderJournalList() {
  const container = document.getElementById('journal-grid');
  if (!container) return;
  const q = (state.journalSearchQuery || '').toLowerCase().trim();
  const notes = state.vault?.notes || [];

  const filtered = q
    ? notes.filter(n =>
        (n.title || '').toLowerCase().includes(q) ||
        (n.content || '').toLowerCase().includes(q)
      )
    : notes;

  // Sort: most recently updated first
  const sorted = [...filtered].sort((a, b) =>
    new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0)
  );

  // Update count badge
  const countBadge = document.getElementById('journal-count-badge');
  if (countBadge) {
    const total = notes.length;
    const shown = sorted.length;
    countBadge.textContent = q ? `${shown} of ${total}` : `${total} note${total !== 1 ? 's' : ''}`;
  }
  updateNavBadges();

  if (sorted.length === 0) {
    container.innerHTML = `
      <div class="journal-empty">
        <div class="vault-empty-icon">
          <svg width="32" height="32" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" opacity=".3">
            <path d="M12 2H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V3a1 1 0 0 0-1-1z"/>
            <path d="M6 5h4M6 8h4M6 11h2"/>
          </svg>
        </div>
        <h3>${q ? `No notes for "${escapeHtml(q)}"` : 'No notes yet'}</h3>
        <p>${q ? 'Try a different search.' : 'Tap + to write your first journal entry.'}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  sorted.forEach(note => {
    const card = document.createElement('div');
    card.className = 'journal-card';
    card.dataset.id = note.id;

    const titleHtml = note.title
      ? `<div class="journal-card-title">${escapeHtml(note.title)}</div>`
      : '';
    const previewHtml = note.content
      ? `<div class="journal-card-preview">${escapeHtml(note.content)}</div>`
      : '';
    const dateStr = formatJournalCardDate(note.updated_at || note.created_at);

    card.innerHTML = `
      ${titleHtml}
      ${previewHtml}
      <div class="journal-card-date">${dateStr}</div>
    `;

    card.addEventListener('click', () => {
      openNoteEditor(note.id);
    });

    container.appendChild(card);
  });
}

function openNoteEditor(noteId) {
  state.editingNoteId = noteId;
  const titleInput = document.getElementById('note-title-input');
  const contentInput = document.getElementById('note-content-input');
  const dateLabel = document.getElementById('note-date-label');
  const deleteBtn = document.getElementById('note-delete-btn');

  if (noteId) {
    const note = state.vault?.notes?.find(n => n.id === noteId);
    if (!note) return;
    titleInput.value = note.title || '';
    contentInput.value = note.content || '';
    dateLabel.textContent = formatNoteEditorDate(note.updated_at || note.created_at);
    if (deleteBtn) deleteBtn.style.display = 'inline-flex';
  } else {
    titleInput.value = '';
    contentInput.value = '';
    dateLabel.textContent = formatNoteEditorDate(new Date().toISOString());
    if (deleteBtn) deleteBtn.style.display = 'none';
  }

  updateNoteCharCount();
  showScreen('note-editor');
  if (!noteId) {
    titleInput.focus();
  }
}

async function saveCurrentNote() {
  const title = (document.getElementById('note-title-input')?.value || '').trim();
  const content = (document.getElementById('note-content-input')?.value || '');
  const hasContent = title.length > 0 || content.trim().length > 0;
  const now = new Date().toISOString();

  if (!state.vault) return;
  if (!state.vault.notes) state.vault.notes = [];

  let changed = false;

  if (state.editingNoteId) {
    const idx = state.vault.notes.findIndex(n => n.id === state.editingNoteId);
    if (idx !== -1) {
      const existing = state.vault.notes[idx];
      if (existing.title !== title || existing.content !== content) {
        state.vault.notes[idx] = {
          ...existing,
          title,
          content,
          updated_at: now,
        };
        changed = true;
      }
    }
  } else if (hasContent) {
    state.vault.notes.push({
      id: uuid(),
      title,
      content,
      created_at: now,
      updated_at: now,
    });
    changed = true;
  }

  state.editingNoteId = null;
  showScreen('vault');
  renderJournalList();

  if (changed) {
    await saveVault();
  }
}

async function deleteCurrentNote() {
  if (!state.editingNoteId) return;
  if (!confirm('Delete this note? This cannot be undone.')) return;

  if (state.vault?.notes) {
    state.vault.notes = state.vault.notes.filter(n => n.id !== state.editingNoteId);
  }

  state.editingNoteId = null;
  showScreen('vault');
  renderJournalList();
  await saveVault();
  Toast.success('Note deleted.');
}

// ─── Emergency Documents (Approach B: Individual Encrypted Files) ─────────────

// In-memory cache for decrypted blob URLs: { [file_path]: blobUrl }
const _decryptedDocCache = {};

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function getDocIconInfo(category, name) {
  const n = (name || '').toLowerCase();
  const c = (category || '').toLowerCase();

  if (c === 'signature' || n.includes('sign')) {
    return { icon: '✍️', cls: 'icon-signature' };
  }
  if (n.includes('pan')) {
    return { icon: '🪪', cls: 'icon-pan' };
  }
  if (n.includes('license') || n.includes('dl') || n.includes('driving')) {
    return { icon: '🚗', cls: '' };
  }
  if (n.includes('passport') || c === 'travel') {
    return { icon: '🛂', cls: '' };
  }
  if (n.includes('aadhaar') || n.includes('aadhar')) {
    return { icon: '🆔', cls: '' };
  }
  return { icon: '📄', cls: '' };
}

function renderDocsList() {
  const container = document.getElementById('docs-grid');
  if (!container) return;

  const q = (state.docSearchQuery || '').toLowerCase().trim();
  const cat = state.docCategoryFilter || 'all';
  const docs = state.vault?.docs || [];

  const filtered = docs.filter(d => {
    const matchesCat = cat === 'all' || (d.category || 'other').toLowerCase() === cat.toLowerCase();
    if (!matchesCat) return false;

    if (!q) return true;
    return (
      (d.name || '').toLowerCase().includes(q) ||
      (d.number || '').toLowerCase().includes(q) ||
      (d.holder_name || '').toLowerCase().includes(q) ||
      (d.notes || '').toLowerCase().includes(q)
    );
  });

  // Sort: most recently updated first
  const sorted = [...filtered].sort((a, b) =>
    new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0)
  );

  const countBadge = document.getElementById('docs-count-badge');
  if (countBadge) {
    const total = docs.length;
    const shown = sorted.length;
    countBadge.textContent = q || cat !== 'all' ? `${shown} of ${total}` : `${total} doc${total !== 1 ? 's' : ''}`;
  }
  updateNavBadges();

  if (sorted.length === 0) {
    container.innerHTML = `
      <div class="journal-empty" style="grid-column: 1 / -1;">
        <div class="vault-empty-icon">
          <svg width="34" height="34" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" opacity=".3">
            <rect x="1.5" y="3" width="13" height="10" rx="1.5"/>
            <circle cx="5" cy="7" r="1.5"/>
            <path d="M3.5 11a1.5 1.5 0 0 1 3 0M8.5 6.5h4M8.5 9h2.5"/>
          </svg>
        </div>
        <h3>${q ? `No documents matching "${escapeHtml(q)}"` : 'No emergency documents yet'}</h3>
        <p>${q ? 'Try a different search or filter.' : 'Tap + to add your Driving License, PAN card, Passport, or Signature.'}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  sorted.forEach(doc => {
    const card = document.createElement('div');
    card.className = 'doc-card';
    card.dataset.id = doc.id;

    const { icon, cls } = getDocIconInfo(doc.category, doc.name);

    // Document number quick-copy box
    let numberHtml = '';
    if (doc.number) {
      numberHtml = `
        <div class="doc-num-chip">
          <span class="doc-num-text">${escapeHtml(doc.number)}</span>
          <button type="button" class="doc-num-copy-btn" data-action="copy-num" data-id="${doc.id}" title="Copy number" aria-label="Copy document number">
            <svg class="ic ic-sm"><use href="#ic-copy"/></svg>
            <span>Copy</span>
          </button>
        </div>
      `;
    }

    // Expiry date calculation
    let expiryHtml = '';
    if (doc.expiry_date) {
      const exp = new Date(doc.expiry_date);
      const now = new Date();
      const diffDays = Math.ceil((exp - now) / (1000 * 60 * 60 * 24));

      let badgeCls = '';
      let badgeLabel = `Exp: ${doc.expiry_date}`;
      if (diffDays < 0) {
        badgeCls = 'expired';
        badgeLabel = 'Expired';
      } else if (diffDays <= 90) {
        badgeCls = 'expiring-soon';
        badgeLabel = `Expires in ${diffDays}d`;
      }
      expiryHtml = `<span class="doc-expiry-badge ${badgeCls}">${escapeHtml(badgeLabel)}</span>`;
    }

    // Attached files pills
    let filesHtml = '';
    const files = doc.files || [];
    if (files.length > 0) {
      const pills = files.map(f => {
        const isPdf = (f.file_type || '').includes('pdf') || (f.file_name || '').endsWith('.pdf');
        const iconSymbol = isPdf ? '#ic-doc' : '#ic-eye';
        return `
          <button type="button" class="doc-file-pill" data-action="view-file" data-doc-id="${doc.id}" data-file-id="${f.file_id}">
            <svg class="ic ic-sm"><use href="${iconSymbol}"/></svg>
            <span>${escapeHtml(f.label || f.file_name)}</span>
            <span style="opacity:0.6;font-size:10px">${formatBytes(f.file_size)}</span>
          </button>
        `;
      }).join('');
      filesHtml = `<div class="doc-files-pills">${pills}</div>`;
    }

    const holderHtml = doc.holder_name ? `<div class="doc-card-holder">${escapeHtml(doc.holder_name)}</div>` : '';

    card.innerHTML = `
      <div class="doc-card-header">
        <div class="doc-card-title-row">
          <div class="doc-type-icon ${cls}">${icon}</div>
          <div style="min-width:0;flex:1">
            <div class="doc-card-title">${escapeHtml(doc.name)}</div>
            ${holderHtml}
          </div>
        </div>
        ${expiryHtml}
      </div>
      ${numberHtml}
      ${filesHtml}
    `;

    card.addEventListener('click', e => {
      if (e.target.closest('[data-action]')) return;
      openDocModal(doc.id);
    });

    container.appendChild(card);
  });

  // Action button delegates
  container.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const action = btn.dataset.action;
      if (action === 'copy-num') {
        const docId = btn.dataset.id;
        copyDocNumber(docId, btn);
      } else if (action === 'view-file') {
        const { docId, fileId } = btn.dataset;
        viewDocFile(docId, fileId);
      }
    });
  });
}

async function copyDocNumber(docId, btnElement = null) {
  const doc = state.vault?.docs?.find(d => d.id === docId);
  if (!doc || !doc.number) return;
  await Clipboard.copy(doc.number, `${doc.name} number copied!`);

  if (btnElement) {
    const origHtml = btnElement.innerHTML;
    btnElement.innerHTML = `<svg class="ic ic-sm" style="color:#22c55e"><use href="#ic-check"/></svg><span style="color:#22c55e">Copied</span>`;
    setTimeout(() => {
      btnElement.innerHTML = origHtml;
    }, 1500);
  }
}

function openDocModal(docId) {
  state.editingDocId = docId;
  state.currentDocId = docId || uuid();
  const doc = docId ? state.vault?.docs?.find(d => d.id === docId) : null;

  document.getElementById('modal-doc-title').textContent = doc ? 'Edit Document' : 'Add Document';
  document.getElementById('doc-name').value = doc ? doc.name : '';
  document.getElementById('doc-category').value = doc ? (doc.category || 'identity') : 'identity';
  document.getElementById('doc-number').value = doc ? (doc.number || '') : '';
  document.getElementById('doc-holder-name').value = doc ? (doc.holder_name || '') : '';
  document.getElementById('doc-expiry-date').value = doc ? (doc.expiry_date || '') : '';
  document.getElementById('doc-notes').value = doc ? (doc.notes || '') : '';

  const delBtn = document.getElementById('modal-doc-delete');
  if (delBtn) delBtn.classList.toggle('hidden', !doc);

  state.currentDocDraftFiles = doc?.files ? doc.files.map(f => ({ ...f })) : [];
  renderDocDraftFiles();

  showModal('modal-doc');
  if (!docId) {
    document.getElementById('doc-name').focus();
  }
}

function applyDocPreset(type) {
  const nameInput = document.getElementById('doc-name');
  const catInput  = document.getElementById('doc-category');
  const numInput  = document.getElementById('doc-number');

  if (type === 'pan') {
    nameInput.value = 'PAN Card';
    catInput.value = 'identity';
    numInput.placeholder = 'e.g. ABCDE1234F';
  } else if (type === 'dl') {
    nameInput.value = 'Driving License';
    catInput.value = 'identity';
    numInput.placeholder = 'e.g. DL-1420110012345';
  } else if (type === 'passport') {
    nameInput.value = 'Passport';
    catInput.value = 'travel';
    numInput.placeholder = 'e.g. M1234567';
  } else if (type === 'sign') {
    nameInput.value = 'Digital Signature';
    catInput.value = 'signature';
    numInput.placeholder = '(Optional reference/notes)';
  }
  nameInput.focus();
}

function renderDocDraftFiles() {
  const container = document.getElementById('doc-files-list');
  if (!container) return;

  if (state.currentDocDraftFiles.length === 0) {
    container.innerHTML = `
      <div style="padding:12px;text-align:center;border:1px dashed var(--line2);border-radius:var(--r-sm);color:var(--t3);font-size:12px">
        No files attached yet. Tap "Add File / Doc / PDF" above.
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  state.currentDocDraftFiles.forEach((file, index) => {
    const item = document.createElement('div');
    item.className = 'doc-file-item';

    const isPdf = (file.file_type || '').includes('pdf') || (file.file_name || '').endsWith('.pdf');
    const iconSymbol = isPdf ? '#ic-doc' : '#ic-eye';

    item.innerHTML = `
      <div class="doc-file-info">
        <svg class="ic" style="color:var(--t2)"><use href="${iconSymbol}"/></svg>
        <div style="min-width:0">
          <div class="doc-file-name">${escapeHtml(file.label || file.file_name)}</div>
          <div class="doc-file-meta">${escapeHtml(file.file_name)} • ${formatBytes(file.file_size)} ${file.isNew ? '<span style="color:#38bdf8">(Pending upload)</span>' : ''}</div>
        </div>
      </div>
      <div class="doc-file-actions">
        ${!file.isNew ? `
          <button type="button" class="btn-icon" data-draft-action="preview" data-idx="${index}" title="Preview" aria-label="Preview file">
            <svg class="ic ic-sm"><use href="#ic-eye"/></svg>
          </button>
        ` : ''}
        <button type="button" class="btn-icon" data-draft-action="remove" data-idx="${index}" title="Remove file" aria-label="Remove file">
          <svg class="ic ic-sm" style="color:var(--red)"><use href="#ic-trash"/></svg>
        </button>
      </div>
    `;

    container.appendChild(item);
  });

  container.querySelectorAll('[data-draft-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx, 10);
      const action = btn.dataset.draftAction;
      if (action === 'remove') {
        state.currentDocDraftFiles.splice(idx, 1);
        renderDocDraftFiles();
      } else if (action === 'preview') {
        const file = state.currentDocDraftFiles[idx];
        if (state.editingDocId && file.file_id) {
          viewDocFile(state.editingDocId, file.file_id);
        }
      }
    });
  });
}

async function handleDocFilesSelected(fileList) {
  if (!fileList || fileList.length === 0) return;

  const docId = state.editingDocId || state.currentDocId || uuid();
  state.currentDocId = docId;

  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    const buffer = await file.arrayBuffer();
    const fileId = uuid();
    const safeExt = file.name.split('.').pop() || 'bin';
    const filePath = `docs/${docId}_${fileId.slice(0, 8)}.${safeExt}.enc`;

    state.currentDocDraftFiles.push({
      file_id: fileId,
      label: file.name.replace(/\.[^/.]+$/, ''),
      file_name: file.name,
      file_type: file.type || 'application/octet-stream',
      file_size: file.size,
      file_path: filePath,
      dataBuffer: buffer,
      isNew: true,
    });
  }

  renderDocDraftFiles();
}

async function saveDoc() {
  if (!state.vaultKey || !state.vault) {
    Toast.error('Vault session is locked. Please unlock again to save.');
    hideModal('modal-doc');
    lockVault();
    return;
  }

  const name        = document.getElementById('doc-name').value.trim();
  const category    = document.getElementById('doc-category').value;
  const number      = document.getElementById('doc-number').value.trim();
  const holder_name = document.getElementById('doc-holder-name').value.trim();
  const expiry_date = document.getElementById('doc-expiry-date').value;
  const notes       = document.getElementById('doc-notes').value.trim();

  if (!name) {
    Toast.error('Document name is required.');
    return;
  }

  const saveBtn = document.getElementById('modal-doc-save');
  saveBtn.classList.add('btn-loading');
  saveBtn.disabled = true;

  try {
    const now = new Date().toISOString();
    const docId = state.editingDocId || state.currentDocId || uuid();

    // 1. Commit any new attached files to GitHub under docs/
    const finalFiles = [];

    for (let f of state.currentDocDraftFiles) {
      if (f.isNew && f.dataBuffer) {
        setSyncStatus(`⏳ Encrypting & uploading ${f.file_name}…`);
        const encBlob = await Crypto.encryptBinary(f.dataBuffer, state.vaultKey, state.vaultSalt);

        const sha = await GitHub.commitVault({
          content: encBlob,
          sha:     null,
          owner:   state.config.github_owner,
          repo:    state.config.github_repo,
          path:    f.file_path,
          token:   state.vault.github_pat,
        });

        finalFiles.push({
          file_id:   f.file_id,
          label:     f.label,
          file_name: f.file_name,
          file_type: f.file_type,
          file_size: f.file_size,
          file_path: f.file_path,
          sha:       sha,
          created_at: now,
        });
      } else {
        finalFiles.push({
          file_id:   f.file_id,
          label:     f.label,
          file_name: f.file_name,
          file_type: f.file_type,
          file_size: f.file_size,
          file_path: f.file_path,
          sha:       f.sha,
          created_at: f.created_at || now,
        });
      }
    }

    // 2. Detect removed files and delete them from GitHub
    if (state.editingDocId) {
      const existingDoc = state.vault?.docs?.find(d => d.id === state.editingDocId);
      if (existingDoc && existingDoc.files) {
        const remainingPaths = new Set(finalFiles.map(f => f.file_path));
        for (let oldFile of existingDoc.files) {
          if (!remainingPaths.has(oldFile.file_path) && oldFile.sha) {
            try {
              await GitHub.deleteFile({
                path:  oldFile.file_path,
                sha:   oldFile.sha,
                owner: state.config.github_owner,
                repo:  state.config.github_repo,
                token: state.vault.github_pat,
              });
              delete _decryptedDocCache[oldFile.file_path];
            } catch (err) {
              console.warn('Could not delete old file from GitHub:', err);
            }
          }
        }
      }
    }

    if (!state.vault.docs) state.vault.docs = [];

    if (state.editingDocId) {
      const idx = state.vault.docs.findIndex(d => d.id === state.editingDocId);
      if (idx !== -1) {
        state.vault.docs[idx] = {
          ...state.vault.docs[idx],
          name, category, number, holder_name, expiry_date, notes,
          files: finalFiles,
          updated_at: now,
        };
      }
    } else {
      state.vault.docs.push({
        id:          docId,
        name, category, number, holder_name, expiry_date, notes,
        files:       finalFiles,
        created_at:  now,
        updated_at:  now,
      });
    }

    hideModal('modal-doc');
    renderDocsList();
    Toast.success('Document saved.');
    await saveVault();

  } catch (err) {
    Toast.error(`Save failed: ${err.message}`);
  } finally {
    saveBtn.classList.remove('btn-loading');
    saveBtn.disabled = false;
  }
}

async function deleteDoc() {
  if (!state.editingDocId) return;
  if (!confirm('Delete this document and all its attached files? This cannot be undone.')) return;

  const doc = state.vault?.docs?.find(d => d.id === state.editingDocId);
  if (doc && doc.files) {
    // Delete attached files from GitHub
    for (let f of doc.files) {
      if (f.file_path && f.sha) {
        try {
          await GitHub.deleteFile({
            path:  f.file_path,
            sha:   f.sha,
            owner: state.config.github_owner,
            repo:  state.config.github_repo,
            token: state.vault.github_pat,
          });
          delete _decryptedDocCache[f.file_path];
        } catch (err) {
          console.warn('Could not delete file from GitHub:', err);
        }
      }
    }
  }

  state.vault.docs = (state.vault.docs || []).filter(d => d.id !== state.editingDocId);
  hideModal('modal-doc');
  renderDocsList();
  Toast.success('Document deleted.');
  await saveVault();
}

async function viewDocFile(docId, fileId) {
  const doc = state.vault?.docs?.find(d => d.id === docId);
  if (!doc) return;
  const file = doc.files?.find(f => f.file_id === fileId);
  if (!file) return;

  document.getElementById('viewer-title').textContent = doc.name;
  document.getElementById('viewer-subtitle').textContent = `${file.label || file.file_name} • ${formatBytes(file.file_size)}`;

  const spinner = document.getElementById('viewer-loading-spinner');
  const container = document.getElementById('viewer-container');
  container.innerHTML = '';
  spinner.style.display = 'block';

  showModal('modal-doc-viewer');

  try {
    if (!state.vaultKey) {
      throw new Error('Vault is locked. Please unlock your vault first.');
    }

    let blobUrl = _decryptedDocCache[file.file_path];

    if (!blobUrl) {
      const { blob } = await GitHub.fetchFile(
        state.config.github_owner,
        state.config.github_repo,
        file.file_path,
        state.vault.github_pat
      );

      const decryptedBuffer = await Crypto.decryptBinary(blob, state.vaultKey);
      const mimeType = file.file_type || 'application/octet-stream';
      const fileBlob = new Blob([decryptedBuffer], { type: mimeType });
      blobUrl = URL.createObjectURL(fileBlob);
      _decryptedDocCache[file.file_path] = blobUrl;
    }

    spinner.style.display = 'none';

    const isPdf   = (file.file_type || '').includes('pdf') || (file.file_name || '').toLowerCase().endsWith('.pdf');
    const isImage = (file.file_type || '').startsWith('image/') || /\.(jpg|jpeg|png|webp|gif|svg)$/i.test(file.file_name || '');

    if (isPdf) {
      container.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;height:100%;width:100%">
          <iframe src="${blobUrl}" style="width:100%;height:100%;border:none;border-radius:var(--r)"></iframe>
        </div>
      `;
    } else if (isImage) {
      container.innerHTML = `
        <img src="${blobUrl}" alt="${escapeHtml(file.file_name)}" />
      `;
    } else {
      // Word (.docx, .doc), text, or other document format
      container.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;text-align:center;padding:30px 16px;">
          <div style="font-size:52px;">📄</div>
          <div style="font-size:17px;font-weight:600;color:var(--w);">${escapeHtml(file.file_name)}</div>
          <div style="font-size:12px;color:var(--t2);">${formatBytes(file.file_size)} • Decrypted document</div>
          <p class="hint" style="max-width:340px;font-size:12.5px;">This file is decrypted and ready to open in Microsoft Word, Google Docs, or your office app.</p>
          <button type="button" class="btn-primary" id="viewer-doc-direct-dl-btn" style="margin-top:8px;">
            <svg class="ic ic-sm"><use href="#ic-download"/></svg>
            <span>Download Decrypted File</span>
          </button>
        </div>
      `;
      document.getElementById('viewer-doc-direct-dl-btn')?.addEventListener('click', () => {
        document.getElementById('viewer-download-btn')?.click();
      });
    }

    // Set download button
    const dlBtn = document.getElementById('viewer-download-btn');
    dlBtn.onclick = () => {
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = file.file_name || `${doc.name}_${file.label || 'doc'}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };

  } catch (err) {
    spinner.style.display = 'none';
    container.innerHTML = `
      <div style="color:var(--red);text-align:center;padding:20px">
        Failed to decrypt file: ${escapeHtml(err.message)}
      </div>
    `;
  }
}

// ─── Credit / Debit Cards & Bank Presets ─────────────────────────────────────

const BANK_PRESETS = {
  hdfc: {
    name: 'HDFC Bank',
    theme: 'card-theme-hdfc',
    cardType: 'credit',
    ifscPrefix: 'HDFC000',
  },
  sbi: {
    name: 'State Bank of India',
    theme: 'card-theme-sbi',
    cardType: 'debit',
    ifscPrefix: 'SBIN000',
  },
  icici: {
    name: 'ICICI Bank',
    theme: 'card-theme-icici',
    cardType: 'credit',
    ifscPrefix: 'ICIC000',
  },
  axis: {
    name: 'Axis Bank',
    theme: 'card-theme-axis',
    cardType: 'credit',
    ifscPrefix: 'UTIB000',
  },
  kotak: {
    name: 'Kotak Mahindra Bank',
    theme: 'card-theme-kotak',
    cardType: 'debit',
    ifscPrefix: 'KKBK000',
  },
  amex: {
    name: 'American Express',
    theme: 'card-theme-gold',
    cardType: 'credit',
    ifscPrefix: '',
  },
  rupay: {
    name: 'RuPay Card',
    theme: 'card-theme-emerald',
    cardType: 'credit',
    ifscPrefix: '',
  },
};

function detectCardNetwork(number) {
  const clean = (number || '').replace(/\D/g, '');
  if (/^4/.test(clean)) return 'visa';
  if (/^(5[1-5]|2[2-7])/.test(clean)) return 'mastercard';
  if (/^(60|6521|6522|508)/.test(clean)) return 'rupay';
  if (/^3[47]/.test(clean)) return 'amex';
  if (/^(6011|65|64[4-9])/.test(clean)) return 'discover';
  return 'other';
}

function formatCardNumber(num, network = 'other') {
  const digits = (num || '').replace(/\D/g, '').slice(0, 16);
  if (network === 'amex') {
    const p1 = digits.slice(0, 4);
    const p2 = digits.slice(4, 10);
    const p3 = digits.slice(10, 15);
    return [p1, p2, p3].filter(Boolean).join(' ');
  }
  const parts = [];
  for (let i = 0; i < digits.length; i += 4) {
    parts.push(digits.slice(i, i + 4));
  }
  return parts.join(' ');
}

function formatCardExpiry(val) {
  const digits = (val || '').replace(/\D/g, '').slice(0, 4);
  if (digits.length >= 3) {
    return digits.slice(0, 2) + '/' + digits.slice(2);
  }
  return digits;
}

function maskCardNumber(num) {
  const digits = (num || '').replace(/\D/g, '');
  if (digits.length <= 4) return digits || '••••';
  const last4 = digits.slice(-4);
  if (digits.length === 15) {
    return `•••• •••••• •${last4}`;
  }
  return `•••• •••• •••• ${last4}`;
}

function setCardModalMode(mode) {
  state.cardMode = mode;
  const isCard = mode === 'card';

  document.getElementById('btn-toggle-type-card')?.classList.toggle('active', isCard);
  document.getElementById('btn-toggle-type-bank')?.classList.toggle('active', !isCard);

  document.getElementById('card-preview-container')?.classList.toggle('hidden', !isCard);
  document.getElementById('fields-payment-card')?.classList.toggle('hidden', !isCard);
  document.getElementById('fields-bank-account')?.classList.toggle('hidden', isCard);

  const title = document.getElementById('modal-card-title');
  if (title) {
    if (state.editingCardId) {
      title.textContent = isCard ? 'Edit Payment Card' : 'Edit Bank Account';
    } else {
      title.textContent = isCard ? 'Add Payment Card' : 'Add Bank Account';
    }
  }
}

function selectCardTheme(theme) {
  state.selectedCardTheme = theme;
  document.querySelectorAll('#card-theme-palette .theme-swatch').forEach(sw => {
    sw.classList.toggle('active', sw.dataset.theme === theme);
  });
  updateLiveCardPreview();
}

function applyBankPreset(key) {
  const preset = BANK_PRESETS[key];
  if (!preset) return;

  if (state.cardMode === 'card') {
    const bankInput = document.getElementById('card-bank-name');
    if (bankInput) bankInput.value = preset.name;
    const typeSelect = document.getElementById('card-type-select');
    if (typeSelect && preset.cardType) typeSelect.value = preset.cardType;
    selectCardTheme(preset.theme);
  } else {
    const bankInput = document.getElementById('bank-account-bank');
    if (bankInput) bankInput.value = preset.name;
    const ifscInput = document.getElementById('bank-account-ifsc');
    if (ifscInput && preset.ifscPrefix && !ifscInput.value) {
      ifscInput.value = preset.ifscPrefix;
    }
  }
}

function updateLiveCardPreview() {
  const bankInput   = document.getElementById('card-bank-name');
  const typeSelect  = document.getElementById('card-type-select');
  const holderInput = document.getElementById('card-holder-name');
  const numInput    = document.getElementById('card-number');
  const expInput    = document.getElementById('card-expiry');

  const previewCard  = document.getElementById('card-live-preview');
  const prevBank     = document.getElementById('prev-bank-name');
  const prevType     = document.getElementById('prev-card-type');
  const prevHolder   = document.getElementById('prev-card-holder');
  const prevNum      = document.getElementById('prev-card-number');
  const prevExp      = document.getElementById('prev-card-expiry');
  const prevNet      = document.getElementById('prev-card-network');
  const detectedPill = document.getElementById('card-detected-network');

  const bankVal   = bankInput?.value.trim()   || 'BANK NAME';
  const typeVal   = typeSelect?.value         || 'credit';
  const holderVal = holderInput?.value.trim() || 'YOUR NAME';
  const rawNum    = (numInput?.value || '').replace(/\D/g, '');
  const expVal    = expInput?.value.trim()    || 'MM/YY';

  const network = detectCardNetwork(rawNum);

  if (prevBank) prevBank.textContent = bankVal.toUpperCase();
  if (prevType) prevType.textContent = typeVal.toUpperCase();
  if (prevHolder) prevHolder.textContent = holderVal.toUpperCase();
  if (prevExp) prevExp.textContent = expVal;

  const netDisplay = network === 'mastercard' ? 'Mastercard' : (network === 'rupay' ? 'RuPay' : (network === 'amex' ? 'AMEX' : (network === 'discover' ? 'Discover' : 'VISA')));
  if (prevNet) prevNet.textContent = netDisplay;
  if (detectedPill) detectedPill.textContent = netDisplay;

  if (prevNum) {
    if (!rawNum) {
      prevNum.textContent = '•••• •••• •••• ••••';
    } else {
      prevNum.textContent = formatCardNumber(rawNum, network);
    }
  }

  if (previewCard) {
    const allThemes = ['card-theme-black', 'card-theme-hdfc', 'card-theme-sbi', 'card-theme-icici', 'card-theme-axis', 'card-theme-kotak', 'card-theme-emerald', 'card-theme-gold', 'card-theme-purple'];
    allThemes.forEach(t => previewCard.classList.remove(t));
    previewCard.classList.add(state.selectedCardTheme || 'card-theme-black');
  }
}

function openCardModal(id = null) {
  state.editingCardId = id;

  const card = id ? state.vault?.cards?.find(c => c.id === id) : null;
  const mode = card ? (card.type || 'card') : 'card';
  setCardModalMode(mode);

  if (card) {
    document.getElementById('modal-card-title').textContent = mode === 'card' ? 'Edit Payment Card' : 'Edit Bank Account';
    document.getElementById('modal-card-delete')?.classList.remove('hidden');

    if (mode === 'card') {
      document.getElementById('card-bank-name').value   = card.bank_name   || '';
      document.getElementById('card-type-select').value = card.card_type   || 'credit';
      document.getElementById('card-holder-name').value = card.card_holder || '';
      document.getElementById('card-number').value      = formatCardNumber(card.card_number || '', card.card_network);
      document.getElementById('card-expiry').value      = card.expiry      || '';
      document.getElementById('card-cvv').value         = card.cvv         || '';
      document.getElementById('card-pin').value         = card.pin         || '';
      selectCardTheme(card.color_theme || 'card-theme-black');
    } else {
      document.getElementById('bank-account-bank').value           = card.bank_name      || '';
      document.getElementById('bank-account-type').value           = card.account_type   || 'savings';
      document.getElementById('bank-account-holder').value         = card.card_holder    || '';
      document.getElementById('bank-account-number').value         = card.account_number || '';
      document.getElementById('bank-account-ifsc').value           = card.ifsc           || '';
      document.getElementById('bank-account-branch').value         = card.branch         || '';
      document.getElementById('bank-account-upi').value            = card.upi_id         || '';
      document.getElementById('bank-account-cif').value            = card.cif_no         || '';
      document.getElementById('bank-account-netbanking-id').value  = card.netbanking_id  || '';
    }
    document.getElementById('card-notes').value = card.notes || '';
  } else {
    document.getElementById('modal-card-title').textContent = 'Add Payment Card';
    document.getElementById('modal-card-delete')?.classList.add('hidden');

    // Reset card fields
    document.getElementById('card-bank-name').value   = '';
    document.getElementById('card-type-select').value = 'credit';
    document.getElementById('card-holder-name').value = '';
    document.getElementById('card-number').value      = '';
    document.getElementById('card-expiry').value      = '';
    document.getElementById('card-cvv').value         = '';
    document.getElementById('card-pin').value         = '';

    // Reset bank fields
    document.getElementById('bank-account-bank').value          = '';
    document.getElementById('bank-account-type').value          = 'savings';
    document.getElementById('bank-account-holder').value        = '';
    document.getElementById('bank-account-number').value        = '';
    document.getElementById('bank-account-ifsc').value          = '';
    document.getElementById('bank-account-branch').value        = '';
    document.getElementById('bank-account-upi').value           = '';
    document.getElementById('bank-account-cif').value           = '';
    document.getElementById('bank-account-netbanking-id').value = '';

    document.getElementById('card-notes').value = '';
    selectCardTheme('card-theme-black');
  }

  updateLiveCardPreview();
  showModal('modal-card');
}

async function saveCard() {
  const mode = state.cardMode;
  const now = new Date().toISOString();

  if (!state.vault.cards) state.vault.cards = [];

  let cardObj = null;

  if (mode === 'card') {
    const bankName   = document.getElementById('card-bank-name').value.trim();
    const cardType   = document.getElementById('card-type-select').value;
    const cardHolder = document.getElementById('card-holder-name').value.trim();
    const rawNumber  = document.getElementById('card-number').value.replace(/\D/g, '');
    const expiry     = document.getElementById('card-expiry').value.trim();
    const cvv        = document.getElementById('card-cvv').value.trim();
    const pin        = document.getElementById('card-pin').value.trim();
    const notes      = document.getElementById('card-notes').value.trim();

    if (!bankName || !cardHolder || !rawNumber) {
      Toast.error('Please enter the bank name, cardholder name, and card number.');
      return;
    }

    const network = detectCardNetwork(rawNumber);

    cardObj = {
      type: 'card',
      bank_name: bankName,
      card_type: cardType,
      card_holder: cardHolder,
      card_number: rawNumber,
      card_network: network,
      expiry,
      cvv,
      pin,
      color_theme: state.selectedCardTheme || 'card-theme-black',
      notes,
    };
  } else {
    const bankName      = document.getElementById('bank-account-bank').value.trim();
    const accountType   = document.getElementById('bank-account-type').value;
    const holder        = document.getElementById('bank-account-holder').value.trim();
    const accountNumber = document.getElementById('bank-account-number').value.trim();
    const ifsc          = document.getElementById('bank-account-ifsc').value.trim().toUpperCase();
    const branch        = document.getElementById('bank-account-branch').value.trim();
    const upiId         = document.getElementById('bank-account-upi').value.trim();
    const cifNo         = document.getElementById('bank-account-cif').value.trim();
    const netbankingId  = document.getElementById('bank-account-netbanking-id').value.trim();
    const notes         = document.getElementById('card-notes').value.trim();

    if (!bankName || !accountNumber) {
      Toast.error('Please enter the bank name and account number.');
      return;
    }

    cardObj = {
      type: 'bank',
      bank_name: bankName,
      account_type: accountType,
      card_holder: holder,
      account_number: accountNumber,
      ifsc,
      branch,
      upi_id: upiId,
      cif_no: cifNo,
      netbanking_id: netbankingId,
      notes,
    };
  }

  if (state.editingCardId) {
    const idx = state.vault.cards.findIndex(c => c.id === state.editingCardId);
    if (idx !== -1) {
      state.vault.cards[idx] = {
        ...state.vault.cards[idx],
        ...cardObj,
        updated_at: now,
      };
    }
  } else {
    state.vault.cards.push({
      id: uuid(),
      ...cardObj,
      created_at: now,
      updated_at: now,
    });
  }

  hideModal('modal-card');
  renderCardsList();
  Toast.success(mode === 'card' ? 'Card saved securely.' : 'Bank account saved securely.');
  await saveVault();
}

async function deleteCard() {
  if (!state.editingCardId) return;
  if (!confirm('Delete this card / bank account? This cannot be undone.')) return;

  state.vault.cards = (state.vault.cards || []).filter(c => c.id !== state.editingCardId);
  hideModal('modal-card');
  renderCardsList();
  Toast.success('Item deleted.');
  await saveVault();
}

function renderCardsList() {
  const container = document.getElementById('cards-grid');
  if (!container) return;

  const q = (state.cardsSearchQuery || '').toLowerCase().trim();
  const filter = state.cardCategoryFilter || 'all';
  const allCards = state.vault?.cards || [];

  const filtered = allCards.filter(c => {
    // Category filter
    if (filter === 'credit' && (c.type !== 'card' || c.card_type !== 'credit')) return false;
    if (filter === 'debit' && (c.type !== 'card' || c.card_type !== 'debit')) return false;
    if (filter === 'bank' && c.type !== 'bank') return false;

    // Search query
    if (q) {
      const matchBank   = (c.bank_name || '').toLowerCase().includes(q);
      const matchHolder = (c.card_holder || '').toLowerCase().includes(q);
      const matchNum    = (c.card_number || c.account_number || '').includes(q);
      const matchUpi    = (c.upi_id || '').toLowerCase().includes(q);
      const matchIfsc   = (c.ifsc || '').toLowerCase().includes(q);
      return matchBank || matchHolder || matchNum || matchUpi || matchIfsc;
    }
    return true;
  });

  const sorted = [...filtered].sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));

  const countBadge = document.getElementById('cards-count-badge');
  if (countBadge) {
    const total = allCards.length;
    countBadge.textContent = q || filter !== 'all' ? `${sorted.length} of ${total}` : `${total} item${total !== 1 ? 's' : ''}`;
  }
  updateNavBadges();

  if (sorted.length === 0) {
    container.innerHTML = `
      <div class="vault-empty" style="grid-column: 1 / -1;">
        <div class="vault-empty-icon">
          <svg width="36" height="36" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" opacity=".3">
            <rect x="1.5" y="3" width="13" height="10" rx="1.5"/>
            <path d="M1.5 6.5h13M4 10.5h2.5"/>
          </svg>
        </div>
        <h3>${q ? `No cards match "${escapeHtml(q)}"` : 'No cards or bank accounts added'}</h3>
        <p>${q ? 'Try a different search.' : 'Press + to securely store credit cards, debit cards, or bank details.'}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = '';

  sorted.forEach(item => {
    if (item.type === 'bank') {
      const cardEl = document.createElement('div');
      cardEl.className = 'bank-account-card';
      cardEl.dataset.id = item.id;

      const maskedAcc = item.account_number ? (item.account_number.length > 4 ? `•••• •••• ${item.account_number.slice(-4)}` : item.account_number) : '—';
      const upiDisplay = item.upi_id ? `<div class="bank-detail-item"><span class="bank-detail-label">UPI ID</span><div class="bank-detail-value-row"><span>${escapeHtml(item.upi_id)}</span><button type="button" class="bank-detail-copy-btn" data-copy="${escapeHtml(item.upi_id)}" data-label="UPI ID" title="Copy UPI ID"><svg class="ic ic-sm"><use href="#ic-copy"/></svg></button></div></div>` : '';
      const branchDisplay = item.branch ? `<div class="bank-detail-item"><span class="bank-detail-label">Branch</span><span class="bank-detail-value-row">${escapeHtml(item.branch)}</span></div>` : '';

      cardEl.innerHTML = `
        <div class="bank-card-header">
          <div class="bank-card-title-group">
            <div class="bank-card-icon">
              <svg class="ic"><use href="#ic-bank"/></svg>
            </div>
            <div>
              <div class="bank-card-name">${escapeHtml(item.bank_name || 'Bank Account')}</div>
              <div style="font-size:11px;color:var(--t3);">${escapeHtml(item.card_holder || '')}</div>
            </div>
          </div>
          <span class="bank-card-type-badge">${escapeHtml(item.account_type || 'Savings')}</span>
        </div>

        <div class="bank-card-details-grid">
          <div class="bank-detail-item">
            <span class="bank-detail-label">Account No.</span>
            <div class="bank-detail-value-row">
              <span id="bank-acc-display-${item.id}">${maskedAcc}</span>
              <button type="button" class="bank-detail-copy-btn" data-copy="${escapeHtml(item.account_number)}" data-label="Account Number" title="Copy Account No."><svg class="ic ic-sm"><use href="#ic-copy"/></svg></button>
            </div>
          </div>
          <div class="bank-detail-item">
            <span class="bank-detail-label">IFSC Code</span>
            <div class="bank-detail-value-row">
              <span>${escapeHtml(item.ifsc || '—')}</span>
              ${item.ifsc ? `<button type="button" class="bank-detail-copy-btn" data-copy="${escapeHtml(item.ifsc)}" data-label="IFSC Code" title="Copy IFSC"><svg class="ic ic-sm"><use href="#ic-copy"/></svg></button>` : ''}
            </div>
          </div>
          ${upiDisplay}
          ${branchDisplay}
        </div>

        <div class="card-quick-actions">
          <div class="card-action-btn-group">
            <button type="button" class="card-action-chip" data-copy="${escapeHtml(item.account_number)}" data-label="Account Number">
              <svg class="ic ic-sm"><use href="#ic-copy"/></svg>
              <span>Copy A/C</span>
            </button>
            ${item.ifsc ? `
              <button type="button" class="card-action-chip" data-copy="${escapeHtml(item.ifsc)}" data-label="IFSC Code">
                <svg class="ic ic-sm"><use href="#ic-copy"/></svg>
                <span>Copy IFSC</span>
              </button>
            ` : ''}
          </div>
          <button type="button" class="btn-icon" data-action="edit" data-id="${item.id}" title="Edit" aria-label="Edit">
            <svg class="ic"><use href="#ic-edit"/></svg>
          </button>
        </div>
      `;

      cardEl.addEventListener('click', e => {
        if (e.target.closest('[data-copy]') || e.target.closest('[data-action]')) return;
        openCardModal(item.id);
      });

      container.appendChild(cardEl);

    } else {
      const cardWrapper = document.createElement('div');
      cardWrapper.className = 'card-item-wrapper';
      cardWrapper.dataset.id = item.id;

      const network = item.card_network || detectCardNetwork(item.card_number);
      const netDisplay = network === 'mastercard' ? 'Mastercard' : (network === 'rupay' ? 'RuPay' : (network === 'amex' ? 'AMEX' : (network === 'discover' ? 'Discover' : 'VISA')));
      const masked = maskCardNumber(item.card_number);
      const formattedFull = formatCardNumber(item.card_number, network);
      const themeClass = item.color_theme || 'card-theme-black';

      cardWrapper.innerHTML = `
        <div class="digital-card ${themeClass}" id="card-view-${item.id}">
          <div class="card-top-row">
            <span class="card-preview-bank">${escapeHtml(item.bank_name || 'CARD')}</span>
            <span class="card-preview-badge">${escapeHtml((item.card_type || 'credit').toUpperCase())}</span>
          </div>
          <div class="card-chip-row">
            <div class="card-emv-chip">
              <div class="chip-line horizontal"></div>
              <div class="chip-line vertical"></div>
            </div>
            <div class="card-contactless-icon">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M8.5 16.5a5 5 0 0 1 0-9"/><path d="M12 19a8.5 8.5 0 0 0 0-14"/><path d="M15.5 21.5a12 12 0 0 0 0-19"/></svg>
            </div>
          </div>
          <div class="card-preview-number" id="card-num-text-${item.id}" data-masked="${masked}" data-full="${formattedFull}">${masked}</div>
          <div class="card-bottom-row">
            <div class="card-preview-meta">
              <span class="card-meta-label">CARDHOLDER</span>
              <span class="card-meta-val">${escapeHtml((item.card_holder || 'YOUR NAME').toUpperCase())}</span>
            </div>
            <div class="card-preview-meta">
              <span class="card-meta-label">EXPIRES</span>
              <span class="card-meta-val">${escapeHtml(item.expiry || '••/••')}</span>
            </div>
            <div class="card-network-logo">${netDisplay}</div>
          </div>
        </div>

        <div class="card-quick-actions">
          <div class="card-action-btn-group">
            <button type="button" class="card-action-chip" data-copy="${escapeHtml(item.card_number)}" data-label="Card Number" title="Copy Card Number">
              <svg class="ic ic-sm"><use href="#ic-copy"/></svg>
              <span>Copy No.</span>
            </button>
            ${item.cvv ? `
              <button type="button" class="card-action-chip" data-copy="${escapeHtml(item.cvv)}" data-label="CVV" title="Copy CVV">
                <svg class="ic ic-sm"><use href="#ic-shield-check"/></svg>
                <span>CVV •••</span>
              </button>
            ` : ''}
            <button type="button" class="card-action-chip" data-action="toggle-number" data-id="${item.id}" title="Toggle full number">
              <svg class="ic ic-sm"><use href="#ic-eye"/></svg>
              <span>Reveal</span>
            </button>
          </div>
          <button type="button" class="btn-icon" data-action="edit" data-id="${item.id}" title="Edit" aria-label="Edit">
            <svg class="ic"><use href="#ic-edit"/></svg>
          </button>
        </div>
      `;

      cardWrapper.addEventListener('click', e => {
        if (e.target.closest('[data-copy]') || e.target.closest('[data-action]')) return;
        openCardModal(item.id);
      });

      container.appendChild(cardWrapper);
    }
  });

  container.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const val = btn.dataset.copy;
      const label = btn.dataset.label || 'Value';
      if (!val) return;
      await Clipboard.copy(val, `${label} copied to clipboard!`);
    });
  });

  container.querySelectorAll('[data-action="toggle-number"]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const numEl = document.getElementById(`card-num-text-${id}`);
      if (!numEl) return;
      const isFull = numEl.textContent === numEl.dataset.full;
      numEl.textContent = isFull ? numEl.dataset.masked : numEl.dataset.full;
      btn.querySelector('span').textContent = isFull ? 'Reveal' : 'Hide';
    });
  });

  container.querySelectorAll('[data-action="edit"]').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      openCardModal(btn.dataset.id);
    });
  });
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

// ─── Biometrics & Settings ───────────────────────────────────────────────────

async function triggerBiometricUnlock() {
  const isQuickOnly = state.screen === 'unlock' && !document.getElementById('unlock-quick-only').classList.contains('hidden');
  const errEl = isQuickOnly
    ? document.getElementById('unlock-quick-error')
    : document.getElementById('unlock-error');

  const btn = isQuickOnly
    ? document.getElementById('unlock-quick-bio-btn')
    : document.getElementById('unlock-full-bio-btn');

  if (btn) btn.classList.add('btn-loading');

  try {
    const masterSecret = await Biometrics.unlock();
    if (!masterSecret) return;

    let blob = state.vaultBlob || sessionGet('vault_blob');
    if (!blob) {
      setLoadingMsg('Fetching encrypted vault…');
      const { blob: fetchedBlob, sha } = await GitHub.fetchVault(
        state.config.github_owner,
        state.config.github_repo,
        state.config.github_path || 'vault.enc'
      );
      blob = fetchedBlob;
      state.vaultBlob = blob;
      state.vaultSha  = sha;
      sessionSet('vault_sha', sha);
    }

    const { data, key, salt } = await Crypto.decryptVault(blob, masterSecret);

    state.vault        = data;
    if (state.vault && !state.vault.notes) state.vault.notes = [];
    if (state.vault && !state.vault.docs)  state.vault.docs  = [];
    state.vaultKey     = key;
    state.vaultSalt    = salt;
    state.vaultBlob    = blob;
    state.vaultSha     = state.vaultSha || sessionGet('vault_sha');
    state.masterSecret = masterSecret;

    // Cache wrapped key for quick session unlock
    const parts = masterSecret.split('\x00');
    const quickSecret = parts[1] || '';
    if (quickSecret) {
      await cacheKeyForQuickUnlock(key, quickSecret);
    }

    showScreen('vault');
    renderActiveTab();
    Toast.success('Unlocked with Biometrics');

  } catch (err) {
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
      console.log('Biometric prompt was dismissed.');
    } else {
      console.warn('Biometric unlock failed:', err);
      if (errEl) {
        showErr(errEl, err.message === 'DECRYPT_FAILED'
          ? 'Biometric data could not be decrypted. Please unlock with master password.'
          : (err.message || 'Biometric unlock failed.')
        );
      }
    }
  } finally {
    if (btn) btn.classList.remove('btn-loading');
  }
}

async function openSettingsModal() {
  const isEnrolled = typeof Biometrics !== 'undefined' && Biometrics.isEnrolled();
  const isAvail    = typeof Biometrics !== 'undefined' && await Biometrics.isAvailable();

  const badge      = document.getElementById('settings-bio-status-badge');
  const toggleBtn  = document.getElementById('settings-bio-toggle-btn');
  const toggleLbl  = document.getElementById('settings-bio-toggle-label');
  const msgEl      = document.getElementById('settings-bio-msg');

  if (badge) badge.style.display = isEnrolled ? 'inline-block' : 'none';

  if (!isAvail && !isEnrolled) {
    if (toggleBtn) {
      toggleBtn.disabled = true;
      toggleBtn.className = 'btn-secondary btn-sm';
    }
    if (toggleLbl) toggleLbl.textContent = 'Not Supported on Device';
    if (msgEl) {
      msgEl.textContent = 'Face ID, Touch ID, or fingerprint sensors are not available in this browser.';
      msgEl.style.display = 'block';
    }
  } else if (isEnrolled) {
    if (toggleBtn) {
      toggleBtn.disabled = false;
      toggleBtn.className = 'btn-danger btn-sm';
    }
    if (toggleLbl) toggleLbl.textContent = 'Disable Biometrics';
    if (msgEl) {
      msgEl.textContent = 'Active: You can unlock this vault using your biometric sensor.';
      msgEl.style.display = 'block';
    }
  } else {
    if (toggleBtn) {
      toggleBtn.disabled = false;
      toggleBtn.className = 'btn-primary btn-sm';
    }
    if (toggleLbl) toggleLbl.textContent = 'Enable Biometric Unlock';
    if (msgEl) {
      msgEl.style.display = 'none';
    }
  }

  // Quick mode info
  const quickLabel = document.getElementById('settings-quick-mode-label');
  if (quickLabel) {
    quickLabel.textContent = (state.config?.quick_unlock_type || 'PIN').toUpperCase();
  }

  // Repository info
  const repoName = document.getElementById('settings-repo-name');
  if (repoName && state.config?.github_owner) {
    repoName.textContent = `${state.config.github_owner}/${state.config.github_repo || 'vault'}`;
  }

  showModal('modal-settings');
}

async function handleToggleBiometrics() {
  const btn = document.getElementById('settings-bio-toggle-btn');
  if (!btn) return;

  if (Biometrics.isEnrolled()) {
    Biometrics.disable();
    Toast.info('Biometric unlock disabled.');
    openSettingsModal();
    return;
  }

  let secret = state.masterSecret;
  if (!secret) {
    const pw = prompt('Please enter your Master Password to enable biometrics on this device:');
    if (!pw) return;
    const qSecret = state.config?.quick_unlock_type === 'pattern'
      ? prompt('Please enter your pattern coordinates (or PIN):')
      : prompt('Please enter your PIN:');
    if (!qSecret) return;
    secret = pw + '\x00' + qSecret;
  }

  btn.classList.add('btn-loading');
  try {
    await Biometrics.enroll(secret, state.config?.github_owner || 'Vault User');
    state.masterSecret = secret;
    Toast.success('Biometric unlock enabled!');
    openSettingsModal();
  } catch (err) {
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
      Toast.error('Biometric verification cancelled.');
    } else {
      Toast.error(`Enrollment failed: ${err.message}`);
    }
  } finally {
    btn.classList.remove('btn-loading');
  }
}

// ─── Event Wiring ─────────────────────────────────────────────────────────────

function initEventListeners() {

  // ── Navigation Tabs (Desktop pills & Mobile bottom dock) ───────────────────
  document.querySelectorAll('[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      if (tab) switchVaultTab(tab);
    });
  });
  document.getElementById('tab-passwords-btn')?.addEventListener('click', () => switchVaultTab('passwords'));
  document.getElementById('tab-cards-btn')?.addEventListener('click',     () => switchVaultTab('cards'));
  document.getElementById('tab-docs-btn')?.addEventListener('click',      () => switchVaultTab('docs'));
  document.getElementById('tab-journal-btn')?.addEventListener('click',   () => switchVaultTab('journal'));
  document.getElementById('bottom-tab-passwords')?.addEventListener('click', () => switchVaultTab('passwords'));
  document.getElementById('bottom-tab-cards')?.addEventListener('click',     () => switchVaultTab('cards'));
  document.getElementById('bottom-tab-docs')?.addEventListener('click',      () => switchVaultTab('docs'));
  document.getElementById('bottom-tab-journal')?.addEventListener('click',   () => switchVaultTab('journal'));

  // ── Settings modal ────────────────────────────────────────────────────────
  document.getElementById('vault-settings-btn')?.addEventListener('click', openSettingsModal);
  document.getElementById('modal-settings-close')?.addEventListener('click', () => hideModal('modal-settings'));
  document.getElementById('settings-bio-toggle-btn')?.addEventListener('click', handleToggleBiometrics);
  document.getElementById('settings-switch-quick-btn')?.addEventListener('click', () => {
    hideModal('modal-settings');
    const newType = state.config?.quick_unlock_type === 'pattern' ? 'pin' : 'pattern';
    if (confirm(`Switch session quick unlock to ${newType.toUpperCase()}?`)) {
      state.config.quick_unlock_type = newType;
      saveConfig(state.config);
      Toast.success(`Quick unlock set to ${newType.toUpperCase()}`);
    }
  });

  // ── Biometric unlock buttons on unlock screens ────────────────────────────
  document.getElementById('unlock-quick-bio-btn')?.addEventListener('click', triggerBiometricUnlock);
  document.getElementById('unlock-full-bio-btn')?.addEventListener('click', triggerBiometricUnlock);

  // ── Vault screen ──────────────────────────────────────────────────────────
  document.getElementById('vault-add-btn')?.addEventListener('click', () => {
    if (state.activeTab === 'journal') {
      openNoteEditor(null);
    } else if (state.activeTab === 'docs') {
      openDocModal(null);
    } else if (state.activeTab === 'cards') {
      openCardModal(null);
    } else {
      openAddModal();
    }
  });

  document.getElementById('vault-fab-btn')?.addEventListener('click', () => {
    if (state.activeTab === 'journal') {
      openNoteEditor(null);
    } else if (state.activeTab === 'docs') {
      openDocModal(null);
    } else if (state.activeTab === 'cards') {
      openCardModal(null);
    } else {
      openAddModal();
    }
  });

  document.getElementById('vault-gen-btn')?.addEventListener('click', openGeneratorModal);
  document.getElementById('vault-lock-btn')?.addEventListener('click', lockVault);

  document.getElementById('vault-search').addEventListener('input', e => {
    state.searchQuery = e.target.value;
    renderVaultList();
  });

  // ── Cards Search & Filter ─────────────────────────────────────────────────
  document.getElementById('cards-search')?.addEventListener('input', e => {
    state.cardsSearchQuery = e.target.value;
    renderCardsList();
  });

  document.querySelectorAll('#cards-category-pills .journal-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#cards-category-pills .journal-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.cardCategoryFilter = pill.dataset.cardFilter || 'all';
      renderCardsList();
    });
  });

  // ── Card / Bank Modal ─────────────────────────────────────────────────────
  document.getElementById('modal-card-close')?.addEventListener('click',  () => hideModal('modal-card'));
  document.getElementById('modal-card-cancel')?.addEventListener('click', () => hideModal('modal-card'));
  document.getElementById('modal-card-save')?.addEventListener('click',   saveCard);
  document.getElementById('modal-card-delete')?.addEventListener('click', deleteCard);

  document.getElementById('btn-toggle-type-card')?.addEventListener('click', () => setCardModalMode('card'));
  document.getElementById('btn-toggle-type-bank')?.addEventListener('click', () => setCardModalMode('bank'));

  document.querySelectorAll('#bank-preset-chips .doc-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => applyBankPreset(btn.dataset.bankPreset));
  });

  document.querySelectorAll('#card-theme-palette .theme-swatch').forEach(sw => {
    sw.addEventListener('click', () => selectCardTheme(sw.dataset.theme));
  });

  document.getElementById('card-number')?.addEventListener('input', e => {
    const raw = e.target.value.replace(/\D/g, '');
    const net = detectCardNetwork(raw);
    e.target.value = formatCardNumber(raw, net);
    updateLiveCardPreview();
  });

  document.getElementById('card-expiry')?.addEventListener('input', e => {
    e.target.value = formatCardExpiry(e.target.value);
    updateLiveCardPreview();
  });

  ['card-bank-name', 'card-holder-name', 'card-type-select'].forEach(id => {
    document.getElementById(id)?.addEventListener('input', updateLiveCardPreview);
    document.getElementById(id)?.addEventListener('change', updateLiveCardPreview);
  });

  document.getElementById('bank-account-ifsc')?.addEventListener('input', e => {
    e.target.value = e.target.value.toUpperCase();
  });

  // ── Journal Screen & Filter ───────────────────────────────────────────────
  document.getElementById('journal-search')?.addEventListener('input', e => {
    state.journalSearchQuery = e.target.value;
    renderJournalList();
  });

  document.getElementById('journal-pill-all')?.addEventListener('click', () => {
    const input = document.getElementById('journal-search');
    if (input) input.value = '';
    state.journalSearchQuery = '';
    renderJournalList();
  });

  // ── Emergency Documents View & Search ─────────────────────────────────────
  document.getElementById('docs-search')?.addEventListener('input', e => {
    state.docSearchQuery = e.target.value;
    renderDocsList();
  });

  document.querySelectorAll('#docs-category-pills .journal-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#docs-category-pills .journal-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.docCategoryFilter = pill.dataset.cat || 'all';
      renderDocsList();
    });
  });

  // ── Document Modal ────────────────────────────────────────────────────────
  document.getElementById('modal-doc-close')?.addEventListener('click',  () => hideModal('modal-doc'));
  document.getElementById('modal-doc-cancel')?.addEventListener('click', () => hideModal('modal-doc'));
  document.getElementById('modal-doc-save')?.addEventListener('click',   saveDoc);
  document.getElementById('modal-doc-delete')?.addEventListener('click', deleteDoc);

  document.querySelectorAll('.doc-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => applyDocPreset(btn.dataset.preset));
  });

  document.getElementById('doc-add-file-btn')?.addEventListener('click', () => {
    state.isPickingFile = true;
    document.getElementById('doc-file-input')?.click();
  });

  document.getElementById('doc-file-input')?.addEventListener('change', async e => {
    state.isPickingFile = false;
    if (e.target.files?.length) {
      await handleDocFilesSelected(e.target.files);
      e.target.value = '';
    }
  });

  document.getElementById('doc-file-input')?.addEventListener('cancel', () => {
    state.isPickingFile = false;
  });

  // ── Document Viewer Modal ─────────────────────────────────────────────────
  document.getElementById('modal-viewer-close')?.addEventListener('click', () => hideModal('modal-doc-viewer'));

  // ── Note Editor ───────────────────────────────────────────────────────────
  document.getElementById('note-back-btn')?.addEventListener('click', saveCurrentNote);
  document.getElementById('note-save-btn')?.addEventListener('click', saveCurrentNote);
  document.getElementById('note-delete-btn')?.addEventListener('click', deleteCurrentNote);

  document.getElementById('note-title-input')?.addEventListener('input', updateNoteCharCount);
  document.getElementById('note-content-input')?.addEventListener('input', updateNoteCharCount);

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

  // TOTP live preview and paste in entry modal
  document.getElementById('entry-totp')?.addEventListener('input', updateTotpPreview);
  document.getElementById('entry-totp-paste')?.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        document.getElementById('entry-totp').value = text.trim();
        updateTotpPreview();
        Toast.info('Pasted 2FA secret from clipboard');
      }
    } catch {
      document.getElementById('entry-totp').focus();
    }
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
    state.isPickingFile = true;
    document.getElementById('csv-file-input').click();
  });

  document.getElementById('csv-file-input').addEventListener('change', async e => {
    state.isPickingFile = false;
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      await handleCsvSelected(file);
    } finally {
      // Always clear the input so the same file can be re-selected if needed
      e.target.value = '';
    }
  });

  document.getElementById('csv-file-input')?.addEventListener('cancel', () => {
    state.isPickingFile = false;
  });

  // ── Import modal ──────────────────────────────────────────────────────────
  document.getElementById('modal-import-close').addEventListener('click',  () => hideModal('modal-import'));
  document.getElementById('modal-import-cancel').addEventListener('click', () => hideModal('modal-import'));
  document.getElementById('modal-import-confirm').addEventListener('click', confirmImport);
}

// ─── Keyboard Shortcuts ───────────────────────────────────────────────────────

function initKeyboardShortcuts() {
  document.addEventListener('keydown', e => {
    if (state.screen !== 'vault' && state.screen !== 'note-editor') return;
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    if (state.screen === 'vault') {
      switch (e.key.toLowerCase()) {
        case 'a':
          if (state.activeTab === 'journal') {
            openNoteEditor(null);
          } else if (state.activeTab === 'docs') {
            openDocModal(null);
          } else {
            openAddModal();
          }
          break;
        case 'g': openGeneratorModal();                                break;
        case 'i': document.getElementById('csv-file-input').click();  break;
        case 'l': lockVault();                                         break;
      }
    }
  });

  // Close modals or save/exit note editor with Escape
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (state.screen === 'note-editor') {
        saveCurrentNote();
        return;
      }
      ['modal-entry', 'modal-generator', 'modal-import', 'modal-doc', 'modal-doc-viewer'].forEach(id => {
        const m = document.getElementById(id);
        if (m && m.classList.contains('visible')) hideModal(id);
      });
    }
  });
}

// ─── Auto-Lock on Tab Hidden ──────────────────────────────────────────────────

document.addEventListener('visibilitychange', async () => {
  // If the user is currently picking a file via OS dialog, do not lock
  if (state.isPickingFile) {
    return;
  }
  if (document.hidden) {
    if (state.screen === 'note-editor') {
      await saveCurrentNote();
    }
    if (state.screen === 'vault' || state.screen === 'note-editor') {
      lockVault();
    }
  }
});

// Reset isPickingFile when browser window regains focus
window.addEventListener('focus', () => {
  setTimeout(() => {
    state.isPickingFile = false;
  }, 1000);
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
    totp:       e.totp || '',
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
  const totpCol     = headers.findIndex(h => h === 'totp' || h === 'otp' || h === 'login_totp' || h === '2fa');

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
      totp:  totpCol >= 0 ? (cols[totpCol]?.trim() || '') : '',
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
