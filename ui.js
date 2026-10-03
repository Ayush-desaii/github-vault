/**
 * ui.js — UI helpers, pattern lock widget, numpad, toast, modals
 */

'use strict';

// ─── Toast Notifications ──────────────────────────────────────────────────────

const Toast = (() => {
  let timer = null;
  const el  = () => document.getElementById('toast');

  function show(msg, type = 'info', duration = 3000) {
    const t = el();
    t.textContent  = msg;
    t.className    = `toast toast-${type}`;
    clearTimeout(timer);
    // Force reflow to restart the animation
    void t.offsetWidth;
    t.classList.add('visible');
    timer = setTimeout(() => t.classList.remove('visible'), duration);
  }

  return { show, info: m => show(m, 'info'), success: m => show(m, 'success'), error: m => show(m, 'error') };
})();

// ─── Clipboard ────────────────────────────────────────────────────────────────

const Clipboard = (() => {
  let clearTimer = null;

  async function copy(text, label = 'Copied!', autoClearSeconds = 30) {
    try {
      await navigator.clipboard.writeText(text);
      Toast.success(`${label} Clears in ${autoClearSeconds}s.`);
      clearTimeout(clearTimer);
      clearTimer = setTimeout(async () => {
        try { await navigator.clipboard.writeText(''); } catch {}
      }, autoClearSeconds * 1000);
    } catch {
      // Fallback for browsers where clipboard API isn't available
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity  = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      Toast.success(`${label} Clears in ${autoClearSeconds}s.`);
    }
  }

  return { copy };
})();

// ─── Password Visibility Toggle ───────────────────────────────────────────────

function initPasswordToggles() {
  document.addEventListener('click', e => {
    const btn = e.target.closest('.toggle-pw');
    if (!btn) return;
    const targetId = btn.dataset.target;
    const input    = document.getElementById(targetId);
    if (!input) return;
    const isHidden  = input.type === 'password';
    input.type      = isHidden ? 'text' : 'password';
    btn.textContent = isHidden ? '🙈' : '👁';
  });
}

// ─── PIN Numpad ───────────────────────────────────────────────────────────────

class PinInput {
  /**
   * @param {object} opts
   * @param {string}   opts.displayId  id of the dot-display container
   * @param {string}   opts.numpadId   id of the numpad container
   * @param {number}   opts.minLen     minimum PIN length (default 4)
   * @param {number}   opts.maxLen     maximum PIN length (default 8)
   * @param {Function} opts.onComplete callback(pinString) called when min length reached
   */
  constructor(opts) {
    this.displayEl  = document.getElementById(opts.displayId);
    this.numpadEl   = document.getElementById(opts.numpadId);
    this.minLen     = opts.minLen     || 4;
    this.maxLen     = opts.maxLen     || 8;
    this.onComplete = opts.onComplete || null;
    this.digits     = [];
    this._build();
  }

  _build() {
    // Build numpad
    const keys = ['1','2','3','4','5','6','7','8','9','','0','⌫'];
    this.numpadEl.innerHTML = '';
    keys.forEach(k => {
      const btn = document.createElement('button');
      btn.className   = k === '' ? 'numpad-key numpad-empty' : 'numpad-key';
      btn.textContent = k;
      btn.disabled    = k === '';
      if (k !== '') {
        btn.addEventListener('click', () => {
          if (k === '⌫') { this._backspace(); }
          else            { this._press(k); }
        });
      }
      this.numpadEl.appendChild(btn);
    });
    this._updateDisplay();
  }

  _press(digit) {
    if (this.digits.length >= this.maxLen) return;
    this.digits.push(digit);
    this._updateDisplay();
    if (this.digits.length >= this.minLen && this.onComplete) {
      this.onComplete(this.getPin());
    }
  }

  _backspace() {
    this.digits.pop();
    this._updateDisplay();
  }

  _updateDisplay() {
    this.displayEl.innerHTML = '';
    for (let i = 0; i < this.maxLen; i++) {
      const dot = document.createElement('span');
      dot.className = 'pin-dot' + (i < this.digits.length ? ' filled' : '');
      this.displayEl.appendChild(dot);
    }
  }

  getPin() { return this.digits.join(''); }

  reset() {
    this.digits = [];
    this._updateDisplay();
  }

  isComplete() { return this.digits.length >= this.minLen; }
}

// ─── Pattern Lock ─────────────────────────────────────────────────────────────

class PatternLock {
  /**
   * @param {HTMLCanvasElement} canvas
   * @param {object}           opts
   * @param {Function}         opts.onChange  callback(patternArray) on pattern end
   * @param {number}           opts.minDots   minimum dots required (default 4)
   */
  constructor(canvas, opts = {}) {
    this.canvas   = canvas;
    this.ctx      = canvas.getContext('2d');
    this.onChange = opts.onChange || null;
    this.minDots  = opts.minDots || 4;
    this.pattern  = [];
    this.drawing  = false;
    this.curPos   = null;
    this.error    = false;

    this._buildDots();
    this._bind();
    this._draw();
  }

  _buildDots() {
    const size    = this.canvas.width;
    const padding = 38;
    const gap     = (size - padding * 2) / 2;
    this.dots = [];
    for (let r = 0; r < 3; r++) {
      for (let c = 0; c < 3; c++) {
        this.dots.push({
          x:   padding + c * gap,
          y:   padding + r * gap,
          idx: r * 3 + c,
        });
      }
    }
  }

  _bind() {
    const c = this.canvas;
    const down = e => { e.preventDefault(); this._onStart(this._getPos(e.touches?.[0] || e)); };
    const move = e => { e.preventDefault(); this._onMove(this._getPos(e.touches?.[0] || e)); };
    const up   = () => this._onEnd();

    c.addEventListener('mousedown',  down);
    c.addEventListener('mousemove',  move);
    c.addEventListener('mouseup',    up);
    c.addEventListener('touchstart', down, { passive: false });
    c.addEventListener('touchmove',  move, { passive: false });
    c.addEventListener('touchend',   up);
  }

  _getPos(e) {
    const r  = this.canvas.getBoundingClientRect();
    const sx = this.canvas.width  / r.width;
    const sy = this.canvas.height / r.height;
    return { x: (e.clientX - r.left) * sx, y: (e.clientY - r.top) * sy };
  }

  _hit(pos) {
    return this.dots.find(d => Math.hypot(d.x - pos.x, d.y - pos.y) < 24);
  }

  _onStart(pos) {
    this.drawing = true;
    this.error   = false;
    this.pattern = [];
    this.curPos  = pos;
    const hit = this._hit(pos);
    if (hit) this.pattern.push(hit.idx);
    this._draw();
  }

  _onMove(pos) {
    if (!this.drawing) return;
    this.curPos = pos;
    const hit = this._hit(pos);
    if (hit && !this.pattern.includes(hit.idx)) {
      this.pattern.push(hit.idx);
    }
    this._draw();
  }

  _onEnd() {
    if (!this.drawing) return;
    this.drawing = false;
    this.curPos  = null;
    if (this.onChange) this.onChange(this.pattern);
    this._draw();
  }

  _draw() {
    const ctx    = this.ctx;
    const W      = this.canvas.width;
    const H      = this.canvas.height;
    const active = new Set(this.pattern);

    ctx.clearRect(0, 0, W, H);

    // Draw connection lines
    if (this.pattern.length > 0) {
      ctx.beginPath();
      ctx.strokeStyle = this.error ? 'rgba(255,85,85,.5)' : 'rgba(255,255,255,.2)';
      ctx.lineWidth   = 2;
      ctx.lineJoin    = 'round';
      ctx.lineCap     = 'round';

      const first = this.dots[this.pattern[0]];
      ctx.moveTo(first.x, first.y);
      for (let i = 1; i < this.pattern.length; i++) {
        const d = this.dots[this.pattern[i]];
        ctx.lineTo(d.x, d.y);
      }
      if (this.drawing && this.curPos) {
        ctx.lineTo(this.curPos.x, this.curPos.y);
      }
      ctx.stroke();
    }

    // Draw dots
    this.dots.forEach(dot => {
      const isActive = active.has(dot.idx);
      const activeColor = this.error ? 'rgba(255,85,85,.9)' : 'rgba(255,255,255,.9)';

      // Outer ring
      ctx.beginPath();
      ctx.arc(dot.x, dot.y, 14, 0, Math.PI * 2);
      ctx.strokeStyle = isActive ? 'rgba(255,255,255,.3)' : 'rgba(255,255,255,.1)';
      ctx.lineWidth   = 1;
      ctx.stroke();

      // Fill when active
      if (isActive) {
        ctx.beginPath();
        ctx.arc(dot.x, dot.y, 14, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255,255,255,.05)';
        ctx.fill();
      }

      // Inner dot
      ctx.beginPath();
      ctx.arc(dot.x, dot.y, isActive ? 5 : 3, 0, Math.PI * 2);
      ctx.fillStyle = isActive ? activeColor : 'rgba(255,255,255,.2)';
      ctx.fill();
    });
  }

  /** Show error flash (wrong pattern attempt) */
  flashError() {
    this.error = true;
    this._draw();
    setTimeout(() => {
      this.error = false;
      this._draw();
    }, 600);
  }

  /** Reset pattern */
  reset() {
    this.pattern = [];
    this.drawing = false;
    this.curPos  = null;
    this.error   = false;
    if (this.onChange) this.onChange(this.pattern);
    this._draw();
  }

  /** Returns a string like "0-1-4-3" */
  getSecret() { return this.pattern.join('-'); }

  isComplete() { return this.pattern.length >= this.minDots; }
}

// ─── Modal Helpers ────────────────────────────────────────────────────────────

function showModal(id) {
  const m = document.getElementById(id);
  m.classList.remove('hidden');
  requestAnimationFrame(() => m.classList.add('visible'));
}

function hideModal(id) {
  const m = document.getElementById(id);
  m.classList.remove('visible');
  setTimeout(() => m.classList.add('hidden'), 250);
}

// Close modal when clicking backdrop
document.addEventListener('click', e => {
  if (e.target.classList.contains('modal-backdrop')) {
    e.target.closest('.modal')?.classList.contains('visible') &&
      hideModal(e.target.closest('.modal').id);
  }
});

// ─── Misc ─────────────────────────────────────────────────────────────────────

/** Generate a UUID v4 */
function uuid() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

/** Escape HTML to prevent XSS when injecting user data into innerHTML */
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/** Get favicon URL for a domain */
function favicon(url) {
  try {
    const host = new URL(url).hostname;
    return `https://www.google.com/s2/favicons?domain=${host}&sz=32`;
  } catch {
    return null;
  }
}

/** Format relative time (e.g. "2 hours ago") */
function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const m    = Math.floor(diff / 60000);
  if (m < 1)   return 'just now';
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}
