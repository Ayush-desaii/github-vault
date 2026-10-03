/**
 * crypto.js — Zero-knowledge encryption engine
 *
 * Algorithm choices:
 *   Key Derivation : PBKDF2-SHA512, 600,000 iterations  (NIST SP 800-132 compliant)
 *   Encryption     : AES-256-GCM  (authenticated encryption — detects tampering)
 *   Quick-unlock   : AES-256-GCM key-wrapping with PIN/pattern-derived key
 *
 * All operations use the browser's native Web Crypto API.
 * No external libraries, no CDN, works fully offline.
 *
 * Vault blob format (base64 encoded):
 *   [16 bytes — PBKDF2 salt] [12 bytes — AES-GCM IV] [N bytes — AES-256-GCM ciphertext]
 *
 * Quick-unlock session blob format (base64 encoded):
 *   [16 bytes — wrap salt] [12 bytes — wrap IV] [N bytes — AES-256-GCM encrypted raw key]
 */

'use strict';

const Crypto = (() => {

  // ─── Constants ────────────────────────────────────────────────────────────

  const PBKDF2_ITERATIONS      = 600_000;
  const WRAP_PBKDF2_ITERATIONS = 200_000;  // wrap key: fewer iters, limited attack surface
  const PBKDF2_HASH   = 'SHA-512';
  const AES_ALG       = 'AES-GCM';
  const AES_KEY_LEN   = 256;
  const SALT_LEN      = 16;  // bytes
  const IV_LEN        = 12;  // bytes — 96-bit GCM nonce

  // ─── Utilities ────────────────────────────────────────────────────────────

  /** base64 string → Uint8Array */
  function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  /** Uint8Array → base64 string */
  function bytesToB64(bytes) {
    // chunk to avoid "Maximum call stack exceeded" on large buffers
    const CHUNK = 8192;
    let str = '';
    for (let i = 0; i < bytes.length; i += CHUNK) {
      str += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
    }
    return btoa(str);
  }

  /** Generate cryptographically secure random bytes */
  function randomBytes(len) {
    return crypto.getRandomValues(new Uint8Array(len));
  }

  // ─── Key Derivation ───────────────────────────────────────────────────────

  /**
   * Derive an AES-256-GCM CryptoKey from a secret string + salt.
   * @param {string}     secret     master secret (masterPw + '\x00' + quickSecret)
   * @param {Uint8Array} salt       16 random bytes
   * @param {number}     iterations PBKDF2 iteration count
   * @param {boolean}    extractable whether the key can be exported
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(secret, salt, iterations = PBKDF2_ITERATIONS, extractable = true) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: PBKDF2_HASH },
      keyMaterial,
      { name: AES_ALG, length: AES_KEY_LEN },
      extractable,
      ['encrypt', 'decrypt']
    );
  }

  // ─── Vault Encryption / Decryption ────────────────────────────────────────

  /**
   * Create a brand-new encrypted vault blob (called once during first-run setup).
   * Generates a fresh random salt and derives the vault key.
   *
   * @param {string} masterSecret  masterPw + '\x00' + quickSecret
   * @param {object} initialData   the initial vault JSON object
   * @returns {Promise<{ blob: string, key: CryptoKey, salt: Uint8Array }>}
   */
  async function createVault(masterSecret, initialData) {
    const salt = randomBytes(SALT_LEN);
    const key  = await deriveKey(masterSecret, salt);
    const blob = await _encrypt(initialData, key, salt);
    return { blob, key, salt };
  }

  /**
   * Re-encrypt vault data using an already-derived in-memory key.
   * Called on every save (same key, same salt, fresh random IV).
   *
   * @param {object}     vaultData
   * @param {CryptoKey}  key    the in-memory vault key
   * @param {Uint8Array} salt   the original PBKDF2 salt (stays constant for this vault)
   * @returns {Promise<string>} base64 blob
   */
  async function encryptVault(vaultData, key, salt) {
    return _encrypt(vaultData, key, salt);
  }

  /**
   * Decrypt a vault blob using the master secret.
   * Extracts the embedded salt, re-derives the key, then decrypts.
   *
   * @param {string} b64blob      base64-encoded vault blob
   * @param {string} masterSecret masterPw + '\x00' + quickSecret
   * @returns {Promise<{ data: object, key: CryptoKey, salt: Uint8Array }>}
   * @throws if decryption fails (wrong password / tampered data)
   */
  async function decryptVault(b64blob, masterSecret) {
    const bytes      = b64ToBytes(b64blob);
    const salt       = bytes.slice(0, SALT_LEN);
    const iv         = bytes.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const ciphertext = bytes.slice(SALT_LEN + IV_LEN);

    const key = await deriveKey(masterSecret, salt);

    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt({ name: AES_ALG, iv }, key, ciphertext);
    } catch {
      throw new Error('DECRYPT_FAILED');
    }

    const data = JSON.parse(new TextDecoder().decode(plaintext));
    return { data, key, salt };
  }

  /**
   * Internal: encrypt object → base64 blob (salt + iv + ciphertext).
   */
  async function _encrypt(obj, key, salt) {
    const iv         = randomBytes(IV_LEN);  // fresh nonce every encryption
    const plaintext  = new TextEncoder().encode(JSON.stringify(obj));
    const ciphertext = await crypto.subtle.encrypt({ name: AES_ALG, iv }, key, plaintext);

    const out = new Uint8Array(SALT_LEN + IV_LEN + ciphertext.byteLength);
    out.set(salt, 0);
    out.set(iv, SALT_LEN);
    out.set(new Uint8Array(ciphertext), SALT_LEN + IV_LEN);

    return bytesToB64(out);
  }

  // ─── Quick-Unlock Key Wrapping ────────────────────────────────────────────
  //
  // After a full unlock the vault key lives in memory (state.vaultKey).
  // We export its raw bytes and re-encrypt them with a PIN/pattern-derived key,
  // then store the result in sessionStorage. The session is wiped when the tab closes.
  //
  // Wrapped blob format (base64):
  //   [16 bytes — wrap salt] [12 bytes — wrap IV] [32+ bytes — AES-GCM ciphertext of raw key]

  /**
   * Wrap the vault CryptoKey so it can be stored in sessionStorage for quick unlock.
   *
   * @param {CryptoKey} vaultKey   the live vault key
   * @param {string}    quickSecret  PIN digits string or pattern coordinate string
   * @returns {Promise<string>} base64-encoded wrapped key blob
   */
  async function wrapKey(vaultKey, quickSecret) {
    const wrapSalt    = randomBytes(SALT_LEN);
    const wrapIv      = randomBytes(IV_LEN);
    // Use a different secret suffix so the wrap key ≠ vault key even with same input
    const wrapDerived = await deriveKey(quickSecret + '\x01WRAP', wrapSalt, WRAP_PBKDF2_ITERATIONS, false);
    const rawKey      = await crypto.subtle.exportKey('raw', vaultKey);
    const wrapped     = await crypto.subtle.encrypt({ name: AES_ALG, iv: wrapIv }, wrapDerived, rawKey);

    const out = new Uint8Array(SALT_LEN + IV_LEN + wrapped.byteLength);
    out.set(wrapSalt, 0);
    out.set(wrapIv, SALT_LEN);
    out.set(new Uint8Array(wrapped), SALT_LEN + IV_LEN);

    return bytesToB64(out);
  }

  /**
   * Unwrap a session-cached key using the quick secret.
   *
   * @param {string} b64wrapped  blob from sessionStorage
   * @param {string} quickSecret PIN digits or pattern string
   * @returns {Promise<CryptoKey>}
   * @throws if wrong PIN/pattern
   */
  async function unwrapKey(b64wrapped, quickSecret) {
    const bytes   = b64ToBytes(b64wrapped);
    const wrapSalt   = bytes.slice(0, SALT_LEN);
    const wrapIv     = bytes.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const wrappedKey = bytes.slice(SALT_LEN + IV_LEN);

    const wrapDerived = await deriveKey(quickSecret + '\x01WRAP', wrapSalt, WRAP_PBKDF2_ITERATIONS, false);

    let rawKey;
    try {
      rawKey = await crypto.subtle.decrypt({ name: AES_ALG, iv: wrapIv }, wrapDerived, wrappedKey);
    } catch {
      throw new Error('WRONG_QUICK_SECRET');
    }

    return crypto.subtle.importKey('raw', rawKey, { name: AES_ALG, length: AES_KEY_LEN }, true, ['encrypt', 'decrypt']);
  }

  // ─── Password Generator ───────────────────────────────────────────────────

  /**
   * Generate a cryptographically secure random password.
   *
   * @param {number}  length  desired length (default 20)
   * @param {object}  opts    character set options
   * @param {boolean} opts.upper   include A-Z (default true)
   * @param {boolean} opts.lower   include a-z (default true)
   * @param {boolean} opts.digits  include 0-9 (default true)
   * @param {boolean} opts.symbols include !@#... (default true)
   * @returns {string}
   */
  function generatePassword(length = 20, opts = {}) {
    const { upper = true, lower = true, digits = true, symbols = true } = opts;
    const sets = [];
    if (upper)   sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (lower)   sets.push('abcdefghijklmnopqrstuvwxyz');
    if (digits)  sets.push('0123456789');
    if (symbols) sets.push('!@#$%^&*()-_=+[]{}|;:,.<>?');

    // Ensure at least one character from each enabled set
    const chars = sets.join('');
    if (!chars) return '';

    // Guarantee at least one char from each character class
    const guaranteed = sets.map(s => {
      const arr = new Uint32Array(1);
      crypto.getRandomValues(arr);
      return s[arr[0] % s.length];
    });

    const remaining = length - guaranteed.length;
    const randoms   = new Uint32Array(Math.max(0, remaining));
    crypto.getRandomValues(randoms);
    const rest = Array.from(randoms, n => chars[n % chars.length]);

    // Shuffle all characters together
    const combined = [...guaranteed, ...rest];
    for (let i = combined.length - 1; i > 0; i--) {
      const arr = new Uint32Array(1);
      crypto.getRandomValues(arr);
      const j = arr[0] % (i + 1);
      [combined[i], combined[j]] = [combined[j], combined[i]];
    }

    return combined.join('');
  }

  // ─── Password Strength ────────────────────────────────────────────────────

  /**
   * Estimate password strength (0–4).
   * Returns { score: 0-4, label: string }
   */
  function passwordStrength(pw) {
    if (!pw || pw.length === 0) return { score: 0, label: '' };
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    // cap at 4
    score = Math.min(4, score);

    const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
    return { score, label: labels[score] };
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  return {
    createVault,
    encryptVault,
    decryptVault,
    wrapKey,
    unwrapKey,
    generatePassword,
    passwordStrength,
  };

})();
