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

  /**
   * Encrypt arbitrary binary data (Uint8Array or ArrayBuffer) using AES-256-GCM.
   * Format: base64-encoded [16 bytes salt] [12 bytes IV] [ciphertext]
   *
   * @param {ArrayBuffer|Uint8Array} bufferOrUint8
   * @param {CryptoKey}  key   in-memory vault key
   * @param {Uint8Array} salt  vault salt
   * @returns {Promise<string>} base64 blob
   */
  async function encryptBinary(bufferOrUint8, key, salt) {
    const iv = randomBytes(IV_LEN);
    const data = bufferOrUint8 instanceof Uint8Array ? bufferOrUint8 : new Uint8Array(bufferOrUint8);
    const ciphertext = await crypto.subtle.encrypt({ name: AES_ALG, iv }, key, data);

    const out = new Uint8Array(SALT_LEN + IV_LEN + ciphertext.byteLength);
    out.set(salt, 0);
    out.set(iv, SALT_LEN);
    out.set(new Uint8Array(ciphertext), SALT_LEN + IV_LEN);

    return bytesToB64(out);
  }

  /**
   * Decrypt a base64 encrypted binary blob into an ArrayBuffer using the vault key.
   *
   * @param {string} b64blob
   * @param {CryptoKey} key
   * @returns {Promise<ArrayBuffer>} decrypted plaintext buffer
   */
  async function decryptBinary(b64blob, key) {
    const bytes = b64ToBytes(b64blob);
    const iv = bytes.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const ciphertext = bytes.slice(SALT_LEN + IV_LEN);

    try {
      return await crypto.subtle.decrypt({ name: AES_ALG, iv }, key, ciphertext);
    } catch {
      throw new Error('DECRYPT_FAILED');
    }
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

  // ─── Biometric Payload Helpers ────────────────────────────────────────────

  /**
   * Encrypt a text string (such as masterSecret) with a 256-bit raw key using AES-256-GCM.
   * Format: base64 [12 bytes IV] [ciphertext]
   *
   * @param {string}     secretText
   * @param {Uint8Array} rawKeyBytes 32-byte key
   * @returns {Promise<string>} base64 blob
   */
  async function encryptSecretWithKey(secretText, rawKeyBytes) {
    const iv = randomBytes(IV_LEN);
    const key = await crypto.subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: AES_ALG, length: AES_KEY_LEN },
      false,
      ['encrypt']
    );
    const ciphertext = await crypto.subtle.encrypt(
      { name: AES_ALG, iv },
      key,
      new TextEncoder().encode(secretText)
    );
    const out = new Uint8Array(IV_LEN + ciphertext.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ciphertext), IV_LEN);
    return bytesToB64(out);
  }

  /**
   * Decrypt a base64 ciphertext with a 256-bit raw key using AES-256-GCM.
   *
   * @param {string}     b64Encrypted
   * @param {Uint8Array} rawKeyBytes 32-byte key
   * @returns {Promise<string>} decrypted text
   */
  async function decryptSecretWithKey(b64Encrypted, rawKeyBytes) {
    const bytes = b64ToBytes(b64Encrypted);
    const iv = bytes.slice(0, IV_LEN);
    const ciphertext = bytes.slice(IV_LEN);
    const key = await crypto.subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: AES_ALG, length: AES_KEY_LEN },
      false,
      ['decrypt']
    );
    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: AES_ALG, iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch {
      throw new Error('DECRYPT_FAILED');
    }
  }

  // ─── TOTP / 2FA Authenticator (RFC 6238 / RFC 4226) ─────────────────────────

  /** Cache imported HMAC CryptoKeys by algorithm + secret */
  const totpKeyCache = new Map();

  /**
   * Decode Base32 string (RFC 4648) to Uint8Array.
   * Tolerates spaces, dashes, lowercase, and omitted padding.
   * @param {string} b32
   * @returns {Uint8Array}
   */
  function base32ToBytes(b32) {
    if (!b32 || typeof b32 !== 'string') return new Uint8Array(0);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = b32.toUpperCase().replace(/[\s=-]/g, '');
    if (!clean) return new Uint8Array(0);

    let bits = 0;
    let value = 0;
    const bytes = [];

    for (let i = 0; i < clean.length; i++) {
      const idx = alphabet.indexOf(clean[i]);
      if (idx === -1) {
        throw new Error(`Invalid Base32 character: ${clean[i]}`);
      }
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(bytes);
  }

  /**
   * Parse a raw Base32 secret or otpauth:// URI.
   * Returns normalized metadata or null if invalid.
   * @param {string} input
   * @returns {{secret: string, period: number, digits: number, algorithm: string}|null}
   */
  function parseTotpSecret(input) {
    if (!input || typeof input !== 'string') return null;
    const str = input.trim();
    if (!str) return null;

    if (str.toLowerCase().startsWith('otpauth://')) {
      try {
        const url = new URL(str);
        const secret = url.searchParams.get('secret');
        if (!secret) return null;
        const period = parseInt(url.searchParams.get('period') || '30', 10);
        const digits = parseInt(url.searchParams.get('digits') || '6', 10);
        const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
        const cleanSecret = secret.replace(/[\s-]/g, '').toUpperCase();
        if (!/^[A-Z2-7]+=*$/.test(cleanSecret)) return null;
        return {
          secret: cleanSecret,
          period: isNaN(period) || period <= 0 ? 30 : period,
          digits: isNaN(digits) || digits <= 0 ? 6 : digits,
          algorithm: algorithm === 'SHA256' ? 'SHA-256' : (algorithm === 'SHA512' ? 'SHA-512' : 'SHA-1')
        };
      } catch {
        const match = str.match(/secret=([A-Za-z2-7=]+)/i);
        if (match) {
          const cleanSecret = match[1].replace(/[\s-]/g, '').toUpperCase();
          if (/^[A-Z2-7]+=*$/.test(cleanSecret)) {
            return { secret: cleanSecret, period: 30, digits: 6, algorithm: 'SHA-1' };
          }
        }
        return null;
      }
    }

    const clean = str.replace(/[\s-]/g, '').toUpperCase();
    if (/^[A-Z2-7]+=*$/.test(clean)) {
      return {
        secret: clean,
        period: 30,
        digits: 6,
        algorithm: 'SHA-1'
      };
    }

    return null;
  }

  /**
   * Get or import an HMAC CryptoKey for TOTP.
   */
  async function getTotpCryptoKey(secret, algorithm = 'SHA-1') {
    const cacheKey = `${algorithm}:${secret}`;
    let key = totpKeyCache.get(cacheKey);
    if (!key) {
      const keyBytes = base32ToBytes(secret);
      key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: { name: algorithm } },
        false,
        ['sign']
      );
      totpKeyCache.set(cacheKey, key);
    }
    return key;
  }

  /**
   * Generate RFC 6238 TOTP code.
   * @param {string} secretInput  Raw Base32 or otpauth:// URI
   * @param {object} [options]
   * @param {number} [options.period=30]
   * @param {number} [options.digits=6]
   * @param {string} [options.algorithm='SHA-1']
   * @param {number} [options.timestamp=Date.now()]
   * @returns {Promise<string|null>} 6 (or 8) digit code
   */
  async function generateTOTP(secretInput, options = {}) {
    const parsed = parseTotpSecret(secretInput);
    if (!parsed) return null;

    const period    = options.period    || parsed.period    || 30;
    const digits    = options.digits    || parsed.digits    || 6;
    const algorithm = options.algorithm || parsed.algorithm || 'SHA-1';
    const timestamp = options.timestamp !== undefined ? options.timestamp : Date.now();

    const epochSeconds = Math.floor(timestamp / 1000);
    const counter = Math.floor(epochSeconds / period);

    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);

    try {
      const cryptoKey = await getTotpCryptoKey(parsed.secret, algorithm);
      const signature = await crypto.subtle.sign('HMAC', cryptoKey, buffer);
      const hmac = new Uint8Array(signature);
      const offset = hmac[hmac.length - 1] & 0x0f;
      const binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

      const otp = binary % Math.pow(10, digits);
      return String(otp).padStart(digits, '0');
    } catch {
      return null;
    }
  }

  /**
   * Calculate remaining seconds in current TOTP cycle.
   * @param {number} [period=30]
   * @param {number} [timestamp=Date.now()]
   * @returns {number}
   */
  function getTotpRemainingSeconds(period = 30, timestamp = Date.now()) {
    const epochSeconds = Math.floor(timestamp / 1000);
    const rem = period - (epochSeconds % period);
    return rem === 0 ? period : rem;
  }

  /**
   * Format code with a space for human readability (e.g. "123 456").
   * @param {string} code
   * @returns {string}
   */
  function formatTotpCode(code) {
    if (!code || typeof code !== 'string') return '';
    if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
    if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
    return code;
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  return {
    randomBytes,
    b64ToBytes,
    bytesToB64,
    createVault,
    encryptVault,
    decryptVault,
    encryptBinary,
    decryptBinary,
    encryptSecretWithKey,
    decryptSecretWithKey,
    wrapKey,
    unwrapKey,
    generatePassword,
    passwordStrength,
    base32ToBytes,
    parseTotpSecret,
    generateTOTP,
    getTotpRemainingSeconds,
    formatTotpCode,
  };

})();
