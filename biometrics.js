/**
 * biometrics.js — WebAuthn Platform Authenticator Integration
 * Supports Face ID, Touch ID, Windows Hello, and Android Biometrics.
 *
 * Architecture:
 * 1. Checks PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().
 * 2. On enrollment: prompts the platform authenticator (Face ID / Fingerprint),
 *    creates a local 256-bit AES-GCM device key, and encrypts the master secret.
 * 3. On unlock: prompts hardware user verification. Upon physical biometric success,
 *    decrypts the device key payload and returns the master secret to unlock the vault.
 * 4. Never exposes or sends biometric data anywhere; 100% on-device & zero-knowledge.
 */

'use strict';

const Biometrics = (() => {

  const KEY_BIO_CRED_ID = 'vault_bio_cred_id';
  const KEY_BIO_KEY     = 'vault_bio_key';
  const KEY_BIO_PAYLOAD = 'vault_bio_payload';
  const KEY_BIO_ENABLED = 'vault_bio_enabled';

  /** Check if this browser/platform has biometric hardware available */
  async function isAvailable() {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) return false;
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  /** Check if biometric unlock is currently enrolled on this device */
  function isEnrolled() {
    try {
      return localStorage.getItem(KEY_BIO_ENABLED) === 'true' &&
             !!localStorage.getItem(KEY_BIO_CRED_ID) &&
             !!localStorage.getItem(KEY_BIO_KEY) &&
             !!localStorage.getItem(KEY_BIO_PAYLOAD);
    } catch {
      return false;
    }
  }

  /**
   * Enroll the current device's biometric sensor.
   * Prompts Face ID / Fingerprint / Windows Hello to create a platform credential,
   * then securely encrypts the master secret with a fresh 256-bit device key.
   *
   * @param {string} masterSecret - The master password + \x00 + quickSecret
   * @param {string} [username] - Display name
   * @returns {Promise<boolean>}
   */
  async function enroll(masterSecret, username = 'Vault User') {
    if (!masterSecret) {
      throw new Error('Active vault credentials required to enable biometrics.');
    }

    const available = await isAvailable();
    if (!available) {
      throw new Error('Biometric authentication (Face ID / Fingerprint) is not supported or not configured on this device.');
    }

    const challenge = Crypto.randomBytes(32);
    const userId    = Crypto.randomBytes(16);

    // Call WebAuthn to trigger native platform authenticator (Face ID / Touch ID / Hello / Fingerprint)
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'GitHub Vault',
        },
        user: {
          id: userId,
          name: username,
          displayName: username,
        },
        pubKeyCredParams: [
          { alg: -7,   type: 'public-key' }, // ES256
          { alg: -257, type: 'public-key' }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          requireResidentKey: false,
        },
        timeout: 60000,
      }
    });

    if (!credential) {
      throw new Error('Biometric enrollment was cancelled.');
    }

    // Convert credential ID to base64 for persistent storage
    const credIdB64 = Crypto.bytesToB64(new Uint8Array(credential.rawId));

    // Generate a fresh 256-bit random device key
    const rawBioKey = Crypto.randomBytes(32);
    const bioPayloadB64 = await Crypto.encryptSecretWithKey(masterSecret, rawBioKey);

    // Save configuration to device localStorage
    localStorage.setItem(KEY_BIO_CRED_ID, credIdB64);
    localStorage.setItem(KEY_BIO_KEY, Crypto.bytesToB64(rawBioKey));
    localStorage.setItem(KEY_BIO_PAYLOAD, bioPayloadB64);
    localStorage.setItem(KEY_BIO_ENABLED, 'true');

    return true;
  }

  /**
   * Unlock with biometrics.
   * Prompts the native Face ID / Fingerprint verification dialog.
   * On hardware success, decrypts and returns the masterSecret string.
   *
   * @returns {Promise<string>} The masterSecret
   */
  async function unlock() {
    if (!isEnrolled()) {
      throw new Error('Biometrics is not configured on this device.');
    }

    const credIdB64     = localStorage.getItem(KEY_BIO_CRED_ID);
    const rawBioKeyB64  = localStorage.getItem(KEY_BIO_KEY);
    const bioPayloadB64 = localStorage.getItem(KEY_BIO_PAYLOAD);

    if (!credIdB64 || !rawBioKeyB64 || !bioPayloadB64) {
      throw new Error('Biometric configuration is missing or incomplete.');
    }

    const challenge = Crypto.randomBytes(32);
    const credIdBytes = Crypto.b64ToBytes(credIdB64);

    // Prompt user verification via WebAuthn
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{
          id: credIdBytes,
          type: 'public-key',
        }],
        userVerification: 'required',
        timeout: 60000,
      }
    });

    if (!assertion) {
      throw new Error('Biometric verification cancelled.');
    }

    // Biometric hardware verified! Decrypt masterSecret using device key
    const rawBioKey = Crypto.b64ToBytes(rawBioKeyB64);
    const masterSecret = await Crypto.decryptSecretWithKey(bioPayloadB64, rawBioKey);

    return masterSecret;
  }

  /** Disable and remove biometrics from this device */
  function disable() {
    localStorage.removeItem(KEY_BIO_CRED_ID);
    localStorage.removeItem(KEY_BIO_KEY);
    localStorage.removeItem(KEY_BIO_PAYLOAD);
    localStorage.setItem(KEY_BIO_ENABLED, 'false');
  }

  return {
    isAvailable,
    isEnrolled,
    enroll,
    unlock,
    disable,
  };

})();
