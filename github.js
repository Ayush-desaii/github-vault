/**
 * github.js — GitHub REST API storage layer
 *
 * Responsibilities:
 *   - Fetch vault.enc from GitHub (public endpoint — no token needed for public repos)
 *   - Commit an updated vault.enc back to GitHub (requires PAT from inside decrypted vault)
 *   - Validate a PAT + check if a repo exists (used during setup wizard)
 *
 * API base: https://api.github.com
 */

'use strict';

const GitHub = (() => {

  const API = 'https://api.github.com';

  // ─── Helpers ──────────────────────────────────────────────────────────────

  async function request(url, opts = {}) {
    const res = await fetch(url, {
      ...opts,
      headers: {
        'Accept':       'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        ...(opts.headers || {}),
      },
    });

    if (res.status === 404) throw new Error('NOT_FOUND');
    if (res.status === 401) throw new Error('UNAUTHORIZED');
    if (res.status === 403) throw new Error('FORBIDDEN');
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const j = await res.json(); msg = j.message || msg; } catch {}
      throw new Error(msg);
    }

    return res.status === 204 ? null : res.json();
  }

  function authHeaders(token) {
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * Fetch the contents of vault.enc from GitHub.
   * For public repos, no token is required.
   *
   * @param {string} owner
   * @param {string} repo
   * @param {string} path  e.g. 'vault.enc'
   * @param {string} [token]  optional, required for private repos
   * @returns {Promise<{ blob: string, sha: string }>}
   *   blob — base64-encoded encrypted vault content
   *   sha  — GitHub file SHA needed for subsequent commits
   */
  async function fetchVault(owner, repo, path, token = null) {
    const url  = `${API}/repos/${owner}/${repo}/contents/${path}`;
    const data = await request(url, { headers: authHeaders(token) });

    // GitHub returns content as base64 with line breaks — strip them
    const blob = data.content.replace(/\n/g, '');
    return { blob, sha: data.sha };
  }

  /**
   * Commit (create or update) vault.enc on GitHub.
   *
   * @param {object} opts
   * @param {string} opts.content  base64-encoded encrypted vault blob
   * @param {string} opts.sha      current file SHA (null if creating for the first time)
   * @param {string} opts.owner
   * @param {string} opts.repo
   * @param {string} opts.path
   * @param {string} opts.token    GitHub PAT with Contents:write permission
   * @returns {Promise<string>} new SHA of the committed file
   */
  async function commitVault({ content, sha, owner, repo, path, token }) {
    const url  = `${API}/repos/${owner}/${repo}/contents/${path}`;
    const body = {
      message: `vault: update ${new Date().toISOString()}`,
      content,                   // GitHub expects base64 content
      ...(sha ? { sha } : {}),   // include sha when updating existing file
    };

    const data = await request(url, {
      method:  'PUT',
      headers: authHeaders(token),
      body:    JSON.stringify(body),
    });

    return data.content.sha;
  }

  /**
   * Validate a GitHub PAT and check that the repo is accessible and writable.
   * Used in the setup wizard (step 3).
   *
   * @param {string} owner
   * @param {string} repo
   * @param {string} token
   * @returns {Promise<void>} resolves on success, throws on failure
   */
  async function validateAccess(owner, repo, token) {
    // Check repo exists and token has access
    const repoData = await request(
      `${API}/repos/${owner}/${repo}`,
      { headers: authHeaders(token) }
    );

    // Verify the repo belongs to the expected owner
    if (repoData.owner.login.toLowerCase() !== owner.toLowerCase()) {
      throw new Error('Repo owner mismatch');
    }

    // Verify write permission
    const perms = repoData.permissions || {};
    if (!perms.push && !perms.admin) {
      throw new Error('Token does not have write access to this repository');
    }
  }

  /**
   * Check whether vault.enc already exists in the repo.
   *
   * @param {string} owner
   * @param {string} repo
   * @param {string} path
   * @param {string} token
   * @returns {Promise<{ exists: boolean, sha?: string }>}
   */
  async function checkVaultExists(owner, repo, path, token) {
    try {
      const url  = `${API}/repos/${owner}/${repo}/contents/${path}`;
      const data = await request(url, { headers: authHeaders(token) });
      return { exists: true, sha: data.sha };
    } catch (err) {
      if (err.message === 'NOT_FOUND') return { exists: false };
      throw err;
    }
  }

  return {
    fetchVault,
    commitVault,
    validateAccess,
    checkVaultExists,
  };

})();
