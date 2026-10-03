/**
 * sw.js — Vault Service Worker
 *
 * Strategy: Cache-first for all static assets (app shell).
 * GitHub API calls (vault.enc reads/writes) always go through the network.
 *
 * On install  → cache all static assets
 * On activate → delete old caches
 * On fetch    → cache-first for app shell, network-only for github API
 */

'use strict';

const CACHE_NAME = 'vault-v1';

const APP_SHELL = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './crypto.js',
  './github.js',
  './ui.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

// ── Install: pre-cache the app shell ─────────────────────────────────────────

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL))
  );
  // Activate immediately — don't wait for old tabs to close
  self.skipWaiting();
});

// ── Activate: delete old caches ───────────────────────────────────────────────

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    )
  );
  // Take control of all open clients immediately
  self.clients.claim();
});

// ── Fetch: cache-first for app shell, network-only for GitHub API ─────────────

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Always network for GitHub API — vault reads/writes must be live
  if (url.hostname === 'api.github.com' || url.hostname === 'www.google.com') {
    event.respondWith(fetch(event.request));
    return;
  }

  // Cache-first for everything else (app shell)
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;

      // Not in cache — fetch from network and cache it
      return fetch(event.request).then(response => {
        // Only cache valid, same-origin responses
        if (
          !response ||
          response.status !== 200 ||
          response.type === 'opaque'
        ) {
          return response;
        }

        caches.open(CACHE_NAME).then(cache =>
          cache.put(event.request, response.clone())
        );

        return response;
      });
    })
  );
});
