/**
 * Offline cache for unlockgen.
 *
 * Network-first, cache-fallback: an online visit always gets the current
 * version and refreshes the cache, and an offline visit gets the last one that
 * loaded. There is nothing dynamic to invalidate, so this needs no versioning
 * beyond the cache name.
 */

const CACHE = "unlockgen-v1";
const ASSETS = [
  "./",
  "index.html",
  "styles.css",
  "app.js",
  "unlockgen.js",
  "digest.js",
  "vectors.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names.filter((name) => name !== CACHE).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy)).catch(() => {});
        return response;
      })
      .catch(() => caches.match(event.request).then((hit) => hit ?? caches.match("index.html"))),
  );
});
