// ============================================
// sw.js — Service Worker для Empty
// Стратегии:
//   - HTML/CSS/JS приложения: cache-first (app shell)
//   - esm.sh / gstatic / cdn.jsdelivr: stale-while-revalidate
//   - Firebase / Firestore: network-only (не кэшируем!)
// ============================================

const CACHE_VERSION = 'empty-v1';
const APP_SHELL_CACHE = `${CACHE_VERSION}-shell`;
const VENDOR_CACHE = `${CACHE_VERSION}-vendor`;

// Файлы «каркаса» приложения — кэшируем при установке
const APP_SHELL = [
  './',
  './index.html',
  './messenger.html',
  './index.js',
  './messenger.js',
  './crypto.js',
  './firebase-init.js',
  './manifest.json'
];

// Домены, которые НЕ кэшируем (Firebase, Firestore)
const NETWORK_ONLY_HOSTS = [
  'firestore.googleapis.com',
  'firebaseio.com',
  'identitytoolkit.googleapis.com',
  'securetoken.googleapis.com',
  'fcmregistrations.googleapis.com'
];

// Домены вендоров (esm.sh, jsdelivr, gstatic) — кэшируем надолго
const VENDOR_HOSTS = [
  'esm.sh',
  'cdn.jsdelivr.net',
  'www.gstatic.com'
];

// ---------- install ----------
self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(APP_SHELL_CACHE);
      // addAll упадёт, если хоть один файл 404 — используем индивидуально
      await Promise.all(
        APP_SHELL.map(async (url) => {
          try {
            await cache.add(new Request(url, { cache: 'reload' }));
          } catch (e) {
            console.warn('[SW] Не удалось закэшировать:', url, e);
          }
        })
      );
      await self.skipWaiting();
    })()
  );
});

// ---------- activate ----------
self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter((k) => !k.startsWith(CACHE_VERSION))
          .map((k) => caches.delete(k))
      );
      await self.clients.claim();
    })()
  );
});

// ---------- fetch ----------
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Только GET — POST/PUT к Firestore не трогаем
  if (req.method !== 'GET') return;

  // Network-only: Firebase
  if (NETWORK_ONLY_HOSTS.some((h) => url.hostname.endsWith(h))) {
    return; // пропускаем — пойдёт напрямую в сеть
  }

  // Vendor: stale-while-revalidate
  if (VENDOR_HOSTS.some((h) => url.hostname.endsWith(h))) {
    event.respondWith(staleWhileRevalidate(req, VENDOR_CACHE));
    return;
  }

  // Same-origin: cache-first для app shell
  if (url.origin === self.location.origin) {
    event.respondWith(cacheFirst(req, APP_SHELL_CACHE));
    return;
  }

  // Всё остальное — просто в сеть
});

// ---------- Стратегии ----------

async function cacheFirst(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(req);
  if (cached) return cached;

  try {
    const fresh = await fetch(req);
    if (fresh && fresh.status === 200 && fresh.type === 'basic') {
      cache.put(req, fresh.clone());
    }
    return fresh;
  } catch (e) {
    // Офлайн и нет в кэше — отдаём index.html как fallback для навигации
    if (req.mode === 'navigate') {
      const fallback = await cache.match('./index.html');
      if (fallback) return fallback;
    }
    throw e;
  }
}

async function staleWhileRevalidate(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(req);

  const fetchPromise = fetch(req)
    .then((fresh) => {
      if (fresh && fresh.status === 200) {
        cache.put(req, fresh.clone());
      }
      return fresh;
    })
    .catch(() => cached);

  return cached || fetchPromise;
}

// ---------- Сообщения от страницы ----------
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
