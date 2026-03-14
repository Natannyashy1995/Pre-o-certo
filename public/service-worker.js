/**
 * PreçoCerto — Service Worker v2
 * Cache First: assets estáticos
 * Network First: API e dados dinâmicos
 * Auto-update: notifica novo conteúdo
 */

const SW_VERSION = 'precocerto-v3';
const CACHE_STATIC = `${SW_VERSION}-static`;
const CACHE_PAGES  = `${SW_VERSION}-pages`;

// Assets que fazem sentido cachear offline
const STATIC_ASSETS = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  'https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&family=Open+Sans:wght@400;500;600&display=swap',
];

// ── INSTALL ──────────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC)
      .then(cache => cache.addAll(STATIC_ASSETS).catch(() => {}))
      .then(() => self.skipWaiting()) // Ativa imediatamente sem esperar fechar abas
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_STATIC && k !== CACHE_PAGES)
          .map(k => {
            console.log('[SW] Removendo cache antigo:', k);
            return caches.delete(k);
          })
      )
    ).then(() => self.clients.claim()) // Controla todas as abas imediatamente
  );
});

// ── FETCH ─────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignora requests não-GET, extensões e blobs
  if (request.method !== 'GET') return;
  if (url.protocol === 'chrome-extension:') return;
  if (url.protocol === 'blob:') return;

  // ── API: Network First ─────────────────────────────────────
  // Sempre busca dados frescos da API; cai no cache se offline
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request)
        .then(response => {
          // Cache só respostas OK de GET para /api/mercados, /api/produtos, /api/precos
          if (response.ok && ['/api/mercados','/api/produtos','/api/precos','/api/config'].some(p => url.pathname.startsWith(p))) {
            const clone = response.clone();
            caches.open(CACHE_PAGES).then(cache => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => caches.match(request)) // Offline: usa cache
    );
    return;
  }

  // ── Fontes Google: Cache First ────────────────────────────
  if (url.origin === 'https://fonts.googleapis.com' || url.origin === 'https://fonts.gstatic.com') {
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        return fetch(request).then(response => {
          if (response.ok) {
            caches.open(CACHE_STATIC).then(cache => cache.put(request, response.clone()));
          }
          return response;
        });
      })
    );
    return;
  }

  // ── App Shell (HTML principal): Network First com fallback ─
  // HTML sempre da rede — nunca serve versão antiga no Safari
  if (url.pathname === '/' || url.pathname === '/index.html') {
    event.respondWith(
      fetch(request, { cache: 'no-store' })
        .catch(() => caches.match('/') || caches.match(request))
    );
    return;
  }

  // ── Assets estáticos (imagens, ícones): Cache First ────────
  if (url.pathname.startsWith('/icons/') || url.pathname.match(/\.(png|jpg|jpeg|webp|svg|ico|woff2?|css|js)$/)) {
    event.respondWith(
      caches.match(request).then(cached => {
        if (cached) return cached;
        return fetch(request).then(response => {
          if (response.ok) {
            caches.open(CACHE_STATIC).then(cache => cache.put(request, response.clone()));
          }
          return response;
        }).catch(() => cached);
      })
    );
    return;
  }

  // ── Default: Network First ─────────────────────────────────
  event.respondWith(
    fetch(request).catch(() => caches.match(request))
  );
});

// ── MENSAGENS DO APP ──────────────────────────────────────────
self.addEventListener('message', event => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data === 'GET_VERSION') {
    event.ports[0].postMessage(SW_VERSION);
  }
});

// ── PUSH NOTIFICATIONS (preparado para futuro) ────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();
  self.registration.showNotification(data.title || 'PreçoCerto', {
    body: data.body || '',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-96.png',
    data: { url: data.url || '/' },
    vibrate: [100, 50, 100],
  });
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(clientList => {
      for (const client of clientList) {
        if (client.url === url && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
