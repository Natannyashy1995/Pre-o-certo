// PreçoCerto — Service Worker v3
// Adiciona suporte a Web Push Notifications

const CACHE_NAME = 'precocerto-v3';
const ASSETS = ['/'];

// ── INSTALL ──────────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(c => c.addAll(ASSETS))
  );
  self.skipWaiting();
});

// ── ACTIVATE ─────────────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── FETCH ────────────────────────────────────────────────
self.addEventListener('fetch', e => {
  // Só faz cache de GET de mesma origem
  if (e.request.method !== 'GET') return;
  if (!e.request.url.startsWith(self.location.origin)) return;

  e.respondWith(
    fetch(e.request)
      .then(res => {
        // Atualiza cache com resposta mais recente
        const clone = res.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});

// ── PUSH ─────────────────────────────────────────────────
self.addEventListener('push', e => {
  let data = { titulo: 'PreçoCerto 🔍', corpo: 'Nova notificação!', url: '/' };
  try {
    if (e.data) data = { ...data, ...JSON.parse(e.data.text()) };
  } catch(_) {}

  e.waitUntil(
    self.registration.showNotification(data.titulo, {
      body:    data.corpo,
      icon:    '/icon-192.png',
      badge:   '/icon-96.png',
      vibrate: [200, 100, 200],
      data:    { url: data.url },
      actions: [{ action: 'abrir', title: '🔍 Ver no app' }]
    })
  );
});

// ── NOTIFICATION CLICK ────────────────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = e.notification.data?.url || '/';

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // Se já tem o app aberto, foca e navega
      for (const client of list) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.focus();
          client.postMessage({ type: 'PUSH_RECEIVED', titulo: e.notification.title });
          return;
        }
      }
      // Senão abre uma nova janela
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
