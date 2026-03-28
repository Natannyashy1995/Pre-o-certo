// PreçoCerto — Service Worker v4
// Suporte a Web Push + Tela de Manutenção

const CACHE_NAME = 'precocerto-v4';
const ASSETS = ['/'];

// ── HTML da tela de manutenção ────────────────────────────
const MANUTENCAO_HTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PreçoCerto — Em Manutenção</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      background: linear-gradient(135deg, #1565C0 0%, #1976D2 50%, #26A69A 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      padding: 24px;
    }
    .card {
      background: #fff;
      border-radius: 24px;
      padding: 40px 32px;
      max-width: 360px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 60px rgba(0,0,0,0.2);
    }
    .logo { font-size: 52px; margin-bottom: 16px; }
    .title {
      font-size: 22px;
      font-weight: 900;
      color: #1565C0;
      margin-bottom: 8px;
    }
    .subtitle {
      font-size: 15px;
      color: #64748B;
      line-height: 1.6;
      margin-bottom: 28px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: #FEF3C7;
      border: 1.5px solid #FDE68A;
      border-radius: 20px;
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 700;
      color: #92400E;
      margin-bottom: 24px;
    }
    .spinner {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: #F59E0B;
      animation: pulse 1.2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.8); }
    }
    .retry {
      background: #1565C0;
      color: #fff;
      border: none;
      border-radius: 12px;
      padding: 14px 28px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      width: 100%;
    }
    .footer {
      margin-top: 20px;
      font-size: 12px;
      color: #94A3B8;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🔍</div>
    <div class="title">PreçoCerto</div>
    <div class="subtitle">
      O app está em manutenção no momento.<br>
      Voltaremos em breve!
    </div>
    <div class="badge">
      <div class="spinner"></div>
      Em manutenção
    </div>
    <button class="retry" onclick="location.reload()">
      🔄 Tentar novamente
    </button>
    <div class="footer">Piatã, BA — Comparador de preços</div>
  </div>
</body>
</html>`;

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
  if (e.request.method !== 'GET') return;

  const url = new URL(e.request.url);
  const isSameOrigin = url.origin === self.location.origin;
  const isNavigation = e.request.mode === 'navigate';

  // Para navegações (abertura do app), tenta buscar do servidor
  // Se falhar, mostra tela de manutenção
  if (isNavigation) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          // Salva no cache se OK
          if (res.ok) {
            const clone = res.clone();
            caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          }
          return res;
        })
        .catch(() => {
          // Servidor offline — tenta cache primeiro
          return caches.match(e.request).then(cached => {
            if (cached) return cached;
            // Sem cache — mostra tela de manutenção
            return new Response(MANUTENCAO_HTML, {
              headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
          });
        })
    );
    return;
  }

  // Para assets de mesma origem — cache first, fallback rede
  if (isSameOrigin) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
  }
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
      for (const client of list) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.focus();
          client.postMessage({ type: 'PUSH_RECEIVED', titulo: e.notification.title });
          return;
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
