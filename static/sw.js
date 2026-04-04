// ZeusChat Service Worker
const CACHE_NAME = 'zeuschat-v1';
const STATIC_CACHE = 'zeuschat-static-v1';
const DYNAMIC_CACHE = 'zeuschat-dynamic-v1';

// Assets to cache on install
const STATIC_ASSETS = [
  '/',
  '/chat.html',
  '/login.html',
  '/profile.html',
  '/settings.html',
  '/subscription',
  '/pending-approval',
  '/offline.html',
  '/static/manifest.json',
  '/zeuschat-icon.png',
  '/zeuschat-logo.png',
  '/zeustech-background.mp4'
];

// Install event - cache static assets
self.addEventListener('install', event => {
  console.log('[SW] Installing...');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('[SW] Caching static assets');
        return Promise.allSettled(
          STATIC_ASSETS.map(asset => cache.add(asset))
        );
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean old caches
self.addEventListener('activate', event => {
  console.log('[SW] Activating...');
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(
        keys
          .filter(key => key !== STATIC_CACHE && key !== DYNAMIC_CACHE && key !== CACHE_NAME)
          .map(key => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - network first, fallback to cache
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // Skip API calls - don't cache
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Skip socket.io
  if (url.pathname.includes('socket.io')) {
    return;
  }

  event.respondWith(
    fetch(request)
      .then(response => {
        // Cache successful responses
        if (response.status === 200) {
          const clone = response.clone();
          caches.open(DYNAMIC_CACHE).then(cache => {
            cache.put(request, clone);
          });
        }
        return response;
      })
      .catch(() => {
        // Fallback to cache
        return caches.match(request)
          .then(cached => {
            if (cached) return cached;

            // If requesting HTML, return offline page
            if ((request.headers.get('accept') || '').includes('text/html')) {
              return caches.match('/offline.html');
            }
            return undefined;
          });
      })
  );
});

// Push notification handler
self.addEventListener('push', event => {
  let data = {};
  try {
    data = event.data.json();
  } catch (e) {
    data = { title: 'ZeusChat', body: 'New message received' };
  }

  const options = {
    body: data.body || 'You have a new message',
    icon: '/zeuschat-icon.png',
    badge: '/zeuschat-icon.png',
    vibrate: [200, 100, 200],
    data: {
      url: data.url || '/chat.html'
    },
    actions: [
      { action: 'open', title: 'Open ZeusChat' },
      { action: 'close', title: 'Dismiss' }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'ZeusChat', options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', event => {
  event.notification.close();

  if (event.action === 'close') {
    return;
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(windowClients => {
        for (let client of windowClients) {
          if (client.url.includes('/chat') && 'focus' in client) {
            return client.focus();
          }
        }
        if (clients.openWindow) {
          return clients.openWindow(event.notification.data.url || '/chat.html');
        }
      })
  );
});