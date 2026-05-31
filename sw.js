const CACHE = 'bsak-v2';
const ASSETS = ['./index.html', './wallpaper.jpg', './manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  // Network first for API calls, cache first for assets
  if(e.request.url.includes('bible-api.com') || e.request.url.includes('bolls.life') || e.request.url.includes('fonts.gstatic')) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
  } else {
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
  }
});
