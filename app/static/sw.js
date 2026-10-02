// Service worker for the installable admin app. Caches the app shell so the
// tool opens offline; API calls always go to the network.
const CACHE = "xlogin-admin-v1";
const SHELL = [
  "/admin",
  "/static/admin.css?v=1",
  "/static/admin.js?v=1",
  "/static/manifest.webmanifest",
  "/static/icon-192.png",
  "/static/icon-512.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;                 // POST /sessions etc. -> network
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  // Never serve API / live session pages from cache.
  if (url.pathname === "/sessions" || url.pathname === "/healthz" ||
      url.pathname.startsWith("/login")) return;
  if (req.mode === "navigate") {
    e.respondWith(fetch(req).catch(() => caches.match("/admin")));
    return;
  }
  e.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
});
