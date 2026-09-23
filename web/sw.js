// FM Aero Code 2 Service Worker v3.8.1
const CACHE = "fmaero2-3.8.1";
const SHELL = ["./", "./index.html", "./manifest.json", "./print.html", "./diag.html"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL).catch(() => {})));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) =>
    Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname.includes("/pkg/")) {
    e.respondWith(caches.match(req).then((cached) =>
      cached || fetch(req).then((resp) => {
        if (resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return resp;
      })));
    return;
  }

  e.respondWith(fetch(req).then((resp) => {
    if (resp.ok) {
      const copy = resp.clone();
      caches.open(CACHE).then((c) => c.put(req, copy));
    }
    return resp;
  }).catch(() => caches.match(req).then((r) => r || caches.match("./index.html"))));
});