// 소원물류 기사앱 서비스워커 (오프라인 캐시)
const CACHE = "sowon-app-v17";
const ASSETS = ["./","./index.html","./manifest.json"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS))); self.skipWaiting(); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k))))); self.clients.claim(); });
self.addEventListener("fetch", e => {
  const u=new URL(e.request.url);
  e.respondWith(fetch(e.request).then(resp=>{
    if(e.request.method==="GET" && resp.ok && u.origin===location.origin){const cp=resp.clone();caches.open(CACHE).then(c=>c.put(e.request,cp));}
    return resp;
  }).catch(()=>caches.match(e.request)));
});
