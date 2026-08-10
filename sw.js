// 소원물류 기사앱 서비스워커 (오프라인 캐시 + 웹푸시 / 앱 종료 상태에서도 알림)
const CACHE = "sowon-app-v20";
const ASSETS = ["./","./index.html","./manifest.json","./icon-192.png","./icon-512.png"];
const SB_URL = "https://xmydkovpxivdyjxagnou.supabase.co";
const SB_ANON = "sb_publishable_Fyp35Hgs7ECBiAnAqbWirQ_25BTo9R8";
const VAPID_PUB = "BPj5bqis2eiVTK4GN4EhXU6D68t6oRt_zjGG8-wfz-PEFjTZylfsk9jZrpPmb7fnZfWX5NidJUea6CCm6Sckbyo";

function u8(s){s=String(s).replace(/-/g,'+').replace(/_/g,'/');var p='='.repeat((4-s.length%4)%4);var r=atob(s+p);var a=new Uint8Array(r.length);for(var i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a;}
async function saveAuth(token,group){const c=await caches.open("sowon-auth");await c.put("/__token",new Response(token||""));await c.put("/__group",new Response(group||""));}
async function getAuth(){try{const c=await caches.open("sowon-auth");const t=await c.match("/__token");const g=await c.match("/__group");return {token:t?await t.text():"",group:g?await g.text():""};}catch(_){return {token:"",group:""};}}
async function clearAuth(){try{const c=await caches.open("sowon-auth");await c.delete("/__token");await c.delete("/__group");}catch(_){}}

self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS))); self.skipWaiting(); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE&&k!=="sowon-auth").map(k=>caches.delete(k))))); self.clients.claim(); });
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (u.hostname.endsWith("supabase.co")) return;
  // HTML/문서는 network-first → 항상 최신 앱을 받음 (오프라인이면 캐시)
  const isDoc = e.request.mode === "navigate" || u.pathname === "/" || u.pathname.endsWith("/") || u.pathname.endsWith(".html");
  if (isDoc && u.origin === location.origin) {
    e.respondWith(fetch(e.request).then(resp => {
      if (resp && resp.ok) { const cp = resp.clone(); caches.open(CACHE).then(c => c.put(e.request, cp)); }
      return resp;
    }).catch(() => caches.match(e.request).then(r => r || caches.match("./index.html"))));
    return;
  }
  // 정적 자산은 cache-first
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request).then(resp=>{
    if(e.request.method==="GET" && resp.ok && u.origin===location.origin){const cp=resp.clone();caches.open(CACHE).then(c=>c.put(e.request,cp));}
    return resp;
  }).catch(()=>caches.match("./index.html"))));
});

// 앱에서 로그인/로그아웃 시 토큰 전달 → 재구독에 사용
self.addEventListener("message", e => {
  const d = e.data || {};
  if (d.type === "auth") e.waitUntil(saveAuth(d.token, d.group));
  if (d.type === "logout") e.waitUntil(clearAuth());
});

// ===== 웹푸시 수신 (앱이 꺼져 있어도 동작) =====
self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch(_) { try { d = { body: e.data.text() }; } catch(__) { d = {}; } }
  const title = d.title || "소원물류 기사앱";
  const opts = {
    body: d.body || "",
    icon: "./icon-192.png",
    badge: "./icon-192.png",
    tag: d.tag || undefined,
    renotify: !!d.tag,
    data: { url: d.url || "" },
    vibrate: [80,40,80]
  };
  e.waitUntil(self.registration.showNotification(title, opts));
});

// ===== 알림 클릭 → 앱 열기/포커스 (딥링크) =====
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const raw = (e.notification.data && e.notification.data.url) || "";
  const q = raw && raw.indexOf("go=") >= 0 ? ("?" + raw.replace(/^\?/, "")) : "";
  const full = raw.startsWith("http") ? raw : ("./index.html" + q);
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of all) {
      if ("focus" in c) {
        try { if (q && "navigate" in c) await c.navigate(full); } catch(_) {}
        return c.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(full);
  })());
});

// ===== 구독 만료 시 자동 재구독 (앱을 안 열어도 알림 유지) =====
self.addEventListener("pushsubscriptionchange", e => {
  e.waitUntil((async () => {
    try {
      const sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: u8(VAPID_PUB) });
      const j = sub.toJSON();
      const { token, group } = await getAuth();
      if (!token) return;
      await fetch(SB_URL + "/rest/v1/rpc/save_push_sub", {
        method: "POST",
        headers: { "apikey": SB_ANON, "Authorization": "Bearer " + SB_ANON, "Content-Type": "application/json" },
        body: JSON.stringify({ p_token: token, p_endpoint: sub.endpoint, p_p256dh: j.keys.p256dh, p_auth: j.keys.auth, p_group: group || "" })
      });
    } catch (_) {}
  })());
});
