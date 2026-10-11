// Service Worker Q-EKH (E.2) — precache semua aset lokal supaya aplikasi
// berjalan 100% offline (sinergi dengan vendor lokal A.1).
// Strategi: NETWORK-FIRST dengan fallback cache saat offline.
// PENTING: respons server yang eksplisit (401 auth, 404) selalu diteruskan
// apa adanya — cache TIDAK boleh melewati gerbang Basic Auth serve.py
// (bug lama: cache-first membuat "batal login" tetap bisa masuk).
const CACHE = 'qekh-v6-7';

const ASSETS = [
    "./",
    "./index.html",
    "./style.css",
    "./ui.js",
    "./crypto.js",
    "./otp.js",
    "./cw.js",
    "./argon2-worker.js",
    "./manifest.webmanifest",
    "./icons/icon-192.png",
    "./icons/icon-512.png",
    "./icons/icon-maskable-192.png",
    "./icons/icon-maskable-512.png",
    "./icons/favicon-16.png",
    "./icons/favicon-32.png",
    "./vendor/noble-curves-2.3.0/abstract/fft.js",
    "./vendor/noble-curves-2.3.0/abstract/modular.js",
    "./vendor/noble-curves-2.3.0/utils.js",
    "./vendor/noble-hashes-2.4.0/_blake.js",
    "./vendor/noble-hashes-2.4.0/_md.js",
    "./vendor/noble-hashes-2.4.0/_u64.js",
    "./vendor/noble-hashes-2.4.0/argon2.js",
    "./vendor/noble-hashes-2.4.0/blake1.js",
    "./vendor/noble-hashes-2.4.0/blake2.js",
    "./vendor/noble-hashes-2.4.0/blake3.js",
    "./vendor/noble-hashes-2.4.0/eskdf.js",
    "./vendor/noble-hashes-2.4.0/hkdf.js",
    "./vendor/noble-hashes-2.4.0/hmac.js",
    "./vendor/noble-hashes-2.4.0/index.js",
    "./vendor/noble-hashes-2.4.0/legacy.js",
    "./vendor/noble-hashes-2.4.0/pbkdf2.js",
    "./vendor/noble-hashes-2.4.0/scrypt.js",
    "./vendor/noble-hashes-2.4.0/sha2.js",
    "./vendor/noble-hashes-2.4.0/sha3-addons.js",
    "./vendor/noble-hashes-2.4.0/sha3.js",
    "./vendor/noble-hashes-2.4.0/utils.js",
    "./vendor/noble-hashes-2.4.0/webcrypto.js",
    "./vendor/noble-post-quantum-0.7.0/_crystals.js",
    "./vendor/noble-post-quantum-0.7.0/ml-kem.js",
    "./vendor/noble-post-quantum-0.7.0/slh-dsa.js",
    "./vendor/noble-post-quantum-0.7.0/utils.js",
    "./vendor/qrcode-generator-1.4.4/qrcode.js",
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    if (event.request.method !== 'GET' || new URL(event.request.url).origin !== self.location.origin) {
        return;
    }
    event.respondWith(
        fetch(event.request).then((resp) => {
            if (resp && resp.ok) {
                const copy = resp.clone();
                caches.open(CACHE).then((cache) => cache.put(event.request, copy));
            }
            // Respons eksplisit server (401/404/dll) diteruskan apa adanya.
            return resp;
        }).catch(async () => {
            // Jaringan benar-benar tak terjangkau (offline) -> cache.
            const cached = await caches.match(event.request, { ignoreSearch: true });
            return cached || Response.error();
        })
    );
});
