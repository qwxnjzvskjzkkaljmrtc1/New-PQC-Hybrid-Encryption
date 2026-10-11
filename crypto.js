// Q-EKH Protocol v6 — modul kripto murni (tanpa DOM). Bisa diimpor dari browser
// maupun Node (untuk tes otomatis).
//
// Perubahan v6 (lihat rekomendasi-pengembangan-qekh.txt):
//   - A.1: pustaka noble tidak lagi dimuat dari CDN esm.sh, melainkan dari
//     folder vendor/ lokal (hash SHA-256 tiap file tercatat di vendor/HASHES.txt).
//   - A.2: runCryptoSelfTest() menguji HKDF (RFC 5869), AES-256-GCM (vektor NIST),
//     Argon2id (RFC 9106), ML-KEM-768, SLH-DSA, X25519, dan Ed25519 sebelum UI aktif.
//   - D.3: Kunci Publik boleh memuat field opsional "expires" (ISO 8601).
//   - E.3: Argon2id bisa berjalan di Web Worker (argon2-worker.js) dengan laporan
//     progres, supaya UI tidak membeku. Otomatis fallback ke thread utama di Node.
//   - B.4/C.1: konversi base32 grup-5-huruf (RFC 4648) untuk radio: toLetterGroups/
//     fromLetterGroups dipakai bersama oleh mode radiogram dan sistem OTP.
//
// Inti protokol (X25519 + ML-KEM-768, AES-256-GCM, Ed25519 + SLH-DSA, sealed
// sender, Argon2id) TIDAK diubah — pesan v5 tetap terbaca persis seperti dulu,
// demikian pula v3/v4 lama.
import { ml_kem768 } from './vendor/noble-post-quantum-0.7.0/ml-kem.js';
import { slh_dsa_sha2_192s } from './vendor/noble-post-quantum-0.7.0/slh-dsa.js';
import { argon2id, argon2idAsync } from './vendor/noble-hashes-2.4.0/argon2.js';

const PROTOCOL_VERSION = 'QEKH-v5'; // format pesan tidak berubah sejak v5
const KEY_VERSIONS = ['QEKH-v5', 'QEKH-v4', 'QEKH-v3']; // format material kunci identik; v4+ menambah bagian "public" di kunci privat
const HKDF_INFO = new TextEncoder().encode('QEKH-v5-HKDF');
const V4_HKDF_INFO = new TextEncoder().encode('QEKH-v4-HKDF');
const LEGACY_HKDF_INFO = new TextEncoder().encode('QEKH-v3-HKDF');
const SIG_DOMAIN = new TextEncoder().encode('QEKH-v5-SIG');
const AAD_DOMAIN = new TextEncoder().encode('QEKH-v5-AAD');
const ARGON2_PARAMS = Object.freeze({ t: 3, m: 65536, p: 1, dkLen: 32 }); // 64 MB — memory-hard
const ARGON2_LIMITS = Object.freeze({ minM: 8192, maxM: 262144, minT: 1, maxT: 10, minP: 1, maxP: 4 });
const PBKDF2_ITERATIONS = 600000; // hanya untuk membuka kunci privat format lama
const MAX_PBKDF2_ITERATIONS = 10000000;
const MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;
const PAD_BLOCK = 512; // padding panjang pesan per kelipatan 512 byte
// --- Enkripsi FILE chunked (D.1) — konstruksi STREAM ala miscreant ---
const FILE_MAGIC = new TextEncoder().encode('QEKHF1');
const FILE_VERSION = 'QEKH-FILE-v1';
const FILE_CHUNK = 64 * 1024;              // 64 KiB per chunk AES-GCM
const FILE_AAD_DOMAIN = new TextEncoder().encode('QEKH-FILE-v1-AAD');
const MAX_FILE_BYTES = 256 * 1024 * 1024;  // batas praktis (dirakit di memori)
const MAX_FILE_HEADER_BYTES = 1024 * 1024;
const BYTE_LENGTHS = Object.freeze({
    x25519Public: 32,
    x25519Private: 48,
    mlkemPublic: 1184,
    mlkemPrivate: 2400,
    mlkemCiphertext: 1088,
    ed25519Public: 32,
    ed25519Private: 48,
    ed25519Signature: 64,
    slhdsaPublic: 48,
    slhdsaPrivate: 96,
    slhdsaSignature: 16224,
    argonSalt: 16,
    salt: 32,
    iv: 12,
});
const subtleCrypto = globalThis.crypto.subtle;

// --- Byte / Base64 / Hex Helpers ---
export const arrayBufferToBase64 = (buffer) => {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
};

export const base64ToUint8Array = (base64, expectedLength, field = 'data') => {
    if (typeof base64 !== 'string' || !base64.trim()) throw new Error(`Field "${field}" harus berupa base64 yang tidak kosong.`);
    const clean = base64.replace(/\s+/g, '');
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clean)) {
        throw new Error(`Field "${field}" bukan base64 yang valid.`);
    }
    let bytes;
    try { bytes = Uint8Array.from(atob(clean), c => c.charCodeAt(0)); } catch {
        throw new Error(`Field "${field}" bukan base64 yang valid.`);
    }
    if (expectedLength !== undefined && bytes.length !== expectedLength) {
        throw new Error(`Panjang "${field}" tidak valid (${bytes.length} byte; diharapkan ${expectedLength}).`);
    }
    return bytes;
};

export const concatBytes = (...arrays) => {
    const parts = arrays.map(a => (a instanceof Uint8Array ? a : new Uint8Array(a)));
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        result.set(p, offset);
        offset += p.length;
    }
    return result;
};

export const encodeText = (s) => new TextEncoder().encode(s);
export const decodeText = (b) => new TextDecoder().decode(b);
export const getRandomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export const bytesToHex = (bytes) =>
    Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

export const hexToBytes = (hex) => {
    const clean = hex.replace(/\s+/g, '');
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(clean)) throw new Error('Hex tidak valid.');
    return Uint8Array.from(clean.match(/../g).map(h => parseInt(h, 16)));
};

// Perbandingan waktu-konstan untuk tag MAC.
export const constantTimeEqual = (a, b) => {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
};

// ===================================================================
//           BASE32 GRUP-5-HURUF (RFC 4648) — format radio (B.4/C.1)
// ===================================================================
// Alfabet A–Z2–7 tanpa padding, huruf kapital, dikelompokkan per 5 karakter.
// Ekspansi ~1,6x dari biner; bisa dibacakan lewat voice/CW dan disalin tangan
// tanpa ambiguitas huruf besar/kecil. Parser toleran spasi, baris baru, dan
// huruf kecil.
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes) {
    let out = '';
    let buffer = 0;
    let bitsLeft = 0;
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            out += B32_ALPHABET[(buffer >>> (bitsLeft - 5)) & 31];
            bitsLeft -= 5;
        }
    }
    if (bitsLeft > 0) out += B32_ALPHABET[(buffer << (5 - bitsLeft)) & 31];
    return out;
}

export function base32Decode(text) {
    if (typeof text !== 'string') throw new Error('Input base32 harus berupa teks.');
    const clean = text.toUpperCase().replace(/[\s-]+/g, '');
    if (!clean) throw new Error('Teks grup huruf kosong.');
    if (!/^[A-Z2-7]+$/.test(clean)) {
        throw new Error('Grup huruf mengandung karakter di luar alfabet base32 (A–Z dan 2–7).');
    }
    let buffer = 0;
    let bitsLeft = 0;
    const out = [];
    for (const ch of clean) {
        buffer = (buffer << 5) | B32_ALPHABET.indexOf(ch);
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            out.push((buffer >>> (bitsLeft - 8)) & 0xff);
            bitsLeft -= 8;
            buffer &= (1 << bitsLeft) - 1; // cegah overflow melewati 32 bit
        }
    }
    // Sisa bit di akhir harus nol semua (kanonik) — tolak yang tidak.
    if (bitsLeft > 0 && buffer !== 0) {
        throw new Error('Grup huruf bukan base32 kanonik (sisa bit tidak nol) — kemungkinan salah salin.');
    }
    return new Uint8Array(out);
}

export function toLetterGroups(bytes, groupSize = 5) {
    const b32 = base32Encode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    const groups = [];
    for (let i = 0; i < b32.length; i += groupSize) groups.push(b32.slice(i, i + groupSize));
    return groups.join(' ');
}

export function fromLetterGroups(text) {
    return base32Decode(text);
}

// Header opsional di baris pertama (mis. "QEKH5 123 GRUP", "OTPV2", "QPAD1 BUKU").
const LETTER_HEADER_RE = /^\s*(QEKH5|OTPV2|QPAD1)[^\n]*\n/i;

export function stripLetterHeader(text) {
    return String(text).replace(LETTER_HEADER_RE, '');
}

// Deteksi apakah teks tampak seperti grup huruf (bukan base64 biasa).
export function looksLikeLetterGroups(text) {
    if (typeof text !== 'string') return false;
    const body = stripLetterHeader(text).trim();
    if (!body) return false;
    const compact = body.replace(/[\s-]+/g, '');
    return compact.length >= 8 && /^[A-Z2-7]+$/i.test(compact);
}

// ===================================================================
//                          CRYPTO LOGIC INTI
// ===================================================================

async function generateX25519Keys() {
    return await subtleCrypto.generateKey({ name: 'X25519' }, true, ['deriveBits']);
}

async function generateEd25519Keys() {
    return await subtleCrypto.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
}

export async function hashBytes(...arrays) {
    return new Uint8Array(await subtleCrypto.digest('SHA-256', concatBytes(...arrays)));
}

// Hash identitas = SHA-256 atas keempat kunci publik (urutan tetap).
// Dipakai untuk mengikat KDF & tanda tangan ke identitas para pihak.
async function identityHashOfPublicFields(pub) {
    return await hashBytes(
        base64ToUint8Array(pub.x25519, BYTE_LENGTHS.x25519Public, 'x25519'),
        base64ToUint8Array(pub.mlkem, BYTE_LENGTHS.mlkemPublic, 'mlkem'),
        base64ToUint8Array(pub.ed25519, BYTE_LENGTHS.ed25519Public, 'ed25519'),
        base64ToUint8Array(pub.slhdsa, BYTE_LENGTHS.slhdsaPublic, 'slhdsa')
    );
}

async function computeFingerprint(x25519PkBytes, kyberPkBytes, ed25519PkBytes, slhdsaPkBytes) {
    const hash = await hashBytes(x25519PkBytes, kyberPkBytes, ed25519PkBytes, slhdsaPkBytes);
    const hex = bytesToHex(hash).toUpperCase();
    return hex.match(/.{1,4}/g).join(' ');
}

// HKDF-SHA256 manual (extract + expand via HMAC). Dipakai sebagai pengganti
// HKDF native karena sebagian implementasi WebCrypto membatasi panjang "info"
// (mis. maks. 1024 byte) — padahal info v4 memuat ciphertext KEM (1088 byte).
// Hasilnya identik dengan HKDF native, jadi pesan v3/v4 lama tetap terbuka.
export async function hmacSha256(keyBytes, dataBytes) {
    const key = await subtleCrypto.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtleCrypto.sign({ name: 'HMAC' }, key, dataBytes));
}

export async function hkdfSha256(ikm, salt, info, length = 32) {
    const prk = await hmacSha256(salt, ikm); // extract
    const blocks = Math.ceil(length / 32);
    let t = new Uint8Array(0);
    let okm = new Uint8Array(0);
    for (let i = 1; i <= blocks; i++) { // expand
        t = await hmacSha256(prk, concatBytes(t, info, new Uint8Array([i])));
        okm = concatBytes(okm, t);
    }
    prk.fill(0);
    t.fill(0);
    return okm.slice(0, length);
}

async function deriveEncryptionKey(combinedSecretBytes, salt, info) {
    const keyBytes = await hkdfSha256(combinedSecretBytes, salt, info, 32);
    combinedSecretBytes.fill(0); // best-effort: hapus rahasia mentah dari memori
    const key = await subtleCrypto.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    keyBytes.fill(0);
    return key;
}

// Payload tanda tangan v3/v4 (tanda tangan di luar lapisan enkripsi) — dipertahankan
// hanya untuk memverifikasi pesan lama.
function buildLegacySignablePayload(version, x25519PublicKeyRaw, kyberCipherText, salt, iv, ciphertext) {
    return concatBytes(
        encodeText(version),
        x25519PublicKeyRaw,
        kyberCipherText,
        salt,
        iv,
        ciphertext
    );
}

// Payload tanda tangan v5: domain separator + transkrip + hash identitas kedua
// pihak + paket inti. Mengikat tanda tangan ke pertukaran & identitas spesifik.
function buildSignablePayloadV5(ephemeralPkRaw, kyberCipherText, salt, iv, hSender, hRecipient, coreBytes) {
    return concatBytes(SIG_DOMAIN, ephemeralPkRaw, kyberCipherText, salt, iv, hSender, hRecipient, coreBytes);
}

async function encryptMessage(key, dataBytes, iv, aad) {
    const params = { name: 'AES-GCM', iv: iv };
    if (aad) params.additionalData = aad;
    const ciphertext = await subtleCrypto.encrypt(params, key, dataBytes);
    return new Uint8Array(ciphertext);
}

async function decryptMessage(key, iv, ciphertext, aad) {
    const params = { name: 'AES-GCM', iv: iv };
    if (aad) params.additionalData = aad;
    return new Uint8Array(await subtleCrypto.decrypt(params, key, ciphertext));
}

// Padding acak: panjang paket dibulatkan ke kelipatan PAD_BLOCK plus 0–2 blok
// ekstra acak, supaya panjang ciphertext tidak membocorkan panjang pesan persis.
// Opsi bucket (D.5): panjang akhir dibulatkan ke kelipatan `bucket` byte —
// semua paket tampak seragam per kelas ukuran, melawan analisis ukuran yang
// lebih teliti. Melempar error bila pesan sudah melebihi bucket terbesar.
const BUCKET_SIZES = Object.freeze([32768, 65536, 131072, 262144]);
function makePadding(currentLength, bucket = 0) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let padLen;
    if (bucket) {
        if (!BUCKET_SIZES.includes(bucket)) throw new Error('Ukuran bucket tidak dikenal.');
        if (currentLength > bucket) {
            throw new Error(`Pesan (${currentLength} byte) melebihi bucket ${bucket / 1024} KB — pilih bucket lebih besar atau mode blok acak.`);
        }
        padLen = (bucket - (currentLength % bucket)) + getRandomBytes(1)[0] % 2 * bucket;
    } else {
        const extraBlocks = getRandomBytes(1)[0] % 3;
        padLen = (PAD_BLOCK - (currentLength % PAD_BLOCK)) + extraBlocks * PAD_BLOCK;
    }
    const rand = getRandomBytes(padLen);
    let s = '';
    for (let i = 0; i < padLen; i++) s += alphabet[rand[i] & 63];
    return s;
}

// --- Parsing & validasi JSON kunci ---
function validateKeyObject(obj, expectedType) {
    if (!obj || typeof obj !== 'object') throw new Error('JSON kunci tidak valid.');
    if (!KEY_VERSIONS.includes(obj.version)) {
        throw new Error(`Versi kunci tidak dikenal ("${obj.version || '?'}"). Dibutuhkan ${PROTOCOL_VERSION}, v4, atau v3 lama.`);
    }
    if (obj.type !== expectedType) {
        throw new Error(`Kunci yang ditempel bertipe "${obj.type}", padahal yang dibutuhkan "${expectedType}".`);
    }
}

function requireKeyFields(obj) {
    const lengths = obj.type === 'public'
        ? { x25519: BYTE_LENGTHS.x25519Public, mlkem: BYTE_LENGTHS.mlkemPublic, ed25519: BYTE_LENGTHS.ed25519Public, slhdsa: BYTE_LENGTHS.slhdsaPublic }
        : { x25519: BYTE_LENGTHS.x25519Private, mlkem: BYTE_LENGTHS.mlkemPrivate, ed25519: BYTE_LENGTHS.ed25519Private, slhdsa: BYTE_LENGTHS.slhdsaPrivate };
    for (const [field, length] of Object.entries(lengths)) {
        if (typeof obj[field] !== 'string' || !obj[field]) throw new Error(`Field "${field}" hilang dari JSON kunci.`);
        base64ToUint8Array(obj[field], length, field);
    }
    if (obj.public) {
        if (typeof obj.public !== 'object') throw new Error('Bagian public pada kunci privat tidak valid.');
        for (const [field, length] of Object.entries({ x25519: BYTE_LENGTHS.x25519Public, mlkem: BYTE_LENGTHS.mlkemPublic, ed25519: BYTE_LENGTHS.ed25519Public, slhdsa: BYTE_LENGTHS.slhdsaPublic })) {
            base64ToUint8Array(obj.public[field], length, `public.${field}`);
        }
    }
    // D.3: masa berlaku opsional — bila ada harus berupa tanggal ISO yang valid.
    if (obj.expires !== undefined) {
        if (typeof obj.expires !== 'string' || isNaN(new Date(obj.expires))) {
            throw new Error('Field "expires" pada kunci bukan tanggal ISO 8601 yang valid.');
        }
    }
}

export function loadPublicKey(text) {
    let obj;
    try {
        obj = JSON.parse(text);
    } catch {
        throw new Error('JSON kunci tidak valid — pastikan seluruh blok kunci tersalin lengkap.');
    }
    validateKeyObject(obj, 'public');
    requireKeyFields(obj);
    return obj;
}

// Info ringkas Kunci Publik untuk UI: fingerprint + masa berlaku (D.3).
export async function publicKeyInfo(text) {
    const obj = loadPublicKey(text);
    const fingerprint = await fingerprintOfPublicFields(obj);
    const expires = typeof obj.expires === 'string' ? obj.expires : null;
    return { fingerprint, expires, expired: expires ? new Date(expires).getTime() < Date.now() : false };
}

// --- Argon2id: Web Worker (E.3) dengan fallback thread utama ---
let argon2Worker = null;
let argon2WorkerReqId = 0;
const argon2WorkerPending = new Map();

function getArgon2Worker() {
    if (typeof Worker === 'undefined' || typeof document === 'undefined') return null;
    if (argon2Worker) return argon2Worker;
    try {
        argon2Worker = new Worker('./argon2-worker.js', { type: 'module' });
    } catch {
        return null; // worker gagal dibuat (mis. kebijakan ketat) — fallback thread utama
    }
    argon2Worker.onmessage = (ev) => {
        const msg = ev.data || {};
        const pending = argon2WorkerPending.get(msg.id);
        if (!pending) return;
        if (msg.type === 'progress') {
            if (pending.onProgress) pending.onProgress(msg.value);
        } else if (msg.type === 'done') {
            argon2WorkerPending.delete(msg.id);
            pending.resolve(new Uint8Array(msg.key));
        } else if (msg.type === 'error') {
            argon2WorkerPending.delete(msg.id);
            pending.reject(new Error(msg.error || 'Argon2 gagal di worker.'));
        }
    };
    argon2Worker.onerror = () => {
        for (const p of argon2WorkerPending.values()) p.reject(new Error('Argon2 worker berhenti.'));
        argon2WorkerPending.clear();
        argon2Worker = null;
    };
    return argon2Worker;
}

// Turunkan kunci Argon2id; di browser berjalan di worker dengan laporan progres
// (0..1), di Node (tes) langsung sinkron-async tanpa worker.
export function deriveKeyArgon2(passBytes, salt, params, onProgress) {
    const worker = getArgon2Worker();
    if (worker) {
        const id = ++argon2WorkerReqId;
        const passCopy = new Uint8Array(passBytes);
        const saltCopy = new Uint8Array(salt);
        return new Promise((resolve, reject) => {
            argon2WorkerPending.set(id, { resolve, reject, onProgress });
            worker.postMessage(
                { id, pass: passCopy.buffer, salt: saltCopy.buffer, params },
                [passCopy.buffer, saltCopy.buffer]
            );
        });
    }
    return argon2idAsync(passBytes, salt, { ...params, onProgress });
}

// --- Enkripsi Kunci Privat dengan passphrase ---
// Argon2id (memory-hard, 64 MB) + AES-256-GCM. Kunci lama ber-PBKDF2-SHA256
// tetap bisa dibuka.
async function protectPrivateKey(privateJsonText, passphrase, onProgress) {
    const salt = getRandomBytes(BYTE_LENGTHS.argonSalt);
    const iv = getRandomBytes(BYTE_LENGTHS.iv);
    const rawKey = await deriveKeyArgon2(encodeText(passphrase), salt, ARGON2_PARAMS, onProgress);
    const key = await subtleCrypto.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
    rawKey.fill(0);
    const data = await encryptMessage(key, encodeText(privateJsonText), iv, null);
    return JSON.stringify({
        version: PROTOCOL_VERSION,
        type: 'private',
        encrypted: true,
        kdf: 'Argon2id',
        m: ARGON2_PARAMS.m,
        t: ARGON2_PARAMS.t,
        p: ARGON2_PARAMS.p,
        salt: arrayBufferToBase64(salt),
        iv: arrayBufferToBase64(iv),
        data: arrayBufferToBase64(data),
    }, null, 2);
}

async function decryptProtectedPrivateKey(obj, passphrase, onProgress) {
    const salt = base64ToUint8Array(obj.salt, BYTE_LENGTHS.argonSalt, 'salt');
    const iv = base64ToUint8Array(obj.iv, BYTE_LENGTHS.iv, 'iv');
    const data = base64ToUint8Array(obj.data, undefined, 'data');
    if (data.length < 17 || data.length > MAX_ENVELOPE_BYTES) throw new Error('Panjang data kunci terenkripsi tidak valid.');
    try {
        if (obj.kdf === 'Argon2id') {
            const { m, t, p } = obj;
            if (![m, t, p].every(Number.isSafeInteger)
                || m < ARGON2_LIMITS.minM || m > ARGON2_LIMITS.maxM
                || t < ARGON2_LIMITS.minT || t > ARGON2_LIMITS.maxT
                || p < ARGON2_LIMITS.minP || p > ARGON2_LIMITS.maxP) {
                throw new Error('Parameter Argon2id kunci tidak valid atau terlalu besar.');
            }
            const rawKey = await deriveKeyArgon2(encodeText(passphrase), salt, { t, m, p, dkLen: 32 }, onProgress);
            const key = await subtleCrypto.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
            rawKey.fill(0);
            return await decryptMessage(key, iv, data, null);
        }
        if (obj.kdf === 'PBKDF2-SHA256') { // format lama (v3/v4)
            if (!Number.isSafeInteger(obj.iterations) || obj.iterations < 100000 || obj.iterations > MAX_PBKDF2_ITERATIONS) {
                throw new Error('Parameter KDF kunci tidak valid atau terlalu besar.');
            }
            const keyMaterial = await subtleCrypto.importKey('raw', encodeText(passphrase), 'PBKDF2', false, ['deriveKey']);
            const key = await subtleCrypto.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: obj.iterations, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            return await decryptMessage(key, iv, data, null);
        }
        throw new Error(`KDF tidak dikenal ("${obj.kdf || '?'}").`);
    } catch (e) {
        if (e.message.startsWith('Parameter') || e.message.startsWith('KDF') || e.message.startsWith('Panjang')) throw e;
        throw new Error('Gagal membuka kunci — Passphrase salah atau data kunci rusak.');
    }
}

export async function loadPrivateKey(text, passphrase = '', onProgress) {
    let obj;
    try {
        obj = JSON.parse(text);
    } catch {
        throw new Error('JSON kunci tidak valid — pastikan seluruh blok kunci tersalin lengkap.');
    }
    validateKeyObject(obj, 'private');

    if (obj.encrypted === true) {
        if (!passphrase) {
            throw new Error('Kunci Privat ini terenkripsi — isi dulu Passphrase-nya di kolom yang tersedia.');
        }
        const plain = await decryptProtectedPrivateKey(obj, passphrase, onProgress);
        try {
            obj = JSON.parse(decodeText(plain));
        } catch {
            throw new Error('Isi kunci rusak setelah didekripsi.');
        }
        validateKeyObject(obj, 'private');
    }

    requireKeyFields(obj);
    return obj;
}

async function fingerprintOfPublicFields(pub) {
    return await computeFingerprint(
        base64ToUint8Array(pub.x25519),
        base64ToUint8Array(pub.mlkem),
        base64ToUint8Array(pub.ed25519),
        base64ToUint8Array(pub.slhdsa)
    );
}

// --- Pembuatan identitas hibrida (4 pasang kunci) ---
// opts.expires: string ISO 8601 opsional (D.3) — diumumkan di Kunci Publik.
export async function generateIdentity(passphrase = '', opts = {}) {
    const x25519KeyPair = await generateX25519Keys();
    const kyberKeys = ml_kem768.keygen();
    const ed25519KeyPair = await generateEd25519Keys();
    const slhKeys = slh_dsa_sha2_192s.keygen();

    const x25519Pk = new Uint8Array(await subtleCrypto.exportKey('raw', x25519KeyPair.publicKey));
    const x25519Sk = new Uint8Array(await subtleCrypto.exportKey('pkcs8', x25519KeyPair.privateKey));
    const ed25519Pk = new Uint8Array(await subtleCrypto.exportKey('raw', ed25519KeyPair.publicKey));
    const ed25519Sk = new Uint8Array(await subtleCrypto.exportKey('pkcs8', ed25519KeyPair.privateKey));

    const fingerprint = await computeFingerprint(x25519Pk, kyberKeys.publicKey, ed25519Pk, slhKeys.publicKey);

    const publicFields = {
        x25519: arrayBufferToBase64(x25519Pk),
        mlkem: arrayBufferToBase64(kyberKeys.publicKey),
        ed25519: arrayBufferToBase64(ed25519Pk),
        slhdsa: arrayBufferToBase64(slhKeys.publicKey),
    };

    const publicKeyObj = {
        version: PROTOCOL_VERSION,
        type: 'public',
        ...publicFields,
    };
    if (opts.expires) publicKeyObj.expires = opts.expires;
    const publicKeyJson = JSON.stringify(publicKeyObj, null, 2);

    let privateKeyJson = JSON.stringify({
        version: PROTOCOL_VERSION,
        type: 'private',
        x25519: arrayBufferToBase64(x25519Sk),
        mlkem: arrayBufferToBase64(kyberKeys.secretKey),
        ed25519: arrayBufferToBase64(ed25519Sk),
        slhdsa: arrayBufferToBase64(slhKeys.secretKey),
        public: publicFields, // bagian publik ikut disimpan: dipakai untuk hash identitas & segel sidik jari
    }, null, 2);

    if (passphrase) {
        privateKeyJson = await protectPrivateKey(privateKeyJson, passphrase, opts.onProgress);
    }

    return { publicKeyJson, privateKeyJson, fingerprint };
}

// --- Enkripsi + tanda tangan ganda TERSEGEL (v5) ---
export async function encryptHybrid(recipientPublicJsonText, senderPrivateJsonText, plaintext, senderPassphrase = '', opts = {}) {
    if (!plaintext) throw new Error('Pesan masih kosong — tulis dulu plaintext-nya.');
    const recipient = loadPublicKey(recipientPublicJsonText);
    const sender = await loadPrivateKey(senderPrivateJsonText, senderPassphrase, opts.onProgress);

    if (!sender.public || typeof sender.public !== 'object') {
        throw new Error('Kunci Privat Anda format lama (v3) dan tidak memuat bagian publik. Buat pasangan kunci baru di tab 1 — cepat & gratis — lalu bagikan ulang Kunci Publiknya.');
    }
    const senderFingerprint = await fingerprintOfPublicFields(sender.public);
    const recipientFingerprint = await fingerprintOfPublicFields(recipient);
    const hSender = await identityHashOfPublicFields(sender.public);
    const hRecipient = await identityHashOfPublicFields(recipient);

    // X25519: pasangan kunci ephemeral, deriveBits dengan kunci publik penerima
    const ephemeral = await generateX25519Keys();
    const recipientX25519Pub = await subtleCrypto.importKey(
        'raw', base64ToUint8Array(recipient.x25519), { name: 'X25519' }, false, []
    );
    const x25519Shared = new Uint8Array(await subtleCrypto.deriveBits(
        { name: 'X25519', public: recipientX25519Pub }, ephemeral.privateKey, 256
    ));
    const ephemeralPkRaw = new Uint8Array(await subtleCrypto.exportKey('raw', ephemeral.publicKey));

    // ML-KEM-768: enkapsulasi terhadap kunci publik penerima
    const { cipherText: kyberCipherText, sharedSecret: kyberShared } =
        ml_kem768.encapsulate(base64ToUint8Array(recipient.mlkem));

    // Gabung rahasia: PQ lebih dulu, baru klasik. Info HKDF diikat ke transkrip
    // (kunci ephemeral + ciphertext KEM) DAN identitas penerima, sehingga kunci
    // AES unik per pertukaran dan tak bisa dipakai ulang untuk identitas lain.
    const salt = getRandomBytes(BYTE_LENGTHS.salt);
    const combined = concatBytes(kyberShared, x25519Shared);
    kyberShared.fill(0);
    x25519Shared.fill(0);
    const transcriptHash = await hashBytes(ephemeralPkRaw, kyberCipherText);
    const hkdfInfo = concatBytes(HKDF_INFO, transcriptHash, hRecipient);
    const aesKey = await deriveEncryptionKey(combined, salt, hkdfInfo);

    // AAD mengikat ciphertext ke header envelope — potong-tempel ciphertext ke
    // envelope lain akan gagal didekripsi.
    const aad = await hashBytes(AAD_DOMAIN, ephemeralPkRaw, kyberCipherText, salt);

    // Paket inti: identitas pengirim & penerima ikut tersegel di dalam enkripsi
    const coreJson = JSON.stringify({
        from: senderFingerprint,
        to: recipientFingerprint,
        at: new Date().toISOString(),
        body: plaintext,
    });
    const coreBytes = encodeText(coreJson);

    // Tanda tangan ganda atas transkrip + identitas kedua pihak + paket inti.
    // Tanda tangan disimpan DI DALAM paket terenkripsi (sealed sender).
    const iv = getRandomBytes(BYTE_LENGTHS.iv);
    const signablePayload = buildSignablePayloadV5(ephemeralPkRaw, kyberCipherText, salt, iv, hSender, hRecipient, coreBytes);
    const ed25519Sk = await subtleCrypto.importKey(
        'pkcs8', base64ToUint8Array(sender.ed25519), { name: 'Ed25519' }, false, ['sign']
    );
    const ed25519Signature = new Uint8Array(
        await subtleCrypto.sign({ name: 'Ed25519' }, ed25519Sk, signablePayload)
    );
    const slhdsaSignature = slh_dsa_sha2_192s.sign(signablePayload, base64ToUint8Array(sender.slhdsa));

    const signedPackage = {
        from: senderFingerprint,
        to: recipientFingerprint,
        at: JSON.parse(coreJson).at,
        body: plaintext,
        sig: {
            ed25519: arrayBufferToBase64(ed25519Signature),
            slhdsa: arrayBufferToBase64(slhdsaSignature),
        },
    };
    signedPackage.pad = makePadding(encodeText(JSON.stringify({ ...signedPackage, pad: '' })).length, opts.bucket || 0);

    const ciphertext = await encryptMessage(aesKey, encodeText(JSON.stringify(signedPackage)), iv, aad);

    const envelope = {
        version: PROTOCOL_VERSION,
        ephemeralX25519: arrayBufferToBase64(ephemeralPkRaw),
        kyberCiphertext: arrayBufferToBase64(kyberCipherText),
        salt: arrayBufferToBase64(salt),
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(ciphertext),
    };
    return arrayBufferToBase64(encodeText(JSON.stringify(envelope)));
}

// --- Verifikasi tanda tangan v3/v4 (tanda tangan di luar envelope) ---
async function verifyLegacySignatures(envelope, sender, signablePayload) {
    let ed25519Ok = false;
    try {
        if (envelope.signatures && typeof envelope.signatures.ed25519 === 'string') {
            const ed25519Pk = await subtleCrypto.importKey(
                'raw', base64ToUint8Array(sender.ed25519), { name: 'Ed25519' }, false, ['verify']
            );
            ed25519Ok = await subtleCrypto.verify(
                { name: 'Ed25519' }, ed25519Pk,
                base64ToUint8Array(envelope.signatures.ed25519, BYTE_LENGTHS.ed25519Signature, 'signatures.ed25519'), signablePayload
            );
        }
    } catch { ed25519Ok = false; }

    let slhdsaOk = false;
    try {
        if (envelope.signatures && typeof envelope.signatures.slhdsa === 'string') {
            slhdsaOk = slh_dsa_sha2_192s.verify(
                base64ToUint8Array(envelope.signatures.slhdsa, BYTE_LENGTHS.slhdsaSignature, 'signatures.slhdsa'), signablePayload,
                base64ToUint8Array(sender.slhdsa)
            );
        }
    } catch { slhdsaOk = false; }

    return { ed25519Ok, slhdsaOk };
}

// --- Dekripsi + verifikasi tanda tangan ---
export async function decryptHybrid(recipientPrivateJsonText, payloadBase64Text, senderPublicJsonText, recipientPassphrase = '', opts = {}) {
    const recipient = await loadPrivateKey(recipientPrivateJsonText, recipientPassphrase, opts.onProgress);

    let envelope;
    try {
        envelope = JSON.parse(decodeText(base64ToUint8Array(payloadBase64Text)));
    } catch (e) {
        if (e.message.includes('base64')) throw e;
        throw new Error('Ciphertext tidak valid — bukan payload Q-EKH yang utuh.');
    }
    if (!envelope || typeof envelope !== 'object') throw new Error('Payload tidak valid.');
    const isV5 = envelope.version === 'QEKH-v5';
    const isLegacyV4 = envelope.version === 'QEKH-v4';
    const isLegacyV3 = envelope.version === 'QEKH-v3';
    if (!isV5 && !isLegacyV4 && !isLegacyV3) {
        throw new Error(`Versi payload tidak dikenal ("${envelope.version || '?'}"). Dibutuhkan ${PROTOCOL_VERSION}, v4, atau v3 lama.`);
    }
    for (const field of ['ephemeralX25519', 'kyberCiphertext', 'salt', 'iv', 'ciphertext']) {
        if (typeof envelope[field] !== 'string') {
            throw new Error(`Field "${field}" hilang dari payload.`);
        }
    }

    const ephemeralPkRaw = base64ToUint8Array(envelope.ephemeralX25519, BYTE_LENGTHS.x25519Public, 'ephemeralX25519');
    const kyberCipherText = base64ToUint8Array(envelope.kyberCiphertext, BYTE_LENGTHS.mlkemCiphertext, 'kyberCiphertext');
    const salt = base64ToUint8Array(envelope.salt, BYTE_LENGTHS.salt, 'salt');
    const iv = base64ToUint8Array(envelope.iv, BYTE_LENGTHS.iv, 'iv');
    const ciphertext = base64ToUint8Array(envelope.ciphertext, undefined, 'ciphertext');
    if (ciphertext.length < 17 || ciphertext.length > MAX_ENVELOPE_BYTES) throw new Error('Panjang ciphertext tidak valid.');

    // Untuk v3/v4 tanda tangan ada di luar envelope, jadi bisa diverifikasi
    // sebelum pesan dibuka. Untuk v5 tanda tangan tersegel di dalam — diverifikasi
    // setelah dekripsi (integritas ciphertext sendiri sudah dijamin AES-GCM).
    let sender = null;
    if (senderPublicJsonText && senderPublicJsonText.trim()) {
        sender = loadPublicKey(senderPublicJsonText);
    }
    let legacyVerification = null;
    if (!isV5 && sender) {
        const signablePayload = buildLegacySignablePayload(envelope.version, ephemeralPkRaw, kyberCipherText, salt, iv, ciphertext);
        const { ed25519Ok, slhdsaOk } = await verifyLegacySignatures(envelope, sender, signablePayload);
        legacyVerification = {
            status: (ed25519Ok && slhdsaOk) ? 'verified' : 'failed',
            ed25519: ed25519Ok,
            slhdsa: slhdsaOk,
            senderFingerprint: await fingerprintOfPublicFields(sender),
        };
    }

    // Hash identitas penerima (dibutuhkan KDF v5); kunci privat v3 tidak memuatnya
    let hRecipient = null;
    let ownFingerprint = null;
    if (isV5) {
        if (!recipient.public || typeof recipient.public !== 'object') {
            throw new Error('Pesan v5 ini membutuhkan Kunci Privat format baru (yang memuat bagian publik). Buat pasangan kunci baru di tab 1, lalu bagikan ulang Kunci Publiknya ke lawan bicara Anda.');
        }
        hRecipient = await identityHashOfPublicFields(recipient.public);
        ownFingerprint = await fingerprintOfPublicFields(recipient.public);
    }

    // Bangun ulang rahasia gabungan lalu buka AES-GCM
    const x25519Sk = await subtleCrypto.importKey(
        'pkcs8', base64ToUint8Array(recipient.x25519), { name: 'X25519' }, false, ['deriveBits']
    );
    const ephemeralPub = await subtleCrypto.importKey(
        'raw', ephemeralPkRaw, { name: 'X25519' }, false, []
    );
    const x25519Shared = new Uint8Array(await subtleCrypto.deriveBits(
        { name: 'X25519', public: ephemeralPub }, x25519Sk, 256
    ));
    const kyberShared = ml_kem768.decapsulate(kyberCipherText, base64ToUint8Array(recipient.mlkem));

    const combined = concatBytes(kyberShared, x25519Shared);
    kyberShared.fill(0);
    x25519Shared.fill(0);
    const hkdfInfo = isLegacyV3
        ? LEGACY_HKDF_INFO
        : isLegacyV4
            ? concatBytes(V4_HKDF_INFO, ephemeralPkRaw, kyberCipherText)
            : concatBytes(HKDF_INFO, await hashBytes(ephemeralPkRaw, kyberCipherText), hRecipient);
    const aesKey = await deriveEncryptionKey(combined, salt, hkdfInfo);

    let plaintextBytes;
    try {
        const aad = isV5 ? await hashBytes(AAD_DOMAIN, ephemeralPkRaw, kyberCipherText, salt) : null;
        plaintextBytes = await decryptMessage(aesKey, iv, ciphertext, aad);
    } catch {
        throw new Error('Dekripsi gagal — Kunci Privat tidak cocok dengan pesan ini, atau ciphertext sudah diubah/rusak.');
    }
    const rawPlaintext = decodeText(plaintextBytes);

    // --- Jalur lama v3/v4 ---
    if (!isV5) {
        let meta = null;
        let plaintext = rawPlaintext;
        if (isLegacyV4) {
            try {
                const pkg = JSON.parse(rawPlaintext);
                if (pkg && typeof pkg.body === 'string') {
                    plaintext = pkg.body;
                    meta = {
                        from: typeof pkg.from === 'string' ? pkg.from : null,
                        at: typeof pkg.at === 'string' ? pkg.at : null,
                    };
                }
            } catch { /* paket tidak terbaca — tampilkan mentah */ }
        }
        const verification = sender ? legacyVerification : { status: 'unverified' };
        return { plaintext, verification, meta };
    }

    // --- Jalur v5: paket tersegel berisi tanda tangan ---
    let pkg;
    try {
        pkg = JSON.parse(rawPlaintext);
    } catch {
        throw new Error('Paket pesan rusak setelah didekripsi.');
    }
    if (!pkg || typeof pkg.body !== 'string' || !pkg.sig || typeof pkg.sig !== 'object') {
        throw new Error('Struktur paket pesan v5 tidak valid.');
    }
    if (typeof pkg.from !== 'string' || typeof pkg.to !== 'string' || typeof pkg.at !== 'string') {
        throw new Error('Metadata paket pesan v5 tidak lengkap.');
    }
    const coreBytes = encodeText(JSON.stringify({ from: pkg.from, to: pkg.to, at: pkg.at, body: pkg.body }));

    const meta = {
        from: pkg.from,
        at: pkg.at,
        toMismatch: pkg.to !== ownFingerprint,
    };

    let verification;
    if (sender) {
        const hSender = await identityHashOfPublicFields(sender);
        const signablePayload = buildSignablePayloadV5(ephemeralPkRaw, kyberCipherText, salt, iv, hSender, hRecipient, coreBytes);

        let ed25519Ok = false;
        try {
            const sigBytes = base64ToUint8Array(pkg.sig.ed25519, BYTE_LENGTHS.ed25519Signature, 'sig.ed25519');
            const ed25519Pk = await subtleCrypto.importKey(
                'raw', base64ToUint8Array(sender.ed25519), { name: 'Ed25519' }, false, ['verify']
            );
            ed25519Ok = await subtleCrypto.verify({ name: 'Ed25519' }, ed25519Pk, sigBytes, signablePayload);
        } catch { ed25519Ok = false; }

        let slhdsaOk = false;
        try {
            slhdsaOk = slh_dsa_sha2_192s.verify(
                base64ToUint8Array(pkg.sig.slhdsa, BYTE_LENGTHS.slhdsaSignature, 'sig.slhdsa'), signablePayload,
                base64ToUint8Array(sender.slhdsa)
            );
        } catch { slhdsaOk = false; }

        verification = {
            status: (ed25519Ok && slhdsaOk) ? 'verified' : 'failed',
            ed25519: ed25519Ok,
            slhdsa: slhdsaOk,
            senderFingerprint: await fingerprintOfPublicFields(sender),
        };
    } else {
        verification = { status: 'unverified' };
    }

    return { plaintext: pkg.body, verification, meta };
}

// --- Fingerprint dari JSON Kunci Publik (untuk pencocokan anti-MITM) ---
export async function fingerprintFromPublicJson(publicJsonText) {
    return await fingerprintOfPublicFields(loadPublicKey(publicJsonText));
}

// ===================================================================
//              ENKRIPSI FILE CHUNKED — .qekhf (D.1)
// ===================================================================
// Konstruksi STREAM ala miscreant: kunci file acak 32 byte disegel sebagai
// "pesan" v5 biasa ke penerima (jadi autentikasi pengirim ikut serta),
// lalu isi file dipotong per 64 KiB dan tiap potongan di-AES-256-GCM dengan
// nonce = prefix acak 7B || counter u32 BE || flagLAST 1B. Satu chunk rusak/
// terpotong = gagal total — tidak ada plaintext parsial yang diam-diam lolos.
//
// Layout biner kontainer:
//   magic "QEKHF1" (6B) | headerLen u32 LE | headerJSON
//   | [ chunkLen u32 LE | chunkCiphertext (pt + tag 16B) ] x N
// headerJSON: { version, name, size, chunk, prefix(b64 7B), sealed(b64 env v5) }
// AAD tiap chunk = SHA-256("QEKH-FILE-v1-AAD" || headerJSON bytes).

function u32le(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return b;
}

function chunkNonce(prefix, counter, isLast) {
    const nonce = new Uint8Array(12);
    nonce.set(prefix, 0);
    new DataView(nonce.buffer).setUint32(7, counter, false); // big-endian
    nonce[11] = isLast ? 1 : 0;
    return nonce;
}

function sanitizeFileName(name) {
    const clean = String(name || '').replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').trim();
    return clean || 'file';
}

export async function encryptFileHybrid(recipientPublicJsonText, senderPrivateJsonText, fileBytes, fileName, senderPassphrase = '', opts = {}) {
    const data = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes);
    if (data.length > MAX_FILE_BYTES) {
        throw new Error(`File terlalu besar (${(data.length / 1048576).toFixed(1)} MB) — batas ${MAX_FILE_BYTES / 1048576} MB.`);
    }
    const name = sanitizeFileName(fileName).slice(0, 200);

    // Segel kunci file sebagai pesan v5 -> envelope membawa tanda tangan ganda
    const fileKey = getRandomBytes(32);
    const sealed = await encryptHybrid(recipientPublicJsonText, senderPrivateJsonText, arrayBufferToBase64(fileKey), senderPassphrase, opts.passphraseProgress ? { onProgress: opts.passphraseProgress } : {});
    const aesKey = await subtleCrypto.importKey('raw', fileKey, { name: 'AES-GCM' }, false, ['encrypt']);
    fileKey.fill(0);

    const prefix = getRandomBytes(7);
    const headerJson = JSON.stringify({
        version: FILE_VERSION,
        name,
        size: data.length,
        chunk: FILE_CHUNK,
        prefix: arrayBufferToBase64(prefix),
        sealed,
    });
    const headerBytes = encodeText(headerJson);
    const aad = await hashBytes(FILE_AAD_DOMAIN, headerBytes);

    const chunkCount = Math.max(1, Math.ceil(data.length / FILE_CHUNK));
    const parts = [FILE_MAGIC, u32le(headerBytes.length), headerBytes];
    for (let i = 0; i < chunkCount; i++) {
        const slice = data.subarray(i * FILE_CHUNK, Math.min((i + 1) * FILE_CHUNK, data.length));
        const ct = await encryptMessage(aesKey, slice, chunkNonce(prefix, i, i === chunkCount - 1), aad);
        parts.push(u32le(ct.length), ct);
        if (opts.onProgress) opts.onProgress((i + 1) / chunkCount);
    }
    return { container: concatBytes(...parts), fileName: name + '.qekhf', chunkCount };
}

export async function decryptFileHybrid(recipientPrivateJsonText, containerBytes, senderPublicJsonText, recipientPassphrase = '', opts = {}) {
    const buf = containerBytes instanceof Uint8Array ? containerBytes : new Uint8Array(containerBytes);
    if (buf.length < FILE_MAGIC.length + 4) throw new Error('File terlalu kecil — bukan kontainer .qekhf yang valid.');
    if (!constantTimeEqual(buf.slice(0, 6), FILE_MAGIC)) throw new Error('Magic tidak cocok — bukan file .qekhf.');
    const headerLen = new DataView(buf.buffer, buf.byteOffset + 6, 4).getUint32(0, true);
    if (headerLen < 2 || headerLen > MAX_FILE_HEADER_BYTES || 10 + headerLen > buf.length) {
        throw new Error('Panjang header tidak valid — file rusak atau terpotong.');
    }
    const headerBytes = buf.slice(10, 10 + headerLen);
    let header;
    try {
        header = JSON.parse(decodeText(headerBytes));
    } catch {
        throw new Error('Header .qekhf rusak — bukan JSON yang utuh.');
    }
    if (!header || header.version !== FILE_VERSION) {
        throw new Error(`Versi file tidak dikenal ("${header && header.version || '?'}"). Dibutuhkan ${FILE_VERSION}.`);
    }
    if (typeof header.name !== 'string' || !Number.isSafeInteger(header.size) || header.size < 0 || header.size > MAX_FILE_BYTES
        || header.chunk !== FILE_CHUNK || typeof header.sealed !== 'string') {
        throw new Error('Field header .qekhf tidak valid.');
    }
    const prefix = base64ToUint8Array(header.prefix, 7, 'prefix');

    // Buka segel kunci file — verifikasi tanda tangan pengirim ikut terbawa
    const opened = await decryptHybrid(recipientPrivateJsonText, header.sealed, senderPublicJsonText, recipientPassphrase, opts.passphraseProgress ? { onProgress: opts.passphraseProgress } : {});
    const fileKey = base64ToUint8Array(opened.plaintext.trim(), 32, 'kunci file');
    const aesKey = await subtleCrypto.importKey('raw', fileKey, { name: 'AES-GCM' }, false, ['decrypt']);
    fileKey.fill(0);
    const aad = await hashBytes(FILE_AAD_DOMAIN, headerBytes);

    const plainParts = [];
    let offset = 10 + headerLen;
    let counter = 0;
    let totalPlain = 0;
    let sawLast = false;
    while (offset < buf.length) {
        if (sawLast) throw new Error('Ada data setelah chunk terakhir — struktur .qekhf rusak.');
        if (offset + 4 > buf.length) throw new Error('Chunk terpotong — file tidak utuh.');
        const chunkLen = new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, true);
        if (chunkLen < 16 || chunkLen > FILE_CHUNK + 16) throw new Error('Panjang chunk tidak valid — file rusak.');
        offset += 4;
        if (offset + chunkLen > buf.length) throw new Error('Chunk terpotong — file tidak utuh.');
        const ct = buf.slice(offset, offset + chunkLen);
        offset += chunkLen;
        const isLast = offset === buf.length;
        let plain;
        try {
            plain = new Uint8Array(await decryptMessage(aesKey, chunkNonce(prefix, counter, isLast), ct, aad));
        } catch {
            throw new Error(`Chunk #${counter + 1} gagal diautentikasi — file sudah diubah, rusak, atau kunci tidak cocok. Tidak ada plaintext yang dikeluarkan.`);
        }
        plainParts.push(plain);
        totalPlain += plain.length;
        if (totalPlain > MAX_FILE_BYTES) throw new Error('Ukuran plaintext melewati batas — file tidak valid.');
        sawLast = isLast;
        counter++;
        if (opts.onProgress) opts.onProgress(counter / Math.max(1, Math.ceil(header.size / FILE_CHUNK)));
    }
    if (counter === 0) throw new Error('Kontainer tidak memuat chunk apa pun.');
    if (totalPlain !== header.size) {
        throw new Error(`Ukuran plaintext tidak cocok dengan header (${totalPlain} != ${header.size}) — file rusak.`);
    }
    return {
        name: sanitizeFileName(header.name),
        data: concatBytes(...plainParts),
        chunkCount: counter,
        verification: opened.verification,
        meta: opened.meta,
    };
}

// ===================================================================
//        VISUAL FINGERPRINT (randomart identicon 9x9 simetris) (A.4)
// ===================================================================
// Manusia buruk membandingkan 64 karakter hex — membandingkan GAMBAR jauh
// lebih cepat & andal (lihat randomart SSH / safety numbers Signal).
// Fungsi murni: fingerprint hex -> { cells: 81 sel (9x9, mirror kiri-kanan),
// hue } — pemanggil bebas merender ke canvas/SVG. Nol dependensi.
export function fingerprintArt(fingerprintHex) {
    const bytes = hexToBytes(String(fingerprintHex).replace(/\s+/g, ''));
    if (bytes.length < 8) throw new Error('Fingerprint terlalu pendek untuk sidik visual.');
    const cells = new Uint8Array(81); // 9 baris x 9 kolom
    // 45 sel kiri (5 kolom x 9 baris) diisi dari 45 bit pertama hash,
    // lalu dicerminkan ke kanan -> pola simetris khas identicon.
    for (let i = 0; i < 45; i++) {
        const bit = (bytes[i >> 3] >> (i & 7)) & 1;
        const r = Math.floor(i / 5);
        const c = i % 5;
        cells[r * 9 + c] = bit;
        cells[r * 9 + (8 - c)] = bit;
    }
    const hue = ((bytes[6] << 8) | bytes[7]) % 360;
    return { cells, hue };
}

// ===================================================================
//        JADWAL FHSS DARI KUNCI BERSAMA (C.4) — murni tampilan
// ===================================================================
// hkdfSha256(kunciBersama, salt=tanggal, info="QEKH-FHSS") -> urutan kanal
// pseudo-acak yang SAMA di kedua pihak. Radio tetap dioperasikan manual;
// tabel hanya menjawab "pukul berapa di kanal mana hari ini".
export async function fhssSchedule(sharedSecretText, dateISO, opts = {}) {
    const slots = opts.slots ?? 48;
    const slotMinutes = opts.slotMinutes ?? 30;
    const channels = opts.channels ?? 16;
    if (!sharedSecretText) throw new Error('Kunci bersama masih kosong.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateISO)) throw new Error('Tanggal harus format YYYY-MM-DD.');
    if (!Number.isSafeInteger(slots) || !Number.isSafeInteger(slotMinutes) || slots < 1 || slotMinutes < 1 || slots * slotMinutes > 1440) {
        throw new Error('Konfigurasi slot tidak valid (slots × menit harus ≤ 1440).');
    }
    if (!Number.isSafeInteger(channels) || channels < 2 || channels > 256) {
        throw new Error('Jumlah kanal harus 2–256.');
    }
    const okm = await hkdfSha256(encodeText(sharedSecretText), encodeText(dateISO), encodeText('QEKH-FHSS'), slots);
    const out = [];
    for (let i = 0; i < slots; i++) {
        const mins = i * slotMinutes;
        out.push({
            slot: i,
            time: `${String(Math.floor(mins / 60)).padStart(2, '0')}:${String(mins % 60).padStart(2, '0')}`,
            channel: okm[i] % channels,
        });
    }
    return out;
}

// ===================================================================
//                  SELF-TEST KRIPTO SAAT STARTUP (A.2)
// ===================================================================
// Menguji setiap primitif terhadap vektor resmi / round-trip SEBELUM UI aktif.
// Kegagalan berarti pustaka vendor atau WebCrypto rusak/termManipulasi — UI
// mengunci semua tombol aksi dan menampilkan peringatan besar.
//
// Vektor yang dipakai:
//   - HKDF-SHA256  : RFC 5869 Test Case 1
//   - AES-256-GCM  : NIST GCM (kunci=0, IV=0, PT=16 byte nol)
//   - Argon2id     : RFC 9106 (dengan secret & personalization)
//   - ML-KEM-768   : keygen -> encapsulate -> decapsulate, rahasia harus sama
//   - SLH-DSA-192s : sign -> verify OK; pesan diubah 1 bit HARUS gagal
//   - X25519       : deriveBits dua arah harus menghasilkan rahasia sama
//   - Ed25519      : sign -> verify OK; tanda tangan diubah 1 bit HARUS gagal

const SELFTEST_VECTORS = Object.freeze({
    hkdf: {
        ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        salt: '000102030405060708090a0b0c',
        info: 'f0f1f2f3f4f5f6f7f8f9',
        length: 42,
        okmHex: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    },
    aesGcm: {
        // kunci 32B nol, IV 12B nol, plaintext 16B nol -> ct || tag
        expectedHex: 'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919',
    },
    argon2: {
        outHex: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
    },
});

async function selfTestStep(name, fn, results) {
    try {
        await fn();
        results.push({ name, ok: true });
    } catch (e) {
        results.push({ name, ok: false, detail: e.message || String(e) });
    }
}

export async function runCryptoSelfTest(onStep) {
    const results = [];
    const step = async (name, fn) => {
        await selfTestStep(name, fn, results);
        if (onStep) onStep(results[results.length - 1]);
    };

    await step('HKDF-SHA256 (RFC 5869)', async () => {
        const v = SELFTEST_VECTORS.hkdf;
        const okm = await hkdfSha256(hexToBytes(v.ikm), hexToBytes(v.salt), hexToBytes(v.info), v.length);
        if (bytesToHex(okm) !== v.okmHex) throw new Error('Output HKDF tidak cocok dengan vektor RFC 5869.');
    });

    await step('AES-256-GCM (vektor NIST)', async () => {
        const key = await subtleCrypto.importKey('raw', new Uint8Array(32), { name: 'AES-GCM' }, false, ['encrypt']);
        const out = await encryptMessage(key, new Uint8Array(16), new Uint8Array(12), null);
        if (bytesToHex(out) !== SELFTEST_VECTORS.aesGcm.expectedHex) {
            throw new Error('Output AES-GCM tidak cocok dengan vektor NIST.');
        }
    });

    await step('Argon2id (RFC 9106)', async () => {
        const out = argon2id(
            new Uint8Array(32).fill(1), new Uint8Array(16).fill(2),
            { t: 3, m: 32, p: 4, dkLen: 32, key: new Uint8Array(8).fill(3), personalization: new Uint8Array(12).fill(4) }
        );
        if (bytesToHex(out) !== SELFTEST_VECTORS.argon2.outHex) {
            throw new Error('Output Argon2id tidak cocok dengan vektor RFC 9106.');
        }
    });

    await step('ML-KEM-768 (round-trip)', async () => {
        const keys = ml_kem768.keygen();
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(keys.publicKey);
        const back = ml_kem768.decapsulate(cipherText, keys.secretKey);
        if (!constantTimeEqual(sharedSecret, back)) throw new Error('Rahasia bersama ML-KEM tidak sama.');
    });

    await step('SLH-DSA-192s (sign/verify + tamper)', async () => {
        const keys = slh_dsa_sha2_192s.keygen();
        const msg = encodeText('qekh-selftest');
        const sig = slh_dsa_sha2_192s.sign(msg, keys.secretKey);
        if (!slh_dsa_sha2_192s.verify(sig, msg, keys.publicKey)) throw new Error('Verifikasi SLH-DSA gagal untuk tanda tangan valid.');
        const tampered = new Uint8Array(msg);
        tampered[0] ^= 1;
        if (slh_dsa_sha2_192s.verify(sig, tampered, keys.publicKey)) throw new Error('SLH-DSA menerima pesan yang diubah!');
    });

    await step('X25519 (ECDH dua arah)', async () => {
        const a = await generateX25519Keys();
        const b = await generateX25519Keys();
        const ab = new Uint8Array(await subtleCrypto.deriveBits({ name: 'X25519', public: b.publicKey }, a.privateKey, 256));
        const ba = new Uint8Array(await subtleCrypto.deriveBits({ name: 'X25519', public: a.publicKey }, b.privateKey, 256));
        if (!constantTimeEqual(ab, ba)) throw new Error('Rahasia X25519 dua arah tidak sama.');
    });

    await step('Ed25519 (sign/verify + tamper)', async () => {
        const keys = await generateEd25519Keys();
        const msg = encodeText('qekh-selftest');
        const sig = new Uint8Array(await subtleCrypto.sign({ name: 'Ed25519' }, keys.privateKey, msg));
        if (!await subtleCrypto.verify({ name: 'Ed25519' }, keys.publicKey, sig, msg)) {
            throw new Error('Verifikasi Ed25519 gagal untuk tanda tangan valid.');
        }
        const badSig = new Uint8Array(sig);
        badSig[0] ^= 1;
        if (await subtleCrypto.verify({ name: 'Ed25519' }, keys.publicKey, badSig, msg)) {
            throw new Error('Ed25519 menerima tanda tangan yang diubah!');
        }
    });

    const ok = results.every(r => r.ok);
    return { ok, results };
}
