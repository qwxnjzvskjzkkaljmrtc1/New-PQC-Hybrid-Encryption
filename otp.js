// OTP-v2 — One-Time Pad terautentikasi dengan Buku Pad (rekomendasi B.1–B.4).
//
// OTP murni (XOR + pad acak) sudah sempurna secara teori informasi, tapi punya
// tiga kelemahan praktis: (1) bit-flip ciphertext tidak terdeteksi, (2) pad yang
// terpakai ulang menghancurkan keamanan, (3) distribusi pad tidak terkelola.
// Modul ini menutup ketiganya:
//
//   B.1 Autentikasi  : setiap paket membawa tag HMAC-SHA256 (32 byte) yang kunci
//                      MAC-nya diambil dari SEGMEN BUKU PAD TERPISAH (dialokasikan
//                      dari ujung belakang buku, sedangkan pad enkripsi dari
//                      depan — dua segmen tidak pernah beririsan). Verifikasi
//                      selalu dilakukan SEBELUM plaintext ditampilkan
//                      (verify-then-decrypt). Jujur: autentikasi ini kuat
//                      "setara AES" (komputasional), bukan information-theoretic.
//   B.2 Buku Pad     : file .qpad berisi byte acak CSPRNG yang dipegang IDENTIK
//                      oleh kedua pihak (ditukar sekali secara aman/tatap muka).
//                      Format: magic "QPAD1" | bookId 16B | ukuran u32 LE |
//                      checksum SHA-256 32B | data.
//   B.3 Anti reuse   : registry per bookId (localStorage di browser; adapter
//                      lain di Node/tes) mencatat kursor alokasi + hash tiap
//                      segmen terkirim/terverifikasi. Enkripsi menolak saat
//                      buku habis; paket masuk dengan offset yang sama tapi isi
//                      berbeda memicu peringatan PAD TERDETEKSI DIPAKAI ULANG.
//   B.4 Radio        : paket & buku kecil bisa diekspor sebagai grup 5 huruf
//                      kapital base32 (lihat crypto.js), bisa dibacakan via
//                      voice/CW.
//
// Format paket (JSON -> base64):
//   { v:"OTP-v2", padId:<b64 16B bookId>, off:<offset pad enkripsi>,
//     moff:<offset kunci MAC>, ct:<b64>, tag:<b64 32B> }
// Tag = HMAC-SHA256(kunci=buku[moff..moff+32],
//                   data="QEKH-OTP-v2" || padId || u64le(off) || u64le(moff) || ct)

import {
    arrayBufferToBase64, base64ToUint8Array, concatBytes, constantTimeEqual,
    encodeText, decodeText, getRandomBytes, hashBytes, hmacSha256,
    bytesToHex, hexToBytes, toLetterGroups, fromLetterGroups,
} from './crypto.js';

const PADBOOK_MAGIC = 'QPAD1';
const OTP_VERSION = 'OTP-v2';
const MAC_DOMAIN = encodeText('QEKH-OTP-v2');
const MAC_KEY_LEN = 32;
const BOOK_ID_LEN = 16;
const BOOK_HEADER_LEN = 5 + BOOK_ID_LEN + 4 + 32; // magic | bookId | ukuran | checksum
const DEFAULT_BOOK_SIZE = 1024 * 1024; // 1 MiB
const MIN_BOOK_SIZE = 4096;
const MAX_BOOK_SIZE = 64 * 1024 * 1024;
const REGISTRY_PREFIX = 'qekh.padbook.v1.';

// --- Penyimpanan registry: localStorage di browser, memori di Node/tes ---
export function createMemoryStorage() {
    const map = new Map();
    return {
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => { map.set(k, String(v)); },
        removeItem: (k) => { map.delete(k); },
    };
}

function defaultStorage() {
    try {
        if (typeof localStorage !== 'undefined') return localStorage;
    } catch { /* akses localStorage bisa ditolak (mode privat ketat) */ }
    return createMemoryStorage();
}

// ===================================================================
//                         BUKU PAD (.qpad)
// ===================================================================

export function generatePadBook(sizeBytes = DEFAULT_BOOK_SIZE) {
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < MIN_BOOK_SIZE || sizeBytes > MAX_BOOK_SIZE) {
        throw new Error(`Ukuran buku pad harus antara ${MIN_BOOK_SIZE} dan ${MAX_BOOK_SIZE} byte.`);
    }
    const data = new Uint8Array(sizeBytes);
    const CHUNK = 65536; // batas getRandomValues per panggilan
    for (let i = 0; i < sizeBytes; i += CHUNK) {
        data.set(getRandomBytes(Math.min(CHUNK, sizeBytes - i)), i);
    }
    return { bookId: getRandomBytes(BOOK_ID_LEN), data, createdAt: new Date().toISOString() };
}

export async function serializePadBook(book) {
    const sizeField = new Uint8Array(4);
    new DataView(sizeField.buffer).setUint32(0, book.data.length, true);
    const checksum = await hashBytes(book.data);
    return concatBytes(encodeText(PADBOOK_MAGIC), book.bookId, sizeField, checksum, book.data);
}

export async function parsePadBook(bytes) {
    const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (buf.length < BOOK_HEADER_LEN + 1) throw new Error('File terlalu kecil — bukan buku pad .qpad yang valid.');
    if (decodeText(buf.slice(0, 5)) !== PADBOOK_MAGIC) throw new Error('Magic tidak cocok — bukan file .qpad.');
    const bookId = buf.slice(5, 5 + BOOK_ID_LEN);
    const size = new DataView(buf.buffer, buf.byteOffset + 5 + BOOK_ID_LEN, 4).getUint32(0, true);
    const checksum = buf.slice(5 + BOOK_ID_LEN + 4, BOOK_HEADER_LEN);
    const data = buf.slice(BOOK_HEADER_LEN);
    if (data.length !== size) throw new Error(`Ukuran data tidak cocok dengan header (${data.length} != ${size}) — file rusak atau terpotong.`);
    const actual = await hashBytes(data);
    if (!constantTimeEqual(actual, checksum)) throw new Error('Checksum SHA-256 buku pad tidak cocok — file rusak atau sudah diubah.');
    return { bookId, data, createdAt: null };
}

export const bookIdHex = (book) => bytesToHex(book.bookId);
export const bookIdShort = (book) => bytesToHex(book.bookId).slice(0, 8).toUpperCase();

// Ekspor/impor buku pad sebagai grup huruf (hanya masuk akal untuk buku kecil).
export async function padBookToLetterGroups(book) {
    return toLetterGroups(await serializePadBook(book));
}

export async function padBookFromLetterGroups(text) {
    return await parsePadBook(fromLetterGroups(text));
}

// ===================================================================
//                      REGISTRY ANTI-PEMAKAIAN-ULANG
// ===================================================================
// Struktur per bookId:
//   { front: <kursor alokasi enkripsi dari depan>,
//     back:  <kursor alokasi kunci MAC dari belakang>,
//     segments: [ { off, len, moff, dir:"out"|"in", hash:<b64 sha256 ct+tag>, at } ],
//     destroyed: [ { off, len } ] }
// Kursor disimpan supaya buku yang dimuat ulang di sesi baru TIDAK pernah
// memakai ulang byte yang sama.

function loadRegistry(storage, bookIdHexStr) {
    const raw = storage.getItem(REGISTRY_PREFIX + bookIdHexStr);
    if (!raw) return null;
    try {
        const reg = JSON.parse(raw);
        if (!reg || !Number.isSafeInteger(reg.front) || !Number.isSafeInteger(reg.back) || !Array.isArray(reg.segments)) return null;
        if (!Array.isArray(reg.destroyed)) reg.destroyed = [];
        return reg;
    } catch {
        return null;
    }
}

function saveRegistry(storage, bookIdHexStr, reg) {
    storage.setItem(REGISTRY_PREFIX + bookIdHexStr, JSON.stringify(reg));
}

function registryFor(storage, book) {
    const id = bookIdHex(book);
    let reg = loadRegistry(storage, id);
    if (!reg) {
        reg = { front: 0, back: book.data.length, segments: [], destroyed: [] };
        saveRegistry(storage, id, reg);
    }
    // Kursor tak boleh mundur melewati data (buku korup/dipotong).
    reg.front = Math.min(Math.max(0, reg.front), book.data.length);
    reg.back = Math.min(Math.max(0, reg.back), book.data.length);
    return reg;
}

async function packetHash(ct, tag) {
    return arrayBufferToBase64(await hashBytes(ct, tag));
}

const rangesOverlap = (aOff, aLen, bOff, bLen) => aOff < bOff + bLen && bOff < aOff + aLen;

// ===================================================================
//                     PAKET OTP TERAUTENTIKASI (B.1)
// ===================================================================

function u64le(n) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
    return b;
}

async function computeTag(macKey, padId, off, moff, ct) {
    return await hmacSha256(macKey, concatBytes(MAC_DOMAIN, padId, u64le(off), u64le(moff), ct));
}

// Kirim pesan: alokasikan pad enkripsi dari depan buku + kunci MAC dari
// belakang, XOR, tag, catat di registry. MENOLAK saat buku tidak cukup.
export async function otpSend(book, plaintext, storage = defaultStorage()) {
    const msgBytes = encodeText(plaintext);
    if (msgBytes.length === 0) throw new Error('Pesan masih kosong.');
    const reg = registryFor(storage, book);

    const off = reg.front;
    const moff = reg.back - MAC_KEY_LEN;
    if (off + msgBytes.length > moff) {
        throw new Error(`Buku pad HABIS — sisa ${Math.max(0, moff - off)} byte, pesan butuh ${msgBytes.length} byte. Buat & tukar buku pad baru. Segmen terpakai TIDAK pernah dipakai ulang.`);
    }

    const pad = book.data.subarray(off, off + msgBytes.length);
    const ct = new Uint8Array(msgBytes.length);
    for (let i = 0; i < msgBytes.length; i++) ct[i] = msgBytes[i] ^ pad[i];
    const tag = await computeTag(book.data.subarray(moff, moff + MAC_KEY_LEN), book.bookId, off, moff, ct);

    const packet = {
        v: OTP_VERSION,
        padId: arrayBufferToBase64(book.bookId),
        off,
        moff,
        ct: arrayBufferToBase64(ct),
        tag: arrayBufferToBase64(tag),
    };

    // Baru catat setelah paket berhasil dibangun.
    reg.front = off + msgBytes.length;
    reg.back = moff;
    reg.segments.push({ off, len: msgBytes.length, moff, dir: 'out', hash: await packetHash(ct, tag), at: new Date().toISOString() });
    saveRegistry(storage, bookIdHex(book), reg);

    const packetJson = JSON.stringify(packet);
    return {
        packet,
        packetBase64: arrayBufferToBase64(encodeText(packetJson)),
        letterGroups: 'OTPV2\n' + toLetterGroups(encodeText(packetJson)),
        bytesUsed: msgBytes.length + MAC_KEY_LEN,
    };
}

// Terima pesan: cek reuse DULU, verifikasi tag, baru dekripsi.
// Mengembalikan { plaintext, duplicate, reuseDetected }.
export async function otpReceive(book, packetBase64, storage = defaultStorage()) {
    let packet;
    try {
        packet = JSON.parse(decodeText(base64ToUint8Array(packetBase64)));
    } catch (e) {
        if (e.message.includes('base64')) throw e;
        throw new Error('Paket OTP tidak valid — bukan base64 JSON yang utuh.');
    }
    if (!packet || packet.v !== OTP_VERSION) {
        throw new Error(`Versi paket tidak dikenal ("${packet && packet.v || '?'}"). Dibutuhkan ${OTP_VERSION}.`);
    }
    if (!constantTimeEqual(base64ToUint8Array(packet.padId, BOOK_ID_LEN, 'padId'), book.bookId)) {
        throw new Error(`Paket ini untuk buku pad LAIN (padId ${packet.padId.slice(0, 12)}…). Muat buku pad yang cocok dulu.`);
    }
    if (!Number.isSafeInteger(packet.off) || !Number.isSafeInteger(packet.moff) || packet.off < 0 || packet.moff < 0) {
        throw new Error('Offset paket tidak valid.');
    }
    const ct = base64ToUint8Array(packet.ct, undefined, 'ct');
    const tag = base64ToUint8Array(packet.tag, MAC_KEY_LEN, 'tag');
    if (ct.length === 0) throw new Error('Ciphertext paket kosong.');
    if (packet.off + ct.length > book.data.length || packet.moff + MAC_KEY_LEN > book.data.length) {
        throw new Error('Offset paket melewati ukuran buku pad — paket rusak atau bukan untuk buku ini.');
    }
    if (packet.off + ct.length > packet.moff) {
        throw new Error('Segmen enkripsi dan segmen MAC beririsan — paket menyalahi konstruksi OTP-v2.');
    }

    // --- Verify-then-decrypt: tag diverifikasi SEBELUM registry dipercaya
    // maupun plaintext dibuka. Paket tak terautentikasi tidak berhak memicu
    // apa pun (siapa pun bisa mengirim sampah dengan offset sembarang). ---
    const expectedTag = await computeTag(book.data.subarray(packet.moff, packet.moff + MAC_KEY_LEN), book.bookId, packet.off, packet.moff, ct);
    if (!constantTimeEqual(expectedTag, tag)) {
        throw new Error('Tag autentikasi TIDAK COCOK — paket sudah diubah, rusak, atau bukan dari pemegang buku pad. Pesan tidak ditampilkan.');
    }

    // --- Anti pemakaian ulang (B.3): paket sudah terbukti sah, sekarang
    // periksa apakah segmennya pernah dipakai untuk isi yang BERBEDA ---
    const reg = registryFor(storage, book);
    const hash = await packetHash(ct, tag);
    const sameOff = reg.segments.filter(s => s.off === packet.off);
    const duplicate = sameOff.some(s => s.hash === hash);
    const reuseDetected = sameOff.some(s => s.hash !== hash)
        || reg.segments.some(s => s.hash !== hash && rangesOverlap(s.off, s.len, packet.off, ct.length));
    const macOverlap = reg.segments.some(s => s.moff === packet.moff && s.hash !== hash);
    if (macOverlap) {
        throw new Error('PERINGATAN: kunci MAC untuk paket ini sudah pernah dipakai paket lain — buku pad diduga dipakai ulang. Paket DITOLAK.');
    }

    const pad = book.data.subarray(packet.off, packet.off + ct.length);
    const out = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) out[i] = ct[i] ^ pad[i];
    let plaintext;
    try {
        plaintext = new TextDecoder('utf-8', { fatal: true }).decode(out);
    } catch {
        throw new Error('Hasil dekripsi bukan teks UTF-8 yang valid — paket tidak cocok dengan buku pad ini.');
    }

    // Catat penerimaan (duplikat persis tidak mengubah registry).
    if (!duplicate) {
        reg.segments.push({ off: packet.off, len: ct.length, moff: packet.moff, dir: 'in', hash, at: new Date().toISOString() });
        // Pesan masuk yang sah juga "memakai" wilayah tersebut untuk kita:
        // majukan kursor bila paket masuk berada tepat di depan kursor, supaya
        // pesan KELUAR berikutnya tidak menimpa wilayah yang baru dipakai lawan.
        if (packet.off === reg.front) reg.front = packet.off + ct.length;
        if (packet.moff === reg.back - MAC_KEY_LEN) reg.back = packet.moff;
        saveRegistry(storage, bookIdHex(book), reg);
    }

    return { plaintext, duplicate, reuseDetected, at: new Date().toISOString() };
}

// ===================================================================
//                    STATUS & PEMUSNAHAN (B.2/B.3)
// ===================================================================

export function getBookStatus(book, storage = defaultStorage()) {
    const reg = registryFor(storage, book);
    const usedBytes = reg.segments.reduce((sum, s) => sum + s.len + MAC_KEY_LEN, 0);
    const remaining = Math.max(0, reg.back - reg.front);
    return {
        bookId: bookIdHex(book),
        bookIdShort: bookIdShort(book),
        total: book.data.length,
        usedBytes,
        remaining,
        remainingMessagesEstimate: Math.floor(remaining / (140 + MAC_KEY_LEN)), // asumsi pesan ~140 byte
        segmentCount: reg.segments.length,
        percentUsed: book.data.length ? Math.min(100, Math.round((reg.front + (book.data.length - reg.back)) / book.data.length * 100)) : 100,
        exhausted: remaining < MAC_KEY_LEN + 1,
    };
}

// Musnahkan segmen terpakai: zero-fill wilayah yang tercatat di registry.
// Mengembalikan jumlah byte yang dihapus. Setelah ini, paket lama yang
// merujuk segmen termusnahkan tidak akan bisa diverifikasi lagi — itulah
// tujuannya (forward secrecy manual ala OTP).
export function destroyUsedSegments(book, storage = defaultStorage()) {
    const reg = registryFor(storage, book);
    let wiped = 0;
    for (const s of reg.segments) {
        if (!reg.destroyed.some(d => d.off === s.off && d.len === s.len)) {
            book.data.fill(0, s.off, s.off + s.len);
            book.data.fill(0, s.moff, s.moff + MAC_KEY_LEN);
            reg.destroyed.push({ off: s.off, len: s.len }, { off: s.moff, len: MAC_KEY_LEN });
            wiped += s.len + MAC_KEY_LEN;
        }
    }
    saveRegistry(storage, bookIdHex(book), reg);
    return wiped;
}

// Hapus seluruh jejak registry untuk bookId (mis. setelah buku dimusnahkan total).
export function forgetBook(book, storage = defaultStorage()) {
    storage.removeItem(REGISTRY_PREFIX + bookIdHex(book));
}
