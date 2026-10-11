// tools/gen-test-vectors.mjs — bangun docs/test-vectors.json (butir E.1).
// Vektor deterministik: kunci & seed tetap -> output harus selalu sama.
// Tujuannya dua: (1) tes otomatis mendeteksi drift pustaka vendor,
// (2) bahan verifikasi bagi implementasi ulang (lihat docs/SPEC.md).
//
// Jalankan:  node tools/gen-test-vectors.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { ml_kem768 } from '../vendor/noble-post-quantum-0.7.0/ml-kem.js';
import { slh_dsa_sha2_192s } from '../vendor/noble-post-quantum-0.7.0/slh-dsa.js';
import {
    hkdfSha256, hexToBytes, bytesToHex, arrayBufferToBase64,
    encodeText, decodeText, toLetterGroups, fingerprintFromPublicJson,
    hashBytes,
} from '../crypto.js';
import { otpSend, serializePadBook, createMemoryStorage } from '../otp.js';

const seq = (n, mul = 37, add = 11) => {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (i * mul + add) & 0xff;
    return b;
};

const vectors = {
    meta: {
        generator: 'tools/gen-test-vectors.mjs',
        spec: 'docs/SPEC.md',
        note: 'Semua byte ditulis hex kecuali dinyatakan lain. Vektor ini deterministik — regenerasi harus menghasilkan file identik.',
    },
};

// --- HKDF-SHA256: RFC 5869 Test Case 1 ---
vectors.hkdfSha256 = {
    ikm: '0b'.repeat(22),
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    length: 42,
    okm: bytesToHex(await hkdfSha256(hexToBytes('0b'.repeat(22)), hexToBytes('000102030405060708090a0b0c'), hexToBytes('f0f1f2f3f4f5f6f7f8f9'), 42)),
};

// --- AES-256-GCM: kunci/IV/plaintext nol ---
{
    const key = await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, key, new Uint8Array(16)));
    vectors.aes256gcm = { key: '00'.repeat(32), iv: '00'.repeat(12), pt: '00'.repeat(16), ct: bytesToHex(ct) };
}

// --- Grup huruf base32 (RFC 4648, grup 5) ---
{
    const bytes = seq(26);
    vectors.letterGroups = { bytesHex: bytesToHex(bytes), groups: toLetterGroups(bytes) };
}

// --- Fingerprint identitas: SHA-256(x||k||e||s), hex kapital grup 4 ---
{
    const pub = {
        version: 'QEKH-v5', type: 'public',
        x25519: arrayBufferToBase64(seq(32)),
        mlkem: arrayBufferToBase64(seq(1184)),
        ed25519: arrayBufferToBase64(seq(32, 7, 3)),
        slhdsa: arrayBufferToBase64(seq(48, 13, 5)),
    };
    vectors.fingerprint = {
        publicKeyJson: JSON.stringify(pub),
        fingerprint: await fingerprintFromPublicJson(JSON.stringify(pub)),
    };
}

// --- ML-KEM-768: keygen(seed 64B) + encapsulate(pk, msg 32B) deterministik ---
{
    const seed = seq(64);
    const keys = ml_kem768.keygen(seed);
    const msg = seq(32, 91, 17);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(keys.publicKey, msg);
    vectors.mlkem768 = {
        seed: bytesToHex(seed),
        msg: bytesToHex(msg),
        publicKey: bytesToHex(keys.publicKey),
        secretKeySha256: bytesToHex(await hashBytes(keys.secretKey)),
        cipherText: bytesToHex(cipherText),
        sharedSecret: bytesToHex(sharedSecret),
    };
}

// --- SLH-DSA-SHA2-192s: keygen(seed 72B); sign diverifikasi ---
{
    const seed = seq(72, 53, 7);
    const keys = slh_dsa_sha2_192s.keygen(seed);
    const msg = encodeText('QEKH test vector — pesan tetap untuk SLH-DSA.\n');
    // extraEntropy:false -> opt_rand = PK.seed (varian deterministik FIPS 205),
    // supaya vektor stabil. Produksi tetap memakai default hedged (acak).
    const sig1 = slh_dsa_sha2_192s.sign(msg, keys.secretKey, { extraEntropy: false });
    const sig2 = slh_dsa_sha2_192s.sign(msg, keys.secretKey, { extraEntropy: false });
    const deterministic = constantTimeHex(bytesToHex(sig1), bytesToHex(sig2));
    if (!slh_dsa_sha2_192s.verify(sig1, msg, keys.publicKey)) throw new Error('verify gagal');
    vectors.slhdsa192s = {
        seed: bytesToHex(seed),
        messageUtf8: decodeText(msg),
        publicKey: bytesToHex(keys.publicKey),
        secretKeySha256: bytesToHex(await hashBytes(keys.secretKey)),
        signatureLength: sig1.length,
        signatureSha256: bytesToHex(await hashBytes(sig1)),
        signDeterministic: deterministic,
        signature: deterministic ? bytesToHex(sig1) : null,
    };
}

// --- OTP-v2: buku pad berpola tetap -> paket sepenuhnya deterministik ---
{
    const book = { bookId: seq(16, 3, 41), data: seq(4096), createdAt: null };
    const store = createMemoryStorage();
    const msg = 'TEST VECTOR OTP — jangan dipakai di lapangan.';
    const s = await otpSend(book, msg, store);
    vectors.otpv2 = {
        bookId: bytesToHex(book.bookId),
        bookSize: book.data.length,
        bookDataPattern: 'byte[i] = (i*37+11) & 0xff',
        message: msg,
        packet: s.packet,
        qpadSha256: bytesToHex(await hashBytes(await serializePadBook(book))),
        letterGroups: s.letterGroups,
    };
}

function constantTimeHex(a, b) { return a === b; }

mkdirSync(new URL('../docs/', import.meta.url), { recursive: true });
writeFileSync(new URL('../docs/test-vectors.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n');
console.log('docs/test-vectors.json ditulis.');
console.log('SLH-DSA sign deterministik:', vectors.slhdsa192s.signDeterministic);
