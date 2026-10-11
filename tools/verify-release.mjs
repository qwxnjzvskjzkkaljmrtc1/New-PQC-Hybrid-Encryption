// tools/verify-release.mjs — verifikasi tanda tangan rilis Q-EKH (E.3).
// Siapa pun bisa memastikan vendor/HASHES.txt benar ditandatangani oleh
// pemegang kunci rilis (Ed25519 DAN SLH-DSA-192s — dua-duanya harus valid).
//
//   node tools/verify-release.mjs
//
// Exit 0 = sah (keduanya valid + hash cocok). Exit 1 = GAGAL.
import { readFileSync } from 'node:fs';
import { slh_dsa_sha2_192s } from '../vendor/noble-post-quantum-0.7.0/slh-dsa.js';
import {
    base64ToUint8Array, encodeText, hashBytes, bytesToHex, concatBytes,
} from '../crypto.js';

const PUB_FILE = new URL(process.env.QEKH_RELEASE_PUB || '../docs/release-pubkey.json', import.meta.url);
const HASHES_FILE = new URL(process.env.QEKH_HASHES || '../vendor/HASHES.txt', import.meta.url);
const SIG_FILE = new URL(process.env.QEKH_SIG_IN || '../vendor/HASHES.txt.qekhsig', import.meta.url);
const SIGN_DOMAIN = 'QEKH-RELEASE-v1';

function fail(msg) {
    console.error('❌ VERIFIKASI GAGAL:', msg);
    process.exit(1);
}

let pub, sig, fileBytes;
try {
    pub = JSON.parse(readFileSync(PUB_FILE, 'utf8'));
} catch {
    fail(`kunci publik rilis tidak ditemukan (${PUB_FILE.pathname}) — maintainer menjalankan "sign-release.mjs init" dulu.`);
}
try {
    sig = JSON.parse(readFileSync(SIG_FILE, 'utf8'));
} catch {
    fail(`file tanda tangan tidak ditemukan (${SIG_FILE.pathname}) — rilis ini belum ditandatangani.`);
}
fileBytes = new Uint8Array(readFileSync(HASHES_FILE));

if (sig.version !== SIGN_DOMAIN || sig.file !== 'HASHES.txt') {
    fail('format tanda tangan tidak dikenal.');
}
const digest = await hashBytes(fileBytes);
if (bytesToHex(digest) !== sig.sha256) {
    fail(`HASHES.txt sudah berubah sejak ditandatangani (${bytesToHex(digest)} != ${sig.sha256}).`);
}
const payload = concatBytes(encodeText(SIGN_DOMAIN), encodeText('\n'), encodeText(sig.file), digest);

const edPk = await globalThis.crypto.subtle.importKey('raw', base64ToUint8Array(pub.ed25519, 32, 'ed25519'), { name: 'Ed25519' }, false, ['verify']);
const edOk = await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, edPk, base64ToUint8Array(sig.sig.ed25519, 64, 'sig.ed25519'), payload);
const slhOk = slh_dsa_sha2_192s.verify(base64ToUint8Array(sig.sig.slhdsa, 16224, 'sig.slhdsa'), payload, base64ToUint8Array(pub.slhdsa, 48, 'slhdsa'));

if (!edOk || !slhOk) {
    fail(`tanda tangan TIDAK VALID (Ed25519 ${edOk ? '✓' : '✗'}, SLH-DSA ${slhOk ? '✓' : '✗'}).`);
}
const fp = bytesToHex(await hashBytes(base64ToUint8Array(pub.ed25519), base64ToUint8Array(pub.slhdsa)))
    .toUpperCase().match(/.{1,4}/g).join(' ');
if (sig.signerFingerprint && sig.signerFingerprint !== fp) {
    fail(`fingerprint penandatangan tidak cocok (${sig.signerFingerprint} != ${fp}).`);
}
console.log('✅ Rilis SAH — HASHES.txt ditandatangani oleh pemegang kunci rilis.');
console.log('   signer fingerprint :', fp);
console.log('   sha256 HASHES.txt  :', sig.sha256);
console.log('   ditandatangani pada:', sig.at);
