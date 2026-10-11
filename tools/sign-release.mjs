// tools/sign-release.mjs — tandatangani vendor/HASHES.txt dengan identitas
// rilis (Ed25519 + SLH-DSA-192s) memakai konstruksi yang sama dengan
// crypto.js (butir E.3). Hasil: vendor/HASHES.txt.qekhsig (JSON).
//
// Ritual maintainer:
//   node tools/sign-release.mjs init    # sekali: buat kunci rilis
//   node tools/sign-release.mjs sign    # setiap rilis / setelah vendor-update
//
// Kunci privat disimpan di tools/release-key.json (GITIGNORED — jangan
// pernah commit). Kunci publik diterbitkan di docs/release-pubkey.json
// supaya siapa pun bisa memverifikasi lewat tools/verify-release.mjs.
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { slh_dsa_sha2_192s } from '../vendor/noble-post-quantum-0.7.0/slh-dsa.js';
import {
    arrayBufferToBase64, base64ToUint8Array, encodeText,
    hashBytes, bytesToHex, concatBytes,
} from '../crypto.js';

const KEY_FILE = new URL(process.env.QEKH_RELEASE_KEY || '../tools/release-key.json', import.meta.url);
const PUB_FILE = new URL(process.env.QEKH_RELEASE_PUB || '../docs/release-pubkey.json', import.meta.url);
const HASHES_FILE = new URL(process.env.QEKH_HASHES || '../vendor/HASHES.txt', import.meta.url);
const SIG_FILE = new URL(process.env.QEKH_SIG_OUT || '../vendor/HASHES.txt.qekhsig', import.meta.url);
const SIGN_DOMAIN = 'QEKH-RELEASE-v1';

async function fingerprintOf(pub) {
    const h = await hashBytes(
        base64ToUint8Array(pub.ed25519, 32, 'ed25519'),
        base64ToUint8Array(pub.slhdsa, 48, 'slhdsa'));
    return bytesToHex(h).toUpperCase().match(/.{1,4}/g).join(' ');
}

// Payload yang ditandatangani: domain || "\n" || nama file || sha256(file).
async function payloadFor(fileBytes, fileName) {
    const digest = await hashBytes(fileBytes);
    return {
        payload: concatBytes(encodeText(SIGN_DOMAIN), encodeText('\n'), encodeText(fileName), digest),
        digestHex: bytesToHex(digest),
    };
}

async function cmdInit() {
    try {
        readFileSync(KEY_FILE);
        console.error('Kunci rilis sudah ada di', KEY_FILE.pathname, '— hapus manual bila ingin ganti.');
        process.exit(1);
    } catch { /* belum ada — lanjut */ }
    const ed = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const slh = slh_dsa_sha2_192s.keygen();
    const key = {
        version: 'QEKH-RELEASE-KEY-v1',
        type: 'private',
        ed25519: arrayBufferToBase64(new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', ed.privateKey))),
        slhdsa: arrayBufferToBase64(slh.secretKey),
    };
    const pub = {
        version: 'QEKH-RELEASE-KEY-v1',
        type: 'public',
        ed25519: arrayBufferToBase64(new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', ed.publicKey))),
        slhdsa: arrayBufferToBase64(slh.publicKey),
    };
    pub.fingerprint = await fingerprintOf(pub);
    writeFileSync(KEY_FILE, JSON.stringify(key, null, 2) + '\n');
    chmodSync(KEY_FILE, 0o600);
    mkdirSync(new URL('../docs/', import.meta.url), { recursive: true });
    writeFileSync(PUB_FILE, JSON.stringify(pub, null, 2) + '\n');
    console.log('Kunci rilis dibuat.');
    console.log('  privat :', KEY_FILE.pathname, '(mode 600, JANGAN di-commit)');
    console.log('  publik :', PUB_FILE.pathname, '(commit & sebarkan)');
    console.log('  fingerprint:', pub.fingerprint);
}

async function cmdSign() {
    const key = JSON.parse(readFileSync(KEY_FILE, 'utf8'));
    if (key.type !== 'private') throw new Error('File kunci bukan kunci privat rilis.');
    const fileBytes = new Uint8Array(readFileSync(HASHES_FILE));
    const { payload, digestHex } = await payloadFor(fileBytes, 'HASHES.txt');
    const edSk = await globalThis.crypto.subtle.importKey('pkcs8', base64ToUint8Array(key.ed25519), { name: 'Ed25519' }, false, ['sign']);
    const sigEd = new Uint8Array(await globalThis.crypto.subtle.sign({ name: 'Ed25519' }, edSk, payload));
    const sigSlh = slh_dsa_sha2_192s.sign(payload, base64ToUint8Array(key.slhdsa));
    const pub = JSON.parse(readFileSync(PUB_FILE, 'utf8'));
    const sig = {
        version: SIGN_DOMAIN,
        file: 'HASHES.txt',
        sha256: digestHex,
        at: new Date().toISOString(),
        signerFingerprint: await fingerprintOf(pub),
        sig: { ed25519: arrayBufferToBase64(sigEd), slhdsa: arrayBufferToBase64(sigSlh) },
    };
    writeFileSync(SIG_FILE, JSON.stringify(sig, null, 2) + '\n');
    console.log('Ditandatangani ->', SIG_FILE.pathname);
    console.log('  sha256 HASHES.txt:', digestHex);
    console.log('  signer:', sig.signerFingerprint);
}

const cmd = process.argv[2];
if (cmd === 'init') await cmdInit();
else if (cmd === 'sign') await cmdSign();
else {
    console.log('Pemakaian: node tools/sign-release.mjs init|sign');
    process.exit(1);
}
