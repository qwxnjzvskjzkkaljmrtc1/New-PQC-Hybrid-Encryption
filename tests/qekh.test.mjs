// Tes otomatis Q-EKH (F.2) — jalan di Node:  node tests/qekh.test.mjs
// Menguji modul murni crypto.js & otp.js tanpa browser:
//   - self-test vektor resmi (HKDF RFC 5869, AES-GCM NIST, Argon2id RFC 9106)
//   - round-trip v5 (dengan & tanpa passphrase) + fingerprint
//   - tamper test: 1 byte ciphertext diubah -> dekripsi HARUS gagal;
//     kunci pengirim salah -> verifikasi HARUS gagal
//   - uji batas: pesan kosong, base64 rusak, JSON rusak, passphrase salah
//   - OTP-v2: round-trip, tamper tag, buku salah, duplikat, anti-reuse,
//     buku habis, musnahkan segmen, serialisasi .qpad + checksum rusak
//   - grup huruf base32: round-trip + parser toleran
//   - A.4 randomart, C.1 morse/WAV, D.1 file chunked, D.5 bucket konstan
//   - E.1: vektor deterministik docs/test-vectors.json (drift vendor/vendor)
// Catatan: round-trip v3/v4 tidak diuji karena encoder legacy memang tidak
// ada di codebase (dekripsi legacy hanya untuk pesan lama).
import { readFileSync } from 'node:fs';
import { ml_kem768 } from '../vendor/noble-post-quantum-0.7.0/ml-kem.js';
import { slh_dsa_sha2_192s } from '../vendor/noble-post-quantum-0.7.0/slh-dsa.js';
import {
    generateIdentity, encryptHybrid, decryptHybrid, fingerprintFromPublicJson,
    publicKeyInfo, runCryptoSelfTest, hkdfSha256, hexToBytes, bytesToHex,
    toLetterGroups, fromLetterGroups, looksLikeLetterGroups, stripLetterHeader,
    arrayBufferToBase64, base64ToUint8Array, encodeText, decodeText,
    fingerprintArt, constantTimeEqual, encryptFileHybrid, decryptFileHybrid,
    fhssSchedule,
} from '../crypto.js';
import {
    generatePadBook, serializePadBook, parsePadBook, otpSend, otpReceive,
    getBookStatus, destroyUsedSegments, createMemoryStorage,
} from '../otp.js';
import {
    MORSE_TABLE, morseTimeline, timelineMs, renderCwPcm, encodeWavPcm16,
    CW_SAMPLE_RATE,
} from '../cw.js';

let passed = 0;
let failed = 0;

function ok(name, cond) {
    if (cond) { passed++; console.log(`  ok  ${name}`); }
    else { failed++; console.error(`GAGAL ${name}`); }
}

async function throws(name, fn, fragment) {
    try {
        await fn();
        failed++;
        console.error(`GAGAL ${name} — seharusnya melempar error`);
    } catch (e) {
        if (fragment && !String(e.message).includes(fragment)) {
            failed++;
            console.error(`GAGAL ${name} — error tidak mengandung "${fragment}": ${e.message}`);
        } else {
            passed++;
            console.log(`  ok  ${name}`);
        }
    }
}

// --- Helper: ubah 1 byte pada envelope base64 (di dalam field ciphertext) ---
function tamperEnvelopeCiphertext(payloadB64) {
    const env = JSON.parse(decodeText(base64ToUint8Array(payloadB64)));
    const ct = base64ToUint8Array(env.ciphertext);
    ct[0] ^= 1;
    env.ciphertext = arrayBufferToBase64(ct);
    return arrayBufferToBase64(encodeText(JSON.stringify(env)));
}

async function main() {
    console.log('== Self-test vektor resmi ==');
    const st = await runCryptoSelfTest();
    ok('runCryptoSelfTest lolos semua', st.ok);
    ok('self-test mencakup 7 primitif', st.results.length === 7);
    const okm = await hkdfSha256(hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
        hexToBytes('000102030405060708090a0b0c'), hexToBytes('f0f1f2f3f4f5f6f7f8f9'), 42);
    ok('HKDF RFC 5869 case 1', bytesToHex(okm) === '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

    console.log('== Identitas & round-trip v5 ==');
    const alice = await generateIdentity();
    const bob = await generateIdentity();
    ok('fingerprint alice format 16x4 hex', /^([0-9A-F]{4} ){15}[0-9A-F]{4}$/.test(alice.fingerprint));
    ok('fingerprint stabil dari JSON publik', (await fingerprintFromPublicJson(alice.publicKeyJson)) === alice.fingerprint);

    const infoA = await publicKeyInfo(alice.publicKeyJson);
    ok('publicKeyInfo tanpa expires', infoA.fingerprint === alice.fingerprint && infoA.expires === null && !infoA.expired);

    const pesan = 'Pesan rahasia untuk Bob — unit bergerak ke grid 4. 🔐';
    const ct = await encryptHybrid(bob.publicKeyJson, alice.privateKeyJson, pesan);
    const dec = await decryptHybrid(bob.privateKeyJson, ct, alice.publicKeyJson);
    ok('round-trip v5 plaintext sama', dec.plaintext === pesan);
    ok('tanda tangan terverifikasi (ed+slh)', dec.verification.status === 'verified' && dec.verification.ed25519 && dec.verification.slhdsa);
    ok('meta from = fingerprint alice', dec.meta.from === alice.fingerprint);

    const decNoSender = await decryptHybrid(bob.privateKeyJson, ct, '');
    ok('tanpa kunci pengirim: unverified', decNoSender.verification.status === 'unverified' && decNoSender.plaintext === pesan);

    console.log('== Tamper & negative test ==');
    await throws('ciphertext diubah 1 byte -> dekripsi gagal', () => decryptHybrid(bob.privateKeyJson, tamperEnvelopeCiphertext(ct), alice.publicKeyJson));
    const decWrongSender = await decryptHybrid(bob.privateKeyJson, ct, bob.publicKeyJson);
    ok('kunci pengirim salah -> tanda tangan TIDAK VALID', decWrongSender.verification.status === 'failed');
    await throws('penerima salah -> dekripsi gagal', () => decryptHybrid(alice.privateKeyJson, ct, alice.publicKeyJson));
    await throws('pesan kosong ditolak', () => encryptHybrid(bob.publicKeyJson, alice.privateKeyJson, ''), 'kosong');
    await throws('base64 rusak ditolak', () => decryptHybrid(bob.privateKeyJson, '!!!bukan-base64!!!', ''), 'base64');
    await throws('JSON rusak ditolak', () => decryptHybrid(bob.privateKeyJson, arrayBufferToBase64(encodeText('{rusak')), ''), 'Ciphertext');
    await throws('kunci publik rusak ditolak', () => encryptHybrid('{"version":"QEKH-v5"}', alice.privateKeyJson, 'x'), 'tipe');

    console.log('== Bucket ukuran konstan (D.5) ==');
    const ctBucket = await encryptHybrid(bob.publicKeyJson, alice.privateKeyJson, 'pesan bucket 32KB', '', { bucket: 32768 });
    const envBucket = JSON.parse(decodeText(base64ToUint8Array(ctBucket)));
    const ctBucketBytes = base64ToUint8Array(envBucket.ciphertext);
    ok('ciphertext bucket: (panjang - tag 16B) kelipatan 32 KB', (ctBucketBytes.length - 16) % 32768 === 0);
    const decBucket = await decryptHybrid(bob.privateKeyJson, ctBucket, alice.publicKeyJson);
    ok('round-trip bucket tetap benar', decBucket.plaintext === 'pesan bucket 32KB' && decBucket.verification.status === 'verified');
    await throws('pesan melebihi bucket ditolak', () => encryptHybrid(bob.publicKeyJson, alice.privateKeyJson, 'X'.repeat(40000), '', { bucket: 32768 }), 'bucket');

    console.log('== Kunci ber-passphrase (Argon2id 64 MB — agak lambat) ==');
    const cara = await generateIdentity('kunci rahasia 123');
    ok('kunci privat terenkripsi (kdf Argon2id)', cara.privateKeyJson.includes('"kdf": "Argon2id"'));
    const ct2 = await encryptHybrid(bob.publicKeyJson, cara.privateKeyJson, 'halo dari cara', 'kunci rahasia 123');
    const dec2 = await decryptHybrid(bob.privateKeyJson, ct2, cara.publicKeyJson);
    ok('round-trip kunci ber-passphrase', dec2.plaintext === 'halo dari cara' && dec2.verification.status === 'verified');
    await throws('passphrase salah ditolak', () => encryptHybrid(bob.publicKeyJson, cara.privateKeyJson, 'x', 'salah'), 'Passphrase salah');
    await throws('passphrase kosong pada kunci terenkripsi ditolak', () => encryptHybrid(bob.publicKeyJson, cara.privateKeyJson, 'x'), 'terenkripsi');

    console.log('== Grup huruf base32 (B.4/C.1) ==');
    const sample = getSampleBytes(257);
    const groups = toLetterGroups(sample);
    ok('grup 5 huruf format benar', /^([A-Z2-7]{5} )*[A-Z2-7]{1,5}$/.test(groups));
    const back = fromLetterGroups(groups.toLowerCase().replace(/ /g, '  \n')); // toleran huruf kecil & spasi berlebih
    ok('round-trip grup huruf', bytesToHex(back) === bytesToHex(sample));
    ok('stripLetterHeader bekerja', stripLetterHeader('QEKH5 12 GRUP\nAAAAA') === 'AAAAA');
    ok('deteksi grup huruf', looksLikeLetterGroups('QEKH5 2 GRUP\n' + groups) && !looksLikeLetterGroups(arrayBufferToBase64(sample)));
    await throws('karakter non-base32 ditolak', () => fromLetterGroups('AAAA1'), 'alfabet');

    console.log('== Sidik visual randomart (A.4) ==');
    const art1 = fingerprintArt(alice.fingerprint);
    const art2 = fingerprintArt(alice.fingerprint.toLowerCase().replace(/ /g, ''));
    ok('randomart 81 sel (9x9)', art1.cells.length === 81);
    ok('randomart deterministik & toleran format (spasi/huruf kecil)', constantTimeEqual(art1.cells, art2.cells) && art1.hue === art2.hue);
    let simetris = true;
    for (let r = 0; r < 9 && simetris; r++) for (let c = 0; c < 5; c++) {
        if (art1.cells[r * 9 + c] !== art1.cells[r * 9 + (8 - c)]) { simetris = false; break; }
    }
    ok('randomart simetris kiri-kanan', simetris);
    ok('randomart hue dalam 0..359', art1.hue >= 0 && art1.hue < 360);
    const artBob = fingerprintArt(bob.fingerprint);
    ok('fingerprint berbeda -> gambar berbeda', !constantTimeEqual(art1.cells, artBob.cells));
    await throws('fingerprint kependekan ditolak', () => fingerprintArt('AB12'), 'pendek');

    console.log('== CW morse (C.1) ==');
    ok('tabel morse mencakup seluruh alfabet base32 (A-Z, 2-7)',
        Array.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567').every(ch => MORSE_TABLE[ch]));
    const tlE = morseTimeline('E', 60); // unit = 1200/60 = 20 ms
    ok('E @60wpm = satu nada 20 ms', tlE.length === 1 && tlE[0].on && Math.abs(tlE[0].ms - 20) < 1e-9);
    const tlSOS = morseTimeline('SOS', 60); // 5 + 3 + 11 + 3 + 5 = 27 unit
    ok('SOS @60wpm = 540 ms (timing PARIS)', Math.abs(timelineMs(tlSOS) - 540) < 1e-9);
    const tlAB = morseTimeline('A B', 60); // 5 + 7 + 9 = 21 unit
    ok('jeda antar kata = 7 unit', Math.abs(timelineMs(tlAB) - 420) < 1e-9);
    ok('teks tanpa karakter morse -> timeline kosong', morseTimeline('!!!', 60).length === 0);
    const pcm = renderCwPcm('E', 60);
    ok('PCM E ≈ 20 ms', Math.abs(pcm.length - 0.02 * CW_SAMPLE_RATE) <= 1);
    ok('PCM berisi sinyal nada', Math.max(...Array.from(pcm, Math.abs)) > 0.3);
    const pcmGap = renderCwPcm('E E', 60); // nada 20 ms + hening 140 ms + nada 20 ms
    const mid = pcmGap.subarray(Math.round(0.05 * CW_SAMPLE_RATE), Math.round(0.15 * CW_SAMPLE_RATE));
    ok('jeda antar kata benar-benar hening', Math.max(...Array.from(mid, Math.abs)) === 0);
    const wav = encodeWavPcm16(pcm, CW_SAMPLE_RATE);
    ok('WAV header RIFF/WAVE benar', String.fromCharCode(...wav.subarray(0, 4)) === 'RIFF' && String.fromCharCode(...wav.subarray(8, 12)) === 'WAVE');
    ok('WAV panjang = 44 + 2n', wav.length === 44 + pcm.length * 2);

    console.log('== Enkripsi FILE chunked .qekhf (D.1) ==');
    const fileData = getSampleBytes(150 * 1024); // 150 KiB -> 3 chunk
    const fenc = await encryptFileHybrid(bob.publicKeyJson, alice.privateKeyJson, fileData, 'laporan grid-4.txt');
    ok('kontainer .qekhf 3 chunk', fenc.chunkCount === 3 && fenc.fileName === 'laporan grid-4.txt.qekhf');
    ok('magic QEKHF1 di awal', decodeText(fenc.container.slice(0, 6)) === 'QEKHF1');
    const fdec = await decryptFileHybrid(bob.privateKeyJson, fenc.container, alice.publicKeyJson);
    ok('round-trip file: byte identik', bytesToHex(fdec.data) === bytesToHex(fileData));
    ok('round-trip file: nama & tanda tangan', fdec.name === 'laporan grid-4.txt' && fdec.verification.status === 'verified');

    const emptyEnc = await encryptFileHybrid(bob.publicKeyJson, alice.privateKeyJson, new Uint8Array(0), 'kosong.bin');
    const emptyDec = await decryptFileHybrid(bob.privateKeyJson, emptyEnc.container, alice.publicKeyJson);
    ok('file kosong (1 chunk tag saja) round-trip', emptyDec.data.length === 0 && emptyEnc.chunkCount === 1);

    // tamper 1 byte di chunk terakhir -> gagal total
    const badFile = new Uint8Array(fenc.container);
    badFile[badFile.length - 5] ^= 1;
    await throws('chunk file diubah -> dekripsi gagal total', () => decryptFileHybrid(bob.privateKeyJson, badFile, alice.publicKeyJson), 'gagal diautentikasi');
    const truncFile = fenc.container.slice(0, fenc.container.length - 10);
    await throws('file terpotong -> ditolak', () => decryptFileHybrid(bob.privateKeyJson, truncFile, alice.publicKeyJson), 'terpotong');
    await throws('penerima salah -> segel kunci gagal dibuka', () => decryptFileHybrid(alice.privateKeyJson, fenc.container, alice.publicKeyJson));
    await throws('magic salah -> ditolak', () => decryptFileHybrid(bob.privateKeyJson, encodeText('XXXXXX' + '0'.repeat(100)), ''), 'Magic');

    console.log('== Buku pad .qpad ==');
    const book = generatePadBook(4096);
    const file = await serializePadBook(book);
    const parsed = await parsePadBook(file);
    ok('serialisasi .qpad round-trip', bytesToHex(parsed.bookId) === bytesToHex(book.bookId) && bytesToHex(parsed.data) === bytesToHex(book.data));
    const corrupted = new Uint8Array(file);
    corrupted[corrupted.length - 1] ^= 1;
    await throws('checksum .qpad rusak ditolak', () => parsePadBook(corrupted), 'Checksum');
    await throws('magic salah ditolak', () => parsePadBook(encodeText('XXXXX' + '0'.repeat(100))), 'Magic');

    console.log('== OTP-v2 ==');
    const storageA = createMemoryStorage();
    const storageB = createMemoryStorage(); // pihak penerima, buku identik
    const bookB = await parsePadBook(await serializePadBook(book)); // salinan identik

    const s1 = await otpSend(book, 'SERangan fajar 0500', storageA);
    const r1 = await otpReceive(bookB, s1.packetBase64, storageB);
    ok('OTP round-trip', r1.plaintext === 'SERangan fajar 0500' && !r1.reuseDetected && !r1.duplicate);

    const r1dup = await otpReceive(bookB, s1.packetBase64, storageB);
    ok('duplikat persis terdeteksi (bukan reuse)', r1dup.duplicate && !r1dup.reuseDetected);

    const tamperedPacket = JSON.parse(decodeText(base64ToUint8Array(s1.packetBase64)));
    const tagBytes = base64ToUint8Array(tamperedPacket.tag);
    tagBytes[0] ^= 1;
    tamperedPacket.tag = arrayBufferToBase64(tagBytes);
    await throws('tag diubah -> ditolak sebelum plaintext', () => otpReceive(bookB, arrayBufferToBase64(encodeText(JSON.stringify(tamperedPacket))), storageB), 'Tag autentikasi');

    const bookLain = generatePadBook(4096);
    await throws('buku pad lain ditolak', () => otpReceive(bookLain, s1.packetBase64, createMemoryStorage()), 'buku pad LAIN');

    // Simulasi reuse: kemunduran kursor (bug/penyerang dengan salinan buku)
    const regKey = 'qekh.padbook.v1.' + bytesToHex(book.bookId);
    const regA = JSON.parse(storageA.getItem(regKey));
    regA.front = 0;
    storageA.setItem(regKey, JSON.stringify(regA));
    const s2 = await otpSend(book, 'pesan lain di offset sama', storageA);
    ok('reuse menghasilkan offset sama', s2.packet.off === s1.packet.off);
    const r2 = await otpReceive(bookB, s2.packetBase64, storageB);
    ok('PAD DIPAKAI ULANG terdeteksi di penerima', r2.reuseDetected === true);

    // Buku habis: buku 4096, sisa setelah 2 pesan kecil masih banyak — pakai buku mini penuh
    const tiny = generatePadBook(4096);
    const tinyStore = createMemoryStorage();
    const bigMsg = 'X'.repeat(4100);
    await throws('buku habis -> menolak mengenkripsi', () => otpSend(tiny, bigMsg, tinyStore), 'HABIS');

    const status = getBookStatus(book, storageA);
    ok('status buku melacak pemakaian', status.segmentCount >= 2 && status.usedBytes > 0);

    const wiped = destroyUsedSegments(book, storageA);
    ok('musnahkan segmen mengembalikan byte > 0', wiped > 0);
    const regAfter = JSON.parse(storageA.getItem(regKey));
    ok('segmen termusnahkan tercatat', regAfter.destroyed.length > 0);

    // Round-trip via grup huruf (jalur radio)
    const s3 = await otpSend(book, 'radio check', storageA);
    const viaRadio = await otpReceive(bookB, arrayBufferToBase64(fromLetterGroups(stripLetterHeader(s3.letterGroups))), storageB);
    ok('paket OTP via grup huruf', viaRadio.plaintext === 'radio check');

    console.log('== Test vector deterministik docs/test-vectors.json (E.1) ==');
    const vectors = JSON.parse(readFileSync(new URL('../docs/test-vectors.json', import.meta.url), 'utf8'));

    const vOkm = await hkdfSha256(hexToBytes(vectors.hkdfSha256.ikm), hexToBytes(vectors.hkdfSha256.salt), hexToBytes(vectors.hkdfSha256.info), vectors.hkdfSha256.length);
    ok('vektor HKDF cocok', bytesToHex(vOkm) === vectors.hkdfSha256.okm);

    const vAesKey = await globalThis.crypto.subtle.importKey('raw', hexToBytes(vectors.aes256gcm.key), { name: 'AES-GCM' }, false, ['encrypt']);
    const vAesCt = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: hexToBytes(vectors.aes256gcm.iv) }, vAesKey, hexToBytes(vectors.aes256gcm.pt)));
    ok('vektor AES-256-GCM cocok', bytesToHex(vAesCt) === vectors.aes256gcm.ct);

    ok('vektor grup huruf cocok', toLetterGroups(hexToBytes(vectors.letterGroups.bytesHex)) === vectors.letterGroups.groups);
    ok('vektor fingerprint cocok', (await fingerprintFromPublicJson(vectors.fingerprint.publicKeyJson)) === vectors.fingerprint.fingerprint);

    const vMk = ml_kem768.keygen(hexToBytes(vectors.mlkem768.seed));
    ok('vektor ML-KEM keygen (pk)', bytesToHex(vMk.publicKey) === vectors.mlkem768.publicKey);
    const vEnc = ml_kem768.encapsulate(vMk.publicKey, hexToBytes(vectors.mlkem768.msg));
    ok('vektor ML-KEM encapsulate (ct+ss)', bytesToHex(vEnc.cipherText) === vectors.mlkem768.cipherText && bytesToHex(vEnc.sharedSecret) === vectors.mlkem768.sharedSecret);
    ok('vektor ML-KEM decapsulate', bytesToHex(ml_kem768.decapsulate(vEnc.cipherText, vMk.secretKey)) === vectors.mlkem768.sharedSecret);

    const vSlh = slh_dsa_sha2_192s.keygen(hexToBytes(vectors.slhdsa192s.seed));
    ok('vektor SLH-DSA keygen (pk)', bytesToHex(vSlh.publicKey) === vectors.slhdsa192s.publicKey);
    ok('vektor SLH-DSA sig terverifikasi', slh_dsa_sha2_192s.verify(hexToBytes(vectors.slhdsa192s.signature), encodeText(vectors.slhdsa192s.messageUtf8), vSlh.publicKey));
    if (vectors.slhdsa192s.signDeterministic) {
        const vSig = slh_dsa_sha2_192s.sign(encodeText(vectors.slhdsa192s.messageUtf8), vSlh.secretKey, { extraEntropy: false });
        ok('vektor SLH-DSA sign deterministik identik', bytesToHex(vSig) === vectors.slhdsa192s.signature);
    }

    const vBook = { bookId: hexToBytes(vectors.otpv2.bookId), data: getSampleBytes(vectors.otpv2.bookSize), createdAt: null };
    const vPkt = await otpSend(vBook, vectors.otpv2.message, createMemoryStorage());
    ok('vektor OTP-v2 paket identik', JSON.stringify(vPkt.packet) === JSON.stringify(vectors.otpv2.packet));
    ok('vektor OTP-v2 grup huruf identik', vPkt.letterGroups === vectors.otpv2.letterGroups);

    console.log('== Jadwal FHSS dari kunci bersama (C.4) ==');
    const sch1 = await fhssSchedule('kunci-bersama-rahasia', '2026-10-09', { slots: 48, slotMinutes: 30, channels: 16 });
    const sch2 = await fhssSchedule('kunci-bersama-rahasia', '2026-10-09', { slots: 48, slotMinutes: 30, channels: 16 });
    ok('FHSS deterministik (input sama -> tabel sama)', JSON.stringify(sch1) === JSON.stringify(sch2));
    const sch3 = await fhssSchedule('kunci-bersama-rahasia', '2026-10-10', { slots: 48, slotMinutes: 30, channels: 16 });
    ok('FHSS beda tanggal -> beda urutan', JSON.stringify(sch1) !== JSON.stringify(sch3));
    const sch4 = await fhssSchedule('kunci-LAIN', '2026-10-09', { slots: 48, slotMinutes: 30, channels: 16 });
    ok('FHSS beda kunci -> beda urutan', JSON.stringify(sch1) !== JSON.stringify(sch4));
    ok('FHSS 48 slot, kanal dalam rentang, waktu benar',
        sch1.length === 48 && sch1[0].time === '00:00' && sch1[47].time === '23:30'
        && sch1.every(s => s.channel >= 0 && s.channel < 16));
    await throws('FHSS kunci kosong ditolak', () => fhssSchedule('', '2026-10-09'), 'kosong');
    await throws('FHSS format tanggal buruk ditolak', () => fhssSchedule('x', '09/10/2026'), 'YYYY-MM-DD');
    await throws('FHSS slot melebihi 24 jam ditolak', () => fhssSchedule('x', '2026-10-09', { slots: 100, slotMinutes: 30 }), 'slot');

    console.log(`\n${passed} lolos, ${failed} gagal`);
    if (failed > 0) process.exit(1);
}

function getSampleBytes(n) {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (i * 37 + 11) & 0xff;
    return b;
}

main().catch((e) => { console.error('TES BERHENTI KARENA ERROR:', e); process.exit(1); });
