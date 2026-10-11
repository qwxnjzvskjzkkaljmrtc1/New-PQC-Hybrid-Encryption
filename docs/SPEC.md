# SPEC.md — Spesifikasi Protokol Q-EKH (format v5 / OTP-v2 / QEKH-FILE-v1 / QEKHB1)

Dokumen ini adalah spesifikasi formal, byte per byte, dari seluruh format
yang diproduksi/dikonsumsi aplikasi. Tujuannya: audit independen dan
implementasi ulang (mis. aplikasi Android native atau firmware ESP32)
tanpa membaca kode sumber.

Implementasi referensi: `crypto.js`, `otp.js`, `cw.js` (modul murni, jalan
di browser & Node). Vektor uji deterministik: `docs/test-vectors.json`
(dibangkitkan oleh `tools/gen-test-vectors.mjs`, diverifikasi oleh
`tests/qekh.test.mjs`).

Konvensi: semua integer multi-byte **little-endian (LE)** kecuali dinyatakan
lain; `||` berarti konkatenasi byte; semua string JSON di-encode UTF-8;
base64 = RFC 4648 standar dengan padding; base32 = RFC 4648 alfabet
`A–Z2–7` tanpa padding.

=====================================================================
1. PRIMITIF KRIPTOGRAFI
=====================================================================
| Peran            | Algoritma                         | Implementasi        |
|------------------|-----------------------------------|---------------------|
| KEM klasik       | X25519 (ephemeral)                | Web Crypto API      |
| KEM pasca-kuantum| ML-KEM-768                        | @noble/post-quantum |
| AEAD             | AES-256-GCM (tag 16B)             | Web Crypto API      |
| Tanda tangan     | Ed25519 + SLH-DSA-SHA2-192s       | WebCrypto + noble   |
| KDF              | HKDF-SHA256 (implementasi manual) | crypto.js           |
| KDF passphrase   | Argon2id (m=64 MiB, t=3, p=1)     | @noble/hashes       |
| Hash             | SHA-256                           | Web Crypto API      |

Catatan HKDF manual: `hkdfSha256` adalah extract+expand via HMAC-SHA256
murni (RFC 5869), dipakai karena sebagian WebCrypto membatasi panjang
`info`. Hasil identik dengan HKDF native (teruji vektor RFC 5869).

=====================================================================
2. FORMAT KUNCI
=====================================================================
2.1 Kunci Publik (JSON, `type: "public"`)
-----------------------------------------
```json
{
  "version": "QEKH-v5",
  "type": "public",
  "x25519":  "<base64, 32 byte>",
  "mlkem":   "<base64, 1184 byte>",
  "ed25519": "<base64, 32 byte>",
  "slhdsa":  "<base64, 48 byte>",
  "expires": "<ISO 8601, OPSIONAL>"   // D.3: masa berlaku kunci
}
```

2.2 Kunci Privat polos (JSON, `type: "private"`)
------------------------------------------------
```json
{
  "version": "QEKH-v5",
  "type": "private",
  "x25519":  "<base64, 48 byte PKCS#8>",
  "mlkem":   "<base64, 2400 byte>",
  "ed25519": "<base64, 48 byte PKCS#8>",
  "slhdsa":  "<base64, 96 byte>",
  "public":  { ...objek kunci publik seperti 2.1 (tanpa version/type)... },
  "expires": "<opsional, sama seperti publik>"
}
```
Bagian `public` WAJIB ada untuk memproduksi/membuka pesan v5 (dipakai
untuk hash identitas). Kunci v3 lama tanpa `public` hanya bisa membuka
pesan v3/v4.

2.3 Kunci Privat terenkripsi passphrase
---------------------------------------
```json
{
  "version": "QEKH-v5", "type": "private", "encrypted": true,
  "kdf": "Argon2id", "m": 65536, "t": 3, "p": 1,
  "salt": "<base64, 16 byte>",
  "iv":   "<base64, 12 byte>",
  "data": "<base64 — AES-256-GCM(UTF-8 JSON 2.2), tanpa AAD>"
}
```
Kunci AES = Argon2id(pass=UTF-8 passphrase, salt, m, t, p, dkLen=32).
Parameter divalidasi: 8192 ≤ m ≤ 262144, 1 ≤ t ≤ 10, 1 ≤ p ≤ 4.
Format lama `kdf: "PBKDF2-SHA256"` (field `iterations`, 100000..10^7)
tetap bisa dibuka (kunci AES = PBKDF2-SHA256(pass, salt, iterations)).

=====================================================================
3. ENVELOPE PESAN — QEKH-v5
=====================================================================
Pesan = base64( UTF-8( JSON envelope ) ):

```json
{
  "version":          "QEKH-v5",
  "ephemeralX25519":  "<base64, 32 byte>",
  "kyberCiphertext":  "<base64, 1088 byte>",
  "salt":             "<base64, 32 byte>",
  "iv":               "<base64, 12 byte>",
  "ciphertext":       "<base64, N byte>"
}
```

3.1 Konstruksi kunci enkripsi (pengirim)
----------------------------------------
1. `eph` = pasangan X25519 ephemeral; `ephPub` = 32 byte publiknya.
2. `xShared` = X25519.deriveBits(ephPriv, recipientX25519Pub) — 32 byte.
3. `(kemCt, kemShared)` = ML-KEM-768.encapsulate(recipientMlkemPub).
4. `combined = kemShared || xShared`  (**rahasia PQ lebih dulu**).
5. `transcriptHash = SHA-256(ephPub || kemCt)`.
6. `hRecipient = identityHash(kunci publik penerima)` — lihat §5.
7. `info = "QEKH-v5-HKDF" || transcriptHash || hRecipient`.
8. `aesKey = HKDF-SHA256(ikm=combined, salt=salt32B-acak, info, 32)`.
9. `aad = SHA-256("QEKH-v5-AAD" || ephPub || kemCt || salt)`.

3.2 Paket inti & tanda tangan tersegel
---------------------------------------
`core = UTF-8 JSON {"from": fpSender, "to": fpRecipient, "at": ISO8601,
"body": plaintext}` — fingerprint format §5.

Payload yang ditandatangani:
```
SIG_PAYLOAD = "QEKH-v5-SIG" || ephPub || kemCt || salt || iv
              || hSender || hRecipient || coreBytes
```
Dua tanda tangan atas SIG_PAYLOAD, KEDUANYA wajib valid:
- `sigEd`   = Ed25519.sign(senderEd25519Sk)      — 64 byte
- `sigSlh`  = SLH-DSA-SHA2-192s.sign(senderSlhSk) — 16224 byte
  (produksi: mode hedged default; vektor uji memakai `extraEntropy:false`)

Paket terenkripsi (plaintext AES-GCM):
```json
{"from","to","at","body","sig":{"ed25519":b64,"slhdsa":b64},"pad":"..."}
```
`ciphertext = AES-256-GCM(aesKey, iv12B-acak, UTF-8(paket), aad)`.

3.3 Aturan padding
------------------
Default (blok acak): panjang JSON paket akhir dibulatkan ke kelipatan
512 byte **ditambah 0–2 blok ekstra acak**. `pad` diisi karakter acak dari
alfabet `[A-Za-z0-9-_]`, dihitung terhadap
`panjang(JSON.stringify({...paket, pad:""}))`.

Opsi bucket konstan (D.5): bila `bucket ∈ {32768, 65536, 131072, 262144}`
dipilih, panjang akhir dibulatkan ke kelipatan `bucket` (+0–1 bucket acak).
Pesan yang paket dasarnya sudah melebihi bucket DITOLAK dengan error.

3.4 Verifikasi penerima
-----------------------
Dekripsi AES-GCM dulu (integritas ciphertext), baru parse paket, lalu —
bila Kunci Publik pengirim diberikan — verifikasi KEDUA tanda tangan
terhadap SIG_PAYLOAD yang dibangun ulang. UI wajib menampilkan status:
verified / failed / unverified (kunci pengirim tidak diisi).
`meta.toMismatch=true` bila `pkg.to` ≠ fingerprint kunci penerima.

3.5 Versi lama (read-only)
--------------------------
- `QEKH-v4`: info HKDF = `"QEKH-v4-HKDF" || ephPub || kemCt`; tanpa AAD;
  tanda tangan di LUAR envelope (field `signatures.{ed25519,slhdsa}`)
  atas `"QEKH-v4" || ephPub || kemCt || salt || iv || ct`; plaintext = JSON
  `{from, at, body}` (tanpa sig di dalam).
- `QEKH-v3`: info HKDF = `"QEKH-v3-HKDF"`; tanpa AAD; tanda tangan luar
  atas `"QEKH-v3" || ...`; plaintext = teks mentah.

=====================================================================
4. FINGERPRINT & HASH IDENTITAS
=====================================================================
```
identityBytes = SHA-256(x25519Pub || mlkemPub || ed25519Pub || slhdsaPub)
fingerprint   = hex KAPITAL identityBytes, dikelompokkan per 4 karakter
                dipisah spasi — total 16 grup ("XXXX XXXX ... XXXX").
```
`identityHash` (dipakai di KDF & payload tanda tangan) = identityBytes
mentah (32 byte), bukan teks hex.

Sidik visual (A.4): grid 9×9 simetris kiri-kanan; sel kiri 5×9=45 diisi
dari 45 bit pertama identityBytes (bit ke-i = sel i, kolom-major per
baris), dicerminkan ke kolom 9−c; hue = u16BE(byte[6..8]) mod 360.

=====================================================================
5. FORMAT RADIO: GRUP HURUF BASE32 & JADWAL FHSS
=====================================================================
5.1 Grup huruf base32
---------------------
- Encode: base32 RFC 4648 tanpa padding, huruf kapital, dikelompokkan
  per 5 karakter dipisah spasi (`toLetterGroups`).
- Decode: toleran huruf kecil, spasi, baris baru, tanda hubung; sisa bit
  akhir harus nol (kanonik) — selain itu ditolak sebagai salah salin.
- Baris header opsional (dilepas sebelum decode):
  `QEKH5 <n> GRUP` (ciphertext v5), `OTPV2` (paket OTP), `QPAD1 BUKU`
  (buku pad).

5.2 Jadwal FHSS (C.4) — derivasi tampilan
-----------------------------------------
`fhssSchedule(kunci, tanggal)` membangkitkan urutan kanal pseudo-acak
yang identik di kedua pihak (radio tetap dioperasikan manual):
```
okm      = HKDF-SHA256(ikm=UTF-8(kunciTeks), salt=UTF-8("YYYY-MM-DD"),
                       info="QEKH-FHSS", length=slots)
channel[i] = okm[i] mod channels     untuk slot i
waktu[i]   = 00:00 + i × slotMinutes (maks. 1440 menit/hari)
```
Parameter wajib sama di kedua pihak: kunci teks, tanggal, jumlah kanal
(2–256), dan durasi slot. Deterministik penuh — cocok untuk dicetak.

=====================================================================
6. OTP-v2 — ONE-TIME PAD TERAUTENTIKASI
=====================================================================
6.1 Buku pad (.qpad)
--------------------
```
magic "QPAD1" (5B) | bookId 16B | size u32 LE | SHA-256(data) 32B | data
```
`data` = byte acak CSPRNG; kedua pihak memegang salinan IDENTIK.
Ukuran valid: 4096 .. 64 MiB.

6.2 Alokasi segmen (anti-iris)
------------------------------
Pad enkripsi dialokasikan dari DEPAN buku (kursor `front`); kunci MAC dari
BELAKANG (kursor `back`, 32 byte per pesan). Registry lokal per bookId
mencatat kursor + hash tiap segmen; enkripsi MENOLAK saat buku habis.

6.3 Paket OTP-v2 (JSON -> base64)
---------------------------------
```json
{"v":"OTP-v2","padId":"<b64 16B>","off":int,"moff":int,
 "ct":"<b64>","tag":"<b64 32B>"}
```
- `ct[i] = UTF-8(pesan)[i] XOR book.data[off + i]`
- `tag = HMAC-SHA256(key = book.data[moff .. moff+32],
    data = "QEKH-OTP-v2" || padId || u64le(off) || u64le(moff) || ct)`

6.4 Penerimaan (verify-then-decrypt)
------------------------------------
Urutan WAJIB: validasi struktur → cek padId → **verifikasi tag dulu** →
baru anti-reuse & dekripsi:
- tag salah → tolak, plaintext tidak pernah ditampilkan.
- offset sama dengan segmen lain ber-hash BEDA, atau rentang beririsan →
  peringatan "PAD TERDETEKSI DIPAKAI ULANG".
- `moff` yang sama pernah dipakai paket lain → paket DITOLAK.
- paket identik persis yang sudah tercatat = duplikat (registry tak berubah).
- Penerimaan sah memajukan kursor lokal bila paket tepat di depan kursor.

Pemusnahan: segmen terpakai bisa di-zero-fill dari salinan buku lokal;
paket lama yang merujuknya tak bisa diverifikasi lagi (by design).

=====================================================================
7. ENKRIPSI FILE — QEKH-FILE-v1 (.qekhf)
=====================================================================
Konstruksi STREAM ala miscreant; satu chunk rusak = gagal total.

7.1 Layout biner
----------------
```
magic "QEKHF1" (6B) | headerLen u32 LE | headerJSON (headerLen byte)
| { chunkLen u32 LE | chunkCt (chunkLen byte) } × N
```
headerJSON:
```json
{"version":"QEKH-FILE-v1","name":"...","size":int,"chunk":65536,
 "prefix":"<b64 7B>","sealed":"<b64 — envelope v5 §3>"}
```
`sealed` = pesan v5 (§3) yang plaintext-nya adalah base64 kunci file
acak 32 byte — sehingga tanda tangan pengirim ikut tersegel.

7.2 Enkripsi chunk
------------------
- `fileKey` acak 32 byte → AES-256-GCM.
- `aad = SHA-256("QEKH-FILE-v1-AAD" || headerJSON bytes)` — sama untuk
  semua chunk; mengikat chunk ke header (nama/ukuran/segel).
- Chunk ke-i (0-based): plaintext = potongan 64 KiB ke-i;
  `nonce = prefix(7B) || counter u32 BIG-ENDIAN || flagLAST(1B; 1 hanya
  pada chunk terakhir)`.
- File kosong → tepat 1 chunk dengan plaintext 0 byte dan flagLAST=1.

7.3 Dekripsi & validasi
-----------------------
Parse header → buka `sealed` (§3.4, verifikasi tanda tangan ikut) →
loop chunk: `chunkLen ∈ [16, 65536+16]`; nonce counter berurutan;
flagLAST hanya boleh pada chunk yang berakhir tepat di EOF; total
plaintext harus == `header.size`. Pelanggaran apa pun → tolak utuh.

Batas implementasi referensi: file ≤ 256 MiB, header ≤ 1 MiB.

=====================================================================
8. TEST VECTOR & VERIFIKASI IMPLEMENTASI
=====================================================================
`docs/test-vectors.json` memuat vektor deterministik untuk: HKDF-SHA256
(RFC 5869 #1), AES-256-GCM (kunci/IV/PT nol), grup huruf base32,
fingerprint (kunci publik berpola tetap), ML-KEM-768 (`keygen(seed 64B)`
+ `encapsulate(pk, msg 32B)` — hook deterministik noble), SLH-DSA-192s
(`keygen(seed 72B)`, tanda tangan `extraEntropy:false` = varian
deterministik FIPS 205 dengan opt_rand = PK.seed), dan OTP-v2 (buku
4096 byte berpola `(i*37+11)&0xff` → paket identik byte-per-byte).

Regenerasi: `node tools/gen-test-vectors.mjs` (harus menghasilkan file
identik — bila tidak, ada drift pada pustaka vendor atau implementasi).
Verifikasi otomatis: `node tests/qekh.test.mjs`.

=====================================================================
10. BATASAN KEAMANAN (jujur)
=====================================================================
- Pustaka pasca-kuantum noble belum diaudit independen pihak ketiga;
  implementasi JS tidak mengklaim tahan side-channel.
- Kunci statis: TANPA forward secrecy — kebocoran kunci privat membuka
  semua ciphertext masa lalu untuk identitas itu. Mitigasi: rotasi kunci
  (field `expires`) + disiplin burst.
- Autentikasi OTP-v2 (HMAC-SHA256) kuat secara komputasional, bukan
  information-theoretic.
- Pesan v3/v4 lama tidak memiliki AAD/domain separation sekuat v5;
  dukungan hanya untuk membaca arsip.
- Keamanan ujung-ke-ujung tetap bergantung pada VERIFIKASI fingerprint
  oleh manusia lewat jalur terpisah (lihat tab Kontak / QR / randomart).
