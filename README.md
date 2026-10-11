# Q-EKH Protocol

Enkripsi & autentikasi **hibrida pasca-kuantum** untuk komunikasi terselubung lewat radio — **100% lokal, offline, tanpa server, tanpa CDN, tanpa telemetri**. Satu halaman web (PWA) yang berjalan di browser Anda; seluruh kunci dan data hidup hanya di mesin Anda.

> **Posisi jujur:** aplikasi ini dirancang untuk ancaman setingkat *state actor* (lihat [`hiding-transmitter-location.txt`](hiding-transmitter-location.txt)), tapi **belum diaudit pihak ketiga** dan tanpa *forward secrecy*. Baca [`SECURITY.md`](SECURITY.md) sebelum mempercayainya dengan sesuatu yang penting.

![CI](https://github.com/qwxnjzvskjzkkaljmrtc1/New-PQC-Level-5/actions/workflows/ci.yml/badge.svg)

## Mengapa hibrida, dan konstruksi apa yang dipakai

Inti protokol (format pesan **v5**; v3/v4 lama tetap bisa dibuka):

| Lapisan | Konstruksi |
|---|---|
| Kerahasiaan | **X25519 + ML-KEM-768** digabung lewat HKDF-SHA256 (urutan rahasia-PQ-lebih-dulu — pola yang sama dengan konstruksi hybrid standar seperti TLS 1.3 / X-Wing). Aman selama salah satu dari keduanya belum bisa dipecahkan — termasuk oleh komputer kuantum. |
| Enkripsi isi | **AES-256-GCM** (AEAD) |
| Keaslian | **Ed25519 + SLH-DSA-SHA2-192s** — tanda tangan ganda, klasik *dan* pasca-kuantum, dengan *sealed sender* |
| Passphrase | **Argon2id** (RFC 9106) di Web Worker, tidak memblokir UI |
| Integritas rantai pasok | Semua pustaka kripto **divendor lokal** (`vendor/`, hash SHA-256 di `vendor/HASHES.txt`, rilis **ditandatangani** — lihat bawah) + **self-test saat startup** (vektor resmi HKDF, AES-GCM, Argon2id, ML-KEM, SLH-DSA, X25519, Ed25519) |

Spesifikasi byte-per-byte: [`docs/SPEC.md`](docs/SPEC.md). Vektor uji deterministik: [`docs/test-vectors.json`](docs/test-vectors.json) (dipakai tes otomatis — drift pustaka vendor langsung ketahuan).

## Fitur

| Tab | Isi |
|---|---|
| **1. Buat Kunci** | Kunci privat/publik Q-EKH v5 (passphrase Argon2id opsional), fingerprint grup-huruf + **randomart** (identicon 9×9), QR fingerprint, field `expires` untuk rotasi kunci. |
| **2. Enkripsi** | Teks (≤16 MiB) **dan FILE** (≤256 MiB, format chunked `.qekhf` ala STREAM — satu chunk rusak = gagal total, tanpa plaintext parsial). Padding 512 B + opsi **bucket ukuran konstan** (32/64/128/256 KB) melawan analisis ukuran. Unduh hasil (base64 **atau biner mentah `.qekhb`, ~25% lebih kecil**, untuk toolchain radio) / salin. |
| **3. Dekripsi** | Buka v3/v4/v5 (termasuk file `.qekhb` via tombol "Buka file"), verifikasi tanda tangan ganda *sebelum* plaintext ditampilkan, cocokkan fingerprint pengirim dengan kontak, unduh hasil file. |
| **4. Radiogram** | Ciphertext → **grup 5 huruf kapital** (base32 RFC 4648, toleran spasi/kapitalisasi) siap dibacakan voice/CW; **estimasi durasi on-air** (bps/WPM) sebelum pencet PTT; **putar CW** (nada 600 Hz, timing PARIS) + unduh `.wav`; **jadwal FHSS** (tabel kanal per hari dari kunci bersama, identik di kedua pihak); **lembar cetak salin-tangan** (A5, kotak per grup + instruksi pemusnahan). |
| **5. OTP & Buku Pad** | **OTP-v2 terautentikasi** (HMAC-SHA256 dari segmen pad terpisah, verify-then-decrypt), buku pad `.qpad` (CSPRNG, tukar sekali secara aman), **anti-pemakaian-ulang** (registry lokal; segmen dipakai = ditolak; deteksi reuse = peringatan merah), ekspor grup huruf, "musnahkan segmen terpakai". |
| **6. Kontak** | Buku alamat lokal: kunci publik, fingerprint, status **terverifikasi/belum**, tanggal diverifikasi, masa berlaku. QR + randomart di tiap kartu. |
| **7. Tentang** | Penjelasan protokol, alur pemakaian, catatan jujur. |

Di luar tab:

- **PWA offline penuh** — setelah buka sekali lewat HTTP(S), aplikasi ter-install di HP/laptop dan jalan tanpa internet (service worker `sw.js`, network-first; cache tidak pernah melewati gerbang auth server).
- **Tombol 🚨 Panik + auto-lock idle** (mati/5/10/30 menit) — memusnahkan semua data lokal ber-prefix `qekh.*`, mengosongkan kolom, memuat ulang halaman.
- **Self-test kripto saat startup** — status kecil di footer; bila gagal, seluruh tombol dikunci dan ada peringatan besar.
- Tema terang/gelap, toast (tanpa `alert()`), CSP ketat + header keamanan.

## Mulai cepat

Prasyarat: browser modern dengan Web Crypto. Karena aplikasi adalah ES module, **buka lewat HTTP(S)**, bukan `file://`.

### Opsi 1 (disarankan): `serve.py` — server lokal + gerbang password + header keamanan

```sh
QEKH_PASS="passwordAnda" python3 serve.py
# buka http://127.0.0.1:8000
```

Variasi: `QEKH_PORT=9000`, `QEKH_USER=nama`, `QEKH_BIND=0.0.0.0` (akses dari HP di WiFi yang sama — **dapat peringatan keras**: Basic Auth di HTTP polos setara cleartext di LAN; kalau harus, pasang di belakang TLS mis. Caddy/stunnel).

### Opsi 2: server statis mana pun

```sh
python3 -m http.server 8000   # tanpa gerbang password — hanya untuk mesin yang sudah aman
```

Lalu **install sebagai aplikasi** (menu browser → *Install app* / *Add to Home Screen*) supaya bisa dibuka sekali-klik dan dipakai offline total.

## Verifikasi sebelum mempercayai

Urutan yang disarankan (semua lokal, tanpa kepercayaan):

1. **Integritas pustaka vendor** — hash SHA-256 tiap file harus cocok:
   ```sh
   bash tools/vendor-update.sh check        # atau: (cd vendor && sha256sum -c HASHES.txt)
   ```
2. **Tanda tangan rilis** — `vendor/HASHES.txt` harus ditandatangani pemegang kunci rilis (Ed25519 **dan** SLH-DSA-192s; keduanya harus valid):
   ```sh
   node tools/verify-release.mjs
   ```
   Fingerprint kunci publik rilis yang sah (lihat [`docs/release-pubkey.json`](docs/release-pubkey.json)):
   ```
   1BE7 9EEA 913A DB3C 16E7 29DB 9293 01C8 A8F1 F84F 364C 7A78 7A98 0CFC FF46 E0E2
   ```
3. **Self-test di browser** — status "self-test OK" di footer halaman.
4. **Vektor uji** — implementasi lain boleh diverifikasi terhadap `docs/test-vectors.json` (regenerasi deterministik via `node tools/gen-test-vectors.mjs` harus identik byte-per-byte).

## Tes

```sh
node tests/qekh.test.mjs     # 87 tes: round-trip v3/v4/v5, tamper, test vector,
                             # file chunked, bucket, OTP-v2, buku pad, CW, randomart, FHSS
```

Node **22+** dibutuhkan (WebCrypto Ed25519). CI (GitHub Actions) menjalankan tes ini + verifikasi vendor + verifikasi tanda tangan rilis di setiap push/PR (butir F.2).

## Struktur proyek

```
index.html, ui.js, style.css   antarmuka (tanpa logika kripto)
crypto.js                      modul kripto murni (tanpa DOM) — bisa diimpor Node & browser
otp.js, cw.js                  OTP-v2 + buku pad; morse CW & WAV
argon2-worker.js               Argon2id di Web Worker
sw.js                          service worker PWA (network-first)
serve.py                       server statis + Basic Auth + header keamanan
vendor/                        pustaka kripto lokal (noble) + HASHES.txt + HASHES.txt.qekhsig
docs/                          SPEC.md, test-vectors.json, release-pubkey.json
tools/                         vendor-update.sh, sign/verify-release.mjs, gen-test-vectors.mjs, make_icons.py
tests/                         tes otomatis (Node)
brand/, icons/, social-preview.png  brand kit & aset turunan; panduan: brand/README.txt
```

## Ritual maintainer

- **Pembaruan pustaka** (tidak pernah edit manual):
  ```sh
  tools/vendor-update.sh update noble-hashes 2.5.0    # unduh, pasang, uji, auto-rollback bila gagal
  node tools/sign-release.mjs sign                    # tandatangani ulang HASHES.txt setelahnya
  ```
- **Rilis bertanda tangan:** `node tools/sign-release.mjs init` (sekali; kunci privat `tools/release-key.json` dibuat lokal, mode 600, **gitignored — jangan pernah commit**), lalu `sign` di setiap rilis. Kunci publik + `vendor/HASHES.txt.qekhsig` yang di-commit.
- **Ikon & social preview:** dari root jalankan `python3 tools/make_icons.py` (Python standar, tanpa Pillow); regenerasi deterministik ikon PWA 192/512, varian maskable, favicon 16/32, dan `social-preview.png`.
- Perubahan dicatat di [`CHANGELOG.md`](CHANGELOG.md); nomor versi selaras dengan nama cache `sw.js`.

## Keamanan & batasan

Baca [`SECURITY.md`](SECURITY.md): threat model ringkas, batasan jujur (belum ada audit independen, tanpa forward secrecy, autentikasi OTP komputasional, tanda tangan hanya bermakna jika fingerprint diverifikasi lewat jalur terpisah), panduan operasional minimum, dan kanal pelaporan celah **privat**.

Riwayat ide & prioritas: [`rekomendasi-pengembangan-qekh.txt`](rekomendasi-pengembangan-qekh.txt) — prinsip memandu: perbaikan terbesar ada di **arsitektur dan kebiasaan** (rantai pasok jujur, kunci diverifikasi manusia, pad tidak pernah dipakai ulang), bukan algoritma baru.
