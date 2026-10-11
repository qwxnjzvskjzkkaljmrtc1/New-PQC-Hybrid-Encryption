# Changelog

Semua perubahan penting Q-EKH Protocol dicatat di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/id/1.1.0/); penomoran selaras
dengan nama cache service worker (`sw.js`) dan format protokol.

Butir yang selesai dari `kotak_inbox_saran.txt` dipindahkan ke sini.

## [v6.4] - 2026-10-09

### Diperbaiki
- **BUG autentikasi serve.py (dilaporkan pengguna):** login ditolak &
  prompt berulang walau kredensial benar, dan menekan "Batal" justru
  bisa masuk. Dua akar: (1) `<link rel="manifest">` di-fetch browser
  tanpa kredensial sehingga mendapat 401 → prompt berulang; respons 401
  juga tanpa `Content-Length`. (2) Service worker cache-first
  menyajikan halaman dari cache meski server menjawab 401 — gerbang
  password ter-bypass. Perbaikan: `crossorigin="use-credentials"` pada
  link manifest; respons 401 kini ber-`Content-Length` + `Connection:
  close` dengan `protocol_version = "HTTP/1.1"`; strategi SW diganti
  menjadi **network-first** — respons eksplisit server (401/404) selalu
  diteruskan apa adanya, cache hanya dipakai saat offline. Cache dibump
  ke `qekh-v6-4`.

### Ditambahkan
- **A.2 Social preview (P2):** `tools/make_icons.py` kini merender
  `social-preview.png` 1280×640 murni Python (font bitmap 5×7 buatan
  sendiri, konstelasi deterministik, perisai hasil `render()`); meta
  `og:*` + `twitter:card` dipasang di `index.html`.
- **E.3 Rilis bertanda tangan (P2):** `tools/sign-release.mjs`
  (`init`/`sign`) menandatangani `vendor/HASHES.txt` dengan Ed25519 +
  SLH-DSA-192s → `HASHES.txt.qekhsig`; `tools/verify-release.mjs`
  memverifikasi keduanya + hash file. Kunci privat di
  `tools/release-key.json` (gitignored), kunci publik diterbitkan di
  `docs/release-pubkey.json`. Path bisa dialihkan via env untuk tes.
- **A.3 Brand kit mini (P3):** `brand/logo.svg` (warna),
  `brand/logo-mono.svg` (satu warna untuk cetak/QSL), favicon turunan
  16/32 px, dan `brand/README.txt` (palet resmi + aturan clear-space &
  ukuran minimum + penulisan nama).
- **C.4 Jadwal FHSS (P3):** `fhssSchedule()` di crypto.js —
  `HKDF-SHA256(kunciBersama, tanggal, "QEKH-FHSS")` → tabel waktu→kanal
  yang identik di kedua pihak; UI grid di tab Radiogram dengan sorotan
  slot aktif hari ini. Murni tampilan; terdokumentasi di SPEC.md §5.2.

### Tes
- 7 tes baru FHSS (determinisme, beda tanggal/kunci, rentang kanal,
  validasi input) — total **87 tes, 0 gagal**.

## [v6.3] - 2026-10-09

### Ditambahkan
- **D.1 Enkripsi FILE chunked (P1):** format kontainer biner `.qekhf`
  (`QEKHF1` | header JSON | chunk berturut-turut). Konstruksi STREAM ala
  miscreant: kunci file acak 32 B disegel sebagai pesan v5 (tanda tangan
  pengirim ikut terbawa), isi dipotong 64 KiB dan tiap potongan
  di-AES-256-GCM dengan nonce = prefix acak 7B ‖ counter u32 BE ‖
  flagLAST; AAD mengikat chunk ke header. Satu chunk rusak/terpotong =
  gagal total, tanpa plaintext parsial. UI: drag & drop di tab Enkripsi,
  pilih file + unduh di tab Dekripsi, progress bar per chunk. Batas
  256 MiB.
- **E.1 SPEC.md + test vector (P1):** `docs/SPEC.md` — spesifikasi byte
  per byte untuk kunci, envelope v5 (+legacy v3/v4), fingerprint &
  randomart, base32 grup huruf, OTP-v2 & .qpad, dan .qekhf.
  `tools/gen-test-vectors.mjs` membangkitkan `docs/test-vectors.json`
  deterministik (HKDF, AES-GCM, base32, fingerprint, ML-KEM via
  `keygen(seed)`/`encapsulate(pk,msg)`, SLH-DSA via `extraEntropy:false`,
  OTP-v2 paket identik byte-per-byte); regenerasi harus identik, dan tes
  Node memverifikasinya setiap jalan — drift pustaka vendor langsung
  ketahuan.
- **D.5 Bucket ukuran konstan (P3):** opsi padding di tab Enkripsi —
  ciphertext dibulatkan ke kelipatan 32/64/128/256 KB (+0–1 bucket acak);
  pesan melebihi bucket ditolak dengan pesan jelas.
- **B.1 Animasi "tersegel" (P3):** overlay perisai ~1,2 dtk setelah
  enkripsi teks/file sukses (stroke-draw + fade); dilewati total saat
  `prefers-reduced-motion`.
- **E.4 SECURITY.md (P2):** threat model (rujuk
  hiding-transmitter-location.txt), batasan jujur (belum ada audit
  pihak ketiga, tanpa forward secrecy, side-channel JS), panduan
  operasional, dan kanal pelaporan celah.

### Diubah
- Cache service worker `qekh-v6-2` → `qekh-v6-3`.
- `renderVerification` di ui.js kini menerima elemen target (dipakai
  bersama oleh dekripsi teks & file).

### Tes
- 24 tes baru (file chunked: round-trip multi-chunk/kosong/tamper/
  terpotong/penerima salah/magic; bucket konstan; 12 verifikasi test
  vector) — total **80 tes, 0 gagal**.

## [v6.2] - 2026-10-09

### Ditambahkan
- **A.1 Ikon maskable (P1):** `tools/make_icons.py` kini punya parameter
  `margin` (safe-zone 10%/sisi; konten di 80% area tengah, latar penuh
  sampai tepi). Menghasilkan `icons/icon-maskable-192.png` dan
  `icon-maskable-512.png`, terdaftar di `manifest.webmanifest` dengan
  `purpose: "maskable"` — aman dipotong lingkaran/squircle oleh Android.
- **D.3 Tombol panik + auto-lock (P1):** tombol 🚨 di header memusnahkan
  seluruh `localStorage` ber-prefix `qekh.*` (kontak + registry buku pad),
  mengosongkan semua textarea & kolom password, lalu `location.reload()`.
  Auto-lock idle (mati/5/10/30 menit, default 10) melakukan hal yang sama
  tanpa konfirmasi; hanya me-reload bila memang ada data sensitif, dan
  menampilkan toast penjelasan setelahnya.
- **E.2 Ritual pembaruan vendor (P1):** `tools/vendor-update.sh` dengan
  mode `check` (verifikasi HASHES.txt), `regen` (tulis ulang HASHES.txt),
  dan `update <pkg> <versi>` — unduh tarball npm, salin himpunan file yang
  dibutuhkan (closure import, dependensi internal baru ikut otomatis),
  tulis ulang import `@noble/*` ke path relatif, laporkan hash lama→baru,
  perbarui referensi di `crypto.js`/`argon2-worker.js`/`sw.js`, jalankan
  tes Node, dan **rollback penuh otomatis** bila tes gagal. Perubahan
  dicatat di `vendor/UPGRADE-LOG.txt`. Registry bisa dialihkan lewat
  `QEKH_NPM_REGISTRY` (berguna untuk mirror/tes).
- **A.5 Lembar cetak radiogram (P2):** tombol "Cetak lembar salin-tangan"
  di tab Radiogram + `@media print` (kertas A5): kotak per grup huruf,
  font mono besar, nomor urut, kotak ceklis per grup, dan instruksi
  pemusnahan lembar.
- **A.4 Sidik visual / randomart (P2, tambahan sesi):** fungsi murni
  `fingerprintArt()` di `crypto.js` (grid identicon 9×9 simetris + hue dari
  SHA-256 kunci publik) dan render canvas di ui.js — tampil di samping
  fingerprint tab Buat Kunci, Enkripsi, Dekripsi, dan setiap kartu kontak.
  Digambar ulang otomatis saat ganti tema.
- **C.1 Radiogram sebagai CW morse (P1, tambahan sesi):** modul baru
  `cw.js` — tabel morse A–Z/0–9, timing PARIS (`unit = 1200/WPM ms`),
  render PCM nada 600 Hz ber-ramp 4 ms anti-klik, dan encoder WAV PCM16
  murni. Tombol "▶ Putar CW" (WebAudio) dan "⬇ Unduh .wav" di tab
  Radiogram; semua lokal, lolos CSP.

### Diubah
- Cache service worker `qekh-v6-1` → `qekh-v6-2`; `cw.js` dan ikon
  maskable masuk daftar precache offline.
- `style.css` dibump ke `?v=7` di `index.html`.
- Tab "Tentang" mendokumentasikan fitur lapangan baru.

### Tes
- 16 tes baru (randomart: determinisme, simetri, validasi; CW: timing
  PARIS, jeda kata 7 unit, hening total di gap, header WAV) — total
  **56 tes, 0 gagal** (`node tests/qekh.test.mjs`).

## [v6.1] - 2026-10-09

Keadaan baseline sebelum CHANGELOG ini dimulai (ringkasan dari komentar
kode dan rekomendasi-pengembangan-qekh.txt): pustaka noble di-vendor lokal
(A.1 rantai pasok), self-test kripto saat startup (A.2), CSP ketat +
header keamanan serve.py (A.3/A.4), OTP-v2 terautentikasi + buku pad
.qpad + registry anti-reuse (B.1–B.4), mode radiogram base32 + estimasi
durasi pancar (C.1 rekomendasi), buku kontak + QR fingerprint + masa
berlaku kunci (D.1–D.3 rekomendasi), PWA offline (E.2), Argon2id di Web
Worker (E.3), toast/dialog (E.4), tema terang/gelap, tes Node di CI (F.2).
