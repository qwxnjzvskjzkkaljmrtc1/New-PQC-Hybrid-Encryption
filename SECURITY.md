# SECURITY.md — Kebijakan Keamanan Q-EKH Protocol

## Melaporkan celah keamanan

Bila Anda menemukan celah (kriptografi, rantai pasok, XSS, kebocoran data
lokal, dll.), **jangan buka issue publik berisi detail eksploit** sebelum
diperbaiki. Laporkan privat ke pemilik proyek (Mr. J0121312) lewat jalur
yang tercantum di profil repo, dengan reproduksi minimal. Laporan yang
baik: versi/commit, langkah reproduksi, dampak, dan (bila ada) usulan
perbaikan.

## Threat model (ringkas)

Aplikasi ini dirancang untuk komunikasi terselubung lewat radio dengan
lawan setingkat **state actor** (lihat `hiding-transmitter-location.txt`):

- **Dalam cakupan:** kerahasiaan & keaslian pesan (termasuk terhadap
  komputer kuantum masa depan, via konstruksi hibrida), verifikasi
  identitas anti-MITM oleh manusia (fingerprint/QR/randomart), pemusnahan
  cepat data lokal (tombol panik/auto-lock), disiplin burst singkat
  (estimasi durasi, CW, lembar cetak).
- **Di luar cakupan:** keamanan perangkat yang sudah terinfeksi malware,
  forensik memori/clipboard OS, analisis lalu lintas tingkat lanjut
  (kami hanya menyediakan padding/bucket — bukan anonymizer), dan
  keamanan fisik operator.

## Batasan jujur

1. **Belum ada audit independen.** Primitif pasca-kuantum berasal dari
   `@noble/post-quantum` (self-audit oleh pembuatnya). Implementasi JS
   tidak mengklaim tahan side-channel.
2. **Tanpa forward secrecy.** Kunci statis: kebocoran kunci privat
   membuka seluruh arsip ciphertext identitas itu. Mitigasi: rotasi
   berkala (field `expires`), pemusnahan segmen OTP terpakai.
3. **Autentikasi OTP-v2 bersifat komputasional** (HMAC-SHA256), bukan
   information-theoretic — dipilih demi anti-bit-flip yang praktis.
4. **Tanda tangan hanya bermakna bila fingerprint diverifikasi lewat
   jalur terpisah.** Tanpa itu, MITM tetap mungkin.
5. **Web Crypto API & JS**: entropy dan eksekusi bergantung pada browser
   yang jujur; self-test saat startup mendeteksi pustaka rusak/terkorupsi,
   tetapi bukan pengganti audit menyeluruh.

## Panduan operasional minimum

- Jalankan lewat `serve.py` di `127.0.0.1` (bukan IP LAN); Basic Auth di
  HTTP polos setara cleartext — lihat peringatan di `serve.py`.
- Verifikasi `vendor/`: `bash tools/vendor-update.sh check`.
- Tukar buku pad `.qpad` hanya lewat jalur aman/tatap muka.
- Aktifkan auto-lock; kenali tombol 🚨 Panik sebelum dibutuhkan.
- Rotasi kunci secara berkala; umumkan fingerprint baru lewat jalur
  terpisah setiap rotasi.
- Spesifikasi format ada di `docs/SPEC.md`; vektor uji di
  `docs/test-vectors.json` — verifikasi implementasi lain sebelum
  mempercayainya.
