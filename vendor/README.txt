============================================================
VENDOR — pustaka pihak ketiga yang disimpan lokal (A.1)
============================================================
Tanggal unduh : 2026-10-09
Sumber        : npm registry (registry.npmjs.org)

Paket:
  @noble/post-quantum 0.7.0 (MIT, Paul Miller)
    https://registry.npmjs.org/@noble/post-quantum/-/post-quantum-0.7.0.tgz
    Dipakai: ml-kem.js (ML-KEM-768), slh-dsa.js (SLH-DSA-SHA2-192s)
    + dependensi internalnya (_crystals.js, utils.js).
  @noble/hashes 2.4.0 (MIT, Paul Miller)
    https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz
    Dipakai: argon2.js (Argon2id). File lain ikut disalin utuh karena
    saling mengimpor secara internal.
  @noble/curves 2.3.0 (MIT, Paul Miller)
    https://registry.npmjs.org/@noble/curves/-/curves-2.3.0.tgz
    Dipakai: utils.js, abstract/fft.js, abstract/modular.js
    (dependensi slh-dsa.js & _crystals.js).
  qrcode-generator 1.4.4 (MIT, Kazuhiko Arase)
    https://registry.npmjs.org/qrcode-generator/-/qrcode-generator-1.4.4.tgz
    Dipakai: qrcode.js (QR fingerprint untuk verifikasi tatap muka).

Modifikasi lokal:
  Import internal '@noble/hashes/...', '@noble/curves/...' di dalam file
  vendor ditulis ulang menjadi path relatif antar-folder (mis.
  '../noble-hashes-2.4.0/sha3.js') supaya berjalan di browser tanpa
  import map dan tetap lolos CSP script-src 'self'. Tidak ada satu pun
  baris logika kriptografi yang diubah.

Verifikasi integritas (dijalankan dari dalam folder vendor/):
  sha256sum -c HASHES.txt
Semua baris harus "OK". HASHES.txt dihitung SETELAH penulisan ulang
import di atas — jadi hash ini mengunci persis byte yang dieksekusi
aplikasi.
============================================================
