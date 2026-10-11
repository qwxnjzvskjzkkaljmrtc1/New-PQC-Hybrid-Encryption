// ui.js — seluruh wiring DOM untuk Q-EKH Protocol (tab, tombol, toast, kontak,
// radiogram, OTP, dekorasi). Tidak berisi logika kripto; semua itu ada di
// crypto.js / otp.js supaya bisa diuji di Node tanpa browser.
import {
    generateIdentity, encryptHybrid, decryptHybrid, publicKeyInfo,
    runCryptoSelfTest, toLetterGroups, fromLetterGroups, looksLikeLetterGroups,
    stripLetterHeader, encodeText, decodeText, arrayBufferToBase64,
    fingerprintArt, encryptFileHybrid, decryptFileHybrid, fhssSchedule,
    payloadToBinary, binaryToPayload,
} from './crypto.js';
import {
    generatePadBook, serializePadBook, parsePadBook, padBookToLetterGroups,
    otpSend, otpReceive, getBookStatus, destroyUsedSegments, forgetBook,
    bookIdShort,
} from './otp.js';
import { renderCwPcm, encodeWavPcm16, CW_SAMPLE_RATE } from './cw.js';

document.addEventListener('DOMContentLoaded', () => {

    // =============================================================
    //                     I18N: BAHASA INDONESIA / ENGLISH (E.6)
    // =============================================================
    // Pesan error teknis dari modul kripto (crypto.js/otp.js/cw.js)
    // sengaja TIDAK diterjemahkan — stabil, konsisten, mudah diaudit.
    const I18N = { id: {
        "common.copy": "Salin",
        "common.copied": "Tersalin!",
        "common.cancel": "Batal",
        "common.confirm": "Lanjutkan",
        "common.delete": "Hapus",
        "common.download": "Unduh",
        "common.copyFailed": "Gagal menyalin — clipboard ditolak browser.",
        "common.fileDownloaded": "File \"{name}\" diunduh.",
        "common.invalidKey": "Kunci tidak valid: {msg}",
        "header.sub": "Enkripsi &amp; autentikasi hibrida pasca-kuantum (X25519 + ML-KEM-768, ditandatangani Ed25519 + SLH-DSA-192s). 100% lokal &amp; offline — tanpa CDN.",
        "header.themeAria": "Ganti tema terang/gelap",
        "header.themeTitle": "Ganti tema",
        "header.panicAria": "Tombol panik: musnahkan data lokal dan muat ulang halaman",
        "header.panicTitle": "Panik: hapus kontak &amp; registry pad, kosongkan layar, muat ulang",
        "header.panic": "🚨 Panik",
        "tabs.generate": "1. Buat Kunci",
        "tabs.encrypt": "2. Enkripsi",
        "tabs.decrypt": "3. Dekripsi",
        "tabs.radiogram": "4. Radiogram",
        "tabs.otp": "5. OTP &amp; Buku Pad",
        "tabs.contacts": "6. Kontak",
        "tabs.about": "7. Tentang",
        "selftest.failedTitle": "⛔ SELF-TEST GAGAL — jangan pakai halaman ini.",
        "selftest.failedDetail": "{reason} Pustaka kripto rusak atau dimanipulasi; unduh ulang aplikasi dari sumber tepercaya.",
        "selftest.noSubtle": "Web Crypto API tidak tersedia. Buka halaman ini lewat https:// atau http://127.0.0.1 — bukan lewat alamat IP jaringan biasa (http://192.168.x.x), karena browser memblokir crypto.subtle di sana.",
        "footer.selftest.pending": "Self-test: belum berjalan",
        "footer.selftest.running": "Self-test: berjalan…",
        "footer.selftest.ok": "Self-test: OK",
        "footer.selftest.failed": "Self-test: GAGAL",
        "footer.note": "Web Crypto API (X25519, Ed25519, HKDF, AES-GCM) + pustaka lokal <code>vendor/</code> (@noble/post-quantum, @noble/hashes) — tanpa CDN, bisa offline penuh.",
        "footer.autolockLabel": "Auto-lock saat idle:",
        "footer.autolock0": "mati",
        "footer.autolock5": "5 menit",
        "footer.autolock10": "10 menit",
        "footer.autolock30": "30 menit",
        "footer.langLabel": "Bahasa / Language:",
        "panic.confirm": "PANIK: semua kontak, registry buku pad, dan isi layar akan DIMUSNAHKAN sekarang, lalu halaman dimuat ulang.\n\nTindakan ini tidak bisa dibatalkan. File .qpad & kunci yang sudah Anda unduh/sendiri simpan tidak terpengaruh.",
        "panic.ok": "MUSNAHKAN SEKARANG",
        "autolock.off": "Auto-lock dimatikan.",
        "autolock.on": "Auto-lock aktif: sesi dikunci setelah {min} menit tanpa aktivitas.",
        "autolock.fired": "🔒 Auto-lock: sesi dikunci karena idle — kontak, registry pad, dan isi layar sudah dibersihkan.",
        "qr.libraryMissing": "Pustaka QR tidak termuat.",
        "qr.tooLong": "Teks terlalu panjang untuk QR.",
        "fpArt.aria": "Sidik visual (randomart) dari fingerprint",
        "gen.title": "Pembuatan Identitas Hibrida",
        "gen.desc": "Membuat 4 pasang kunci sekaligus: X25519 + ML-KEM-768 untuk enkripsi, serta Ed25519 dan SLH-DSA-192s untuk tanda tangan. Simpan Kunci Privat Anda dengan sangat aman dan bagikan Kunci Publik + Fingerprint kepada lawan bicara lewat jalur terpisah.",
        "gen.passLabel": "Passphrase Kunci Privat (opsional)",
        "gen.passPh": "Kosongkan untuk kunci tanpa enkripsi; jangan lupa passphrase ini.",
        "gen.passHint": "Passphrase tidak dapat dipulihkan. Kunci privat terenkripsi memakai Argon2id (dijalankan di Web Worker — UI tidak membeku).",
        "gen.expiresLabel": "Masa berlaku kunci (opsional)",
        "gen.expiresHint": "Bila diisi, tanggal ini ikut tercantum di Kunci Publik dan aplikasi akan mengingatkan lawan bicara saat kunci lewat masa berlakunya. Rotasi berkala membatasi dampak bila kunci bocor.",
        "gen.btn": "Buat Pasangan Kunci Hibrida Baru",
        "gen.btnBusy": "Membuat Kunci...",
        "gen.pubLabel": "Kunci Publik Hibrida (JSON - Bagikan ini)",
        "gen.pubPh": "Kunci Publik gabungan akan dibuat di sini...",
        "gen.pubCopyAria": "Salin kunci publik",
        "gen.downloadPub": "⬇ Unduh kunci publik",
        "gen.fpLabel": "Fingerprint Identitas (untuk verifikasi anti-MITM)",
        "gen.fpPlaceholder": "Buat kunci untuk melihat fingerprint...",
        "gen.fpCopy": "Salin fingerprint",
        "gen.fpHint": "Bacakan atau kirim fingerprint ini ke lawan bicara Anda lewat jalur lain (telepon, tatap muka, chat terpisah) — atau tunjukkan QR di bawah saat bertemu langsung. Kotak gambar di sampingnya adalah <strong>sidik visual</strong> (randomart) dari fingerprint yang sama — mata manusia mencocokkan gambar jauh lebih cepat daripada 64 karakter hex. Ini yang membuat tanda tangan benar-benar berarti.",
        "gen.privLabel": "Kunci Privat Hibrida (JSON - JAGA KERAHASIAANNYA)",
        "gen.privPh": "Kunci Privat gabungan akan dibuat di sini...",
        "gen.privCopyAria": "Salin kunci privat",
        "gen.downloadPriv": "⬇ Unduh kunci privat",
        "gen.waitArgon": "Harap tunggu, membuat 4 pasang kunci + mengenkripsi kunci privat (Argon2id, ±2 detik)...",
        "gen.waitPlain": "Harap tunggu, membuat 4 pasang kunci...",
        "gen.fpComputing": "Menghitung...",
        "gen.okToast": "Pasangan kunci baru selesai dibuat.",
        "gen.fail": "Gagal membuat kunci.",
        "gen.overwriteConfirm": "Kunci yang tampil sekarang akan ditimpa. Pastikan Kunci Privat lama sudah tersimpan aman. Lanjutkan?",
        "gen.expiryInvalid": "Tanggal kedaluwarsa tidak valid.",
        "gen.expiryPast": "Tanggal kedaluwarsa harus di masa depan.",
        "dialog.downloadPriv": "Unduh Kunci Privat sebagai file? Siapa pun yang memegang file ini (plus passphrase-nya) memegang identitas Anda.",
        "enc.title": "Enkripsi &amp; Tanda Tangan Pesan",
        "enc.desc": "Pilih kontak penerima (atau tempel Kunci Publik-nya) dan Kunci Privat Anda sendiri (dipakai untuk menandatangani, bukan untuk enkripsi).",
        "enc.contactLabel": "Penerima dari Buku Kontak",
        "enc.pubLabel": "Kunci Publik Hibrida Penerima (JSON)",
        "enc.pubPh": "Tempel Kunci Publik Hibrida penerima di sini...",
        "enc.fpLabel": "Fingerprint Kunci yang Ditempel",
        "enc.fpHint": "Cocokkan dengan fingerprint yang dibacakan langsung oleh penerima sebelum mengirim pesan rahasia.",
        "enc.privLabel": "Kunci Privat Anda (untuk menandatangani pesan ini)",
        "enc.privPh": "Tempel Kunci Privat Hibrida Anda sendiri di sini...",
        "enc.passLabel": "Passphrase Kunci Privat Anda",
        "enc.passPh": "Isi jika Kunci Privat terenkripsi.",
        "enc.plainLabel": "Teks Biasa (Plaintext)",
        "enc.plainPh": "Tulis pesan rahasia Anda di sini...",
        "enc.bucketLabel": "Padding ukuran (anti analisis ukuran)",
        "enc.bucketOpt0": "Blok acak 512 B (default — disarankan)",
        "enc.bucketOpt32": "Bucket konstan 32 KB",
        "enc.bucketOpt64": "Bucket konstan 64 KB",
        "enc.bucketOpt128": "Bucket konstan 128 KB",
        "enc.bucketOpt256": "Bucket konstan 256 KB",
        "enc.bucketHint": "Bucket konstan membuat semua pesan tampak berukuran persis kelipatan N KB — berguna bila pengamat mencatat ukuran burst Anda dengan teliti. Konsekuensi: ciphertext lebih besar; pesan melebihi bucket akan ditolak.",
        "enc.btn": "Enkripsi &amp; Tandatangani Pesan",
        "enc.outLabel": "Ciphertext Hibrida (Base64)",
        "enc.outPh": "Hasil enkripsi + tanda tangan akan muncul di sini...",
        "enc.copyAria": "Salin ciphertext",
        "enc.download": "⬇ Unduh ciphertext",
        "enc.downloadBin": "⬇ Unduh .qekhb (biner mentah)",
        "enc.downloadBinTitle": "Format biner mentah QEKHB1 — ~25% lebih kecil, untuk toolchain radio",
        "enc.hintRadio": "Untuk dikirim lewat radio (voice/CW): buka tab <strong>4. Radiogram</strong> untuk konversi ke grup huruf + estimasi durasi pancar. <strong>.qekhb</strong> = envelope v5 dalam bentuk biner mentah (tanpa base64/JSON) — untuk toolchain radio sendiri; bisa dibuka lagi di tab 3.",
        "enc.fileTitle": "Enkripsi FILE (chunked .qekhf)",
        "enc.fileDesc": "File dipotong per 64 KiB dan tiap potongan di-AES-256-GCM (nonce = prefix acak ‖ counter ‖ flagLAST, ala STREAM); kunci file acak 32 byte disegel sebagai pesan v5 ke penerima di atas — jadi tanda tangan Anda ikut terbawa. Satu potongan rusak = gagal total, tidak ada plaintext parsial.",
        "enc.dropzone": "Seret &amp; letakkan file di sini, atau klik untuk memilih.",
        "enc.dropzoneAria": "Pilih atau seret file untuk dienkripsi",
        "enc.fileBtn": "Enkripsi File &amp; Unduh .qekhf",
        "encrypt.btnBusy": "Mengenkripsi & menandatangani...",
        "encrypt.emptyMsg": "Pesan masih kosong — tulis dulu plaintext-nya.",
        "encrypt.okToast": "Pesan terenkripsi & tertandatangani.",
        "encrypt.binMissing": "Enkripsi dulu — belum ada ciphertext.",
        "encrypt.binToast": "Ciphertext biner diunduh ({bytes} byte, ~{saving}% lebih kecil dari base64).",
        "encrypt.binFailed": "Gagal membuat format biner: {msg}",
        "encrypt.binTooBig": "file terlalu besar — ini bukan ciphertext pesan (maks ~16 MiB base64).",
        "encrypt.binLoaded": "File .qekhb dimuat ({bytes} byte) — ciphertext siap, lanjut dekripsi.",
        "encrypt.binInvalid": "File .qekhb tidak valid: {msg}",
        "encrypt.expiresExpired": "  ⏰ KEDALUWARSA sejak {date}",
        "encrypt.expiresValid": "  (berlaku s/d {date})",
        "charCount": "{chars} karakter · {bytes} byte · perkiraan ciphertext ≈ {kb} KB base64",
        "dec.title": "Dekripsi &amp; Verifikasi Pesan",
        "dec.desc": "Gunakan Kunci Privat Anda untuk membuka pesan. Isi juga Kunci Publik Pengirim (opsional, tapi sangat disarankan) untuk memverifikasi tanda tangannya.",
        "dec.privLabel": "Kunci Privat Hibrida Anda (JSON)",
        "dec.privPh": "Tempel Kunci Privat Hibrida berformat JSON Anda di sini...",
        "dec.passLabel": "Passphrase Kunci Privat Anda",
        "dec.cipherLabel": "Ciphertext Hibrida (Base64)",
        "dec.cipherPh": "Tempel ciphertext dari pengirim...",
        "dec.openBin": "📂 Buka file .qekhb (biner mentah)",
        "dec.openBinTitle": "Buka file biner mentah QEKHB1 (hasil \"Unduh .qekhb\" tab 2) — otomatis dikonversi ke base64",
        "dec.contactLabel": "Pengirim dari Buku Kontak",
        "dec.senderLabel": "Kunci Publik Pengirim (opsional, untuk verifikasi tanda tangan)",
        "dec.senderPh": "Tempel Kunci Publik Hibrida milik pengirim yang SUDAH Anda verifikasi fingerprint-nya...",
        "dec.fpHint": "Harus cocok dengan fingerprint yang sudah Anda verifikasi langsung dengan pengirim sebelumnya.",
        "dec.btn": "Dekripsi Pesan",
        "dec.outLabel": "Teks Asli (Decrypted)",
        "dec.outPh": "Hasil dekripsi akan muncul di sini...",
        "dec.copyAria": "Salin hasil dekripsi",
        "dec.fileTitle": "Dekripsi FILE .qekhf",
        "dec.fileDesc": "Memakai Kunci Privat dan Kunci Publik Pengirim di atas. Setiap potongan diautentikasi — bila satu pun rusak/diubah, file DITOLAK utuh (tidak ada hasil parsial).",
        "dec.fileLabel": "File .qekhf",
        "dec.fileBtn": "Dekripsi File &amp; Unduh Hasil",
        "decrypt.btnBusy": "Mendekripsi & memverifikasi...",
        "verify.ok": "✅ <strong>Tanda tangan VALID</strong> (Ed25519 ✓ dan SLH-DSA ✓). Pesan ini benar ditandatangani oleh pemilik Kunci Publik yang Anda tempel — selama fingerprint-nya memang sudah Anda verifikasi lewat jalur terpisah.",
        "verify.failed": "❌ <strong>Tanda tangan TIDAK VALID</strong> (Ed25519 {ed}, SLH-DSA {slh}). JANGAN percaya isi pesan ini — bisa jadi pesan sudah diubah, atau pengirimnya bukan pemilik Kunci Publik yang Anda tempel.",
        "verify.unverified": "⚠️ <strong>Pengirim TIDAK diverifikasi.</strong> Kunci Publik pengirim tidak diisi, jadi pesan berhasil didekripsi tanpa bukti siapa pengirimnya.",
        "meta.signedAt": "🕐 Ditandatangani pada: {date}",
        "meta.from": "Sidik jari pengirim (klaim dari dalam pesan): {fp}",
        "meta.fromMatch": "✓ Klaim sidik jari cocok dengan Kunci Publik yang Anda tempel.",
        "meta.fromMismatch": "⚠️ Klaim sidik jari TIDAK cocok dengan Kunci Publik yang Anda tempel!",
        "meta.toMismatch": "⚠️ Catatan: metadata penerima di dalam pesan tidak cocok dengan kunci Anda (inkonsistensi sisi pengirim).",
        "file.chosen": "Dipilih: {name} · {size} KB",
        "file.pickFirst": "Pilih atau seret file dulu ke kotak di atas.",
        "file.encBusy": "Mengenkripsi file...",
        "file.encOk": "File terenkripsi: {chunks} chunk × 64 KiB — kunci file tersegel untuk penerima.",
        "file.encFailed": "Enkripsi file gagal: {msg}",
        "file.decPick": "Pilih file .qekhf dulu.",
        "file.decBusy": "Mendekripsi file...",
        "file.decOk": "File \"{name}\" terdekripsi utuh ({chunks} chunk).",
        "file.decFailed": "Dekripsi file gagal: {msg}",
        "rad.title": "Mode Radiogram (Burst)",
        "rad.desc": "Konversi ciphertext Q-EKH menjadi grup 5 huruf kapital (base32 RFC 4648) yang bisa dibacakan lewat voice/CW dan disalin tangan tanpa ambiguitas. Sebelum memencet PTT, lihat estimasi durasi pancar — makin singkat di udara, makin sulit dilokasi RDF.",
        "rad.inputLabel": "Ciphertext (base64) — atau grup huruf untuk arah sebaliknya",
        "rad.inputPh": "Tempel ciphertext base64 dari tab Enkripsi... (grup huruf juga dikenali otomatis dan diubah balik ke base64)",
        "rad.btn": "Konversi",
        "rad.outLabel": "Hasil Radiogram",
        "rad.outPh": "QEKH5 ... grup huruf akan muncul di sini...",
        "rad.copyAria": "Salin radiogram",
        "rad.download": "⬇ Unduh radiogram",
        "rad.print": "🖨 Cetak lembar salin-tangan",
        "rad.rateLabel": "Laju pancar",
        "rad.wpmOpt": "WPM (kata/menit, PARIS)",
        "rad.bpsOpt": "bps (bit/detik)",
        "rad.cwLabel": "Putar sebagai CW (morse) — nada 600 Hz, semua lokal",
        "rad.cwTitle": "Kecepatan CW dalam WPM (PARIS)",
        "rad.cwPlay": "▶ Putar CW",
        "rad.cwWav": "⬇ Unduh .wav",
        "rad.cwHint": "Timing PARIS (unit = 1200/WPM ms). Header \"QEKH5 … GRUP\" ikut dimainkan sebagai penanda di udara. File .wav bisa diputar ke pemancar/HP lain — seluruh radiogram terpancar tanpa mengetik ulang.",
        "rad.fhssTitle": "Jadwal FHSS dari kunci bersama (C.4)",
        "rad.fhssDesc": "Tabel waktu → kanal pseudo-acak yang <strong>sama di kedua pihak</strong>, diturunkan dari kunci bersama + tanggal lewat HKDF-SHA256. Murni tampilan — radio tetap Anda operasikan manual sesuai tabel. Kedua pihak wajib memakai kunci, tanggal, jumlah kanal, dan durasi slot yang persis sama.",
        "rad.fhssKeyLabel": "Kunci bersama (teks rahasia apa pun — mis. passphrase yang disepakati tatap muka)",
        "rad.fhssKeyPh": "Kunci bersama...",
        "rad.fhssDateTitle": "Tanggal jadwal",
        "rad.fhssChTitle": "Jumlah kanal",
        "rad.fhssSlot60": "slot 60 menit",
        "rad.fhssSlot30": "slot 30 menit",
        "rad.fhssSlot15": "slot 15 menit",
        "rad.fhssSlot10": "slot 10 menit",
        "rad.fhssBtn": "Buat jadwal",
        "radio.empty": "Tempel ciphertext Q-EKH dulu.",
        "radio.lettersOk": "Grup huruf dikenali — hasil base64 siap ditempel di tab Dekripsi.",
        "radio.notBase64": "Input bukan base64 dan bukan grup huruf.",
        "radio.ready": "Radiogram siap: {groups} grup.",
        "radio.estNoteOk": "Durasi pendek — risiko deteksi arah (RDF) relatif rendah.",
        "radio.estNoteWarn": "Cukup lama di udara — stasiun RDF punya kesempatan mengukur. Usahakan burst & pindah lokasi.",
        "radio.estNoteDanger": "LAMA di udara — risiko RDF tinggi. Persingkat pesan, naikkan laju, atau pakai pemancar terpisah/jauh.",
        "radio.estLine": "⏱ Perkiraan durasi pancar: ≈ {dur} ({chars} karakter). {note}",
        "radio.estMinutes": "{n} menit",
        "radio.estSeconds": "{n} detik",
        "print.title": "LEMBAR RADIOGRAM — Q-EKH",
        "print.sub": "Dicetak {date} · {groups} grup · base32 RFC 4648 (A–Z, 2–7)",
        "print.headerLine": "Header pancar: {header}",
        "print.foot": "Total {groups} grup. Salin/bacakan per grup; corek ☐ tiap grup yang sudah terkirim atau tersalin. Cocokkan jumlah grup di ujung. Musnahkan lembar ini setelah terkirim.",
        "print.missing": "Konversi dulu ciphertext-nya — belum ada radiogram untuk dicetak.",
        "print.notGroups": "Output bukan radiogram grup huruf — tidak bisa dicetak sebagai lembar salin.",
        "cw.playMissing": "Konversi dulu ciphertext-nya — belum ada radiogram untuk dimainkan.",
        "cw.downloadMissing": "Konversi dulu ciphertext-nya — belum ada radiogram untuk diunduh.",
        "cw.stop": "■ Stop",
        "cw.playToast": "Memutar CW {wpm} WPM — durasi ≈ {sec} detik.",
        "cw.playFailed": "Gagal memutar CW: {msg}",
        "cw.wavFailed": "Gagal membuat WAV: {msg}",
        "cw.noWebAudio": "WebAudio tidak tersedia di browser ini.",
        "fhss.toast": "Jadwal FHSS {date}: {slots} slot × {channels} kanal. Cocokkan dengan tabel milik lawan bicara.",
        "otp.title": "OTP Terautentikasi &amp; Buku Pad",
        "otp.warnTitle": "⚠️ OTP-v2: pad acak + autentikasi + anti pemakaian ulang",
        "otp.warnText": "XOR dengan pad acak satu-kali sudah sempurna secara teori (Shannon), dan itu tidak berubah. Yang ditambahkan di sini: <strong>tag HMAC-SHA256</strong> (kuncinya dari segmen buku yang terpisah) supaya perubahan ciphertext terdeteksi, <strong>registry anti-reuse</strong> supaya pad tak pernah dipakai dua kali, dan penolakan otomatis saat buku habis. Catatan jujur: autentikasinya kuat secara komputasional (\"setara AES\"), bukan information-theoretic. Distribusi buku pad tetap harga mati: tukar file .qpad secara aman/tatap muka.",
        "otp.bookTitle": "1. Buku Pad",
        "otp.bookLabel": "Buat buku pad baru",
        "otp.bookOpt64": "64 KiB (bisa diekspor grup huruf)",
        "otp.bookOpt1M": "1 MiB (standar lapangan)",
        "otp.bookOpt4M": "4 MiB",
        "otp.bookOpt8M": "8 MiB",
        "otp.bookBtn": "Buat &amp; unduh .qpad",
        "otp.fileLabel": "Muat buku pad dari file",
        "otp.textLabel": "Muat dari teks (base64 / grup huruf)",
        "otp.textPh": "Tempel base64 atau grup huruf buku pad kecil...",
        "otp.textBtn": "Muat dari teks",
        "otp.lettersBtn": "Ekspor grup huruf (buku ≤ 64 KiB)",
        "otp.destroyBtn": "Musnahkan segmen terpakai",
        "otp.forgetBtn": "Lupakan buku",
        "otp.sendTitle": "2. Kirim pesan",
        "otp.sendLabel": "Pesan",
        "otp.sendPh": "Tulis pesan — akan memakai segmen baru dari buku pad...",
        "otp.sendBtn": "Buat Paket OTP-v2",
        "otp.packetLabel": "Paket (base64)",
        "otp.copyAria1": "Salin paket OTP",
        "otp.lettersLabel": "Paket (grup huruf untuk radio)",
        "otp.copyAria2": "Salin grup huruf OTP",
        "otp.recvTitle": "3. Terima pesan",
        "otp.recvLabel": "Paket masuk (base64 / grup huruf)",
        "otp.recvPh": "Tempel paket OTP-v2...",
        "otp.recvBtn": "Verifikasi &amp; Dekripsi OTP",
        "otp.outLabel": "Hasil",
        "otp.copyAria3": "Salin hasil OTP",
        "otp.noBook": "Belum ada buku pad yang dimuat. Buat baru atau muat file .qpad — ingat, kedua pihak harus memegang salinan IDENTIK.",
        "otp.statusLine": "Buku pad {id}… · {size} KiB · terpakai {used}% · sisa ≈ {left} KiB (~{msgs} pesan pendek)",
        "otp.exhausted": "⛔ Buku pad habis. Enkripsi baru ditolak — buat & tukar buku baru dengan lawan bicara.",
        "otp.loaded": "Buku pad {id}… dimuat ({source}).",
        "otp.sourceNew": "baru dibuat",
        "otp.sourceFile": "file {name}",
        "otp.sourceLetters": "grup huruf",
        "otp.sourceB64": "base64",
        "otp.exchangeWarn": "Tukar file .qpad dengan lawan bicara lewat jalur AMAN (tatap muka). JANGAN lewat internet.",
        "otp.loadFailed": "Gagal memuat buku pad: {msg}",
        "otp.loadFirst": "Tempel base64/grup huruf buku pad dulu.",
        "otp.loadBookFirst": "Muat/buat buku pad dulu.",
        "otp.noBookShort": "Belum ada buku pad.",
        "otp.tooBig": "Buku terlalu besar untuk grup huruf (> 64 KiB). Pakai file .qpad.",
        "otp.exported": "Buku pad diekspor sebagai grup huruf ke kolom muat.",
        "otp.destroyConfirm": "Musnahkan semua segmen terpakai (zero-fill)? Paket lama yang merujuk segmen itu tidak akan bisa diverifikasi/dibuka lagi.",
        "otp.destroyOk": "Musnahkan",
        "otp.destroyed": "{bytes} byte segmen terpakai dimusnahkan.",
        "otp.forgetConfirm": "Lupakan buku pad ini? Registry pemakaiannya dihapus dan buku dibuang dari memori. Pastikan salinan .qpad-nya masih ada bila masih diperlukan.",
        "otp.forgetOk": "Lupakan",
        "otp.forgotten": "Buku pad dilupakan.",
        "otp.sendNeedBook": "Muat atau buat buku pad dulu.",
        "otp.sendOk": "Paket OTP-v2 dibuat ({bytes} byte pad terpakai, tidak akan dipakai ulang).",
        "otp.recvNeedBook": "Muat buku pad dulu — paket hanya bisa dibuka dengan buku yang sama.",
        "otp.reuseAlert": "🚨 PAD TERDETEKSI DIPAKAI ULANG: offset paket ini sama dengan paket lain yang isinya BERBEDA. Keamanan pesan-pesan pada offset itu runtuh — ganti buku pad SEKARANG dan selidiki sumbernya.",
        "otp.duplicateNote": "ℹ️ Paket ini persis sama dengan yang sudah pernah diterima (duplikat) — tidak ada segmen baru yang terpakai.",
        "con.title": "Buku Kontak &amp; Verifikasi",
        "con.desc": "Simpan Kunci Publik lawan bicara sekali, lalu pilih dari dropdown di tab Enkripsi/Dekripsi — tidak perlu tempel-menempel berulang (rawan salah tempel = celah MITM praktis). Kontak baru selalu berstatus <strong>belum diverifikasi</strong>; tandai terverifikasi hanya setelah fingerprint-nya Anda cocokkan lewat jalur terpisah (tatap muka/QR/telepon).",
        "con.addTitle": "Tambah kontak",
        "con.nameLabel": "Nama",
        "con.namePh": "Mis. Stasiun Alfa",
        "con.keyLabel": "Kunci Publik Hibrida (JSON)",
        "con.keyPh": "Tempel Kunci Publik kontak...",
        "con.btn": "Tambah ke Buku Kontak",
        "contacts.manualOption": "— tempel manual —",
        "contacts.expiredSuffix": " ⏰KEDALUWARSA",
        "contacts.unverifiedSuffix": " ⚠️belum-verifikasi",
        "contacts.empty": "Belum ada kontak. Tambahkan Kunci Publik lawan bicara di bawah — lalu verifikasi fingerprint-nya lewat jalur terpisah.",
        "contacts.badgeExpired": "⏰ kunci kedaluwarsa",
        "contacts.badgeVerified": "✅ terverifikasi",
        "contacts.badgeUnverified": "⚠️ belum diverifikasi",
        "contacts.verifiedAt": "Diverifikasi: {date}.",
        "contacts.expiresAt": "Berlaku s/d: {date}.",
        "contacts.useEncrypt": "Pakai di Enkripsi",
        "contacts.useDecrypt": "Pakai di Dekripsi",
        "contacts.qrBtn": "QR fingerprint",
        "contacts.markVerified": "Tandai terverifikasi",
        "contacts.markVerifiedConfirm": "Anda akan menandai \"{name}\" sebagai TERVERIFIKASI.\n\nPastikan fingerprint di atas sudah Anda cocokkan LANGSUNG dengan pemiliknya (tatap muka/QR/telepon), bukan lewat saluran yang sama dengan kunci dikirim. Yakin?",
        "contacts.markVerifiedOk": "Ya, sudah saya cocokkan",
        "contacts.markVerifiedToast": "Kontak \"{name}\" ditandai terverifikasi.",
        "contacts.deleteConfirm": "Hapus kontak \"{name}\" dari buku alamat?",
        "contacts.deletedToast": "Kontak \"{name}\" dihapus.",
        "contacts.useEncryptToast": "Kunci Publik \"{name}\" dipakai di tab Enkripsi.",
        "contacts.useDecryptToast": "Kunci Publik \"{name}\" dipakai di tab Dekripsi.",
        "contacts.nameRequired": "Isi nama kontak dulu.",
        "contacts.duplicate": "Kunci ini sudah ada di buku kontak.",
        "contacts.added": "Kontak \"{name}\" ditambahkan — status: BELUM diverifikasi.",
        "contacts.saveFailed": "Gagal menyimpan kontak — penyimpanan lokal penuh/ditolak.",
        "contacts.expiredWarn": "⏰ Kunci \"{name}\" sudah KEDALUWARSA ({date}). Minta kunci baru ke pemiliknya.",
        "contacts.unverifiedWarn": "⚠️ Kontak \"{name}\" BELUM diverifikasi fingerprint-nya. Enkripsi tetap bisa jalan, tapi pastikan dulu lewat jalur terpisah.",
        "about.title": "Tentang Protokol Q-EKH",
        "about.cred": "\"Saya Adalah Mr. J0121312, website ini kredit dari saya.\"",
        "about.intro": "<strong>Q-EKH</strong> adalah protokol enkripsi hibrida pasca-kuantum yang TERAUTENTIKASI. Ada dua lapisan yang bekerja terpisah: lapisan <strong>kerahasiaan</strong> (X25519 + ML-KEM-768) dan lapisan <strong>keaslian pengirim</strong> (Ed25519 + SLH-DSA-192s, tanda tangan ganda).",
        "about.why": "Mengapa Ini Pilihan yang Bagus?",
        "about.why1": "<strong>Kerahasiaan Berlapis:</strong> X25519 (ECC klasik) dan ML-KEM-768 (pasca-kuantum) digabung lewat HKDF dengan urutan rahasia-PQ-lebih-dulu — mengikuti prinsip yang sama dipakai konstruksi hybrid standar seperti TLS 1.3 dan X-Wing — aman selama salah satu dari keduanya belum bisa dipecahkan.",
        "about.why2": "<strong>Keaslian Berlapis:</strong> Setiap pesan ditandatangani DUA kali — Ed25519 (klasik, cepat, teruji puluhan tahun) dan SLH-DSA-192s (berbasis fungsi hash, bukan matematika kisi seperti ML-KEM). Keduanya harus valid. Fondasinya sengaja beda dari lapisan enkripsi, supaya kalau suatu saat ada celah di kriptografi lattice, tanda tangan Anda tidak ikut runtuh.",
        "about.why3": "<strong>Kesiapan Masa Depan:</strong> ML-KEM-768 dan SLH-DSA-192s dirancang tahan komputer kuantum, berdasarkan pengetahuan kriptografi saat ini.",
        "about.quote": "Analoginya seperti mengunci brankas dengan dua gembok berbeda jenis, lalu menyegelnya dengan dua meterai berbeda jenis juga. Penyerang harus membobol satu gembok DAN memalsukan satu meterai — dan dua meterai itu sengaja dibuat dari bahan yang beda total.",
        "about.signTitle": "⚠️ Tanda Tangan Hanya Berarti Kalau Kunci Publiknya Sudah Anda Verifikasi",
        "about.signText": "Tanda tangan digital membuktikan \"pesan ini cocok dengan kunci privat pemegang kunci publik X\" — tapi TIDAK membuktikan kunci publik X itu benar milik orang yang Anda maksud, kecuali Anda sendiri yang sudah memverifikasinya. Alur yang benar selalu: <strong>verifikasi Fingerprint lewat jalur terpisah dulu</strong> (tab 6 Kontak mendukung QR tatap muka), baru simpan Kunci Publik itu sebagai yang dipercaya, baru pakai untuk verifikasi tanda tangan pesan-pesan berikutnya.",
        "about.supplyTitle": "Pengerasan Sisi Pasokan (yang baru)",
        "about.supply1": "<strong>Tanpa CDN:</strong> semua pustaka kripto disimpan lokal di folder <code>vendor/</code> dan hash SHA-256-nya tercatat di <code>vendor/HASHES.txt</code> untuk diaudit ulang. Halaman berjalan 100% offline.",
        "about.supply2": "<strong>Self-test saat startup:</strong> HKDF (RFC 5869), AES-256-GCM (vektor NIST), Argon2id (RFC 9106), ML-KEM-768, SLH-DSA, X25519, dan Ed25519 diuji dulu; bila ada yang gagal, semua tombol aksi terkunci otomatis.",
        "about.supply3": "<strong>CSP ketat:</strong> skrip &amp; gaya hanya dari origin sendiri; tidak ada koneksi jaringan keluar dari halaman.",
        "about.fieldTitle": "Fitur Lapangan",
        "about.field1": "<strong>Tombol 🚨 Panik + auto-lock idle:</strong> satu tombol di header (atau timer idle yang bisa diatur di footer) memusnahkan kontak &amp; registry buku pad dari penyimpanan lokal, mengosongkan semua kolom di layar, lalu memuat ulang halaman.",
        "about.field2": "<strong>Sidik visual (randomart):</strong> di samping setiap fingerprint hex tampil gambar identicon 9×9 yang diturunkan dari hash yang sama — mencocokkan gambar jauh lebih cepat dan tahan-salah daripada membandingkan 64 karakter hex saat verifikasi tatap muka.",
        "about.field3": "<strong>Radiogram → CW:</strong> tab Radiogram bisa memainkan grup huruf sebagai nada morse 600 Hz (timing PARIS, WPM bisa diatur) langsung dari browser, atau mengunduhnya sebagai file .wav untuk diputar ke pemancar.",
        "about.field4": "<strong>Lembar cetak salin-tangan:</strong> tombol \"Cetak lembar\" di tab Radiogram menghasilkan lembar A5 berisi kotak per grup berhuruf mono besar, nomor urut, dan kotak ceklis — meminimalkan salah salin saat menyalin dengan tangan.",
        "about.field5": "<strong>Enkripsi FILE (.qekhf):</strong> tab Enkripsi/Dekripsi kini menerima file (seret &amp; letakkan). Isi dipotong per 64 KiB dan tiap potongan diautentikasi AES-256-GCM (konstruksi STREAM); kunci file acak disegel sebagai pesan v5 — satu potongan rusak berarti file ditolak utuh.",
        "about.field6": "<strong>Output biner mentah (.qekhb):</strong> tombol \"Unduh .qekhb\" di tab Enkripsi menghasilkan ciphertext v5 sebagai biner mentah tanpa base64/JSON — ~25% lebih kecil, untuk toolchain radio milik sendiri. Tab Dekripsi bisa membukanya lagi (tombol \"Buka file .qekhb\"); konversinya bijektif, tidak mengubah satu bit pun kriptografi (SPEC §8).",
        "about.field7": "<strong>Bucket ukuran konstan:</strong> opsi padding di tab Enkripsi yang membuat semua ciphertext persis kelipatan 32–256 KB, melawan analisis ukuran yang lebih teliti daripada blok acak 512 B.",
        "about.field8": "<strong>Spesifikasi formal:</strong> seluruh format (envelope v5, OTP-v2, .qpad, .qekhf, fingerprint) didokumentasikan byte-per-byte di <code>docs/SPEC.md</code> beserta test vector deterministik <code>docs/test-vectors.json</code> — memungkinkan audit dan implementasi ulang.",
        "about.hybridTitle": "Konsep Kunci Hibrida",
        "about.hybrid1": "<strong>Kunci Publik (Public Key):</strong> Gembok digital sekaligus meterai verifikasi — boleh dibagikan bebas.",
        "about.hybrid2": "<strong>Kunci Privat (Private Key):</strong> Dipakai untuk membuka gembok (dekripsi) DAN membubuhkan meterai (tanda tangan). <span class=\"warning\">TIDAK BOLEH DIBAGIKAN.</span>",
        "about.hybridShort": "Singkatnya: <strong>Bagikan gemboknya (Publik), simpan kuncinya (Privat).</strong>",
        "about.usageTitle": "Instruksi Penggunaan",
        "about.usage1": "<strong>Membuat Kunci:</strong> Di tab 1, klik \"Buat Pasangan Kunci\". Bagikan Kunci Publik dan Fingerprint lewat jalur terpisah, simpan Kunci Privat baik-baik.",
        "about.usage2": "<strong>Mengenkripsi:</strong> Di tab 2, pilih kontak penerima (atau tempel Kunci Publik-nya, cocokkan fingerprint-nya) DAN Kunci Privat Anda sendiri, tulis pesan, klik \"Enkripsi &amp; Tandatangani\".",
        "about.usage3": "<strong>Mendekripsi:</strong> Di tab 3, tempel Kunci Privat Anda dan ciphertext-nya. Untuk verifikasi, pilih kontak pengirim yang fingerprint-nya sudah Anda cocokkan sebelumnya.",
        "about.usage4": "<strong>Radio:</strong> Di tab 4, konversi ciphertext ke grup huruf + ukur estimasi durasi pancar. Di tab 5, pakai buku pad untuk OTP terautentikasi satu-arah tanpa kunci publik sama sekali.",
        "about.honesty": "Catatan jujur: primitif pasca-kuantum di sini (ML-KEM, SLH-DSA) berasal dari pustaka <code>@noble/post-quantum</code> yang baru \"self-audited\" oleh pembuatnya sendiri, belum lewat audit independen pihak ketiga, dan implementasi JS-nya tidak mengklaim tahan side-channel. Cukup baik untuk proyek pribadi/edukasi seperti ini."
    }, en: {
        "common.copy": "Copy",
        "common.copied": "Copied!",
        "common.cancel": "Cancel",
        "common.confirm": "Continue",
        "common.delete": "Delete",
        "common.download": "Download",
        "common.copyFailed": "Copy failed — the browser denied clipboard access.",
        "common.fileDownloaded": "File \"{name}\" downloaded.",
        "common.invalidKey": "Invalid key: {msg}",
        "header.sub": "Hybrid post-quantum encryption &amp; authentication (X25519 + ML-KEM-768, signed with Ed25519 + SLH-DSA-192s). 100% local &amp; offline — no CDN.",
        "header.themeAria": "Toggle light/dark theme",
        "header.themeTitle": "Toggle theme",
        "header.panicAria": "Panic button: wipe local data and reload the page",
        "header.panicTitle": "Panic: delete contacts &amp; pad registry, clear the screen, reload",
        "header.panic": "🚨 Panic",
        "tabs.generate": "1. Create Keys",
        "tabs.encrypt": "2. Encrypt",
        "tabs.decrypt": "3. Decrypt",
        "tabs.radiogram": "4. Radiogram",
        "tabs.otp": "5. OTP &amp; Pad Book",
        "tabs.contacts": "6. Contacts",
        "tabs.about": "7. About",
        "selftest.failedTitle": "⛔ SELF-TEST FAILED — do not use this page.",
        "selftest.failedDetail": "{reason} The crypto library is corrupted or has been tampered with; re-download the app from a trusted source.",
        "selftest.noSubtle": "Web Crypto API is not available. Open this page via https:// or http://127.0.0.1 — not a plain network IP address (http://192.168.x.x), because browsers block crypto.subtle there.",
        "footer.selftest.pending": "Self-test: not run yet",
        "footer.selftest.running": "Self-test: running…",
        "footer.selftest.ok": "Self-test: OK",
        "footer.selftest.failed": "Self-test: FAILED",
        "footer.note": "Web Crypto API (X25519, Ed25519, HKDF, AES-GCM) + local libraries in <code>vendor/</code> (@noble/post-quantum, @noble/hashes) — no CDN, fully offline capable.",
        "footer.autolockLabel": "Auto-lock on idle:",
        "footer.autolock0": "off",
        "footer.autolock5": "5 minutes",
        "footer.autolock10": "10 minutes",
        "footer.autolock30": "30 minutes",
        "footer.langLabel": "Bahasa / Language:",
        "panic.confirm": "PANIC: all contacts, the pad book registry, and everything on screen will be WIPED now, then the page reloads.\n\nThis cannot be undone. .qpad files & keys you have already downloaded/stored elsewhere are not affected.",
        "panic.ok": "WIPE NOW",
        "autolock.off": "Auto-lock disabled.",
        "autolock.on": "Auto-lock active: the session locks after {min} minutes of inactivity.",
        "autolock.fired": "🔒 Auto-lock: session locked due to idleness — contacts, pad registry, and on-screen content have been cleared.",
        "qr.libraryMissing": "QR library failed to load.",
        "qr.tooLong": "Text is too long for a QR code.",
        "fpArt.aria": "Visual fingerprint (randomart) derived from the fingerprint",
        "gen.title": "Hybrid Identity Creation",
        "gen.desc": "Creates 4 key pairs at once: X25519 + ML-KEM-768 for encryption, plus Ed25519 and SLH-DSA-192s for signing. Keep your Private Key very safe, and share the Public Key + Fingerprint with your correspondent over a separate channel.",
        "gen.passLabel": "Private Key Passphrase (optional)",
        "gen.passPh": "Leave empty for an unencrypted key; do not forget this passphrase.",
        "gen.passHint": "The passphrase cannot be recovered. The private key is encrypted with Argon2id (run in a Web Worker — the UI does not freeze).",
        "gen.expiresLabel": "Key Expiry (optional)",
        "gen.expiresHint": "If filled in, this date is embedded in the Public Key and the app will remind your correspondent when the key expires. Regular rotation limits the damage if a key leaks.",
        "gen.btn": "Create New Hybrid Key Pair",
        "gen.btnBusy": "Creating keys...",
        "gen.pubLabel": "Hybrid Public Key (JSON - Share this)",
        "gen.pubPh": "The combined Public Key will be created here...",
        "gen.pubCopyAria": "Copy public key",
        "gen.downloadPub": "⬇ Download public key",
        "gen.fpLabel": "Identity Fingerprint (for anti-MITM verification)",
        "gen.fpPlaceholder": "Create keys to see the fingerprint...",
        "gen.fpCopy": "Copy fingerprint",
        "gen.fpHint": "Read or send this fingerprint to your correspondent over another channel (phone, in person, separate chat) — or show the QR below when meeting face to face. The image box beside it is the <strong>visual fingerprint</strong> (randomart) of the same fingerprint — human eyes match pictures far faster than 64 hex characters. This is what makes signatures truly meaningful.",
        "gen.privLabel": "Hybrid Private Key (JSON - KEEP IT SECRET)",
        "gen.privPh": "The combined Private Key will be created here...",
        "gen.privCopyAria": "Copy private key",
        "gen.downloadPriv": "⬇ Download private key",
        "gen.waitArgon": "Please wait, creating 4 key pairs + encrypting the private key (Argon2id, ±2 seconds)...",
        "gen.waitPlain": "Please wait, creating 4 key pairs...",
        "gen.fpComputing": "Computing...",
        "gen.okToast": "New key pair created.",
        "gen.fail": "Failed to create keys.",
        "gen.overwriteConfirm": "The keys currently displayed will be overwritten. Make sure the old Private Key is stored safely. Continue?",
        "gen.expiryInvalid": "The expiry date is not valid.",
        "gen.expiryPast": "The expiry date must be in the future.",
        "dialog.downloadPriv": "Download the Private Key as a file? Anyone holding this file (plus its passphrase) holds your identity.",
        "enc.title": "Encrypt &amp; Sign Message",
        "enc.desc": "Select the recipient contact (or paste their Public Key) and your own Private Key (used to sign, not to encrypt).",
        "enc.contactLabel": "Recipient from Contact Book",
        "enc.pubLabel": "Recipient Hybrid Public Key (JSON)",
        "enc.pubPh": "Paste the recipient Hybrid Public Key here...",
        "enc.fpLabel": "Pasted Key Fingerprint",
        "enc.fpHint": "Match it with the fingerprint read out to you directly by the recipient before sending a secret message.",
        "enc.privLabel": "Your Private Key (to sign this message)",
        "enc.privPh": "Paste your own Hybrid Private Key here...",
        "enc.passLabel": "Your Private Key Passphrase",
        "enc.passPh": "Fill in if the Private Key is encrypted.",
        "enc.plainLabel": "Plain Text (Plaintext)",
        "enc.plainPh": "Write your secret message here...",
        "enc.bucketLabel": "Size Padding (anti size analysis)",
        "enc.bucketOpt0": "Random 512 B blocks (default — recommended)",
        "enc.bucketOpt32": "Constant bucket 32 KB",
        "enc.bucketOpt64": "Constant bucket 64 KB",
        "enc.bucketOpt128": "Constant bucket 128 KB",
        "enc.bucketOpt256": "Constant bucket 256 KB",
        "enc.bucketHint": "Constant buckets make every message appear to be an exact multiple of N KB — useful if an observer carefully logs your burst sizes. Consequence: larger ciphertext; messages exceeding the bucket are rejected.",
        "enc.btn": "Encrypt &amp; Sign Message",
        "enc.outLabel": "Hybrid Ciphertext (Base64)",
        "enc.outPh": "Encryption + signature result will appear here...",
        "enc.copyAria": "Copy ciphertext",
        "enc.download": "⬇ Download ciphertext",
        "enc.downloadBin": "⬇ Download .qekhb (raw binary)",
        "enc.downloadBinTitle": "QEKHB1 raw binary format — ~25% smaller, for your radio toolchain",
        "enc.hintRadio": "To transmit over radio (voice/CW): open tab <strong>4. Radiogram</strong> to convert to letter groups + transmission duration estimate. <strong>.qekhb</strong> = the v5 envelope as raw binary (no base64/JSON) — for your own radio toolchain; can be opened again in tab 3.",
        "enc.fileTitle": "FILE Encryption (chunked .qekhf)",
        "enc.fileDesc": "The file is cut into 64 KiB pieces and each piece is AES-256-GCM-encrypted (nonce = random prefix ‖ counter ‖ flagLAST, STREAM-style); the random 32-byte file key is sealed as a v5 message to the recipient above — so your signature is carried along. One corrupted piece = total failure, no partial plaintext.",
        "enc.dropzone": "Drag &amp; drop a file here, or click to choose.",
        "enc.dropzoneAria": "Pick or drag a file to encrypt",
        "enc.fileBtn": "Encrypt File &amp; Download .qekhf",
        "encrypt.btnBusy": "Encrypting & signing...",
        "encrypt.emptyMsg": "The message is still empty — write the plaintext first.",
        "encrypt.okToast": "Message encrypted & signed.",
        "encrypt.binMissing": "Encrypt first — there is no ciphertext yet.",
        "encrypt.binToast": "Binary ciphertext downloaded ({bytes} bytes, ~{saving}% smaller than base64).",
        "encrypt.binFailed": "Failed to build the binary format: {msg}",
        "encrypt.binTooBig": "file too large — this is not a message ciphertext (max ~16 MiB base64).",
        "encrypt.binLoaded": "Loaded the .qekhb file ({bytes} bytes) — ciphertext ready, continue to decrypt.",
        "encrypt.binInvalid": "Invalid .qekhb file: {msg}",
        "encrypt.expiresExpired": "  ⏰ EXPIRED since {date}",
        "encrypt.expiresValid": "  (valid until {date})",
        "charCount": "{chars} chars · {bytes} bytes · estimated ciphertext ≈ {kb} KB base64",
        "dec.title": "Decrypt &amp; Verify Message",
        "dec.desc": "Use your Private Key to open the message. Also fill in the Sender Public Key (optional, but strongly recommended) to verify its signature.",
        "dec.privLabel": "Your Hybrid Private Key (JSON)",
        "dec.privPh": "Paste your Hybrid Private Key in JSON format here...",
        "dec.passLabel": "Your Private Key Passphrase",
        "dec.cipherLabel": "Hybrid Ciphertext (Base64)",
        "dec.cipherPh": "Paste the ciphertext from the sender...",
        "dec.openBin": "📂 Open .qekhb file (raw binary)",
        "dec.openBinTitle": "Open a QEKHB1 raw binary file (result of \"Download .qekhb\" in tab 2) — automatically converted to base64",
        "dec.contactLabel": "Sender from Contact Book",
        "dec.senderLabel": "Sender Public Key (optional, for signature verification)",
        "dec.senderPh": "Paste the sender's Hybrid Public Key whose fingerprint you have ALREADY verified...",
        "dec.fpHint": "Must match the fingerprint you previously verified directly with the sender.",
        "dec.btn": "Decrypt Message",
        "dec.outLabel": "Original Text (Decrypted)",
        "dec.outPh": "Decryption result will appear here...",
        "dec.copyAria": "Copy decryption result",
        "dec.fileTitle": "Decrypt FILE .qekhf",
        "dec.fileDesc": "Uses the Private Key and Sender Public Key above. Every piece is authenticated — if any is corrupted/altered, the file is REJECTED whole (no partial result).",
        "dec.fileLabel": ".qekhf File",
        "dec.fileBtn": "Decrypt File &amp; Download Result",
        "decrypt.btnBusy": "Decrypting & verifying...",
        "verify.ok": "✅ <strong>SIGNATURE VALID</strong> (Ed25519 ✓ and SLH-DSA ✓). This message was genuinely signed by the owner of the Public Key you pasted — provided you verified its fingerprint over a separate channel.",
        "verify.failed": "❌ <strong>SIGNATURE NOT VALID</strong> (Ed25519 {ed}, SLH-DSA {slh}). Do NOT trust this message's content — it may have been altered, or the sender may not be the owner of the Public Key you pasted.",
        "verify.unverified": "⚠️ <strong>SENDER NOT VERIFIED.</strong> The sender's Public Key was not provided, so the message was decrypted with no proof of who sent it.",
        "meta.signedAt": "🕐 Signed at: {date}",
        "meta.from": "Sender fingerprint (claim from inside the message): {fp}",
        "meta.fromMatch": "✓ The fingerprint claim matches the Public Key you pasted.",
        "meta.fromMismatch": "⚠️ The fingerprint claim does NOT match the Public Key you pasted!",
        "meta.toMismatch": "⚠️ Note: the recipient metadata inside the message does not match your key (sender-side inconsistency).",
        "file.chosen": "Selected: {name} · {size} KB",
        "file.pickFirst": "Pick or drag a file to the box above first.",
        "file.encBusy": "Encrypting file...",
        "file.encOk": "File encrypted: {chunks} chunks × 64 KiB — file key sealed for the recipient.",
        "file.encFailed": "File encryption failed: {msg}",
        "file.decPick": "Pick a .qekhf file first.",
        "file.decBusy": "Decrypting file...",
        "file.decOk": "File \"{name}\" fully decrypted ({chunks} chunks).",
        "file.decFailed": "File decryption failed: {msg}",
        "rad.title": "Radiogram Mode (Burst)",
        "rad.desc": "Converts a Q-EKH ciphertext into groups of 5 capital letters (base32 RFC 4648) that can be read over voice/CW and copied by hand without ambiguity. Before hitting PTT, check the transmission duration estimate — the shorter on air, the harder to locate via RDF.",
        "rad.inputLabel": "Ciphertext (base64) — or letter groups for the reverse direction",
        "rad.inputPh": "Paste the base64 ciphertext from the Encrypt tab... (letter groups are also recognized automatically and converted back to base64)",
        "rad.btn": "Convert",
        "rad.outLabel": "Radiogram Result",
        "rad.outPh": "QEKH5 ... letter groups will appear here...",
        "rad.copyAria": "Copy radiogram",
        "rad.download": "⬇ Download radiogram",
        "rad.print": "🖨 Print hand-copy sheet",
        "rad.rateLabel": "Transmission rate",
        "rad.wpmOpt": "WPM (words/minute, PARIS)",
        "rad.bpsOpt": "bps (bits/second)",
        "rad.cwLabel": "Play as CW (Morse) — 600 Hz tone, all local",
        "rad.cwTitle": "CW speed in WPM (PARIS)",
        "rad.cwPlay": "▶ Play CW",
        "rad.cwWav": "⬇ Download .wav",
        "rad.cwHint": "PARIS timing (unit = 1200/WPM ms). The \"QEKH5 … GRUP\" header is played as an on-air marker. The .wav file can be played into another transmitter/phone — the entire radiogram is transmitted without retyping.",
        "rad.fhssTitle": "FHSS Schedule from Shared Key (C.4)",
        "rad.fhssDesc": "A pseudo-random time → channel table that is <strong>identical on both sides</strong>, derived from the shared key + date via HKDF-SHA256. Display only — you still operate the radio manually per the table. Both sides must use exactly the same key, date, channel count, and slot duration.",
        "rad.fhssKeyLabel": "Shared key (any secret text — e.g. a passphrase agreed in person)",
        "rad.fhssKeyPh": "Shared key...",
        "rad.fhssDateTitle": "Schedule date",
        "rad.fhssChTitle": "Channel count",
        "rad.fhssSlot60": "60-minute slot",
        "rad.fhssSlot30": "30-minute slot",
        "rad.fhssSlot15": "15-minute slot",
        "rad.fhssSlot10": "10-minute slot",
        "rad.fhssBtn": "Build schedule",
        "radio.empty": "Paste a Q-EKH ciphertext first.",
        "radio.lettersOk": "Letter groups recognized — the base64 result is ready to paste into the Decrypt tab.",
        "radio.notBase64": "Input is neither base64 nor letter groups.",
        "radio.ready": "Radiogram ready: {groups} groups.",
        "radio.estNoteOk": "Short duration — relatively low RDF detection risk.",
        "radio.estNoteWarn": "Fairly long on air — an RDF station gets a chance to measure. Aim for bursts and change location.",
        "radio.estNoteDanger": "LONG on air — high RDF risk. Shorten the message, raise the rate, or use a separate/distant transmitter.",
        "radio.estLine": "⏱ Estimated transmission duration: ≈ {dur} ({chars} characters). {note}",
        "radio.estMinutes": "{n} minutes",
        "radio.estSeconds": "{n} seconds",
        "print.title": "RADIOGRAM SHEET — Q-EKH",
        "print.sub": "Printed {date} · {groups} groups · base32 RFC 4648 (A–Z, 2–7)",
        "print.headerLine": "Transmission header: {header}",
        "print.foot": "Total {groups} groups. Copy/read per group; tick ☐ for each transmitted or copied group. Match the group count at the end. Destroy this sheet after transmission.",
        "print.missing": "Convert the ciphertext first — there is no radiogram to print.",
        "print.notGroups": "The output is not a letter-group radiogram — it cannot be printed as a copy sheet.",
        "cw.playMissing": "Convert the ciphertext first — there is no radiogram to play.",
        "cw.downloadMissing": "Convert the ciphertext first — there is no radiogram to download.",
        "cw.stop": "■ Stop",
        "cw.playToast": "Playing CW {wpm} WPM — duration ≈ {sec} seconds.",
        "cw.playFailed": "Failed to play CW: {msg}",
        "cw.wavFailed": "Failed to build the WAV: {msg}",
        "cw.noWebAudio": "WebAudio is not available in this browser.",
        "fhss.toast": "FHSS schedule {date}: {slots} slots × {channels} channels. Match it against your correspondent's table.",
        "otp.title": "Authenticated OTP &amp; Pad Book",
        "otp.warnTitle": "⚠️ OTP-v2: random pad + authentication + anti-reuse",
        "otp.warnText": "XOR with a one-time random pad is already theoretically perfect (Shannon), and that does not change. What is added here: an <strong>HMAC-SHA256 tag</strong> (keyed from a separate book segment) so ciphertext tampering is detected, an <strong>anti-reuse registry</strong> so a pad is never used twice, and automatic rejection when the book runs out. Honest note: the authentication is computationally strong (\"AES-grade\"), not information-theoretic. Pad distribution remains the hard part: exchange the .qpad file safely/in person.",
        "otp.bookTitle": "1. Pad Book",
        "otp.bookLabel": "Create a new pad book",
        "otp.bookOpt64": "64 KiB (exportable as letter groups)",
        "otp.bookOpt1M": "1 MiB (field standard)",
        "otp.bookOpt4M": "4 MiB",
        "otp.bookOpt8M": "8 MiB",
        "otp.bookBtn": "Create &amp; download .qpad",
        "otp.fileLabel": "Load pad book from file",
        "otp.textLabel": "Load from text (base64 / letter groups)",
        "otp.textPh": "Paste the base64 or letter groups of a small pad book...",
        "otp.textBtn": "Load from text",
        "otp.lettersBtn": "Export letter groups (book ≤ 64 KiB)",
        "otp.destroyBtn": "Destroy used segments",
        "otp.forgetBtn": "Forget book",
        "otp.sendTitle": "2. Send message",
        "otp.sendLabel": "Message",
        "otp.sendPh": "Write the message — it will use a fresh segment from the pad book...",
        "otp.sendBtn": "Create OTP-v2 Packet",
        "otp.packetLabel": "Packet (base64)",
        "otp.copyAria1": "Copy OTP packet",
        "otp.lettersLabel": "Packet (letter groups for radio)",
        "otp.copyAria2": "Copy OTP letter groups",
        "otp.recvTitle": "3. Receive message",
        "otp.recvLabel": "Incoming packet (base64 / letter groups)",
        "otp.recvPh": "Paste the OTP-v2 packet...",
        "otp.recvBtn": "Verify &amp; Decrypt OTP",
        "otp.outLabel": "Result",
        "otp.copyAria3": "Copy OTP result",
        "otp.noBook": "No pad book loaded yet. Create one or load a .qpad file — remember, both sides must hold an IDENTICAL copy.",
        "otp.statusLine": "Pad book {id}… · {size} KiB · {used}% used · ≈ {left} KiB left (~{msgs} short messages)",
        "otp.exhausted": "⛔ Pad book exhausted. New encryptions are rejected — create & exchange a new book with your correspondent.",
        "otp.loaded": "Pad book {id}… loaded ({source}).",
        "otp.sourceNew": "newly created",
        "otp.sourceFile": "file {name}",
        "otp.sourceLetters": "letter groups",
        "otp.sourceB64": "base64",
        "otp.exchangeWarn": "Exchange the .qpad file with your correspondent over a SAFE channel (in person). Do NOT use the internet.",
        "otp.loadFailed": "Failed to load the pad book: {msg}",
        "otp.loadFirst": "Paste the pad book base64/letter groups first.",
        "otp.loadBookFirst": "Load/create a pad book first.",
        "otp.noBookShort": "No pad book loaded.",
        "otp.tooBig": "Book too large for letter groups (> 64 KiB). Use a .qpad file.",
        "otp.exported": "Pad book exported as letter groups into the load field.",
        "otp.destroyConfirm": "Destroy all used segments (zero-fill)? Old packets referencing those segments can no longer be verified/opened.",
        "otp.destroyOk": "Destroy",
        "otp.destroyed": "{bytes} bytes of used segments destroyed.",
        "otp.forgetConfirm": "Forget this pad book? Its usage registry is deleted and the book is discarded from memory. Make sure the .qpad copy still exists if you may need it.",
        "otp.forgetOk": "Forget",
        "otp.forgotten": "Pad book forgotten.",
        "otp.sendNeedBook": "Load or create a pad book first.",
        "otp.sendOk": "OTP-v2 packet created ({bytes} bytes of pad used, never reused).",
        "otp.recvNeedBook": "Load the pad book first — a packet can only be opened with the same book.",
        "otp.reuseAlert": "🚨 PAD REUSE DETECTED: this packet's offset matches another packet with DIFFERENT content. The security of messages at that offset is compromised — change the pad book NOW and investigate the source.",
        "otp.duplicateNote": "ℹ️ This packet is identical to one already received (duplicate) — no new segment was used.",
        "con.title": "Contact Book &amp; Verification",
        "con.desc": "Store your correspondent's Public Key once, then pick it from the dropdown in the Encrypt/Decrypt tabs — no repeated pasting (prone to mis-paste = a practical MITM gap). New contacts always start <strong>not verified</strong>; mark them verified only after you matched the fingerprint over a separate channel (in person/QR/phone).",
        "con.addTitle": "Add contact",
        "con.nameLabel": "Name",
        "con.namePh": "E.g. Station Alfa",
        "con.keyLabel": "Hybrid Public Key (JSON)",
        "con.keyPh": "Paste the contact's Public Key...",
        "con.btn": "Add to Contact Book",
        "contacts.manualOption": "— paste manually —",
        "contacts.expiredSuffix": " ⏰EXPIRED",
        "contacts.unverifiedSuffix": " ⚠️unverified",
        "contacts.empty": "No contacts yet. Add your correspondent's Public Key below — then verify its fingerprint over a separate channel.",
        "contacts.badgeExpired": "⏰ key expired",
        "contacts.badgeVerified": "✅ verified",
        "contacts.badgeUnverified": "⚠️ not verified",
        "contacts.verifiedAt": "Verified: {date}.",
        "contacts.expiresAt": "Valid until: {date}",
        "contacts.useEncrypt": "Use in Encrypt",
        "contacts.useDecrypt": "Use in Decrypt",
        "contacts.qrBtn": "QR fingerprint",
        "contacts.markVerified": "Mark as verified",
        "contacts.markVerifiedConfirm": "You are about to mark \"{name}\" as VERIFIED.\n\nMake sure you matched the fingerprint above DIRECTLY with its owner (in person/QR/phone), not over the same channel the key was sent on. Are you sure?",
        "contacts.markVerifiedOk": "Yes, I matched it",
        "contacts.markVerifiedToast": "Contact \"{name}\" marked as verified.",
        "contacts.deleteConfirm": "Delete contact \"{name}\" from the address book?",
        "contacts.deletedToast": "Contact \"{name}\" deleted.",
        "contacts.useEncryptToast": "Public Key \"{name}\" applied in the Encrypt tab.",
        "contacts.useDecryptToast": "Public Key \"{name}\" applied in the Decrypt tab.",
        "contacts.nameRequired": "Enter a contact name first.",
        "contacts.duplicate": "This key is already in the contact book.",
        "contacts.added": "Contact \"{name}\" added — status: NOT verified.",
        "contacts.saveFailed": "Failed to save contacts — local storage is full or denied.",
        "contacts.expiredWarn": "⏰ The key for \"{name}\" is EXPIRED ({date}). Ask the owner for a new key.",
        "contacts.unverifiedWarn": "⚠️ Contact \"{name}\" has NOT had its fingerprint verified yet. Encryption will still work, but verify first over a separate channel.",
        "about.title": "About the Q-EKH Protocol",
        "about.cred": "\"I am Mr. J0121312, this website is credited to me.\"",
        "about.intro": "<strong>Q-EKH</strong> is an AUTHENTICATED hybrid post-quantum encryption protocol. Two layers work separately: the <strong>confidentiality</strong> layer (X25519 + ML-KEM-768) and the <strong>sender authenticity</strong> layer (Ed25519 + SLH-DSA-192s, dual signature).",
        "about.why": "Why Is This a Good Choice?",
        "about.why1": "<strong>Layered Confidentiality:</strong> X25519 (classic ECC) and ML-KEM-768 (post-quantum) are combined via HKDF with the PQ secret first — the same principle used by standard hybrid constructions like TLS 1.3 and X-Wing — secure as long as at least one of them cannot be broken.",
        "about.why2": "<strong>Layered Authenticity:</strong> Every message is signed TWICE — Ed25519 (classic, fast, proven for decades) and SLH-DSA-192s (hash-function based, not lattice math like ML-KEM). Both must be valid. The foundations are deliberately different from the encryption layer, so if a lattice-crypto flaw ever appears, your signatures do not fall with it.",
        "about.why3": "<strong>Future Readiness:</strong> ML-KEM-768 and SLH-DSA-192s are designed to resist quantum computers, based on current cryptographic knowledge.",
        "about.quote": "The analogy: locking a safe with two different kinds of padlocks, then sealing it with two different kinds of seals. An attacker must break one padlock AND forge one seal — and the two seals are deliberately made of entirely different materials.",
        "about.signTitle": "⚠️ Signatures Only Mean Anything Once You Have Verified the Public Key",
        "about.signText": "A digital signature proves \"this message matches the private key of public key X's holder\" — but it does NOT prove that public key X really belongs to the person you mean, unless you yourself verified it. The correct flow is always: <strong>verify the Fingerprint over a separate channel first</strong> (tab 6 Contacts supports face-to-face QR), then store that Public Key as trusted, then use it to verify signatures on subsequent messages.",
        "about.supplyTitle": "Supply-Side Hardening (new)",
        "about.supply1": "<strong>No CDN:</strong> all crypto libraries are stored locally in <code>vendor/</code> and their SHA-256 hashes are recorded in <code>vendor/HASHES.txt</code> for re-audit. The page runs 100% offline.",
        "about.supply2": "<strong>Self-test at startup:</strong> HKDF (RFC 5869), AES-256-GCM (NIST vector), Argon2id (RFC 9106), ML-KEM-768, SLH-DSA, X25519, and Ed25519 are tested first; if any fails, all action buttons are locked automatically.",
        "about.supply3": "<strong>Strict CSP:</strong> scripts &amp; styles only from your own origin; no outbound network connections from the page.",
        "about.fieldTitle": "Field Features",
        "about.field1": "<strong>🚨 Panic button + idle auto-lock:</strong> one button in the header (or an idle timer configurable in the footer) wipes contacts &amp; the pad book registry from local storage, clears every field on screen, then reloads the page.",
        "about.field2": "<strong>Visual fingerprint (randomart):</strong> next to every hex fingerprint a 9×9 identicon image derived from the same hash — matching pictures is far faster and less error-prone than comparing 64 hex characters during face-to-face verification.",
        "about.field3": "<strong>Radiogram → CW:</strong> the Radiogram tab can play the letter groups as a 600 Hz Morse tone (PARIS timing, adjustable WPM) directly from the browser, or download them as a .wav file to play into a transmitter.",
        "about.field4": "<strong>Hand-copy print sheet:</strong> the \"Print sheet\" button in the Radiogram tab produces an A5 sheet with big monospace boxes per group, sequence numbers, and checkboxes — minimizing copy errors when transcribing by hand.",
        "about.field5": "<strong>FILE encryption (.qekhf):</strong> the Encrypt/Decrypt tabs now accept files (drag &amp; drop). The content is cut per 64 KiB and every piece is AES-256-GCM authenticated (STREAM construction); the random file key is sealed as a v5 message — one corrupted piece means the whole file is rejected.",
        "about.field6": "<strong>Raw binary output (.qekhb):</strong> the \"Download .qekhb\" button in the Encrypt tab produces the v5 ciphertext as raw binary without base64/JSON — ~25% smaller, for your own radio toolchain. The Decrypt tab can open it again (\"Open .qekhb file\"); the conversion is bijective and changes no bit of the cryptography (SPEC §8).",
        "about.field7": "<strong>Constant size buckets:</strong> a padding option in the Encrypt tab making every ciphertext an exact multiple of 32–256 KB, countering finer size analysis than random 512 B blocks.",
        "about.field8": "<strong>Formal specification:</strong> every format (v5 envelope, OTP-v2, .qpad, .qekhf, fingerprint) is documented byte-by-byte in <code>docs/SPEC.md</code> with deterministic test vectors in <code>docs/test-vectors.json</code> — enabling independent audit and re-implementation.",
        "about.hybridTitle": "Hybrid Key Concept",
        "about.hybrid1": "<strong>Public Key:</strong> the digital padlock and verification seal at once — free to share.",
        "about.hybrid2": "<strong>Private Key:</strong> used to open the padlock (decrypt) AND to apply the seal (sign). <span class=\"warning\">MUST NOT BE SHARED.</span>",
        "about.hybridShort": "In short: <strong>share the padlock (Public), keep the key (Private).</strong>",
        "about.usageTitle": "Usage Instructions",
        "about.usage1": "<strong>Create Keys:</strong> In tab 1, click \"Create Key Pair\". Share the Public Key and Fingerprint over a separate channel; store the Private Key carefully.",
        "about.usage2": "<strong>Encrypt:</strong> In tab 2, select the recipient contact (or paste their Public Key and match its fingerprint) AND your own Private Key, write the message, click \"Encrypt & Sign\".",
        "about.usage3": "<strong>Decrypt:</strong> In tab 3, paste your Private Key and the ciphertext. For verification, select the sender contact whose fingerprint you matched beforehand.",
        "about.usage4": "<strong>Radio:</strong> In tab 4, convert the ciphertext to letter groups + measure the transmission duration estimate. In tab 5, use a pad book for one-way authenticated OTP without any public keys at all.",
        "about.honesty": "Honest note: the post-quantum primitives here (ML-KEM, SLH-DSA) come from the <code>@noble/post-quantum</code> library, which is only \"self-audited\" by its author, has not passed an independent third-party audit, and its JS implementation does not claim side-channel resistance. Good enough for a personal/educational project like this."
    } };
    let I18N_LANG = 'id';
    try { I18N_LANG = localStorage.getItem('qekh.lang') === 'en' ? 'en' : 'id'; } catch { /* abaikan */ }
    const I18N_LOCALE = () => (I18N_LANG === 'en' ? 'en-US' : 'id-ID');
    function t(key, vars) {
        const dict = I18N[I18N_LANG] || I18N.id;
        let s = dict[key] !== undefined ? dict[key] : (I18N.id[key] !== undefined ? I18N.id[key] : key);
        if (vars) for (const [k, v] of Object.entries(vars)) s = s.split('{' + k + '}').join(String(v));
        return s;
    }
    function applyI18n() {
        document.documentElement.setAttribute('lang', I18N_LANG);
        document.querySelectorAll('[data-i18n]:not([data-i18n-live])').forEach(el => { el.innerHTML = t(el.getAttribute('data-i18n')); });
        document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
        document.querySelectorAll('[data-i18n-aria]').forEach(el => { el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria'))); });
        document.querySelectorAll('[data-i18n-title]').forEach(el => { el.setAttribute('title', t(el.getAttribute('data-i18n-title'))); });
    }

    const byId = (id) => document.getElementById(id);
    const on = (el, ev, fn) => { if (el) el.addEventListener(ev, fn); };

    // ==============================================================
    //                     TOAST & DIALOG (E.4)
    // ==============================================================
    const toastStack = byId('toastStack');
    function showToast(message, type = 'info', ms = 3400) {
        if (!toastStack) return;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.setAttribute('role', 'status');
        toast.textContent = message;
        toastStack.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('show'));
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 350);
        }, ms);
    }

    const confirmModal = byId('confirmModal');
    function confirmDialog(text, okLabel = t('common.confirm')) {
        return new Promise((resolve) => {
            if (!confirmModal) { resolve(false); return; }
            byId('confirmText').textContent = text;
            byId('confirmOk').textContent = okLabel;
            confirmModal.classList.add('open');
            const done = (val) => {
                confirmModal.classList.remove('open');
                byId('confirmOk').onclick = byId('confirmCancel').onclick = null;
                confirmModal.onclick = null;
                document.removeEventListener('keydown', escHandler);
                resolve(val);
            };
            const escHandler = (e) => { if (e.key === 'Escape') done(false); };
            byId('confirmOk').onclick = () => done(true);
            byId('confirmCancel').onclick = () => done(false);
            confirmModal.onclick = (e) => { if (e.target === confirmModal) done(false); };
            document.addEventListener('keydown', escHandler);
            byId('confirmOk').focus();
        });
    }

    // ==============================================================
    //                      TEMA TERANG/GELAP (E.4)
    // ==============================================================
    const themeBtn = byId('themeToggleBtn');
    const applyTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        if (themeBtn) themeBtn.textContent = theme === 'light' ? '🌙' : '☀️';
    };
    let savedTheme = 'dark';
    try { savedTheme = localStorage.getItem('qekh.theme') || 'dark'; } catch { /* abaikan */ }
    applyTheme(savedTheme);
    on(themeBtn, 'click', () => {
        const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        applyTheme(next);
        try { localStorage.setItem('qekh.theme', next); } catch { /* abaikan */ }
        // gambar ulang sidik visual dengan palet tema baru
        document.querySelectorAll('canvas.fp-art[data-fp]').forEach(c => drawFpArt(c, c.dataset.fp));
    });

    // ==============================================================
    //                 TOMBOL PANIK & AUTO-LOCK (D.3)
    // ==============================================================
    // Satu tombol (dan timer idle) yang: menghapus seluruh localStorage
    // ber-prefix qekh.* (kontak, registry buku pad, preferensi), mengosongkan
    // semua textarea & kolom password dari DOM, lalu memuat ulang halaman.
    // Buku pad yang hanya ada di memori ikut hilang oleh reload.
    const AUTOLOCK_PREF_KEY = 'qekh.autolockMin';
    const AUTOLOCK_FLAG = 'qekh.autolocked';

    function wipeSensitiveData() {
        try {
            const keys = [];
            for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
            for (const k of keys) if (k && k.startsWith('qekh.')) localStorage.removeItem(k);
        } catch { /* localStorage bisa ditolak di mode privat ketat */ }
        document.querySelectorAll('textarea').forEach(t => { t.value = ''; });
        document.querySelectorAll('input[type="password"]').forEach(i => { i.value = ''; });
    }

    // Auto-lock hanya me-reload bila memang ada yang perlu dikunci —
    // halaman kosong yang dibiarkan terbuka tidak akan menyegarkan diri.
    function hasSensitiveData() {
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (k && (k.startsWith('qekh.contacts') || k.startsWith('qekh.padbook'))) return true;
            }
        } catch { /* abaikan */ }
        return Array.from(document.querySelectorAll('textarea')).some(t => t.value.trim() !== '');
    }

    on(byId('panicBtn'), 'click', async () => {
        if (!await confirmDialog(
            t('panic.confirm'),
            t('panic.ok')
        )) return;
        wipeSensitiveData();
        location.reload();
    });

    const autoLockSelect = byId('autoLockSelect');
    let autoLockTimer = null;

    function autoLockMinutes() {
        let v = 10;
        try { v = parseInt(localStorage.getItem(AUTOLOCK_PREF_KEY) || '10', 10); } catch { /* abaikan */ }
        return Number.isSafeInteger(v) && v >= 0 ? v : 10;
    }

    function armAutoLock() {
        if (autoLockTimer) clearTimeout(autoLockTimer);
        const min = autoLockMinutes();
        if (!min) return; // 0 = mati
        autoLockTimer = setTimeout(() => {
            if (!hasSensitiveData()) { armAutoLock(); return; }
            try { sessionStorage.setItem(AUTOLOCK_FLAG, '1'); } catch { /* abaikan */ }
            wipeSensitiveData();
            location.reload();
        }, min * 60000);
    }

    if (autoLockSelect) {
        try { autoLockSelect.value = String(autoLockMinutes()); } catch { /* abaikan */ }
        on(autoLockSelect, 'change', () => {
            try { localStorage.setItem(AUTOLOCK_PREF_KEY, autoLockSelect.value); } catch { /* abaikan */ }
            armAutoLock();
            showToast(autoLockSelect.value === '0'
                ? t('autolock.off')
                : t('autolock.on', { min: autoLockSelect.value }), 'info');
        });
    }

    // Aktivitas pengguna me-reset timer idle.
    ['pointerdown', 'keydown'].forEach(ev =>
        document.addEventListener(ev, armAutoLock, { passive: true }));
    armAutoLock();

    // Bila reload barusan adalah hasil auto-lock, beri tahu pengguna.
    try {
        if (sessionStorage.getItem(AUTOLOCK_FLAG)) {
            sessionStorage.removeItem(AUTOLOCK_FLAG);
            showToast(t('autolock.fired'), 'warn', 6500);
        }
    } catch { /* abaikan */ }

    // ==============================================================
    //                   SELF-TEST KRIPTO SAAT STARTUP (A.2)
    // ==============================================================
    const actionButtons = Array.from(document.querySelectorAll('.action-button'));
    const banner = byId('selfTestBanner');
    const footerStatus = byId('selfTestStatus');

    let selfTestState = 'running'; // 'running' | 'ok' | 'failed' — dipakai ulang saat ganti bahasa
    function lockAllActions(reason) {
        actionButtons.forEach(b => { b.disabled = true; });
        if (banner) {
            banner.className = 'selftest-banner failed';
            banner.innerHTML = '';
            const strong = document.createElement('strong');
            strong.textContent = t('selftest.failedTitle');
            const detail = document.createElement('p');
            detail.textContent = t('selftest.failedDetail', { reason });
            banner.appendChild(strong);
            banner.appendChild(detail);
        }
        if (footerStatus) {
            footerStatus.textContent = t('footer.selftest.failed');
            footerStatus.className = 'selftest-status failed';
        }
        selfTestState = 'failed';
    }

    function unlockAllActions() {
        actionButtons.forEach(b => { b.disabled = false; });
        if (banner) banner.className = 'selftest-banner';
        if (footerStatus) {
            footerStatus.textContent = t('footer.selftest.ok');
            footerStatus.className = 'selftest-status ok';
        }
        selfTestState = 'ok';
    }

    if (!globalThis.crypto || !globalThis.crypto.subtle) {
        lockAllActions(t('selftest.noSubtle'));
        return;
    }

    // ==============================================================
    //                        TAB SWITCHING (E.5)
    // ==============================================================
    const tabButtons = document.querySelectorAll('.tab-button');
    const contentSections = document.querySelectorAll('.content-section');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(btn => { btn.classList.remove('active'); btn.setAttribute('aria-selected', 'false'); });
            contentSections.forEach(sec => sec.classList.remove('active'));
            button.classList.add('active');
            button.setAttribute('aria-selected', 'true');
            const view = byId(`${button.getAttribute('data-tab')}-view`);
            if (view) {
                view.classList.add('active');
                view.focus({ preventScroll: true }); // fokus berpindah ke panel (a11y)
            }
        });
    });

    // ==============================================================
    //                 HELPER: SALIN / UNDUH / PROGRESS
    // ==============================================================
    const setupCopyButton = (button, getText) => {
        if (!button) return;
        button.addEventListener('click', async () => {
            const textToCopy = getText();
            if (!textToCopy || textToCopy === '—' || textToCopy.endsWith('...') || textToCopy.startsWith('ERROR:')) return;

            const showCopied = () => {
                const originalText = button.textContent;
                button.textContent = t('common.copied');
                button.classList.add('copied');
                setTimeout(() => { button.textContent = originalText; button.classList.remove('copied'); }, 2000);
            };

            if (navigator.clipboard && navigator.clipboard.writeText) {
                try { await navigator.clipboard.writeText(textToCopy); showCopied(); }
                catch { showToast(t('common.copyFailed'), 'error'); }
            } else {
                const temp = document.createElement('textarea');
                temp.value = textToCopy;
                document.body.appendChild(temp);
                temp.select();
                try { document.execCommand('copy'); showCopied(); } catch { /* abaikan */ }
                document.body.removeChild(temp);
            }
        });
    };

    function downloadText(filename, text, mime = 'text/plain') {
        const blob = new Blob([text], { type: mime });
        downloadBlob(filename, blob);
    }

    function downloadBlob(filename, blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 4000);
        showToast(t('common.fileDownloaded', { name: filename }), 'success');
    }

    const setProgress = (container, fill, value) => {
        if (!container || !fill) return;
        if (value === null) { container.classList.remove('active'); return; }
        container.classList.add('active');
        fill.style.width = `${Math.round(Math.min(1, Math.max(0, value)) * 100)}%`;
    };

    // ==============================================================
    //                    QR CODE (D.2) — pustaka vendor
    // ==============================================================
    function renderQr(boxEl, text) {
        boxEl.innerHTML = '';
        if (typeof qrcode === 'undefined') {
            boxEl.textContent = t('qr.libraryMissing');
            return;
        }
        try {
            const qr = qrcode(0, 'M');
            qr.addData(text);
            qr.make();
            boxEl.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 4, scalable: true });
        } catch {
            boxEl.textContent = t('qr.tooLong');
        }
    }

    // ==============================================================
    //              SIDIK VISUAL / RANDOMART (A.4)
    // ==============================================================
    // Gambar identicon 9x9 di samping setiap fingerprint hex — mencocokkan
    // gambar jauh lebih cepat & andal bagi manusia saat verifikasi tatap muka.
    function drawFpArt(canvas, fingerprintHex) {
        const { cells, hue } = fingerprintArt(fingerprintHex);
        const ctx = canvas.getContext('2d');
        const cell = canvas.width / 9;
        const light = document.documentElement.getAttribute('data-theme') === 'light';
        const on_ = `hsl(${hue} ${light ? 70 : 85}% ${light ? 42 : 62}%)`;
        const off = light ? 'rgba(76,91,124,0.14)' : 'rgba(168,179,207,0.10)';
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (let r = 0; r < 9; r++) {
            for (let c = 0; c < 9; c++) {
                const bit = cells[r * 9 + c];
                const pad = bit ? 0.9 : 2.2;
                const s = cell - pad * 2;
                ctx.fillStyle = bit ? on_ : off;
                ctx.beginPath();
                if (ctx.roundRect) ctx.roundRect(c * cell + pad, r * cell + pad, s, s, bit ? 3 : 2);
                else ctx.rect(c * cell + pad, r * cell + pad, s, s); // fallback browser lama
                ctx.fill();
            }
        }
    }

    function renderFpArt(boxEl, fingerprintHex) {
        if (!boxEl) return;
        let canvas = boxEl.nextElementSibling;
        if (!canvas || !canvas.classList || !canvas.classList.contains('fp-art')) {
            canvas = document.createElement('canvas');
            canvas.className = 'fp-art';
            canvas.width = 126;
            canvas.height = 126;
            canvas.setAttribute('role', 'img');
            canvas.setAttribute('aria-label', t('fpArt.aria'));
            boxEl.after(canvas);
        }
        try {
            drawFpArt(canvas, fingerprintHex);
            canvas.dataset.fp = fingerprintHex;
            canvas.style.display = '';
        } catch {
            canvas.style.display = 'none';
            delete canvas.dataset.fp;
        }
    }

    // ==============================================================
    //                   BUKU KONTAK (D.1–D.3)
    // ==============================================================
    const CONTACTS_KEY = 'qekh.contacts.v1';

    function loadContacts() {
        try {
            const raw = localStorage.getItem(CONTACTS_KEY);
            const list = raw ? JSON.parse(raw) : [];
            return Array.isArray(list) ? list : [];
        } catch { return []; }
    }

    function saveContacts(list) {
        try { localStorage.setItem(CONTACTS_KEY, JSON.stringify(list)); }
        catch { showToast(t('contacts.saveFailed'), 'error'); }
    }

    function findContact(id) { return loadContacts().find(c => c.id === id) || null; }

    function expiryState(contact) {
        if (!contact.expires) return 'none';
        return new Date(contact.expires).getTime() < Date.now() ? 'expired' : 'ok';
    }

    function refreshContactDropdowns() {
        const contacts = loadContacts();
        for (const sel of [byId('contactSelectEncrypt'), byId('contactSelectDecrypt')]) {
            if (!sel) continue;
            const current = sel.value;
            sel.innerHTML = '';
            const manual = document.createElement('option');
            manual.value = '';
            manual.textContent = t('contacts.manualOption');
            sel.appendChild(manual);
            for (const c of contacts) {
                const opt = document.createElement('option');
                opt.value = c.id;
                const warn = expiryState(c) === 'expired' ? t('contacts.expiredSuffix') : (c.verified ? '' : t('contacts.unverifiedSuffix'));
                opt.textContent = `${c.verified ? '✅' : '⚠️'} ${c.name}${warn}`;
                sel.appendChild(opt);
            }
            sel.value = current;
        }
    }

    function renderContactList() {
        const listEl = byId('contactList');
        if (!listEl) return;
        const contacts = loadContacts();
        listEl.innerHTML = '';
        if (!contacts.length) {
            const empty = document.createElement('p');
            empty.className = 'description';
            empty.textContent = t('contacts.empty');
            listEl.appendChild(empty);
            return;
        }
        for (const c of contacts) {
            const card = document.createElement('div');
            card.className = 'contact-card';

            const head = document.createElement('div');
            head.className = 'contact-head';
            const name = document.createElement('strong');
            name.textContent = c.name;
            const badge = document.createElement('span');
            if (expiryState(c) === 'expired') {
                badge.className = 'badge badge-expired';
                badge.textContent = t('contacts.badgeExpired');
            } else if (c.verified) {
                badge.className = 'badge badge-verified';
                badge.textContent = t('contacts.badgeVerified');
            } else {
                badge.className = 'badge badge-unverified';
                badge.textContent = t('contacts.badgeUnverified');
            }
            head.appendChild(name);
            head.appendChild(badge);

            const fp = document.createElement('div');
            fp.className = 'fingerprint-box contact-fp';
            fp.textContent = c.fingerprint;

            const meta = document.createElement('div');
            meta.className = 'contact-meta';
            meta.textContent = (c.verified && c.verifiedAt ? t('contacts.verifiedAt', { date: new Date(c.verifiedAt).toLocaleString(I18N_LOCALE()) }) : '')
                + (c.expires ? t('contacts.expiresAt', { date: new Date(c.expires).toLocaleDateString(I18N_LOCALE()) }) : '');

            const qrBox = document.createElement('div');
            qrBox.className = 'qr-box';

            const actions = document.createElement('div');
            actions.className = 'contact-actions';
            const mkBtn = (label, cls, fn) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = `small-button ${cls || ''}`;
                b.textContent = label;
                b.addEventListener('click', fn);
                actions.appendChild(b);
            };
            mkBtn(t('contacts.useEncrypt'), '', () => {
                byId('publicKey').value = c.keyJson;
                byId('contactSelectEncrypt').value = c.id;
                updateFingerprint(byId('publicKey'), byId('recipientFingerprint'));
                showToast(t('contacts.useEncryptToast', { name: c.name }), 'success');
                document.querySelector('[data-tab="encrypt"]').click();
            });
            mkBtn(t('contacts.useDecrypt'), '', () => {
                byId('senderVerifyKey').value = c.keyJson;
                byId('contactSelectDecrypt').value = c.id;
                updateFingerprint(byId('senderVerifyKey'), byId('senderVerifyFingerprint'));
                showToast(t('contacts.useDecryptToast', { name: c.name }), 'success');
                document.querySelector('[data-tab="decrypt"]').click();
            });
            mkBtn(t('contacts.qrBtn'), '', () => {
                qrBox.classList.toggle('open');
                if (qrBox.classList.contains('open')) renderQr(qrBox, `QEKH ${c.name} ${c.fingerprint}`);
            });
            if (!c.verified) {
                mkBtn(t('contacts.markVerified'), 'verify', async () => {
                    const ok = await confirmDialog(
                        t('contacts.markVerifiedConfirm', { name: c.name }),
                        t('contacts.markVerifiedOk')
                    );
                    if (!ok) return;
                    const list = loadContacts();
                    const target = list.find(x => x.id === c.id);
                    target.verified = true;
                    target.verifiedAt = new Date().toISOString();
                    saveContacts(list);
                    renderContactList();
                    refreshContactDropdowns();
                    showToast(t('contacts.markVerifiedToast', { name: c.name }), 'success');
                });
            }
            mkBtn(t('common.delete'), 'danger', async () => {
                if (!await confirmDialog(t('contacts.deleteConfirm', { name: c.name }), t('common.delete'))) return;
                saveContacts(loadContacts().filter(x => x.id !== c.id));
                renderContactList();
                refreshContactDropdowns();
                showToast(t('contacts.deletedToast', { name: c.name }), 'info');
            });

            card.appendChild(head);
            card.appendChild(fp);
            renderFpArt(fp, c.fingerprint);
            if (meta.textContent) card.appendChild(meta);
            card.appendChild(actions);
            card.appendChild(qrBox);
            listEl.appendChild(card);
        }
    }

    on(byId('contactAddBtn'), 'click', async () => {
        const nameEl = byId('contactName');
        const keyEl = byId('contactKeyJson');
        const name = nameEl.value.trim();
        if (!name) { showToast(t('contacts.nameRequired'), 'warn'); return; }
        try {
            const info = await publicKeyInfo(keyEl.value);
            const list = loadContacts();
            if (list.some(c => c.fingerprint === info.fingerprint)) {
                showToast(t('contacts.duplicate'), 'warn');
                return;
            }
            list.push({
                id: 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
                name,
                keyJson: keyEl.value.trim(),
                fingerprint: info.fingerprint,
                verified: false,
                verifiedAt: null,
                expires: info.expires,
                createdAt: new Date().toISOString(),
            });
            saveContacts(list);
            nameEl.value = '';
            keyEl.value = '';
            renderContactList();
            refreshContactDropdowns();
            showToast(t('contacts.added', { name }), 'success');
        } catch (e) {
            showToast(t('common.invalidKey', { msg: e.message }), 'error', 5200);
        }
    });

    const wireContactSelect = (selectId, textareaId, fpBoxId, warnId) => {
        const sel = byId(selectId);
        on(sel, 'change', () => {
            const warn = byId(warnId);
            if (warn) { warn.textContent = ''; warn.className = 'contact-warn'; }
            if (!sel.value) return;
            const c = findContact(sel.value);
            if (!c) return;
            byId(textareaId).value = c.keyJson;
            updateFingerprint(byId(textareaId), byId(fpBoxId));
            if (warn) {
                if (expiryState(c) === 'expired') {
                    warn.textContent = t('contacts.expiredWarn', { name: c.name, date: new Date(c.expires).toLocaleDateString(I18N_LOCALE()) });
                    warn.className = 'contact-warn expired';
                } else if (!c.verified) {
                    warn.textContent = t('contacts.unverifiedWarn', { name: c.name });
                    warn.className = 'contact-warn unverified';
                }
            }
        });
    };
    wireContactSelect('contactSelectEncrypt', 'publicKey', 'recipientFingerprint', 'contactWarnEncrypt');
    wireContactSelect('contactSelectDecrypt', 'senderVerifyKey', 'senderVerifyFingerprint', 'contactWarnDecrypt');

    // ==============================================================
    //              ELEMEN-ELEMEN FORM PER TAB
    // ==============================================================
    const generateBtn = byId('generateBtn');
    const genPassphraseEl = byId('genPassphrase');
    const genExpiresEl = byId('genExpires');
    const genPublicKeyEl = byId('genPublicKey');
    const genPrivateKeyEl = byId('genPrivateKey');
    const genFingerprintEl = byId('genFingerprint');
    const genProgress = byId('genProgress');
    const genProgressFill = byId('genProgressFill');

    const publicKeyEl = byId('publicKey');
    const recipientFingerprintEl = byId('recipientFingerprint');
    const senderPrivateKeyEl = byId('senderPrivateKey');
    const senderKeyPassphraseEl = byId('senderKeyPassphrase');
    const plainTextEl = byId('plainText');
    const charCountEl = byId('charCount');
    const encryptBtn = byId('encryptBtn');
    const encryptProgress = byId('encryptProgress');
    const encryptProgressFill = byId('encryptProgressFill');
    const encryptedTextEl = byId('encryptedText');

    const privateKeyEl = byId('privateKey');
    const privateKeyPassphraseEl = byId('privateKeyPassphrase');
    const senderVerifyKeyEl = byId('senderVerifyKey');
    const senderVerifyFingerprintEl = byId('senderVerifyFingerprint');
    const cipherTextEl = byId('cipherText');
    const decryptBtn = byId('decryptBtn');
    const decryptProgress = byId('decryptProgress');
    const decryptProgressFill = byId('decryptProgressFill');
    const decryptedTextEl = byId('decryptedText');
    const decryptMetaEl = byId('decryptMeta');
    const verificationStatusEl = byId('verificationStatus');

    // --- Tombol salin ---
    setupCopyButton(byId('copyGenPublicBtn'), () => genPublicKeyEl.value);
    setupCopyButton(byId('copyGenPrivateBtn'), () => genPrivateKeyEl.value);
    setupCopyButton(byId('copyGenFingerprintBtn'), () => genFingerprintEl.dataset.invalid ? '' : genFingerprintEl.textContent);
    setupCopyButton(byId('copyEncryptedBtn'), () => encryptedTextEl.value);
    setupCopyButton(byId('copyDecryptedBtn'), () => decryptedTextEl.value);
    setupCopyButton(byId('copyRadioBtn'), () => byId('radioOutput').value);
    setupCopyButton(byId('copyOtpPacketBtn'), () => byId('otpPacketOut').value);
    setupCopyButton(byId('copyOtpLettersBtn'), () => byId('otpPacketLetters').value);
    setupCopyButton(byId('copyOtpDecryptedBtn'), () => byId('otpDecryptedOut').value);

    // --- Tombol unduh (E.4) ---
    on(byId('downloadGenPublicBtn'), 'click', () => {
        if (genPublicKeyEl.value && !genPublicKeyEl.value.startsWith('ERROR')) {
            downloadText('qekh-kunci-publik.json', genPublicKeyEl.value, 'application/json');
        }
    });
    on(byId('downloadGenPrivateBtn'), 'click', async () => {
        if (!genPrivateKeyEl.value || genPrivateKeyEl.value.startsWith('ERROR')) return;
        if (await confirmDialog(t('dialog.downloadPriv'), t('common.download'))) {
            downloadText('qekh-kunci-privat.json', genPrivateKeyEl.value, 'application/json');
        }
    });
    on(byId('downloadEncryptedBtn'), 'click', () => {
        if (encryptedTextEl.value && !encryptedTextEl.value.startsWith('ERROR')) {
            downloadText('qekh-pesan.txt', encryptedTextEl.value);
        }
    });
    // C.3 — output biner mentah (tanpa base64/JSON) untuk toolchain radio
    on(byId('downloadEncryptedBinBtn'), 'click', () => {
        const val = encryptedTextEl.value;
        if (!val || val.startsWith('ERROR')) {
            showToast(t('encrypt.binMissing'), 'warn');
            return;
        }
        try {
            const bin = payloadToBinary(val);
            downloadBlob('qekh-pesan.qekhb', new Blob([bin], { type: 'application/octet-stream' }));
            const saving = Math.round(100 * (1 - bin.length / val.length));
            showToast(t('encrypt.binToast', { bytes: bin.length, saving }), 'ok');
        } catch (e) {
            showToast(t('encrypt.binFailed', { msg: e.message }), 'err');
        }
    });
    // C.3 — buka file .qekhb di tab Dekripsi: biner -> base64, lalu dekripsi biasa
    const cipherBinInputEl = byId('cipherBinInput');
    on(byId('cipherBinBtn'), 'click', () => cipherBinInputEl.click());
    on(cipherBinInputEl, 'change', async () => {
        const file = cipherBinInputEl.files && cipherBinInputEl.files[0];
        if (!file) return;
        try {
            const buf = new Uint8Array(await file.arrayBuffer());
            if (buf.length > 17 * 1024 * 1024 + 1200) {
                throw new Error(t('encrypt.binTooBig'));
            }
            cipherTextEl.value = binaryToPayload(buf);
            showToast(t('encrypt.binLoaded', { bytes: buf.length }), 'ok');
        } catch (e) {
            showToast(t('encrypt.binInvalid', { msg: e.message }), 'err');
        } finally {
            cipherBinInputEl.value = '';
        }
    });
    on(byId('downloadRadioBtn'), 'click', () => {
        const out = byId('radioOutput').value;
        if (out) downloadText('qekh-radiogram.txt', out);
    });

    // --- Fingerprint langsung saat Kunci Publik ditempel ---
    const updateFingerprint = async (textareaEl, boxEl) => {
        const text = textareaEl.value.trim();
        if (!text) { boxEl.textContent = '—'; renderFpArt(boxEl, ''); return; }
        try {
            const info = await publicKeyInfo(text);
            delete boxEl.dataset.invalid;
            boxEl.textContent = info.fingerprint + (info.expires
                ? (info.expired
                    ? t('encrypt.expiresExpired', { date: new Date(info.expires).toLocaleDateString(I18N_LOCALE()) })
                    : t('encrypt.expiresValid', { date: new Date(info.expires).toLocaleDateString(I18N_LOCALE()) }))
                : '');
            renderFpArt(boxEl, info.fingerprint);
        } catch (e) {
            boxEl.dataset.invalid = '1';
            boxEl.textContent = t('common.invalidKey', { msg: e.message });
            renderFpArt(boxEl, '');
        }
    };
    on(publicKeyEl, 'input', () => updateFingerprint(publicKeyEl, recipientFingerprintEl));
    on(senderVerifyKeyEl, 'input', () => updateFingerprint(senderVerifyKeyEl, senderVerifyFingerprintEl));

    // --- Penghitung karakter + estimasi ukuran terenkripsi (E.4) ---
    on(plainTextEl, 'input', () => {
        if (!charCountEl) return;
        const bytes = encodeText(plainTextEl.value).length;
        // Perkiraan kasar: paket v5 didominasi tanda tangan SLH-DSA (~16 KB) +
        // padding blok 512 B, lalu base64 (~4/3).
        const padded = (Math.floor((bytes + 17500) / 512) + 1) * 512;
        const estB64 = Math.ceil(padded * 4 / 3);
        charCountEl.textContent = t('charCount', { chars: plainTextEl.value.length, bytes, kb: (estB64 / 1024).toFixed(1) });
    });

    // ==============================================================
    //                 TAB 1: PEMBUATAN KUNCI (+ QR D.2)
    // ==============================================================
    on(generateBtn, 'click', async () => {
        const existing = genPrivateKeyEl.value;
        if (existing && !existing.startsWith('ERROR:') && !existing.startsWith('Harap tunggu')) {
            if (!await confirmDialog(t('gen.overwriteConfirm'))) return;
        }

        let expires = null;
        if (genExpiresEl && genExpiresEl.value) {
            const d = new Date(genExpiresEl.value + 'T23:59:59');
            if (isNaN(d)) { showToast(t('gen.expiryInvalid'), 'error'); return; }
            if (d.getTime() <= Date.now()) { showToast(t('gen.expiryPast'), 'warn'); return; }
            expires = d.toISOString();
        }

        const hasPassphrase = !!genPassphraseEl.value;
        generateBtn.disabled = true;
        generateBtn.textContent = t('gen.btnBusy');
        [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = hasPassphrase
            ? t('gen.waitArgon')
            : t('gen.waitPlain'));
        genFingerprintEl.textContent = t('gen.fpComputing');

        try {
            const onProgress = hasPassphrase ? (v) => setProgress(genProgress, genProgressFill, v) : null;
            const { publicKeyJson, privateKeyJson, fingerprint } = await generateIdentity(genPassphraseEl.value, { expires, onProgress });
            genPublicKeyEl.value = publicKeyJson;
            genPrivateKeyEl.value = privateKeyJson;
            genFingerprintEl.textContent = fingerprint;
            renderFpArt(genFingerprintEl, fingerprint);
            const qrBox = byId('genQrBox');
            if (qrBox) {
                renderQr(qrBox, `QEKH ${fingerprint}`);
                qrBox.classList.add('open');
            }
            showToast(t('gen.okToast'), 'success');
        } catch (e) {
            [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = 'ERROR: ' + e.message);
            genFingerprintEl.textContent = t('gen.fail');
            renderFpArt(genFingerprintEl, '');
        } finally {
            setProgress(genProgress, genProgressFill, null);
            generateBtn.disabled = false;
            generateBtn.textContent = t('gen.btn');
        }
    });

    // ==============================================================
    //                      TAB 2: ENKRIPSI
    // ==============================================================
    // B.1: overlay "tersegel" singkat — umpan balik visual bahwa pesan baru
    // saja dikunci. Dihormati prefers-reduced-motion (dilewati total).
    const sealOverlay = byId('sealOverlay');
    function playSeal() {
        if (!sealOverlay) return;
        if (globalThis.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        sealOverlay.classList.remove('seal-active');
        void sealOverlay.offsetWidth; // mulai ulang animasi bila berturut-turut
        sealOverlay.classList.add('seal-active');
        setTimeout(() => sealOverlay.classList.remove('seal-active'), 1400);
    }

    on(encryptBtn, 'click', async () => {
        encryptBtn.disabled = true;
        encryptBtn.textContent = t('encrypt.btnBusy');
        encryptedTextEl.value = '';

        try {
            if (!plainTextEl.value) throw new Error(t('encrypt.emptyMsg'));
            const bucket = parseInt((byId('bucketSelect') || {}).value || '0', 10) || 0;
            encryptedTextEl.value = await encryptHybrid(
                publicKeyEl.value, senderPrivateKeyEl.value, plainTextEl.value, senderKeyPassphraseEl.value,
                { bucket, onProgress: (v) => setProgress(encryptProgress, encryptProgressFill, v) }
            );
            showToast(t('encrypt.okToast'), 'success');
            playSeal();
        } catch (e) {
            encryptedTextEl.value = 'ERROR: ' + e.message;
        } finally {
            setProgress(encryptProgress, encryptProgressFill, null);
            encryptBtn.disabled = false;
            encryptBtn.textContent = t('enc.btn');
        }
    });

    // ==============================================================
    //                      TAB 3: DEKRIPSI
    // ==============================================================
    const renderVerification = (v, targetEl = verificationStatusEl) => {
        targetEl.classList.remove('verified', 'failed', 'unverified');
        if (v.status === 'verified') {
            targetEl.classList.add('verified');
            targetEl.innerHTML = t('verify.ok');
        } else if (v.status === 'failed') {
            targetEl.classList.add('failed');
            targetEl.innerHTML = t('verify.failed', { ed: v.ed25519 ? '✓' : '✗', slh: v.slhdsa ? '✓' : '✗' });
        } else {
            targetEl.classList.add('unverified');
            targetEl.innerHTML = t('verify.unverified');
        }
    };

    const renderMeta = (meta, verification) => {
        decryptMetaEl.textContent = '';
        if (!meta || (!meta.from && !meta.at)) return;
        const addLine = (text) => {
            const div = document.createElement('div');
            div.textContent = text;
            decryptMetaEl.appendChild(div);
        };
        if (meta.at) {
            const d = new Date(meta.at);
            if (!isNaN(d)) addLine(t('meta.signedAt', { date: d.toLocaleString(I18N_LOCALE()) }));
        }
        if (meta.from) {
            addLine(t('meta.from', { fp: meta.from }));
            if (verification.senderFingerprint) {
                addLine(meta.from === verification.senderFingerprint
                    ? t('meta.fromMatch')
                    : t('meta.fromMismatch'));
            }
        }
        if (meta.toMismatch) {
            addLine(t('meta.toMismatch'));
        }
    };

    on(decryptBtn, 'click', async () => {
        decryptBtn.disabled = true;
        decryptBtn.textContent = t('decrypt.btnBusy');
        decryptedTextEl.value = '';
        decryptMetaEl.textContent = '';
        verificationStatusEl.textContent = '';
        verificationStatusEl.className = 'verification-status';

        try {
            const { plaintext, verification, meta } = await decryptHybrid(
                privateKeyEl.value, cipherTextEl.value, senderVerifyKeyEl.value, privateKeyPassphraseEl.value,
                { onProgress: (v) => setProgress(decryptProgress, decryptProgressFill, v) }
            );
            decryptedTextEl.value = plaintext;
            renderVerification(verification);
            renderMeta(meta, verification);
        } catch (e) {
            decryptedTextEl.value = 'ERROR: ' + e.message;
        } finally {
            setProgress(decryptProgress, decryptProgressFill, null);
            decryptBtn.disabled = false;
            decryptBtn.textContent = t('dec.btn');
        }
    });

    // ==============================================================
    //           ENKRIPSI / DEKRIPSI FILE CHUNKED .qekhf (D.1)
    // ==============================================================
    const fileDropZone = byId('fileDropZone');
    const fileEncryptInput = byId('fileEncryptInput');
    const fileEncryptInfo = byId('fileEncryptInfo');
    const fileEncryptBtn = byId('fileEncryptBtn');
    const fileEncryptProgress = byId('fileEncryptProgress');
    const fileEncryptProgressFill = byId('fileEncryptProgressFill');
    const fileDecryptInput = byId('fileDecryptInput');
    const fileDecryptBtn = byId('fileDecryptBtn');
    const fileDecryptProgress = byId('fileDecryptProgress');
    const fileDecryptProgressFill = byId('fileDecryptProgressFill');
    const fileDecryptStatus = byId('fileDecryptStatus');
    let chosenFile = null;

    function setChosenFile(file) {
        chosenFile = file || null;
        if (fileEncryptInfo) {
            fileEncryptInfo.textContent = chosenFile
                ? t('file.chosen', { name: chosenFile.name, size: (chosenFile.size / 1024).toFixed(1) })
                : '';
        }
    }

    if (fileDropZone && fileEncryptInput) {
        fileDropZone.addEventListener('click', () => fileEncryptInput.click());
        fileDropZone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileEncryptInput.click(); }
        });
        fileDropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileDropZone.classList.add('dragover');
        });
        fileDropZone.addEventListener('dragleave', () => fileDropZone.classList.remove('dragover'));
        fileDropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            fileDropZone.classList.remove('dragover');
            const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
            if (f) setChosenFile(f);
        });
        fileEncryptInput.addEventListener('change', () => {
            setChosenFile(fileEncryptInput.files && fileEncryptInput.files[0]);
            fileEncryptInput.value = '';
        });
    }

    on(fileEncryptBtn, 'click', async () => {
        if (!chosenFile) { showToast(t('file.pickFirst'), 'warn'); return; }
        fileEncryptBtn.disabled = true;
        fileEncryptBtn.textContent = t('file.encBusy');
        try {
            const data = new Uint8Array(await chosenFile.arrayBuffer());
            const { container, fileName, chunkCount } = await encryptFileHybrid(
                publicKeyEl.value, senderPrivateKeyEl.value, data, chosenFile.name, senderKeyPassphraseEl.value,
                { onProgress: (v) => setProgress(fileEncryptProgress, fileEncryptProgressFill, v) }
            );
            downloadBlob(fileName, new Blob([container], { type: 'application/octet-stream' }));
            showToast(t('file.encOk', { chunks: chunkCount }), 'success', 5200);
            playSeal();
        } catch (e) {
            showToast(t('file.encFailed', { msg: e.message }), 'error', 6500);
        } finally {
            setProgress(fileEncryptProgress, fileEncryptProgressFill, null);
            fileEncryptBtn.disabled = false;
            fileEncryptBtn.textContent = t('enc.fileBtn');
        }
    });

    on(fileDecryptBtn, 'click', async () => {
        const file = fileDecryptInput && fileDecryptInput.files && fileDecryptInput.files[0];
        if (!file) { showToast(t('file.decPick'), 'warn'); return; }
        fileDecryptBtn.disabled = true;
        fileDecryptBtn.textContent = t('file.decBusy');
        fileDecryptStatus.textContent = '';
        fileDecryptStatus.className = 'verification-status';
        try {
            const buf = new Uint8Array(await file.arrayBuffer());
            const out = await decryptFileHybrid(
                privateKeyEl.value, buf, senderVerifyKeyEl.value, privateKeyPassphraseEl.value,
                { onProgress: (v) => setProgress(fileDecryptProgress, fileDecryptProgressFill, v) }
            );
            renderVerification(out.verification, fileDecryptStatus);
            downloadBlob(out.name, new Blob([out.data], { type: 'application/octet-stream' }));
            showToast(t('file.decOk', { name: out.name, chunks: out.chunkCount }), 'success', 5200);
        } catch (e) {
            showToast(t('file.decFailed', { msg: e.message }), 'error', 6500);
        } finally {
            setProgress(fileDecryptProgress, fileDecryptProgressFill, null);
            fileDecryptBtn.disabled = false;
            fileDecryptBtn.textContent = t('dec.fileBtn');
            fileDecryptInput.value = '';
        }
    });

    // ==============================================================
    //                 TAB 4: MODE RADIOGRAM (C.1)
    // ==============================================================
    const radioInputEl = byId('radioInput');
    const radioOutputEl = byId('radioOutput');
    const radioEstimateEl = byId('radioEstimate');
    const radioRateEl = byId('radioRate');
    const radioUnitEl = byId('radioUnit');

    function radiogramEstimate(letterText) {
        const chars = letterText.replace(/[^A-Z2-7]/gi, '').length;
        const rate = parseFloat(radioRateEl.value);
        if (!rate || rate <= 0 || !chars) { radioEstimateEl.textContent = ''; return; }
        let seconds;
        if (radioUnitEl.value === 'wpm') {
            seconds = chars / (rate * 5 / 60); // PARIS: 5 karakter per kata
        } else {
            seconds = (chars * 5) / rate; // base32 = 5 bit per karakter
        }
        const rounded = Math.max(1, Math.round(seconds));
        let level, note;
        if (rounded <= 30) {
            level = 'ok';
            note = t('radio.estNoteOk');
        } else if (rounded <= 120) {
            level = 'warn';
            note = t('radio.estNoteWarn');
        } else {
            level = 'danger';
            note = t('radio.estNoteDanger');
        }
        radioEstimateEl.className = `radio-estimate ${level}`;
        const dur = rounded >= 60 ? t('radio.estMinutes', { n: (rounded / 60).toFixed(1) }) : t('radio.estSeconds', { n: rounded });
        radioEstimateEl.textContent = t('radio.estLine', { dur, chars, note });
    }

    on(byId('radioConvertBtn'), 'click', () => {
        const raw = radioInputEl.value.trim();
        radioOutputEl.value = '';
        if (!raw) { showToast(t('radio.empty'), 'warn'); return; }
        try {
            let bytes;
            if (looksLikeLetterGroups(raw)) {
                // Arah sebaliknya: grup huruf -> byte (untuk disalin ke tab Dekripsi)
                bytes = fromLetterGroups(stripLetterHeader(raw));
                const text = decodeText(bytes);
                // Jika isinya JSON envelope, tawarkan base64-nya untuk tab Dekripsi
                try {
                    JSON.parse(text);
                    radioOutputEl.value = arrayBufferToBase64(bytes);
                    showToast(t('radio.lettersOk'), 'success');
                    radioEstimateEl.textContent = '';
                    radioEstimateEl.className = 'radio-estimate';
                    return;
                } catch { /* bukan JSON — lanjut tampilkan apa adanya */ }
                radioOutputEl.value = text;
                return;
            }
            // Arah utama: base64 ciphertext -> grup huruf + header versi
            const clean = raw.replace(/\s+/g, '');
            if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(clean)) {
                throw new Error(t('radio.notBase64'));
            }
            bytes = Uint8Array.from(atob(clean), c => c.charCodeAt(0));
            const groups = toLetterGroups(bytes);
            const groupCount = groups.split(' ').length;
            radioOutputEl.value = `QEKH5 ${groupCount} GRUP\n${groups}`;
            radiogramEstimate(groups);
            showToast(t('radio.ready', { groups: groupCount }), 'success');
        } catch (e) {
            radioOutputEl.value = 'ERROR: ' + e.message;
        }
    });
    on(radioRateEl, 'input', () => { if (radioOutputEl.value.includes('\n')) radiogramEstimate(radioOutputEl.value.split('\n').slice(1).join(' ')); });
    on(radioUnitEl, 'change', () => { if (radioOutputEl.value.includes('\n')) radiogramEstimate(radioOutputEl.value.split('\n').slice(1).join(' ')); });

    // --- Lembar cetak salin-tangan (A.5) ---
    // Grup huruf dimaksudkan disalin TANGAN ke kertas. Lembar cetak khusus:
    // font mono besar, kotak per grup, nomor grup, dan kotak ceklis per grup.
    const printSheetEl = byId('printSheet');

    function buildPrintSheet(header, groups) {
        printSheetEl.innerHTML = '';
        const sheet = document.createElement('div');

        const kop = document.createElement('div');
        kop.className = 'ps-kop';
        const h1 = document.createElement('h1');
        h1.textContent = t('print.title');
        const sub = document.createElement('p');
        sub.textContent = t('print.sub', { date: new Date().toLocaleString(I18N_LOCALE()), groups: groups.length });
        kop.appendChild(h1);
        kop.appendChild(sub);
        if (header) {
            const hd = document.createElement('p');
            hd.className = 'ps-header-line';
            hd.textContent = t('print.headerLine', { header });
            kop.appendChild(hd);
        }
        sheet.appendChild(kop);

        const grid = document.createElement('div');
        grid.className = 'ps-grid';
        groups.forEach((g, i) => {
            const box = document.createElement('div');
            box.className = 'ps-group';
            const num = document.createElement('span');
            num.className = 'ps-num';
            num.textContent = String(i + 1);
            const letters = document.createElement('span');
            letters.className = 'ps-letters';
            letters.textContent = g;
            const check = document.createElement('span');
            check.className = 'ps-check';
            check.textContent = '☐';
            box.appendChild(num);
            box.appendChild(letters);
            box.appendChild(check);
            grid.appendChild(box);
        });
        sheet.appendChild(grid);

        const foot = document.createElement('p');
        foot.className = 'ps-foot';
        foot.textContent = t('print.foot', { groups: groups.length });
        sheet.appendChild(foot);

        printSheetEl.appendChild(sheet);
    }

    on(byId('printRadioBtn'), 'click', () => {
        const out = radioOutputEl.value.trim();
        if (!out || out.startsWith('ERROR')) { showToast(t('print.missing'), 'warn'); return; }
        const lines = out.split('\n');
        const header = /^QEKH5/i.test(lines[0]) ? lines[0].trim() : '';
        const body = (header ? lines.slice(1).join(' ') : out).replace(/\s+/g, ' ').trim();
        if (!looksLikeLetterGroups(body)) { showToast(t('print.notGroups'), 'warn'); return; }
        buildPrintSheet(header, body.split(' '));
        window.print();
    });

    // --- Putar radiogram sebagai CW / unduh WAV (C.1) ---
    const cwPlayBtn = byId('cwPlayBtn');
    const cwWpmEl = byId('cwWpm');
    let cwAudio = null; // { ctx, src } saat sedang memutar

    function cwSourceText() {
        const out = radioOutputEl.value.trim();
        return (out && !out.startsWith('ERROR')) ? out : null;
    }

    function cwWpm() {
        const v = parseFloat(cwWpmEl && cwWpmEl.value);
        return Number.isFinite(v) && v >= 5 && v <= 60 ? v : 15;
    }

    function stopCw() {
        if (cwAudio) {
            try { cwAudio.src.onended = null; cwAudio.src.stop(); } catch { /* abaikan */ }
            try { cwAudio.ctx.close(); } catch { /* abaikan */ }
            cwAudio = null;
        }
        if (cwPlayBtn) cwPlayBtn.textContent = t('rad.cwPlay');
    }

    on(cwPlayBtn, 'click', () => {
        if (cwAudio) { stopCw(); return; }
        const text = cwSourceText();
        if (!text) { showToast(t('cw.playMissing'), 'warn'); return; }
        try {
            const wpm = cwWpm();
            const pcm = renderCwPcm(text, wpm);
            const AudioCtx = globalThis.AudioContext || globalThis.webkitAudioContext;
            if (!AudioCtx) throw new Error(t('cw.noWebAudio'));
            const ctx = new AudioCtx();
            const buf = ctx.createBuffer(1, pcm.length, CW_SAMPLE_RATE);
            buf.copyToChannel(pcm, 0);
            const src = ctx.createBufferSource();
            src.buffer = buf;
            src.connect(ctx.destination);
            src.onended = () => stopCw();
            cwAudio = { ctx, src };
            src.start();
            cwPlayBtn.textContent = t('cw.stop');
            showToast(t('cw.playToast', { wpm, sec: Math.max(1, Math.round(pcm.length / CW_SAMPLE_RATE)) }), 'info');
        } catch (e) {
            showToast(t('cw.playFailed', { msg: e.message }), 'error');
            stopCw();
        }
    });

    on(byId('cwWavBtn'), 'click', () => {
        const text = cwSourceText();
        if (!text) { showToast(t('cw.downloadMissing'), 'warn'); return; }
        try {
            const wpm = cwWpm();
            const wav = encodeWavPcm16(renderCwPcm(text, wpm), CW_SAMPLE_RATE);
            downloadBlob(`qekh-cw-${wpm}wpm.wav`, new Blob([wav], { type: 'audio/wav' }));
        } catch (e) {
            showToast(t('cw.wavFailed', { msg: e.message }), 'error');
        }
    });

    // --- Jadwal FHSS dari kunci bersama (C.4) ---
    const fhssDateEl = byId('fhssDate');
    if (fhssDateEl && !fhssDateEl.value) {
        fhssDateEl.value = new Date().toISOString().slice(0, 10); // default: hari ini
    }
    on(byId('fhssBtn'), 'click', async () => {
        const tableEl = byId('fhssTable');
        tableEl.innerHTML = '';
        try {
            const slotMinutes = parseInt(byId('fhssSlot').value, 10);
            const channels = parseInt(byId('fhssChannels').value, 10);
            const slots = Math.floor(1440 / slotMinutes);
            const schedule = await fhssSchedule(byId('fhssKey').value, fhssDateEl.value, { slots, slotMinutes, channels });
            const now = new Date();
            const nowMins = now.getHours() * 60 + now.getMinutes();
            const isToday = fhssDateEl.value === now.toISOString().slice(0, 10);
            for (const s of schedule) {
                const cell = document.createElement('div');
                cell.className = 'fhss-cell';
                if (isToday && nowMins >= s.slot * slotMinutes && nowMins < (s.slot + 1) * slotMinutes) {
                    cell.classList.add('now'); // sorot slot aktif hari ini
                }
                const t = document.createElement('span');
                t.className = 'fhss-time';
                t.textContent = s.time;
                const c = document.createElement('span');
                c.className = 'fhss-ch';
                c.textContent = 'CH ' + String(s.channel).padStart(2, '0');
                cell.appendChild(t);
                cell.appendChild(c);
                tableEl.appendChild(cell);
            }
            showToast(t('fhss.toast', { date: fhssDateEl.value, slots, channels }), 'success');
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    // ==============================================================
    //              TAB 5: OTP TERAUTENTIKASI + BUKU PAD (B)
    // ==============================================================
    let currentBook = null; // buku pad hanya di memori — tidak pernah disimpan otomatis

    const otpBookStatusEl = byId('otpBookStatus');

    function renderBookStatus() {
        if (!otpBookStatusEl) return;
        otpBookStatusEl.innerHTML = '';
        if (!currentBook) {
            const p = document.createElement('p');
            p.className = 'description';
            p.textContent = t('otp.noBook');
            otpBookStatusEl.appendChild(p);
            return;
        }
        const st = getBookStatus(currentBook);
        const wrap = document.createElement('div');
        wrap.className = 'book-status';
        const title = document.createElement('div');
        title.className = 'book-status-line';
        title.textContent = t('otp.statusLine', { id: st.bookIdShort, size: (st.total / 1024).toFixed(0), used: st.percentUsed, left: (st.remaining / 1024).toFixed(1), msgs: st.remainingMessagesEstimate });
        const bar = document.createElement('div');
        bar.className = 'book-bar';
        const fill = document.createElement('div');
        fill.className = 'book-bar-fill' + (st.percentUsed > 85 ? ' danger' : st.percentUsed > 60 ? ' warn' : '');
        fill.style.width = `${st.percentUsed}%`;
        bar.appendChild(fill);
        wrap.appendChild(title);
        wrap.appendChild(bar);
        if (st.exhausted) {
            const warn = document.createElement('p');
            warn.className = 'contact-warn expired';
            warn.textContent = t('otp.exhausted');
            wrap.appendChild(warn);
        }
        otpBookStatusEl.appendChild(wrap);
    }

    async function setCurrentBook(book, sourceLabel) {
        currentBook = book;
        renderBookStatus();
        showToast(t('otp.loaded', { id: bookIdShort(book), source: sourceLabel }), 'success');
    }

    on(byId('otpBookGenBtn'), 'click', async () => {
        const sizeSel = byId('otpBookGenSize');
        const size = parseInt(sizeSel.value, 10);
        try {
            const book = generatePadBook(size);
            const bytes = await serializePadBook(book);
            downloadBlob(`qekh-pad-${bookIdShort(book)}.qpad`, new Blob([bytes], { type: 'application/octet-stream' }));
            await setCurrentBook(book, t('otp.sourceNew'));
            showToast(t('otp.exchangeWarn'), 'warn', 6500);
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    on(byId('otpBookFile'), 'change', async (ev) => {
        const file = ev.target.files && ev.target.files[0];
        if (!file) return;
        try {
            const buf = new Uint8Array(await file.arrayBuffer());
            await setCurrentBook(await parsePadBook(buf), t('otp.sourceFile', { name: file.name }));
        } catch (e) {
            showToast(t('otp.loadFailed', { msg: e.message }), 'error', 5200);
        }
        ev.target.value = '';
    });

    on(byId('otpBookLoadBtn'), 'click', async () => {
        const text = byId('otpBookLoadText').value.trim();
        if (!text) { showToast(t('otp.loadFirst'), 'warn'); return; }
        try {
            if (looksLikeLetterGroups(text)) {
                await setCurrentBook(await parsePadBook(fromLetterGroups(stripLetterHeader(text))), t('otp.sourceLetters'));
            } else {
                const clean = text.replace(/\s+/g, '');
                await setCurrentBook(await parsePadBook(Uint8Array.from(atob(clean), c => c.charCodeAt(0))), t('otp.sourceB64'));
            }
        } catch (e) {
            showToast(t('otp.loadFailed', { msg: e.message }), 'error', 5200);
        }
    });

    on(byId('otpBookLettersBtn'), 'click', async () => {
        if (!currentBook) { showToast(t('otp.loadBookFirst'), 'warn'); return; }
        if (currentBook.data.length > 64 * 1024) {
            showToast(t('otp.tooBig'), 'warn', 5200);
            return;
        }
        const letters = await padBookToLetterGroups(currentBook);
        byId('otpBookLoadText').value = 'QPAD1 BUKU\n' + letters;
        showToast(t('otp.exported'), 'info');
    });

    on(byId('otpDestroyBtn'), 'click', async () => {
        if (!currentBook) { showToast(t('otp.noBookShort'), 'warn'); return; }
        if (!await confirmDialog(t('otp.destroyConfirm'), t('otp.destroyOk'))) return;
        const wiped = destroyUsedSegments(currentBook);
        renderBookStatus();
        showToast(t('otp.destroyed', { bytes: wiped }), 'success');
    });

    on(byId('otpForgetBtn'), 'click', async () => {
        if (!currentBook) { showToast(t('otp.noBookShort'), 'warn'); return; }
        if (!await confirmDialog(t('otp.forgetConfirm'), t('otp.forgetOk'))) return;
        forgetBook(currentBook);
        currentBook = null;
        renderBookStatus();
        showToast(t('otp.forgotten'), 'info');
    });

    on(byId('otpSendBtn'), 'click', async () => {
        const outEl = byId('otpPacketOut');
        const lettersEl = byId('otpPacketLetters');
        outEl.value = '';
        lettersEl.value = '';
        try {
            if (!currentBook) throw new Error(t('otp.sendNeedBook'));
            const { packetBase64, letterGroups, bytesUsed } = await otpSend(currentBook, byId('otpPlainText').value);
            outEl.value = packetBase64;
            lettersEl.value = letterGroups;
            renderBookStatus();
            showToast(t('otp.sendOk', { bytes: bytesUsed }), 'success');
        } catch (e) {
            outEl.value = 'ERROR: ' + e.message;
        }
    });

    on(byId('otpReceiveBtn'), 'click', async () => {
        const inEl = byId('otpPacketIn');
        const outEl = byId('otpDecryptedOut');
        const warnEl = byId('otpWarning');
        outEl.value = '';
        warnEl.textContent = '';
        warnEl.className = 'otp-warning-box';
        try {
            if (!currentBook) throw new Error(t('otp.recvNeedBook'));
            let packetB64 = inEl.value.trim();
            if (looksLikeLetterGroups(packetB64)) {
                packetB64 = arrayBufferToBase64(fromLetterGroups(stripLetterHeader(packetB64)));
            }
            const { plaintext, duplicate, reuseDetected } = await otpReceive(currentBook, packetB64);
            if (reuseDetected) {
                warnEl.className = 'otp-warning-box danger';
                warnEl.textContent = t('otp.reuseAlert');
            } else if (duplicate) {
                warnEl.className = 'otp-warning-box warn';
                warnEl.textContent = t('otp.duplicateNote');
            }
            outEl.value = plaintext;
            renderBookStatus();
        } catch (e) {
            outEl.value = 'ERROR: ' + e.message;
        }
    });

    // ==============================================================
    //                  INISIALISASI & SELF-TEST
    // ==============================================================
    renderContactList();
    refreshContactDropdowns();
    renderBookStatus();

    // Kunci tombol aksi sampai self-test selesai (A.2).
    actionButtons.forEach(b => { b.disabled = true; });
    if (footerStatus) footerStatus.textContent = t('footer.selftest.running');
    runCryptoSelfTest().then(({ ok, results }) => {
        if (ok) {
            unlockAllActions();
            console.info('[QEKH] self-test OK:', results.map(r => r.name).join(', '));
        } else {
            const failed = results.filter(r => !r.ok).map(r => `${r.name} (${r.detail || 'gagal'})`).join('; ');
            lockAllActions(failed);
        }
    }).catch((e) => lockAllActions(e.message || String(e)));

    // =============================================================
    //              BAHASA: SAKLAR ID/EN (E.6)
    // =============================================================
    const langSelect = byId('langSelect');
    function reapplyDynamicI18n() {
        renderContactList();
        refreshContactDropdowns();
        renderBookStatus();
        if (charCountEl && plainTextEl.value) plainTextEl.dispatchEvent(new Event('input'));
        if (radioOutputEl.value.includes('\n')) radiogramEstimate(radioOutputEl.value.split('\n').slice(1).join(' '));
        if (genFingerprintEl.textContent.endsWith('...')) genFingerprintEl.innerHTML = t('gen.fpPlaceholder');
        if (footerStatus) footerStatus.textContent = t('footer.selftest.' + selfTestState);
    }
    if (langSelect) {
        langSelect.value = I18N_LANG;
        on(langSelect, 'change', () => {
            I18N_LANG = langSelect.value === 'en' ? 'en' : 'id';
            try { localStorage.setItem('qekh.lang', I18N_LANG); } catch { /* abaikan */ }
            applyI18n();
            reapplyDynamicI18n();
        });
    }
    applyI18n();

    // ==============================================================
    //                PWA: SERVICE WORKER (E.2)
    // ==============================================================
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('./sw.js').catch(() => { /* offline cache tidak wajib */ });
    }

    // ==============================================================
    //              DEKORASI: KANVAS KONSTELASI PARTIKEL
    // ==============================================================
    (function initConstellation() {
        const canvas = byId('bgCanvas');
        if (!canvas || !canvas.getContext) return;
        const reduced = globalThis.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
        const ctx = canvas.getContext('2d');
        let width = 0, height = 0, particles = [], rafId = null;

        function resize() {
            width = canvas.width = globalThis.innerWidth;
            height = canvas.height = globalThis.innerHeight;
            const count = Math.min(90, Math.floor(width * height / 22000));
            particles = Array.from({ length: count }, () => ({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.35,
                vy: (Math.random() - 0.5) * 0.35,
                r: 1 + Math.random() * 1.8,
            }));
        }

        function drawFrame(move) {
            ctx.clearRect(0, 0, width, height);
            const light = document.documentElement.getAttribute('data-theme') === 'light';
            const dot = light ? 'rgba(14,116,144,0.45)' : 'rgba(103,232,249,0.5)';
            const line = light ? 'rgba(14,116,144,' : 'rgba(139,92,246,';
            for (const p of particles) {
                if (move) {
                    p.x += p.vx; p.y += p.vy;
                    if (p.x < -10) p.x = width + 10; if (p.x > width + 10) p.x = -10;
                    if (p.y < -10) p.y = height + 10; if (p.y > height + 10) p.y = -10;
                }
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fillStyle = dot;
                ctx.fill();
            }
            for (let i = 0; i < particles.length; i++) {
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const d2 = dx * dx + dy * dy;
                    if (d2 < 130 * 130) {
                        ctx.beginPath();
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.strokeStyle = line + (0.16 * (1 - Math.sqrt(d2) / 130)).toFixed(3) + ')';
                        ctx.stroke();
                    }
                }
            }
        }

        function loop() {
            drawFrame(true);
            rafId = requestAnimationFrame(loop);
        }

        resize();
        if (reduced) {
            drawFrame(false); // satu bingkai statis saja
        } else {
            loop();
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) { cancelAnimationFrame(rafId); rafId = null; }
                else if (!rafId) { loop(); }
            });
        }
        globalThis.addEventListener('resize', () => { resize(); if (reduced) drawFrame(false); });
    })();
});
