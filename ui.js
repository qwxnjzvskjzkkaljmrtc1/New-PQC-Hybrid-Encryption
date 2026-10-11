// ui.js — seluruh wiring DOM untuk Q-EKH Protocol (tab, tombol, toast, kontak,
// radiogram, OTP, dekorasi). Tidak berisi logika kripto; semua itu ada di
// crypto.js / otp.js supaya bisa diuji di Node tanpa browser.
import {
    generateIdentity, encryptHybrid, decryptHybrid, publicKeyInfo,
    runCryptoSelfTest, toLetterGroups, fromLetterGroups, looksLikeLetterGroups,
    stripLetterHeader, encodeText, decodeText, arrayBufferToBase64,
    fingerprintArt, encryptFileHybrid, decryptFileHybrid, fhssSchedule,
} from './crypto.js';
import {
    generatePadBook, serializePadBook, parsePadBook, padBookToLetterGroups,
    otpSend, otpReceive, getBookStatus, destroyUsedSegments, forgetBook,
    bookIdShort,
} from './otp.js';
import { renderCwPcm, encodeWavPcm16, CW_SAMPLE_RATE } from './cw.js';

document.addEventListener('DOMContentLoaded', () => {

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
    function confirmDialog(text, okLabel = 'Lanjutkan') {
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
            'PANIK: semua kontak, registry buku pad, dan isi layar akan DIMUSNAHKAN sekarang, lalu halaman dimuat ulang.\n\nTindakan ini tidak bisa dibatalkan. File .qpad & kunci yang sudah Anda unduh/sendiri simpan tidak terpengaruh.',
            'MUSNAHKAN SEKARANG'
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
                ? 'Auto-lock dimatikan.'
                : `Auto-lock aktif: sesi dikunci setelah ${autoLockSelect.value} menit tanpa aktivitas.`, 'info');
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
            showToast('🔒 Auto-lock: sesi dikunci karena idle — kontak, registry pad, dan isi layar sudah dibersihkan.', 'warn', 6500);
        }
    } catch { /* abaikan */ }

    // ==============================================================
    //                   SELF-TEST KRIPTO SAAT STARTUP (A.2)
    // ==============================================================
    const actionButtons = Array.from(document.querySelectorAll('.action-button'));
    const banner = byId('selfTestBanner');
    const footerStatus = byId('selfTestStatus');

    function lockAllActions(reason) {
        actionButtons.forEach(b => { b.disabled = true; });
        if (banner) {
            banner.className = 'selftest-banner failed';
            banner.innerHTML = '';
            const strong = document.createElement('strong');
            strong.textContent = '⛔ SELF-TEST GAGAL — jangan pakai halaman ini.';
            const detail = document.createElement('p');
            detail.textContent = reason + ' Pustaka kripto rusak atau dimanipulasi; unduh ulang aplikasi dari sumber tepercaya.';
            banner.appendChild(strong);
            banner.appendChild(detail);
        }
        if (footerStatus) {
            footerStatus.textContent = 'Self-test: GAGAL';
            footerStatus.className = 'selftest-status failed';
        }
    }

    function unlockAllActions() {
        actionButtons.forEach(b => { b.disabled = false; });
        if (banner) banner.className = 'selftest-banner';
        if (footerStatus) {
            footerStatus.textContent = 'Self-test: OK';
            footerStatus.className = 'selftest-status ok';
        }
    }

    if (!globalThis.crypto || !globalThis.crypto.subtle) {
        lockAllActions('Web Crypto API tidak tersedia. Buka halaman ini lewat https:// atau http://127.0.0.1 — bukan lewat alamat IP jaringan biasa (http://192.168.x.x), karena browser memblokir crypto.subtle di sana.');
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
            if (!textToCopy || textToCopy === '—' || textToCopy.endsWith('...') || textToCopy.startsWith('ERROR:') || textToCopy.startsWith('Kunci tidak valid')) return;

            const showCopied = () => {
                const originalText = button.textContent;
                button.textContent = 'Tersalin!';
                button.classList.add('copied');
                setTimeout(() => { button.textContent = originalText; button.classList.remove('copied'); }, 2000);
            };

            if (navigator.clipboard && navigator.clipboard.writeText) {
                try { await navigator.clipboard.writeText(textToCopy); showCopied(); }
                catch { showToast('Gagal menyalin — clipboard ditolak browser.', 'error'); }
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
        showToast(`File "${filename}" diunduh.`, 'success');
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
            boxEl.textContent = 'Pustaka QR tidak termuat.';
            return;
        }
        try {
            const qr = qrcode(0, 'M');
            qr.addData(text);
            qr.make();
            boxEl.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 4, scalable: true });
        } catch {
            boxEl.textContent = 'Teks terlalu panjang untuk QR.';
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
            canvas.setAttribute('aria-label', 'Sidik visual (randomart) dari fingerprint');
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
        catch { showToast('Gagal menyimpan kontak — penyimpanan lokal penuh/ditolak.', 'error'); }
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
            manual.textContent = '— tempel manual —';
            sel.appendChild(manual);
            for (const c of contacts) {
                const opt = document.createElement('option');
                opt.value = c.id;
                const warn = expiryState(c) === 'expired' ? ' ⏰KEDALUWARSA' : (c.verified ? '' : ' ⚠️belum-verifikasi');
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
            empty.textContent = 'Belum ada kontak. Tambahkan Kunci Publik lawan bicara di bawah — lalu verifikasi fingerprint-nya lewat jalur terpisah.';
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
                badge.textContent = '⏰ kunci kedaluwarsa';
            } else if (c.verified) {
                badge.className = 'badge badge-verified';
                badge.textContent = '✅ terverifikasi';
            } else {
                badge.className = 'badge badge-unverified';
                badge.textContent = '⚠️ belum diverifikasi';
            }
            head.appendChild(name);
            head.appendChild(badge);

            const fp = document.createElement('div');
            fp.className = 'fingerprint-box contact-fp';
            fp.textContent = c.fingerprint;

            const meta = document.createElement('div');
            meta.className = 'contact-meta';
            meta.textContent = (c.verified && c.verifiedAt ? `Diverifikasi: ${new Date(c.verifiedAt).toLocaleString('id-ID')}. ` : '')
                + (c.expires ? `Berlaku s/d: ${new Date(c.expires).toLocaleDateString('id-ID')}.` : '');

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
            mkBtn('Pakai di Enkripsi', '', () => {
                byId('publicKey').value = c.keyJson;
                byId('contactSelectEncrypt').value = c.id;
                updateFingerprint(byId('publicKey'), byId('recipientFingerprint'));
                showToast(`Kunci Publik "${c.name}" dipakai di tab Enkripsi.`, 'success');
                document.querySelector('[data-tab="encrypt"]').click();
            });
            mkBtn('Pakai di Dekripsi', '', () => {
                byId('senderVerifyKey').value = c.keyJson;
                byId('contactSelectDecrypt').value = c.id;
                updateFingerprint(byId('senderVerifyKey'), byId('senderVerifyFingerprint'));
                showToast(`Kunci Publik "${c.name}" dipakai di tab Dekripsi.`, 'success');
                document.querySelector('[data-tab="decrypt"]').click();
            });
            mkBtn('QR fingerprint', '', () => {
                qrBox.classList.toggle('open');
                if (qrBox.classList.contains('open')) renderQr(qrBox, `QEKH ${c.name} ${c.fingerprint}`);
            });
            if (!c.verified) {
                mkBtn('Tandai terverifikasi', 'verify', async () => {
                    const ok = await confirmDialog(
                        `Anda akan menandai "${c.name}" sebagai TERVERIFIKASI.\n\nPastikan fingerprint di atas sudah Anda cocokkan LANGSUNG dengan pemiliknya (tatap muka/QR/telepon), bukan lewat saluran yang sama dengan kunci dikirim. Yakin?`,
                        'Ya, sudah saya cocokkan'
                    );
                    if (!ok) return;
                    const list = loadContacts();
                    const target = list.find(x => x.id === c.id);
                    target.verified = true;
                    target.verifiedAt = new Date().toISOString();
                    saveContacts(list);
                    renderContactList();
                    refreshContactDropdowns();
                    showToast(`Kontak "${c.name}" ditandai terverifikasi.`, 'success');
                });
            }
            mkBtn('Hapus', 'danger', async () => {
                if (!await confirmDialog(`Hapus kontak "${c.name}" dari buku alamat?`, 'Hapus')) return;
                saveContacts(loadContacts().filter(x => x.id !== c.id));
                renderContactList();
                refreshContactDropdowns();
                showToast(`Kontak "${c.name}" dihapus.`, 'info');
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
        if (!name) { showToast('Isi nama kontak dulu.', 'warn'); return; }
        try {
            const info = await publicKeyInfo(keyEl.value);
            const list = loadContacts();
            if (list.some(c => c.fingerprint === info.fingerprint)) {
                showToast('Kunci ini sudah ada di buku kontak.', 'warn');
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
            showToast(`Kontak "${name}" ditambahkan — status: BELUM diverifikasi.`, 'success');
        } catch (e) {
            showToast('Kunci tidak valid: ' + e.message, 'error', 5200);
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
                    warn.textContent = `⏰ Kunci "${c.name}" sudah KEDALUWARSA (${new Date(c.expires).toLocaleDateString('id-ID')}). Minta kunci baru ke pemiliknya.`;
                    warn.className = 'contact-warn expired';
                } else if (!c.verified) {
                    warn.textContent = `⚠️ Kontak "${c.name}" BELUM diverifikasi fingerprint-nya. Enkripsi tetap bisa jalan, tapi pastikan dulu lewat jalur terpisah.`;
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
    setupCopyButton(byId('copyGenFingerprintBtn'), () => genFingerprintEl.textContent);
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
        if (await confirmDialog('Unduh Kunci Privat sebagai file? Siapa pun yang memegang file ini (plus passphrase-nya) memegang identitas Anda.', 'Unduh')) {
            downloadText('qekh-kunci-privat.json', genPrivateKeyEl.value, 'application/json');
        }
    });
    on(byId('downloadEncryptedBtn'), 'click', () => {
        if (encryptedTextEl.value && !encryptedTextEl.value.startsWith('ERROR')) {
            downloadText('qekh-pesan.txt', encryptedTextEl.value);
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
            boxEl.textContent = info.fingerprint + (info.expires
                ? (info.expired
                    ? `  ⏰ KEDALUWARSA sejak ${new Date(info.expires).toLocaleDateString('id-ID')}`
                    : `  (berlaku s/d ${new Date(info.expires).toLocaleDateString('id-ID')})`)
                : '');
            renderFpArt(boxEl, info.fingerprint);
        } catch (e) {
            boxEl.textContent = 'Kunci tidak valid: ' + e.message;
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
        charCountEl.textContent = `${plainTextEl.value.length} karakter · ${bytes} byte · perkiraan ciphertext ≈ ${(estB64 / 1024).toFixed(1)} KB base64`;
    });

    // ==============================================================
    //                 TAB 1: PEMBUATAN KUNCI (+ QR D.2)
    // ==============================================================
    on(generateBtn, 'click', async () => {
        const existing = genPrivateKeyEl.value;
        if (existing && !existing.startsWith('ERROR:') && !existing.startsWith('Harap tunggu')) {
            if (!await confirmDialog('Kunci yang tampil sekarang akan ditimpa. Pastikan Kunci Privat lama sudah tersimpan aman. Lanjutkan?')) return;
        }

        let expires = null;
        if (genExpiresEl && genExpiresEl.value) {
            const d = new Date(genExpiresEl.value + 'T23:59:59');
            if (isNaN(d)) { showToast('Tanggal kedaluwarsa tidak valid.', 'error'); return; }
            if (d.getTime() <= Date.now()) { showToast('Tanggal kedaluwarsa harus di masa depan.', 'warn'); return; }
            expires = d.toISOString();
        }

        const hasPassphrase = !!genPassphraseEl.value;
        generateBtn.disabled = true;
        generateBtn.textContent = 'Membuat Kunci...';
        [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = hasPassphrase
            ? 'Harap tunggu, membuat 4 pasang kunci + mengenkripsi kunci privat (Argon2id, ±2 detik)...'
            : 'Harap tunggu, membuat 4 pasang kunci...');
        genFingerprintEl.textContent = 'Menghitung...';

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
            showToast('Pasangan kunci baru selesai dibuat.', 'success');
        } catch (e) {
            [genPublicKeyEl, genPrivateKeyEl].forEach(el => el.value = 'ERROR: ' + e.message);
            genFingerprintEl.textContent = 'Gagal membuat kunci.';
            renderFpArt(genFingerprintEl, '');
        } finally {
            setProgress(genProgress, genProgressFill, null);
            generateBtn.disabled = false;
            generateBtn.textContent = 'Buat Pasangan Kunci Hibrida Baru';
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
        encryptBtn.textContent = 'Mengenkripsi & menandatangani...';
        encryptedTextEl.value = '';

        try {
            if (!plainTextEl.value) throw new Error('Pesan masih kosong — tulis dulu plaintext-nya.');
            const bucket = parseInt((byId('bucketSelect') || {}).value || '0', 10) || 0;
            encryptedTextEl.value = await encryptHybrid(
                publicKeyEl.value, senderPrivateKeyEl.value, plainTextEl.value, senderKeyPassphraseEl.value,
                { bucket, onProgress: (v) => setProgress(encryptProgress, encryptProgressFill, v) }
            );
            showToast('Pesan terenkripsi & tertandatangani.', 'success');
            playSeal();
        } catch (e) {
            encryptedTextEl.value = 'ERROR: ' + e.message;
        } finally {
            setProgress(encryptProgress, encryptProgressFill, null);
            encryptBtn.disabled = false;
            encryptBtn.textContent = 'Enkripsi & Tandatangani Pesan';
        }
    });

    // ==============================================================
    //                      TAB 3: DEKRIPSI
    // ==============================================================
    const renderVerification = (v, targetEl = verificationStatusEl) => {
        targetEl.classList.remove('verified', 'failed', 'unverified');
        if (v.status === 'verified') {
            targetEl.classList.add('verified');
            targetEl.innerHTML = '✅ <strong>Tanda tangan VALID</strong> (Ed25519 ✓ dan SLH-DSA ✓). Pesan ini benar ditandatangani oleh pemilik Kunci Publik yang Anda tempel — selama fingerprint-nya memang sudah Anda verifikasi lewat jalur terpisah.';
        } else if (v.status === 'failed') {
            targetEl.classList.add('failed');
            targetEl.innerHTML = `❌ <strong>Tanda tangan TIDAK VALID</strong> (Ed25519 ${v.ed25519 ? '✓' : '✗'}, SLH-DSA ${v.slhdsa ? '✓' : '✗'}). JANGAN percaya isi pesan ini — bisa jadi pesan sudah diubah, atau pengirimnya bukan pemilik Kunci Publik yang Anda tempel.`;
        } else {
            targetEl.classList.add('unverified');
            targetEl.innerHTML = '⚠️ <strong>Pengirim TIDAK diverifikasi.</strong> Kunci Publik pengirim tidak diisi, jadi pesan berhasil didekripsi tanpa bukti siapa pengirimnya.';
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
            if (!isNaN(d)) addLine('🕐 Ditandatangani pada: ' + d.toLocaleString('id-ID'));
        }
        if (meta.from) {
            addLine('Sidik jari pengirim (klaim dari dalam pesan): ' + meta.from);
            if (verification.senderFingerprint) {
                addLine(meta.from === verification.senderFingerprint
                    ? '✓ Klaim sidik jari cocok dengan Kunci Publik yang Anda tempel.'
                    : '⚠️ Klaim sidik jari TIDAK cocok dengan Kunci Publik yang Anda tempel!');
            }
        }
        if (meta.toMismatch) {
            addLine('⚠️ Catatan: metadata penerima di dalam pesan tidak cocok dengan kunci Anda (inkonsistensi sisi pengirim).');
        }
    };

    on(decryptBtn, 'click', async () => {
        decryptBtn.disabled = true;
        decryptBtn.textContent = 'Mendekripsi & memverifikasi...';
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
            decryptBtn.textContent = 'Dekripsi Pesan';
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
                ? `Dipilih: ${chosenFile.name} · ${(chosenFile.size / 1024).toFixed(1)} KB`
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
        if (!chosenFile) { showToast('Pilih atau seret file dulu ke kotak di atas.', 'warn'); return; }
        fileEncryptBtn.disabled = true;
        fileEncryptBtn.textContent = 'Mengenkripsi file...';
        try {
            const data = new Uint8Array(await chosenFile.arrayBuffer());
            const { container, fileName, chunkCount } = await encryptFileHybrid(
                publicKeyEl.value, senderPrivateKeyEl.value, data, chosenFile.name, senderKeyPassphraseEl.value,
                { onProgress: (v) => setProgress(fileEncryptProgress, fileEncryptProgressFill, v) }
            );
            downloadBlob(fileName, new Blob([container], { type: 'application/octet-stream' }));
            showToast(`File terenkripsi: ${chunkCount} chunk × 64 KiB — kunci file tersegel untuk penerima.`, 'success', 5200);
            playSeal();
        } catch (e) {
            showToast('Enkripsi file gagal: ' + e.message, 'error', 6500);
        } finally {
            setProgress(fileEncryptProgress, fileEncryptProgressFill, null);
            fileEncryptBtn.disabled = false;
            fileEncryptBtn.textContent = 'Enkripsi File & Unduh .qekhf';
        }
    });

    on(fileDecryptBtn, 'click', async () => {
        const file = fileDecryptInput && fileDecryptInput.files && fileDecryptInput.files[0];
        if (!file) { showToast('Pilih file .qekhf dulu.', 'warn'); return; }
        fileDecryptBtn.disabled = true;
        fileDecryptBtn.textContent = 'Mendekripsi file...';
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
            showToast(`File "${out.name}" terdekripsi utuh (${out.chunkCount} chunk).`, 'success', 5200);
        } catch (e) {
            showToast('Dekripsi file gagal: ' + e.message, 'error', 6500);
        } finally {
            setProgress(fileDecryptProgress, fileDecryptProgressFill, null);
            fileDecryptBtn.disabled = false;
            fileDecryptBtn.textContent = 'Dekripsi File & Unduh Hasil';
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
            note = 'Durasi pendek — risiko deteksi arah (RDF) relatif rendah.';
        } else if (rounded <= 120) {
            level = 'warn';
            note = 'Cukup lama di udara — stasiun RDF punya kesempatan mengukur. Usahakan burst & pindah lokasi.';
        } else {
            level = 'danger';
            note = 'LAMA di udara — risiko RDF tinggi. Persingkat pesan, naikkan laju, atau pakai pemancar terpisah/jauh.';
        }
        radioEstimateEl.className = `radio-estimate ${level}`;
        radioEstimateEl.textContent = `⏱ Perkiraan durasi pancar: ≈ ${rounded >= 60 ? (rounded / 60).toFixed(1) + ' menit' : rounded + ' detik'} (${chars} karakter). ${note}`;
    }

    on(byId('radioConvertBtn'), 'click', () => {
        const raw = radioInputEl.value.trim();
        radioOutputEl.value = '';
        if (!raw) { showToast('Tempel ciphertext Q-EKH dulu.', 'warn'); return; }
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
                    showToast('Grup huruf dikenali — hasil base64 siap ditempel di tab Dekripsi.', 'success');
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
                throw new Error('Input bukan base64 dan bukan grup huruf.');
            }
            bytes = Uint8Array.from(atob(clean), c => c.charCodeAt(0));
            const groups = toLetterGroups(bytes);
            const groupCount = groups.split(' ').length;
            radioOutputEl.value = `QEKH5 ${groupCount} GRUP\n${groups}`;
            radiogramEstimate(groups);
            showToast(`Radiogram siap: ${groupCount} grup.`, 'success');
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
        h1.textContent = 'LEMBAR RADIOGRAM — Q-EKH';
        const sub = document.createElement('p');
        sub.textContent = `Dicetak ${new Date().toLocaleString('id-ID')} · ${groups.length} grup · base32 RFC 4648 (A–Z, 2–7)`;
        kop.appendChild(h1);
        kop.appendChild(sub);
        if (header) {
            const hd = document.createElement('p');
            hd.className = 'ps-header-line';
            hd.textContent = 'Header pancar: ' + header;
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
        foot.textContent = `Total ${groups.length} grup. Salin/bacakan per grup; corek ☐ tiap grup yang sudah terkirim atau tersalin. Cocokkan jumlah grup di ujung. Musnahkan lembar ini setelah terkirim.`;
        sheet.appendChild(foot);

        printSheetEl.appendChild(sheet);
    }

    on(byId('printRadioBtn'), 'click', () => {
        const out = radioOutputEl.value.trim();
        if (!out || out.startsWith('ERROR')) { showToast('Konversi dulu ciphertext-nya — belum ada radiogram untuk dicetak.', 'warn'); return; }
        const lines = out.split('\n');
        const header = /^QEKH5/i.test(lines[0]) ? lines[0].trim() : '';
        const body = (header ? lines.slice(1).join(' ') : out).replace(/\s+/g, ' ').trim();
        if (!looksLikeLetterGroups(body)) { showToast('Output bukan radiogram grup huruf — tidak bisa dicetak sebagai lembar salin.', 'warn'); return; }
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
        if (cwPlayBtn) cwPlayBtn.textContent = '▶ Putar CW';
    }

    on(cwPlayBtn, 'click', () => {
        if (cwAudio) { stopCw(); return; }
        const text = cwSourceText();
        if (!text) { showToast('Konversi dulu ciphertext-nya — belum ada radiogram untuk dimainkan.', 'warn'); return; }
        try {
            const wpm = cwWpm();
            const pcm = renderCwPcm(text, wpm);
            const AudioCtx = globalThis.AudioContext || globalThis.webkitAudioContext;
            if (!AudioCtx) throw new Error('WebAudio tidak tersedia di browser ini.');
            const ctx = new AudioCtx();
            const buf = ctx.createBuffer(1, pcm.length, CW_SAMPLE_RATE);
            buf.copyToChannel(pcm, 0);
            const src = ctx.createBufferSource();
            src.buffer = buf;
            src.connect(ctx.destination);
            src.onended = () => stopCw();
            cwAudio = { ctx, src };
            src.start();
            cwPlayBtn.textContent = '■ Stop';
            showToast(`Memutar CW ${wpm} WPM — durasi ≈ ${Math.max(1, Math.round(pcm.length / CW_SAMPLE_RATE))} detik.`, 'info');
        } catch (e) {
            showToast('Gagal memutar CW: ' + e.message, 'error');
            stopCw();
        }
    });

    on(byId('cwWavBtn'), 'click', () => {
        const text = cwSourceText();
        if (!text) { showToast('Konversi dulu ciphertext-nya — belum ada radiogram untuk diunduh.', 'warn'); return; }
        try {
            const wpm = cwWpm();
            const wav = encodeWavPcm16(renderCwPcm(text, wpm), CW_SAMPLE_RATE);
            downloadBlob(`qekh-cw-${wpm}wpm.wav`, new Blob([wav], { type: 'audio/wav' }));
        } catch (e) {
            showToast('Gagal membuat WAV: ' + e.message, 'error');
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
            showToast(`Jadwal FHSS ${fhssDateEl.value}: ${slots} slot × ${channels} kanal. Cocokkan dengan tabel milik lawan bicara.`, 'success');
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
            p.textContent = 'Belum ada buku pad yang dimuat. Buat baru atau muat file .qpad — ingat, kedua pihak harus memegang salinan IDENTIK.';
            otpBookStatusEl.appendChild(p);
            return;
        }
        const st = getBookStatus(currentBook);
        const wrap = document.createElement('div');
        wrap.className = 'book-status';
        const title = document.createElement('div');
        title.className = 'book-status-line';
        title.textContent = `Buku pad ${st.bookIdShort}… · ${(st.total / 1024).toFixed(0)} KiB · terpakai ${st.percentUsed}% · sisa ≈ ${(st.remaining / 1024).toFixed(1)} KiB (~${st.remainingMessagesEstimate} pesan pendek)`;
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
            warn.textContent = '⛔ Buku pad habis. Enkripsi baru ditolak — buat & tukar buku baru dengan lawan bicara.';
            wrap.appendChild(warn);
        }
        otpBookStatusEl.appendChild(wrap);
    }

    async function setCurrentBook(book, sourceLabel) {
        currentBook = book;
        renderBookStatus();
        showToast(`Buku pad ${bookIdShort(book)}… dimuat (${sourceLabel}).`, 'success');
    }

    on(byId('otpBookGenBtn'), 'click', async () => {
        const sizeSel = byId('otpBookGenSize');
        const size = parseInt(sizeSel.value, 10);
        try {
            const book = generatePadBook(size);
            const bytes = await serializePadBook(book);
            downloadBlob(`qekh-pad-${bookIdShort(book)}.qpad`, new Blob([bytes], { type: 'application/octet-stream' }));
            await setCurrentBook(book, 'baru dibuat');
            showToast('Tukar file .qpad dengan lawan bicara lewat jalur AMAN (tatap muka). JANGAN lewat internet.', 'warn', 6500);
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    on(byId('otpBookFile'), 'change', async (ev) => {
        const file = ev.target.files && ev.target.files[0];
        if (!file) return;
        try {
            const buf = new Uint8Array(await file.arrayBuffer());
            await setCurrentBook(await parsePadBook(buf), `file ${file.name}`);
        } catch (e) {
            showToast('Gagal memuat buku pad: ' + e.message, 'error', 5200);
        }
        ev.target.value = '';
    });

    on(byId('otpBookLoadBtn'), 'click', async () => {
        const text = byId('otpBookLoadText').value.trim();
        if (!text) { showToast('Tempel base64/grup huruf buku pad dulu.', 'warn'); return; }
        try {
            if (looksLikeLetterGroups(text)) {
                await setCurrentBook(await parsePadBook(fromLetterGroups(stripLetterHeader(text))), 'grup huruf');
            } else {
                const clean = text.replace(/\s+/g, '');
                await setCurrentBook(await parsePadBook(Uint8Array.from(atob(clean), c => c.charCodeAt(0))), 'base64');
            }
        } catch (e) {
            showToast('Gagal memuat buku pad: ' + e.message, 'error', 5200);
        }
    });

    on(byId('otpBookLettersBtn'), 'click', async () => {
        if (!currentBook) { showToast('Muat/buat buku pad dulu.', 'warn'); return; }
        if (currentBook.data.length > 64 * 1024) {
            showToast('Buku terlalu besar untuk grup huruf (> 64 KiB). Pakai file .qpad.', 'warn', 5200);
            return;
        }
        const letters = await padBookToLetterGroups(currentBook);
        byId('otpBookLoadText').value = 'QPAD1 BUKU\n' + letters;
        showToast('Buku pad diekspor sebagai grup huruf ke kolom muat.', 'info');
    });

    on(byId('otpDestroyBtn'), 'click', async () => {
        if (!currentBook) { showToast('Belum ada buku pad.', 'warn'); return; }
        if (!await confirmDialog('Musnahkan semua segmen terpakai (zero-fill)? Paket lama yang merujuk segmen itu tidak akan bisa diverifikasi/dibuka lagi.', 'Musnahkan')) return;
        const wiped = destroyUsedSegments(currentBook);
        renderBookStatus();
        showToast(`${wiped} byte segmen terpakai dimusnahkan.`, 'success');
    });

    on(byId('otpForgetBtn'), 'click', async () => {
        if (!currentBook) { showToast('Belum ada buku pad.', 'warn'); return; }
        if (!await confirmDialog('Lupakan buku pad ini? Registry pemakaiannya dihapus dan buku dibuang dari memori. Pastikan salinan .qpad-nya masih ada bila masih diperlukan.', 'Lupakan')) return;
        forgetBook(currentBook);
        currentBook = null;
        renderBookStatus();
        showToast('Buku pad dilupakan.', 'info');
    });

    on(byId('otpSendBtn'), 'click', async () => {
        const outEl = byId('otpPacketOut');
        const lettersEl = byId('otpPacketLetters');
        outEl.value = '';
        lettersEl.value = '';
        try {
            if (!currentBook) throw new Error('Muat atau buat buku pad dulu.');
            const { packetBase64, letterGroups, bytesUsed } = await otpSend(currentBook, byId('otpPlainText').value);
            outEl.value = packetBase64;
            lettersEl.value = letterGroups;
            renderBookStatus();
            showToast(`Paket OTP-v2 dibuat (${bytesUsed} byte pad terpakai, tidak akan dipakai ulang).`, 'success');
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
            if (!currentBook) throw new Error('Muat buku pad dulu — paket hanya bisa dibuka dengan buku yang sama.');
            let packetB64 = inEl.value.trim();
            if (looksLikeLetterGroups(packetB64)) {
                packetB64 = arrayBufferToBase64(fromLetterGroups(stripLetterHeader(packetB64)));
            }
            const { plaintext, duplicate, reuseDetected } = await otpReceive(currentBook, packetB64);
            if (reuseDetected) {
                warnEl.className = 'otp-warning-box danger';
                warnEl.textContent = '🚨 PAD TERDETEKSI DIPAKAI ULANG: offset paket ini sama dengan paket lain yang isinya BERBEDA. Keamanan pesan-pesan pada offset itu runtuh — ganti buku pad SEKARANG dan selidiki sumbernya.';
            } else if (duplicate) {
                warnEl.className = 'otp-warning-box warn';
                warnEl.textContent = 'ℹ️ Paket ini persis sama dengan yang sudah pernah diterima (duplikat) — tidak ada segmen baru yang terpakai.';
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
    if (footerStatus) footerStatus.textContent = 'Self-test: berjalan…';
    runCryptoSelfTest().then(({ ok, results }) => {
        if (ok) {
            unlockAllActions();
            console.info('[QEKH] self-test OK:', results.map(r => r.name).join(', '));
        } else {
            const failed = results.filter(r => !r.ok).map(r => `${r.name} (${r.detail || 'gagal'})`).join('; ');
            lockAllActions(failed);
        }
    }).catch((e) => lockAllActions(e.message || String(e)));

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
