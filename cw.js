// cw.js — radiogram sebagai CW (morse) via WebAudio (butir C.1).
// Semua lokal (lolos CSP): timing PARIS (unit = 1200/WPM ms), nada sine
// 600 Hz dengan ramp 4 ms anti-klik, dan encoder WAV PCM16 murni JS.
// Fungsi di sini tanpa DOM/AudioContext — bisa diuji di Node; pemutaran
// langsung (AudioContext) dirangkai di ui.js.

// Tabel morse untuk alfabet base32 radiogram (A–Z, 2–7) + sisa digit.
export const MORSE_TABLE = Object.freeze({
    A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....',
    I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.',
    Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-',
    Y: '-.--', Z: '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
});

export const CW_DEFAULT_FREQ = 600;     // Hz
export const CW_SAMPLE_RATE = 8000;     // cukup untuk nada 600 Hz, file tetap kecil

// Satu unit waktu morse (PARIS) dalam milidetik.
export function cwUnitMs(wpm) {
    if (!Number.isFinite(wpm) || wpm <= 0) throw new Error('WPM harus angka positif.');
    return 1200 / wpm;
}

// Ubah teks menjadi timeline segmen { on: bool, ms: number }.
// Aturan: titik 1u, garis 3u, jeda intra-karakter 1u, antar huruf 3u,
// antar kata (spasi/baris baru) 7u. Karakter di luar tabel di-skip.
export function morseTimeline(text, wpm = 15) {
    const unit = cwUnitMs(wpm);
    const words = String(text).toUpperCase().split(/\s+/)
        .map(w => Array.from(w).map(ch => MORSE_TABLE[ch]).filter(Boolean))
        .filter(w => w.length > 0);
    const segs = [];
    const push = (on, units) => {
        const last = segs[segs.length - 1];
        if (last && last.on === on) last.ms += units * unit;
        else segs.push({ on, ms: units * unit });
    };
    words.forEach((codes, wi) => {
        if (wi > 0) push(false, 7);
        codes.forEach((code, ci) => {
            if (ci > 0) push(false, 3);
            for (const sym of code) {
                push(true, sym === '.' ? 1 : 3);
                push(false, 1);
            }
            segs.pop(); // jeda intra terakhir digantikan jeda huruf/kata/akhir
        });
    });
    return segs;
}

export const timelineMs = (segs) => segs.reduce((sum, s) => sum + s.ms, 0);

// Render timeline menjadi PCM Float32 mono — sine `freq` Hz, ramp 4 ms di
// setiap tepi nada supaya tidak berbunyi "klik". Murni aritmetika.
export function renderCwPcm(text, wpm = 15, freq = CW_DEFAULT_FREQ, sampleRate = CW_SAMPLE_RATE) {
    const segs = morseTimeline(text, wpm);
    const segSamples = segs.map(s => Math.round(s.ms * sampleRate / 1000));
    const total = segSamples.reduce((a, b) => a + b, 0);
    const out = new Float32Array(total);
    const rampN = Math.round(4 * sampleRate / 1000); // 4 ms
    let pos = 0;
    segs.forEach((seg, si) => {
        const n = segSamples[si];
        if (seg.on) {
            const ramp = Math.min(rampN, Math.floor(n / 2));
            for (let i = 0; i < n; i++) {
                let env = 1;
                if (ramp > 0) {
                    if (i < ramp) env = i / ramp;
                    else if (i >= n - ramp) env = (n - i) / ramp;
                }
                out[pos + i] = Math.sin(2 * Math.PI * freq * (pos + i) / sampleRate) * env * 0.7;
            }
        }
        pos += n;
    });
    return out;
}

// Bungkus PCM Float32 mono menjadi file WAV 16-bit (RIFF) — siap unduh.
export function encodeWavPcm16(samples, sampleRate = CW_SAMPLE_RATE) {
    const n = samples.length;
    const buf = new Uint8Array(44 + n * 2);
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const writeStr = (off, s) => { for (let i = 0; i < s.length; i++) buf[off + i] = s.charCodeAt(i); };
    writeStr(0, 'RIFF');
    dv.setUint32(4, 36 + n * 2, true);
    writeStr(8, 'WAVE');
    writeStr(12, 'fmt ');
    dv.setUint32(16, 16, true);      // ukuran blok fmt
    dv.setUint16(20, 1, true);       // PCM
    dv.setUint16(22, 1, true);       // mono
    dv.setUint32(24, sampleRate, true);
    dv.setUint32(28, sampleRate * 2, true); // byte rate
    dv.setUint16(32, 2, true);       // block align
    dv.setUint16(34, 16, true);      // bit per sampel
    writeStr(36, 'data');
    dv.setUint32(40, n * 2, true);
    for (let i = 0; i < n; i++) {
        const s = Math.max(-1, Math.min(1, samples[i]));
        dv.setInt16(44 + i * 2, Math.round(s * 32767), true);
    }
    return buf;
}
