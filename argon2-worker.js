// Web Worker untuk Argon2id (E.3) — menjaga UI tetap responsif saat
// membuat/membuka kunci privat ber-passphrase (64 MB memory-hard, ±2 detik).
// Menerima { id, pass, salt, params } dan menjawab { id, type:'progress'|'done'|'error' }.
import { argon2idAsync } from './vendor/noble-hashes-2.4.0/argon2.js';

self.onmessage = async (ev) => {
    const { id, pass, salt, params } = ev.data || {};
    try {
        const key = await argon2idAsync(new Uint8Array(pass), new Uint8Array(salt), {
            ...params,
            onProgress: (v) => self.postMessage({ id, type: 'progress', value: v }),
        });
        self.postMessage({ id, type: 'done', key: key.buffer }, [key.buffer]);
    } catch (e) {
        self.postMessage({ id, type: 'error', error: (e && e.message) || String(e) });
    }
};
