'use strict';
/*
 * Ridge end-to-end encryption helpers (Web Crypto, no dependencies).
 *
 *  - Auth secret:   PBKDF2(password, "ridge-auth:<username>") -> sent to the server instead of the password.
 *  - Identity:      ECDH P-256 key pair per user. The private key is stored on the server only as an
 *                   AES-GCM blob encrypted with a key derived from the password (random salt), so a
 *                   new device can restore it after login. The server cannot decrypt it.
 *  - Conversation:  one random AES-256-GCM key per encrypted chat. The creator wraps it for every member
 *                   using ECDH(creatorPrivate, memberPublic) -> AES-GCM. Messages are AES-GCM encrypted.
 */
(function (root) {
  const wc = root.crypto || require('node:crypto').webcrypto;
  const subtle = wc.subtle;
  const rnd = n => wc.getRandomValues(new Uint8Array(n));
  const enc = new TextEncoder(), dec = new TextDecoder();
  const EC = { name: 'ECDH', namedCurve: 'P-256' };

  const b64 = u8 => {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');

  async function pbkdf2(password, salt, bits) {
    const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({
      name: 'PBKDF2', hash: 'SHA-256', iterations: 210000,
      salt: typeof salt === 'string' ? enc.encode(salt) : salt
    }, base, bits));
  }

  const authSecret = async (username, password) => hex(await pbkdf2(password, 'ridge-auth:' + username.toLowerCase(), 256));

  const backupKey = async (password, salt) =>
    subtle.importKey('raw', await pbkdf2(password, salt, 256), 'AES-GCM', false, ['encrypt', 'decrypt']);

  const importPriv = jwk => subtle.importKey('jwk', jwk, EC, false, ['deriveKey']);
  const importPub = s => subtle.importKey('jwk', JSON.parse(s), EC, false, []);

  async function createIdentity(password) {
    const kp = await subtle.generateKey(EC, true, ['deriveKey']);
    const publicKey = JSON.stringify(await subtle.exportKey('jwk', kp.publicKey));
    const privJwk = await subtle.exportKey('jwk', kp.privateKey);
    const salt = rnd(16), iv = rnd(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, await backupKey(password, salt), enc.encode(JSON.stringify(privJwk))));
    return { publicKey, keyBackup: { salt: b64(salt), iv: b64(iv), ct: b64(ct) }, privateKey: await importPriv(privJwk) };
  }

  async function unlockIdentity(password, backup) {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(backup.iv) }, await backupKey(password, unb64(backup.salt)), unb64(backup.ct));
    return importPriv(JSON.parse(dec.decode(pt)));
  }

  const sharedKey = async (priv, pubStr) =>
    subtle.deriveKey({ name: 'ECDH', public: await importPub(pubStr) }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const newConvKey = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

  async function wrapConvKey(convKey, priv, theirPub, myId) {
    const iv = rnd(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, await sharedKey(priv, theirPub), await subtle.exportKey('raw', convKey)));
    return { by: myId, iv: b64(iv), ct: b64(ct) };
  }

  async function unwrapConvKey(w, priv, byPub) {
    const raw = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(w.iv) }, await sharedKey(priv, byPub), unb64(w.ct));
    return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function encryptText(key, text) {
    const iv = rnd(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text)));
    return 'e1:' + b64(iv) + ':' + b64(ct);
  }

  async function decryptText(key, s) {
    const [, iv, ct] = s.split(':');
    return dec.decode(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct)));
  }

  // Short code both people can compare out-of-band to detect a swapped key.
  async function fingerprint(pubA, pubB) {
    const [a, b] = [pubA, pubB].sort();
    const h = new Uint8Array(await subtle.digest('SHA-256', enc.encode(a + '|' + b)));
    return hex(h).slice(0, 24).toUpperCase().match(/.{4}/g).join(' ');
  }

  const api = { authSecret, createIdentity, unlockIdentity, newConvKey, wrapConvKey, unwrapConvKey, encryptText, decryptText, fingerprint };
  root.E2E = api;
})(typeof window !== 'undefined' ? window : globalThis);

export default globalThis.E2E;
