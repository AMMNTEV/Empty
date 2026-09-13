// ============================================
// crypto.js — общие крипто-утилиты
// ============================================

// ---------- Кодирование ----------
export function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function base64ToBuf(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---------- OPFS ----------
export async function opfsWrite(filename, data) {
  const root = await navigator.storage.getDirectory();
  const handle = await root.getFileHandle(filename, { create: true });
  const writable = await handle.createWritable();
  await writable.write(data);
  await writable.close();
}

export async function opfsRead(filename) {
  const root = await navigator.storage.getDirectory();
  const handle = await root.getFileHandle(filename);
  const file = await handle.getFile();
  return await file.arrayBuffer();
}

export async function opfsExists(filename) {
  try {
    const root = await navigator.storage.getDirectory();
    await root.getFileHandle(filename);
    return true;
  } catch {
    return false;
  }
}

export async function opfsDelete(filename) {
  const root = await navigator.storage.getDirectory();
  await root.removeEntry(filename);
}

// ---------- Пароль → ключ (PBKDF2) ----------
export async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password),
    { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------- Шифрование файла identity ----------
export async function encryptIdentity(identity, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKeyFromPassword(password, salt);
  const json = JSON.stringify(identity);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(json)
  );
  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);
  return result;
}

export async function decryptIdentity(encryptedBuf, password) {
  const data = new Uint8Array(encryptedBuf);
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ciphertext = data.slice(28);
  const key = await deriveKeyFromPassword(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, key, ciphertext
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ---------- Генерация identity ----------
export async function generateIdentity(nickname) {
  const x25519 = await crypto.subtle.generateKey(
    { name: 'X25519' }, true, ['deriveKey', 'deriveBits']
  );
  const ed25519 = await crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify']
  );

  const xPub = await crypto.subtle.exportKey('raw', x25519.publicKey);
  const xPriv = await crypto.subtle.exportKey('raw', x25519.privateKey);
  const ePub = await crypto.subtle.exportKey('raw', ed25519.publicKey);
  const ePriv = await crypto.subtle.exportKey('raw', ed25519.privateKey);

  const fpBuf = await crypto.subtle.digest('SHA-256', xPub);

  return {
    version: 1,
    createdAt: Date.now(),
    nickname,
    x25519: { public: bufToBase64(xPub), private: bufToBase64(xPriv) },
    ed25519: { public: bufToBase64(ePub), private: bufToBase64(ePriv) },
    fingerprint: formatFingerprint(fpBuf)
  };
}

export function formatFingerprint(buf) {
  const bytes = new Uint8Array(buf).slice(0, 16);
  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
  return hex.match(/.{1,4}/g).join(':');
}

// ---------- E2EE (X25519 + AES-GCM) ----------
// Из приватного X25519 (base64) и публичного X25519 собеседника (base64)
// получаем симметричный AES ключ
export async function deriveSharedKey(myPrivBase64, peerPubBase64) {
  const myPriv = await crypto.subtle.importKey(
    'raw', base64ToBuf(myPrivBase64),
    { name: 'X25519' }, false, ['deriveKey', 'deriveBits']
  );
  const peerPub = await crypto.subtle.importKey(
    'raw', base64ToBuf(peerPubBase64),
    { name: 'X25519' }, false, []
  );
  return await crypto.subtle.deriveKey(
    { name: 'X25519', public: peerPub },
    myPriv,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptMessage(text, sharedKey) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sharedKey,
    new TextEncoder().encode(text)
  );
  return {
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(ciphertext)
  };
}

export async function decryptMessage(blob, sharedKey) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBuf(blob.iv) },
    sharedKey,
    base64ToBuf(blob.ciphertext)
  );
  return new TextDecoder().decode(plaintext);
}

// ---------- Hash для relay-адресации ----------
// Используем SHA-256 от публичного X25519, чтобы сервер не знал, кто есть кто
export async function hashPubkey(pubBase64) {
  const hash = await crypto.subtle.digest('SHA-256', base64ToBuf(pubBase64));
  return bufToBase64(hash);
}

// ---------- Ed25519 подписи ----------
export async function signBlob(data, ed25519PrivBase64) {
  const privKey = await crypto.subtle.importKey(
    'raw', base64ToBuf(ed25519PrivBase64),
    { name: 'Ed25519' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privKey,
    new TextEncoder().encode(data)
  );
  return bufToBase64(signature);
}

export async function verifyBlob(data, signatureBase64, ed25519PubBase64) {
  try {
    const pubKey = await crypto.subtle.importKey(
      'raw', base64ToBuf(ed25519PubBase64),
      { name: 'Ed25519' }, false, ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      pubKey,
      base64ToBuf(signatureBase64),
      new TextEncoder().encode(data)
    );
  } catch {
    return false;
  }
}

// ---------- UUID для сообщений ----------
export function uuid() {
  return crypto.randomUUID();
}