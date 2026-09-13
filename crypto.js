// ============================================
// crypto.js — общие крипто-утилиты
// X25519 + Ed25519 через @noble/curves
// AES-GCM + PBKDF2 + HKDF через WebCrypto
// ============================================

import { x25519 } from 'https://esm.sh/@noble/curves@1.4.0/ed25519';
import { ed25519 } from 'https://esm.sh/@noble/curves@1.4.0/ed25519';

// ---------- Кодирование ----------
export function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
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

// ---------- UTF-8 ----------
export function utf8Encode(str) {
  return new TextEncoder().encode(str);
}

export function utf8Decode(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

export function utf8ToBase64(str) {
  return bufToBase64(utf8Encode(str));
}

export function base64ToUtf8(b64) {
  return utf8Decode(base64ToBuf(b64));
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

// ---------- PBKDF2 ----------
export async function deriveKeyFromPassword(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', utf8Encode(password),
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
    { name: 'AES-GCM', iv }, key, utf8Encode(json)
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
  return JSON.parse(utf8Decode(decrypted));
}

// ---------- Генерация identity ----------
export async function generateIdentity(nickname) {
  const xPriv = x25519.utils.randomPrivateKey();
  const xPub = x25519.getPublicKey(xPriv);

  const ePriv = ed25519.utils.randomPrivateKey();
  const ePub = ed25519.getPublicKey(ePriv);

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

// ---------- E2EE ----------
export async function deriveSharedKey(myPrivBase64, peerPubBase64) {
  const myPriv = base64ToBuf(myPrivBase64);
  const peerPub = base64ToBuf(peerPubBase64);

  const sharedSecret = x25519.getSharedSecret(myPriv, peerPub);

  const hkdfKey = await crypto.subtle.importKey(
    'raw', sharedSecret,
    { name: 'HKDF' }, false, ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: utf8Encode('empty-messenger-v1')
    },
    hkdfKey,
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
    utf8Encode(text)
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
  return utf8Decode(plaintext);
}

// ---------- Hash ----------
export async function hashPubkey(pubBase64) {
  const hash = await crypto.subtle.digest('SHA-256', base64ToBuf(pubBase64));
  return bufToBase64(hash);
}

// ---------- Ed25519 подписи ----------
export async function signBlob(data, ed25519PrivBase64) {
  const priv = base64ToBuf(ed25519PrivBase64);
  const msg = utf8Encode(data);
  const sig = ed25519.sign(msg, priv);
  return bufToBase64(sig);
}

export async function verifyBlob(data, signatureBase64, ed25519PubBase64) {
  try {
    const pub = base64ToBuf(ed25519PubBase64);
    const sig = base64ToBuf(signatureBase64);
    const msg = utf8Encode(data);
    return ed25519.verify(sig, msg, pub);
  } catch {
    return false;
  }
}

// ---------- UUID ----------
export function uuid() {
  return crypto.randomUUID();
}

// ---------- Экспорт / Импорт identity ----------

// Зашифровать приватные ключи временным паролем для передачи на другое устройство
export async function exportIdentity(identity, exportPassword) {
  // Что передаём в зашифрованном виде:
  const payload = {
    nickname: identity.nickname,
    x25519_private: identity.x25519.private,
    ed25519_private: identity.ed25519.private
  };

  // Публичные ключи + fingerprint передаём открыто — они и так публичны
  const publicData = {
    version: 1,
    type: 'identity-export',
    x25519_public: identity.x25519.public,
    ed25519_public: identity.ed25519.public,
    fingerprint: identity.fingerprint,
    createdAt: identity.createdAt
  };

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKeyFromPassword(exportPassword, salt);

  const json = JSON.stringify(payload);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, utf8Encode(json)
  );

  return {
    ...publicData,
    salt: bufToBase64(salt),
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(encrypted)
  };
}

// Восстановить identity из экспорта с временным паролем
export async function importIdentity(exportObj, exportPassword) {
  if (!exportObj || exportObj.type !== 'identity-export') {
    throw new Error('Это не файл экспорта identity');
  }
  if (!exportObj.salt || !exportObj.iv || !exportObj.ciphertext) {
    throw new Error('Повреждённый экспорт');
  }

  const salt = base64ToBuf(exportObj.salt);
  const iv = base64ToBuf(exportObj.iv);
  const ciphertext = base64ToBuf(exportObj.ciphertext);
  const key = await deriveKeyFromPassword(exportPassword, salt);

  let decrypted;
  try {
    decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, key, ciphertext
    );
  } catch {
    throw new Error('Неверный пароль экспорта');
  }

  const payload = JSON.parse(utf8Decode(decrypted));

  return {
    version: 1,
    createdAt: exportObj.createdAt || Date.now(),
    nickname: payload.nickname,
    x25519: {
      public: exportObj.x25519_public,
      private: payload.x25519_private
    },
    ed25519: {
      public: exportObj.ed25519_public,
      private: payload.ed25519_private
    },
    fingerprint: exportObj.fingerprint
  };
}

// ---------- Мультиаккаунт ----------
const ACCOUNTS_FILE = 'accounts.json';

export async function listAccounts() {
  try {
    if (!await opfsExists(ACCOUNTS_FILE)) return { accounts: [], lastActive: null };
    const buf = await opfsRead(ACCOUNTS_FILE);
    const json = utf8Decode(buf);
    const data = JSON.parse(json);
    if (!Array.isArray(data.accounts)) data.accounts = [];
    return data;
  } catch (e) {
    console.error('Не удалось прочитать accounts.json:', e);
    return { accounts: [], lastActive: null };
  }
}

export async function saveAccounts(data) {
  const json = JSON.stringify(data, null, 2);
  await opfsWrite(ACCOUNTS_FILE, utf8Encode(json));
}

export async function addAccountToIndex(identity) {
  const data = await listAccounts();
  const existing = data.accounts.find(a => a.fingerprint === identity.fingerprint);
  if (!existing) {
    data.accounts.push({
      fingerprint: identity.fingerprint,
      nickname: identity.nickname,
      createdAt: identity.createdAt || Date.now()
    });
  } else {
    // Обновим ник на случай изменения
    existing.nickname = identity.nickname;
  }
  data.lastActive = identity.fingerprint;
  await saveAccounts(data);
}

export async function removeAccountFromIndex(fingerprint) {
  const data = await listAccounts();
  data.accounts = data.accounts.filter(a => a.fingerprint !== fingerprint);
  if (data.lastActive === fingerprint) {
    data.lastActive = data.accounts[0]?.fingerprint || null;
  }
  await saveAccounts(data);
}

export async function setLastActive(fingerprint) {
  const data = await listAccounts();
  data.lastActive = fingerprint;
  await saveAccounts(data);
}

export function identityFilePath(fingerprint) {
  // Имя файла без символов, которые ломают OPFS
  return `identity_${fingerprint.replace(/[:\s]/g, '_')}.enc`;
}

export async function deleteAccountFile(fingerprint) {
  const path = identityFilePath(fingerprint);
  if (await opfsExists(path)) {
    await opfsDelete(path);
  }
}

// ---------- Hash (hex) для имён коллекций Firestore ----------
export async function hashPubkeyHex(pubBase64) {
  const hash = await crypto.subtle.digest('SHA-256', base64ToBuf(pubBase64));
  const bytes = new Uint8Array(hash);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}