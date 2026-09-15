// ============================================
// messenger.js — контакты, чаты, E2EE, relay
// Схема: users/{hashHex}/inbox/{blobId}
// Файлы контактов и чатов — свои на каждый аккаунт
// ============================================
import { db } from './firebase-init.js';
import {
  collection, addDoc, onSnapshot,
  deleteDoc, doc, getDocs, writeBatch
} from "https://www.gstatic.com/firebasejs/10.8.1/firebase-firestore.js";

import {
  opfsWrite, opfsRead, opfsExists,
  decryptIdentity, encryptIdentity,
  deriveSharedKey, encryptMessage, decryptMessage,
  hashPubkeyHex,
  signBlob, verifyBlob, uuid,
  exportIdentity,
  listAccounts, setLastActive, identityFilePath
} from './crypto.js';

const RELAY_TTL_MS = 25 * 60 * 60 * 1000;
const CHAT_TTL_MS = 24 * 60 * 60 * 1000;

// Proof-of-work: сколько ведущих нулевых hex-символов требуем в SHA-256.
// 4 → в среднем ~65536 попыток, ~0.1–0.5 сек на телефоне.
// 5 → ~1M попыток, ~2–5 сек. 6 → ~16M, ~30–60 сек (слишком долго).
const POW_DIFFICULTY = 4;

let myIdentity = null;
let myPassword = null;
let myHashHex = null;
let contacts = {};
let chatHistory = {};
let activeChat = null;
let unsubscribeIncoming = null;
let timerInterval = null;
let saveChatsTimer = null;
let scannerStream = null;
let scannerRAF = null;
let purgeCheckInterval = null;

let CONTACTS_FILE = null;
let CHATS_FILE = null;


// ============================================
// OPFS
// ============================================
async function saveContacts() {
  if (!myPassword || !CONTACTS_FILE) return;
  const encrypted = await encryptIdentity(contacts, myPassword);
  await opfsWrite(CONTACTS_FILE, encrypted);
}

async function loadContacts() {
  if (!myPassword || !CONTACTS_FILE) return {};
  if (!await opfsExists(CONTACTS_FILE)) return {};
  try {
    const enc = await opfsRead(CONTACTS_FILE);
    return await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('[OPFS] контакты:', e);
    return {};
  }
}

async function saveChats() {
  if (!myPassword || !CHATS_FILE) return;
  if (saveChatsTimer) clearTimeout(saveChatsTimer);
  saveChatsTimer = setTimeout(async () => {
    try {
      const encrypted = await encryptIdentity(chatHistory, myPassword);
      await opfsWrite(CHATS_FILE, encrypted);
    } catch (e) {
      console.error('[OPFS] чаты:', e);
    }
  }, 500);
}

async function loadChats() {
  if (!myPassword || !CHATS_FILE) return {};
  if (!await opfsExists(CHATS_FILE)) return {};
  try {
    const enc = await opfsRead(CHATS_FILE);
    return await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('[OPFS] чаты:', e);
    return {};
  }
}


// ============================================
// INBOX
// ============================================
function myInboxRef() {
  return collection(db, 'users', myHashHex, 'inbox');
}


// ============================================
// PROOF-OF-WORK
// ============================================
// Ищем nonce, чтобы SHA-256(ciphertext + ':' + nonce) начинался
// с POW_DIFFICULTY нулевых hex-символов.
async function computePow(ciphertextB64) {
  let nonce = 0;
  while (true) {
    const buf = new TextEncoder().encode(ciphertextB64 + ':' + nonce);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const hex = Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    if (hex.startsWith('0'.repeat(POW_DIFFICULTY))) {
      return nonce;
    }
    nonce++;
    if (nonce > 10_000_000) {
      throw new Error('PoW не сошёлся за разумное время');
    }
  }
}

async function verifyPow(ciphertextB64, pow) {
  if (typeof pow !== 'number' || !Number.isInteger(pow) || pow < 0) return false;
  const buf = new TextEncoder().encode(ciphertextB64 + ':' + pow);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  const hex = Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return hex.startsWith('0'.repeat(POW_DIFFICULTY));
}


// ============================================
// АВТООЧИСТКА
// ============================================
async function purgeExpiredChats() {
  const now = Date.now();
  let changed = false;

  for (const fp in chatHistory) {
    if (chatHistory[fp].expiresAt && chatHistory[fp].expiresAt < now) {
      console.log(`[PURGE] Чат с "${chatHistory[fp].peerNickname}" истёк`);

      purgeRelayForContact(fp).catch(e => console.warn('[PURGE]', e));

      if (activeChat && activeChat.fingerprint === fp) {
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = null;
        activeChat = null;
      }

      delete chatHistory[fp];
      changed = true;
    }
  }

  if (changed) {
    saveChats();
    renderContacts();
    renderChat();
  }
}

async function purgeRelayForContact(peerFingerprint) {
  try {
    const peer = contacts[peerFingerprint];
    if (!peer) return 0;

    const peerHashHex = await hashPubkeyHex(peer.x25519);
    const snapshot = await getDocs(myInboxRef());

    const toDelete = [];
    snapshot.forEach(d => {
      if (d.data().from === peerHashHex) toDelete.push(d.ref);
    });

    for (let i = 0; i < toDelete.length; i += 500) {
      const batch = writeBatch(db);
      toDelete.slice(i, i + 500).forEach(ref => batch.delete(ref));
      await batch.commit();
    }

    if (toDelete.length > 0) {
      console.log(`[PURGE] Удалено блобов от "${peer.nickname}": ${toDelete.length}`);
    }
    return toDelete.length;
  } catch (e) {
    console.warn('[PURGE]', e);
    return 0;
  }
}


// ============================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================
async function init() {
  myPassword = sessionStorage.getItem('_pw');
  const myFp = sessionStorage.getItem('_fp');

  if (!myPassword || !myFp) {
    window.location.href = 'index.html';
    return;
  }

  try {
    const path = identityFilePath(myFp);
    if (!await opfsExists(path)) throw new Error('Файл аккаунта не найден');
    const enc = await opfsRead(path);
    myIdentity = await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('[INIT]', e);
    sessionStorage.removeItem('_pw');
    sessionStorage.removeItem('_fp');
    window.location.href = 'index.html';
    return;
  }

  myHashHex = await hashPubkeyHex(myIdentity.x25519.public);
  CONTACTS_FILE = `contacts_${myHashHex}.enc`;
  CHATS_FILE = `chats_${myHashHex}.enc`;

  document.getElementById('meName').textContent = myIdentity.nickname;

  contacts = await loadContacts();
  chatHistory = await loadChats();

  await purgeExpiredChats();

  renderContacts();
  listenIncoming();
  bindUI();

  if (purgeCheckInterval) clearInterval(purgeCheckInterval);
  purgeCheckInterval = setInterval(() => {
    purgeExpiredChats().catch(e => console.warn('[PURGE]', e));
  }, 60 * 1000);
}


// ============================================
// КАРТОЧКА
// ============================================
function buildMyCard() {
  return {
    version: 1,
    nickname: myIdentity.nickname,
    x25519: myIdentity.x25519.public,
    ed25519: myIdentity.ed25519.public,
    fingerprint: myIdentity.fingerprint
  };
}


// ============================================
// КОНТАКТЫ
// ============================================
function renderContacts() {
  const list = document.getElementById('contactsList');
  const keys = Object.keys(contacts);

  if (keys.length === 0) {
    list.innerHTML = '<div class="empty-sidebar">Нет контактов.<br>Нажмите «Добавить».</div>';
    return;
  }

  list.innerHTML = keys.map(fp => {
    const c = contacts[fp];
    const initial = (c.nickname || '?').charAt(0).toUpperCase();
    const active = activeChat && activeChat.fingerprint === fp ? 'active' : '';
    return `
      <div class="contact ${active}" data-fp="${fp}">
        <div class="avatar">${initial}</div>
        <div class="contact-info">
          <div class="contact-name">${escapeHtml(c.nickname || 'Без имени')}</div>
          <div class="contact-fp">${fp}</div>
        </div>
      </div>
    `;
  }).join('');

  list.querySelectorAll('.contact').forEach(el => {
    el.addEventListener('click', () => openChat(el.dataset.fp));
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}


// ============================================
// QR: МОЯ КАРТОЧКА
// ============================================
async function showMyCard() {
  const card = buildMyCard();
  const json = JSON.stringify(card);
  document.getElementById('myCardJson').value = json;

  const qrBox = document.getElementById('qrBox');
  qrBox.innerHTML = '';

  try {
    if (typeof qrcode !== 'function') throw new Error('QR-библиотека не загружена');
    const qr = qrcode(0, 'M');
    qr.addData(json);
    qr.make();

    const cellSize = 6;
    const margin = 4;
    const count = qr.getModuleCount();
    const size = count * cellSize + margin * 2;

    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';

    for (let row = 0; row < count; row++) {
      for (let col = 0; col < count; col++) {
        if (qr.isDark(row, col)) {
          ctx.fillRect(margin + col * cellSize, margin + row * cellSize, cellSize, cellSize);
        }
      }
    }

    canvas.style.maxWidth = '100%';
    canvas.style.height = 'auto';
    qrBox.appendChild(canvas);
  } catch (e) {
    console.error('[QR]', e);
    qrBox.innerHTML = '<div style="color:#333;font-size:12px;padding:10px;">QR недоступен — используйте JSON</div>';
  }

  document.getElementById('modalMyCard').classList.add('active');
}


// ============================================
// QR-СКАНЕР
// ============================================
async function startScanner() {
  const video = document.getElementById('scannerVideo');
  const errEl = document.getElementById('scanError');
  errEl.textContent = '';

  if (scannerStream) return;

  try {
    scannerStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } }
    });
    video.srcObject = scannerStream;
    await video.play();

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    const tick = () => {
      if (!scannerStream) return;
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        if (typeof jsQR === 'function') {
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert'
          });
          if (code && code.data) {
            handleScannedQR(code.data);
            return;
          }
        }
      }
      scannerRAF = requestAnimationFrame(tick);
    };
    tick();
  } catch (e) {
    console.error('[SCAN]', e);
    errEl.textContent = 'Не удалось получить доступ к камере: ' + e.message;
  }
}

function stopScanner() {
  if (scannerRAF) { cancelAnimationFrame(scannerRAF); scannerRAF = null; }
  if (scannerStream) {
    scannerStream.getTracks().forEach(t => t.stop());
    scannerStream = null;
  }
  const video = document.getElementById('scannerVideo');
  if (video) video.srcObject = null;
}

async function handleScannedQR(text) {
  stopScanner();
  try {
    const card = JSON.parse(text);
    await addContactFromCard(card);
    closeAddContactModal();
    setTimeout(() => alert(`Контакт "${card.nickname}" добавлен`), 100);
  } catch (e) {
    console.error('[SCAN]', e);
    document.getElementById('scanError').textContent = 'Не удалось распознать: ' + e.message;
  }
}


// ============================================
// ДОБАВЛЕНИЕ КОНТАКТА
// ============================================
async function addContactFromCard(card) {
  if (!card || !card.x25519 || !card.fingerprint || !card.ed25519) {
    throw new Error('В карточке нет ключей');
  }
  if (card.fingerprint === myIdentity.fingerprint) {
    throw new Error('Это ваша карточка');
  }

  const existing = contacts[card.fingerprint];
  if (existing) {
    const keysChanged = existing.x25519 !== card.x25519 || existing.ed25519 !== card.ed25519;
    if (keysChanged) {
      const ok = confirm(
        `Ключи контакта "${card.nickname}" изменились.\n` +
        `Обновить контакт? Старая переписка будет удалена.`
      );
      if (!ok) return;
      delete chatHistory[card.fingerprint];
      await saveChats();
    }
  }

  contacts[card.fingerprint] = card;
  await saveContacts();
  renderContacts();

  if (activeChat && activeChat.fingerprint === card.fingerprint) {
    activeChat.peerCard = card;
    renderChat();
  }
}

async function addContactFromJson(json) {
  const errEl = document.getElementById('addError');
  errEl.textContent = '';
  let card;
  try {
    card = JSON.parse(json.trim());
  } catch {
    errEl.textContent = 'Некорректный JSON';
    return;
  }
  try {
    await addContactFromCard(card);
    closeAddContactModal();
    document.getElementById('addCardJson').value = '';
  } catch (e) {
    errEl.textContent = e.message;
  }
}


// ============================================
// МОДАЛКА ДОБАВЛЕНИЯ
// ============================================
function openAddContactModal() {
  document.getElementById('addError').textContent = '';
  document.getElementById('scanError').textContent = '';
  document.getElementById('modalAddContact').classList.add('active');
  switchTab('scan');
}

function closeAddContactModal() {
  stopScanner();
  document.getElementById('modalAddContact').classList.remove('active');
}

function switchTab(tabName) {
  document.querySelectorAll('#modalAddContact .tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tabName);
  });
  document.querySelectorAll('#modalAddContact .tab-panel').forEach(p => {
    p.classList.remove('active');
  });
  if (tabName === 'scan') {
    document.getElementById('tabScan').classList.add('active');
    startScanner();
  } else {
    document.getElementById('tabManual').classList.add('active');
    stopScanner();
  }
}


// ============================================
// ОТКРЫТИЕ ЧАТА
// ============================================
async function openChat(fingerprint) {
  const card = contacts[fingerprint];
  if (!card) return;

  const sharedKey = await deriveSharedKey(
    myIdentity.x25519.private,
    card.x25519
  );

  activeChat = { fingerprint, peerCard: card, sharedKey };

  if (!chatHistory[fingerprint]) {
    chatHistory[fingerprint] = {
      peerNickname: card.nickname,
      messages: [],
      lastActivity: Date.now(),
      expiresAt: Date.now() + CHAT_TTL_MS
    };
    saveChats();
  }

  renderContacts();
  renderChat();
  startTimer();
}


// ============================================
// РЕНДЕР ЧАТА
// ============================================
function renderChat() {
  const chatArea = document.getElementById('chatArea');
  const empty = document.getElementById('chatEmpty');
  const header = document.getElementById('chatHeader');
  const messages = document.getElementById('messages');
  const inputArea = document.getElementById('inputArea');

  if (!activeChat) {
    chatArea.classList.remove('active');
    empty.style.display = 'flex';
    header.classList.remove('active');
    messages.classList.remove('active');
    inputArea.classList.remove('active');
    messages.innerHTML = '';
    return;
  }

  chatArea.classList.add('active');
  empty.style.display = 'none';
  header.classList.add('active');
  messages.classList.add('active');
  inputArea.classList.add('active');

  document.getElementById('chatTitle').textContent = activeChat.peerCard.nickname;

  const history = chatHistory[activeChat.fingerprint];
  const msgs = history ? history.messages : [];

  messages.innerHTML = msgs.map(m => {
    const cls = m.from === 'me' ? 'me' : 'other';
    return `<div class="msg ${cls}">${escapeHtml(m.text)}</div>`;
  }).join('');

  requestAnimationFrame(() => {
    messages.scrollTop = messages.scrollHeight;
  });
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    if (!activeChat) return;
    const history = chatHistory[activeChat.fingerprint];
    if (!history) return;
    const left = history.expiresAt - Date.now();
    if (left <= 0) { endChat(); return; }
    const h = Math.floor(left / 3600000);
    const min = Math.floor((left % 3600000) / 60000);
    const sec = Math.floor((left % 60000) / 1000);
    document.getElementById('chatTimer').textContent =
      `⏱ ${h}:${String(min).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  }, 1000);

  const history = chatHistory[activeChat?.fingerprint];
  if (history) {
    const left = history.expiresAt - Date.now();
    if (left > 0) {
      const h = Math.floor(left / 3600000);
      const min = Math.floor((left % 3600000) / 60000);
      const sec = Math.floor((left % 60000) / 1000);
      document.getElementById('chatTimer').textContent =
        `⏱ ${h}:${String(min).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
    }
  }
}

function endChat() {
  if (!activeChat) return;
  const fp = activeChat.fingerprint;
  const peerNickname = activeChat.peerCard.nickname;

  purgeRelayForContact(fp);

  delete chatHistory[fp];
  saveChats();

  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
  activeChat = null;

  renderContacts();
  renderChat();

  console.log(`[END] Чат с "${peerNickname}" завершён`);
}

function exitChat() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
  activeChat = null;
  renderContacts();
  renderChat();
}


// ============================================
// ОТПРАВКА СООБЩЕНИЯ
// ============================================
async function sendMessage() {
  const input = document.getElementById('msgInput');
  const text = input.value.trim();
  if (!text || !activeChat) return;

  input.value = '';
  input.style.height = 'auto';

  const fp = activeChat.fingerprint;
  const msgId = uuid();
  const ts = Date.now();

  const toHashHex = await hashPubkeyHex(activeChat.peerCard.x25519);

  // payload содержит from/to — они часть шифротекста, подделать нельзя
  const payload = JSON.stringify({
    id: msgId,
    text,
    ts,
    from: myHashHex,
    to: toHashHex
  });

  const blob = await encryptMessage(payload, activeChat.sharedKey);

  // Подпись покрывает ciphertext + from + to
  const signedData = JSON.stringify({
    ciphertext: blob.ciphertext,
    from: myHashHex,
    to: toHashHex
  });
  const signature = await signBlob(signedData, myIdentity.ed25519.private);

  // PoW поверх ciphertext — защита от консольного спама
  let pow;
  try {
    pow = await computePow(blob.ciphertext);
  } catch (e) {
    console.error('[SEND] PoW failed:', e);
    return;
  }

  try {
    const inboxRef = collection(db, 'users', toHashHex, 'inbox');

    await addDoc(inboxRef, {
      from: myHashHex,
      to: toHashHex,
      iv: blob.iv,
      ciphertext: blob.ciphertext,
      signature: signature,
      senderEd25519: myIdentity.ed25519.public,
      pow: pow,
      ttl: Date.now() + RELAY_TTL_MS
    });
  } catch (e) {
    console.error('[SEND]', e);
  }

  if (!chatHistory[fp]) {
    chatHistory[fp] = {
      peerNickname: activeChat.peerCard.nickname,
      messages: [],
      lastActivity: ts,
      expiresAt: ts + CHAT_TTL_MS
    };
  }
  chatHistory[fp].messages.push({ id: msgId, from: 'me', text, ts });
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  saveChats();
  renderChat();
  startTimer();
}


// ============================================
// СЛУШАТЕЛЬ ВХОДЯЩИХ
// ============================================
async function listenIncoming() {
  const inboxRef = myInboxRef();

  unsubscribeIncoming = onSnapshot(inboxRef, async (snapshot) => {
    for (const change of snapshot.docChanges()) {
      if (change.type !== 'added') continue;

      const data = change.doc.data();
      const docId = change.doc.id;
      const docRef = doc(db, 'users', myHashHex, 'inbox', docId);

      // 1. Структурная валидация — режем всё, что не похоже на наше сообщение
      if (
        typeof data.from !== 'string' ||
        typeof data.to !== 'string' ||
        typeof data.iv !== 'string' ||
        typeof data.ciphertext !== 'string' ||
        typeof data.signature !== 'string' ||
        typeof data.senderEd25519 !== 'string' ||
        typeof data.pow !== 'number' ||
        typeof data.ttl !== 'number'
      ) {
        await deleteDoc(docRef); continue;
      }

      // 2. to должен быть нами (защита от переиспользования блоба)
      if (data.to !== myHashHex) {
        await deleteDoc(docRef); continue;
      }

      // 3. TTL
      if (data.ttl < Date.now()) {
        await deleteDoc(docRef); continue;
      }

      // 4. PoW
      if (!await verifyPow(data.ciphertext, data.pow)) {
        await deleteDoc(docRef); continue;
      }

      // 5. Ищем контакт по from. Auto-add УБРАН — только существующие контакты.
      let peerFp = null;
      for (const fp in contacts) {
        const h = await hashPubkeyHex(contacts[fp].x25519);
        if (h === data.from) { peerFp = fp; break; }
      }
      if (!peerFp) {
        // Незнакомец — игнорируем. Контакты добавляются только через QR/JSON.
        await deleteDoc(docRef); continue;
      }

      // 6. senderEd25519 должен совпадать с контактом
      if (data.senderEd25519 !== contacts[peerFp].ed25519) {
        await deleteDoc(docRef); continue;
      }

      // 7. Подпись над {ciphertext, from, to}
      const signedData = JSON.stringify({
        ciphertext: data.ciphertext,
        from: data.from,
        to: data.to
      });
      const valid = await verifyBlob(signedData, data.signature, data.senderEd25519);
      if (!valid) {
        await deleteDoc(docRef); continue;
      }

      // 8. Расшифровка
      const sharedKey = await deriveSharedKey(
        myIdentity.x25519.private,
        contacts[peerFp].x25519
      );

      let payload;
      try {
        const plain = await decryptMessage(
          { iv: data.iv, ciphertext: data.ciphertext },
          sharedKey
        );
        payload = JSON.parse(plain);
      } catch (e) {
        await deleteDoc(docRef); continue;
      }

      // 9. payload.from / payload.to тоже должны совпадать
      if (payload.from !== data.from || payload.to !== myHashHex) {
        await deleteDoc(docRef); continue;
      }

      // 10. Проверка на истёкший чат
      const existingChat = chatHistory[peerFp];
      const chatExpired = existingChat && existingChat.expiresAt && existingChat.expiresAt < Date.now();
      const isActiveWithPeer = activeChat && activeChat.fingerprint === peerFp;

      if (chatExpired && !isActiveWithPeer) {
        await deleteDoc(docRef); continue;
      }

      try { await deleteDoc(docRef); } catch (e) {}

      if (!chatHistory[peerFp]) {
        chatHistory[peerFp] = {
          peerNickname: contacts[peerFp].nickname,
          messages: [],
          lastActivity: payload.ts,
          expiresAt: payload.ts + CHAT_TTL_MS
        };
      }
      chatHistory[peerFp].messages.push({
        id: payload.id,
        from: 'peer',
        text: payload.text,
        ts: payload.ts
      });
      chatHistory[peerFp].lastActivity = payload.ts;
      chatHistory[peerFp].expiresAt = payload.ts + CHAT_TTL_MS;

      saveChats();

      if (activeChat && activeChat.fingerprint === peerFp) {
        renderChat();
        startTimer();
      } else {
        renderContacts();
      }
    }
  }, (error) => {
    console.error('[LISTEN]', error);
  });
}


// ============================================
// UI
// ============================================
function bindUI() {
  document.getElementById('btnMyCard').addEventListener('click', showMyCard);
  document.getElementById('btnAddContact').addEventListener('click', openAddContactModal);

  document.getElementById('btnCloseMyCard').addEventListener('click', () => {
    document.getElementById('modalMyCard').classList.remove('active');
  });
  document.getElementById('btnAccounts').addEventListener('click', openAccountsModal);
  document.getElementById('btnCloseAccounts').addEventListener('click', closeAccountsModal);
  document.getElementById('btnLogout').addEventListener('click', handleLogout);
  document.getElementById('btnAddAnotherAccount').addEventListener('click', handleAddAnotherAccount);

  document.getElementById('btnDevices').addEventListener('click', openDevicesModal);
  document.getElementById('btnCloseDevices').addEventListener('click', closeDevicesModal);
  document.getElementById('btnGenerateExport').addEventListener('click', generateExport);
  document.getElementById('btnCopyExport').addEventListener('click', copyExport);

  document.getElementById('btnCloseAddContact').addEventListener('click', closeAddContactModal);
  document.getElementById('btnStopScan').addEventListener('click', stopScanner);
  document.getElementById('btnSaveContact').addEventListener('click', () => {
    addContactFromJson(document.getElementById('addCardJson').value);
  });

  document.querySelectorAll('#modalAddContact .tab').forEach(t => {
    t.addEventListener('click', () => switchTab(t.dataset.tab));
  });

  document.getElementById('btnCopyCard').addEventListener('click', async () => {
    const ta = document.getElementById('myCardJson');
    ta.select();
    try {
      await navigator.clipboard.writeText(ta.value);
    } catch {
      document.execCommand('copy');
    }
    const btn = document.getElementById('btnCopyCard');
    const prev = btn.textContent;
    btn.textContent = 'Скопировано ✓';
    setTimeout(() => { btn.textContent = prev; }, 1200);
  });

  document.getElementById('btnSend').addEventListener('click', sendMessage);

  const msgInput = document.getElementById('msgInput');
  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && window.innerWidth > 768) {
      e.preventDefault();
      sendMessage();
    }
  });
  msgInput.addEventListener('input', () => {
    msgInput.style.height = 'auto';
    msgInput.style.height = Math.min(msgInput.scrollHeight, 120) + 'px';
  });

  document.getElementById('btnMobileBack').addEventListener('click', exitChat);

  document.getElementById('btnEndChat').addEventListener('click', () => {
    if (confirm('Завершить чат? История будет удалена безвозвратно.')) {
      endChat();
    }
  });
}


// ============================================
// УСТРОЙСТВА
// ============================================
function openDevicesModal() {
  document.getElementById('exportPassword').value = '';
  document.getElementById('exportResult').style.display = 'none';
  document.getElementById('exportJson').value = '';
  document.getElementById('exportQrBox').innerHTML = '';
  document.getElementById('modalDevices').classList.add('active');
}

function closeDevicesModal() {
  document.getElementById('modalDevices').classList.remove('active');
}

async function generateExport() {
  const pw = document.getElementById('exportPassword').value;
  if (pw.length < 6) { alert('Пароль минимум 6 символов'); return; }

  try {
    const exportObj = await exportIdentity(myIdentity, pw);
    const json = JSON.stringify(exportObj);
    document.getElementById('exportJson').value = json;

    const qrBox = document.getElementById('exportQrBox');
    qrBox.innerHTML = '';

    if (typeof qrcode === 'function') {
      const qr = qrcode(0, 'L');
      qr.addData(json);
      qr.make();
      const cellSize = 4;
      const margin = 4;
      const count = qr.getModuleCount();
      const size = count * cellSize + margin * 2;
      const canvas = document.createElement('canvas');
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = '#000000';
      for (let row = 0; row < count; row++) {
        for (let col = 0; col < count; col++) {
          if (qr.isDark(row, col)) {
            ctx.fillRect(margin + col * cellSize, margin + row * cellSize, cellSize, cellSize);
          }
        }
      }
      canvas.style.maxWidth = '100%';
      canvas.style.height = 'auto';
      qrBox.appendChild(canvas);
    }

    document.getElementById('exportResult').style.display = 'block';
  } catch (e) {
    console.error(e);
    alert('Ошибка: ' + e.message);
  }
}

async function copyExport() {
  const ta = document.getElementById('exportJson');
  ta.select();
  try {
    await navigator.clipboard.writeText(ta.value);
    const btn = document.getElementById('btnCopyExport');
    const prev = btn.textContent;
    btn.textContent = 'Скопировано ✓';
    setTimeout(() => { btn.textContent = prev; }, 1200);
  } catch {
    document.execCommand('copy');
  }
}


// ============================================
// АККАУНТЫ
// ============================================
async function openAccountsModal() {
  await renderAccountsModal();
  document.getElementById('modalAccounts').classList.add('active');
}

function closeAccountsModal() {
  document.getElementById('modalAccounts').classList.remove('active');
}

async function renderAccountsModal() {
  const data = await listAccounts();
  const list = document.getElementById('accountsList');

  if (data.accounts.length === 0) {
    list.innerHTML = '<div style="text-align:center;color:#666;font-size:13px;">Нет аккаунтов</div>';
    return;
  }

  const sorted = [...data.accounts].sort((a, b) => {
    if (a.fingerprint === myIdentity.fingerprint) return -1;
    if (b.fingerprint === myIdentity.fingerprint) return 1;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });

  list.innerHTML = sorted.map(acc => {
    const initial = (acc.nickname || '?').charAt(0).toUpperCase();
    const isCurrent = acc.fingerprint === myIdentity.fingerprint;
    return `
      <div class="acct-item ${isCurrent ? 'current' : ''}">
        <div class="acct-avatar">${initial}</div>
        <div class="acct-info">
          <div class="acct-name">${escapeHtml(acc.nickname || 'Без имени')}${isCurrent ? ' (текущий)' : ''}</div>
          <div class="acct-fp">${acc.fingerprint}</div>
        </div>
        ${isCurrent ? '' : `<button class="acct-switch" data-switch="${acc.fingerprint}">Перейти</button>`}
      </div>
    `;
  }).join('');

  list.querySelectorAll('.acct-switch').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const fp = btn.dataset.switch;
      if (!confirm('Переключиться на другой аккаунт? Вас попросят ввести пароль.')) return;
      sessionStorage.removeItem('_pw');
      sessionStorage.removeItem('_fp');
      await setLastActive(fp);
      window.location.href = 'index.html';
    });
  });
}

async function handleLogout() {
  if (!confirm('Выйти из аккаунта? Данные останутся на устройстве — сможете вернуться с паролем.')) return;
  sessionStorage.removeItem('_pw');
  sessionStorage.removeItem('_fp');
  window.location.href = 'index.html';
}

function handleAddAnotherAccount() {
  sessionStorage.removeItem('_pw');
  sessionStorage.removeItem('_fp');
  window.location.href = 'index.html';
}


// ============================================
// СТАРТ
// ============================================
init();