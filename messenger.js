// ============================================
// messenger.js — контакты, чаты, E2EE, relay
// Store-and-forward: Firestore = транзит, история = OPFS
// ============================================
import { db } from './firebase-init.js';
import {
  collection, addDoc, query, where, onSnapshot,
  getDocs, deleteDoc, doc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.8.1/firebase-firestore.js";

import {
  opfsWrite, opfsRead, opfsExists,
  decryptIdentity, encryptIdentity,
  deriveSharedKey, encryptMessage, decryptMessage,
  hashPubkey, formatFingerprint,
  signBlob, verifyBlob, uuid
} from './crypto.js';

// ============================================
// КОНСТАНТЫ
// ============================================
const IDENTITY_FILE = 'identity.enc';
const CONTACTS_FILE = 'contacts.enc';
const CHATS_FILE = 'chats.enc';         // NEW: файл с перепиской

const RELAY_TTL_MS = 7 * 24 * 60 * 60 * 1000;  // NEW: блоб живёт в Firestore 7 дней
const CHAT_TTL_MS = 24 * 60 * 60 * 1000;       // CHANGED: локальная история живёт 24 часа

// ============================================
// СОСТОЯНИЕ
// ============================================
let myIdentity = null;
let myPassword = null;
let contacts = {};                       // { fp: card }
let chatHistory = {};                    // NEW: { fp: { peerNickname, messages[], lastActivity, expiresAt } }
let activeChat = null;                   // { fingerprint, peerCard, sharedKey }
let unsubscribeIncoming = null;
let timerInterval = null;
let saveChatsTimer = null;               // NEW: дебаунс на запись в OPFS


// ============================================
// OPFS: КОНТАКТЫ + ИСТОРИЯ
// ============================================
async function saveContacts() {
  if (!myPassword) return;
  const encrypted = await encryptIdentity(contacts, myPassword);
  await opfsWrite(CONTACTS_FILE, encrypted);
}

async function loadContacts() {
  if (!myPassword) return {};
  if (!await opfsExists(CONTACTS_FILE)) return {};
  try {
    const enc = await opfsRead(CONTACTS_FILE);
    return await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('Не удалось расшифровать контакты:', e);
    return {};
  }
}

// NEW: сохраняем историю с дебаунсом (не чаще раза в 500мс)
async function saveChats() {
  if (!myPassword) return;
  if (saveChatsTimer) clearTimeout(saveChatsTimer);
  saveChatsTimer = setTimeout(async () => {
    try {
      const encrypted = await encryptIdentity(chatHistory, myPassword);
      await opfsWrite(CHATS_FILE, encrypted);
    } catch (e) {
      console.error('Не удалось сохранить историю:', e);
    }
  }, 500);
}

async function loadChats() {
  if (!myPassword) return {};
  if (!await opfsExists(CHATS_FILE)) return {};
  try {
    const enc = await opfsRead(CHATS_FILE);
    return await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('Не удалось расшифровать историю:', e);
    return {};
  }
}

// NEW: очистка просроченных чатов
function purgeExpiredChats() {
  const now = Date.now();
  let changed = false;
  for (const fp in chatHistory) {
    if (chatHistory[fp].expiresAt && chatHistory[fp].expiresAt < now) {
      delete chatHistory[fp];
      changed = true;
    }
  }
  if (changed) saveChats();
}


// ============================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================
async function init() {
  myPassword = sessionStorage.getItem('_pw');
  if (!myPassword) {
    window.location.href = 'index.html';
    return;
  }

  try {
    const enc = await opfsRead(IDENTITY_FILE);
    myIdentity = await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('Не удалось расшифровать identity:', e);
    window.location.href = 'index.html';
    return;
  }

  document.getElementById('meName').textContent = myIdentity.nickname;
  document.getElementById('meFp').textContent = myIdentity.fingerprint;

  // NEW: загружаем историю
  contacts = await loadContacts();
  chatHistory = await loadChats();
  purgeExpiredChats();

  renderContacts();
  listenIncoming();
  bindUI();

  // NEW: переодическая очистка просроченных чатов
  setInterval(purgeExpiredChats, 60 * 1000);
}


// ============================================
// РЕНДЕР КОНТАКТОВ
// ============================================
function renderContacts() {
  const list = document.getElementById('contactsList');
  const keys = Object.keys(contacts);

  if (keys.length === 0) {
    list.innerHTML = '<div style="padding: 20px; color: #555; font-size: 13px;">Нет контактов. Нажмите "Добавить контакт".</div>';
    return;
  }

  list.innerHTML = keys.map(fp => {
    const c = contacts[fp];
    const initial = (c.nickname || '?').charAt(0).toUpperCase();
    const active = activeChat && activeChat.fingerprint === fp ? 'active' : '';
    const hasHistory = chatHistory[fp] && chatHistory[fp].messages.length > 0;
    const badge = hasHistory ? ` <span style="color: #3b82f6; font-size: 11px;">●</span>` : '';
    return `
      <div class="contact ${active}" data-fp="${fp}">
        <div class="avatar">${initial}</div>
        <div class="contact-info">
          <div class="contact-name">${escapeHtml(c.nickname || 'Без имени')}${badge}</div>
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
// МОЯ КАРТОЧКА
// ============================================
function buildMyCard() {
  return {
    version: 1,
    nickname: myIdentity.nickname,
    x25519: myIdentity.x25519.public,
    ed25519: myIdentity.ed25519.public,   // NEW: публичный ключ для подписей
    fingerprint: myIdentity.fingerprint
  };
}

async function showMyCard() {
  const card = buildMyCard();
  const json = JSON.stringify(card);
  document.getElementById('myCardJson').value = json;

  const qrBox = document.getElementById('qrBox');
  qrBox.innerHTML = '';
  try {
    const QR = await import('https://cdn.jsdelivr.net/npm/qrcode@1.5.3/lib/browser.js');
    const dataUrl = await QR.toDataURL(json, { width: 300, margin: 1 });
    const img = document.createElement('img');
    img.src = dataUrl;
    qrBox.appendChild(img);
  } catch (e) {
    qrBox.innerHTML = '<div style="color: #333; font-size: 12px;">QR недоступен — используйте JSON</div>';
  }

  document.getElementById('modalMyCard').classList.add('active');
}


// ============================================
// ДОБАВЛЕНИЕ КОНТАКТА
// ============================================
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

  if (!card.x25519 || !card.fingerprint || !card.ed25519) {  // CHANGED: требуем ed25519
    errEl.textContent = 'В карточке нет ключей';
    return;
  }

  if (card.fingerprint === myIdentity.fingerprint) {
    errEl.textContent = 'Это ваша карточка';
    return;
  }

  contacts[card.fingerprint] = card;
  await saveContacts();
  renderContacts();
  document.getElementById('modalAddContact').classList.remove('active');
  document.getElementById('addCardJson').value = '';
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

  // NEW: если истории нет — создаём пустую запись
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
  const empty = document.getElementById('chatEmpty');
  const header = document.getElementById('chatHeader');
  const messages = document.getElementById('messages');
  const inputArea = document.getElementById('inputArea');

  if (!activeChat) {
    empty.style.display = 'flex';
    header.style.display = 'none';
    messages.style.display = 'none';
    inputArea.style.display = 'none';
    return;
  }

  empty.style.display = 'none';
  header.style.display = 'flex';
  messages.style.display = 'flex';
  inputArea.style.display = 'flex';

  document.getElementById('chatTitle').textContent = activeChat.peerCard.nickname;

  // CHANGED: рендерим из chatHistory
  const history = chatHistory[activeChat.fingerprint];
  const msgs = history ? history.messages : [];

  messages.innerHTML = msgs.map(m => {
    const cls = m.from === 'me' ? 'me' : 'other';
    return `<div class="msg ${cls}">${escapeHtml(m.text)}</div>`;
  }).join('');

  messages.scrollTop = messages.scrollHeight;
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    if (!activeChat) return;
    const history = chatHistory[activeChat.fingerprint];
    if (!history) return;
    const left = history.expiresAt - Date.now();
    if (left <= 0) {
      endChat();
      return;
    }
    const h = Math.floor(left / 3600000);
    const min = Math.floor((left % 3600000) / 60000);
    const sec = Math.floor((left % 60000) / 1000);
    document.getElementById('chatTimer').textContent =
      `⏱ ${h}:${String(min).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  }, 1000);
}

// CHANGED: endChat теперь стирает историю с этим контактом
function endChat() {
  if (!activeChat) return;

  const fp = activeChat.fingerprint;

  // Удаляем историю
  delete chatHistory[fp];
  saveChats();

  // Сбрасываем активный чат
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

  const fp = activeChat.fingerprint;
  const msgId = uuid();
  const ts = Date.now();

  // 1. Формируем payload
  const payload = JSON.stringify({ id: msgId, text, ts });

  // 2. Шифруем
  const blob = await encryptMessage(payload, activeChat.sharedKey);

  // 3. Подписываем (NEW)
  const signature = await signBlob(blob.ciphertext, myIdentity.ed25519.private);

  // 4. Считаем relay-адреса
  const toHash = await hashPubkey(activeChat.peerCard.x25519);
  const fromHash = await hashPubkey(myIdentity.x25519.public);

  // 5. Пишем в Firestore (транзит)
  try {
    await addDoc(collection(db, 'relay'), {
      to: toHash,
      from: fromHash,
      iv: blob.iv,
      ciphertext: blob.ciphertext,
      signature: signature,
      senderEd25519: myIdentity.ed25519.public,   // NEW: чтобы получатель проверил
      ttl: Date.now() + RELAY_TTL_MS
    });
  } catch (e) {
    console.error('Не удалось отправить:', e);
    // Даже если не ушло — сохраняем локально
  }

  // 6. Локально сохраняем
  if (!chatHistory[fp]) {
    chatHistory[fp] = {
      peerNickname: activeChat.peerCard.nickname,
      messages: [],
      lastActivity: ts,
      expiresAt: ts + CHAT_TTL_MS
    };
  }
  chatHistory[fp].messages.push({
    id: msgId, from: 'me', text, ts
  });
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  saveChats();
  renderChat();
}


// ============================================
// СЛУШАТЕЛЬ ВХОДЯЩИХ (store-and-forward)
// ============================================
async function listenIncoming() {
  const myHash = await hashPubkey(myIdentity.x25519.public);

  const q = query(
    collection(db, 'relay'),
    where('to', '==', myHash)
  );

  unsubscribeIncoming = onSnapshot(q, async (snapshot) => {
    for (const change of snapshot.docChanges()) {
      if (change.type !== 'added') continue;

      const data = change.doc.data();
      const docId = change.doc.id;

      // Сразу удаляем из Firestore — store-and-forward
      try {
        await deleteDoc(doc(db, 'relay', docId));
      } catch (e) {
        console.warn('Не удалось удалить блоб:', e);
      }

      // Просроченные игнорируем
      if (data.ttl && data.ttl < Date.now()) continue;

      // Ищем отправителя
      let peerFp = null;
      for (const fp in contacts) {
        const h = await hashPubkey(contacts[fp].x25519);
        if (h === data.from) { peerFp = fp; break; }
      }
      if (!peerFp) continue;

      // NEW: проверяем подпись
      if (data.signature && data.senderEd25519) {
        const valid = await verifyBlob(data.ciphertext, data.signature, data.senderEd25519);
        if (!valid) {
          console.warn('Подпись невалидна, пропускаем');
          continue;
        }
        // Проверяем, что senderEd25519 совпадает с карточкой контакта
        if (data.senderEd25519 !== contacts[peerFp].ed25519) {
          console.warn('Отправитель не совпадает с карточкой');
          continue;
        }
      } else {
        console.warn('Блоб без подписи, пропускаем');
        continue;
      }

      // Расшифровываем
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
        console.error('Не удалось расшифровать:', e);
        continue;
      }

      // NEW: сохраняем в локальную историю
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

      // Если открыт этот чат — обновляем UI
      if (activeChat && activeChat.fingerprint === peerFp) {
        renderChat();
      } else {
        renderContacts(); // обновим бейджи
      }
    }
  });
}


// ============================================
// UI
// ============================================
function bindUI() {
  document.getElementById('btnMyCard').addEventListener('click', showMyCard);
  document.getElementById('btnCloseMyCard').addEventListener('click', () => {
    document.getElementById('modalMyCard').classList.remove('active');
  });
  document.getElementById('btnCopyCard').addEventListener('click', () => {
    const ta = document.getElementById('myCardJson');
    ta.select();
    document.execCommand('copy');
  });

  document.getElementById('btnAddContact').addEventListener('click', () => {
    document.getElementById('addError').textContent = '';
    document.getElementById('modalAddContact').classList.add('active');
  });
  document.getElementById('btnCloseAddContact').addEventListener('click', () => {
    document.getElementById('modalAddContact').classList.remove('active');
  });
  document.getElementById('btnSaveContact').addEventListener('click', () => {
    addContactFromJson(document.getElementById('addCardJson').value);
  });

  document.getElementById('btnSend').addEventListener('click', sendMessage);
  document.getElementById('msgInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendMessage();
  });

  document.getElementById('btnEndChat').addEventListener('click', () => {
    if (confirm('Завершить чат? История будет удалена безвозвратно.')) {
      endChat();
    }
  });
}


// ============================================
// СТАРТ
// ============================================
init();