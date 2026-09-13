// ============================================
// messenger.js — контакты, чаты, E2EE, relay
// Store-and-forward + авто-handshake + адаптив
// ============================================
import { db } from './firebase-init.js';
import {
  collection, addDoc, query, where, onSnapshot,
  deleteDoc, doc
} from "https://www.gstatic.com/firebasejs/10.8.1/firebase-firestore.js";

import {
  opfsWrite, opfsRead, opfsExists,
  decryptIdentity, encryptIdentity,
  deriveSharedKey, encryptMessage, decryptMessage,
  hashPubkey,
  signBlob, verifyBlob, uuid,
  exportIdentity  // ← НОВОЕ
} from './crypto.js';

const IDENTITY_FILE = 'identity.enc';
const CONTACTS_FILE = 'contacts.enc';
const CHATS_FILE = 'chats.enc';

const RELAY_TTL_MS = 7 * 24 * 60 * 60 * 1000;      // блоб живёт на сервере 7 дней
const CHAT_TTL_MS = 24 * 60 * 60 * 1000;           // локальная история — 24 часа

let myIdentity = null;
let myPassword = null;
let contacts = {};
let chatHistory = {};
let activeChat = null;
let unsubscribeIncoming = null;
let timerInterval = null;
let saveChatsTimer = null;
let scannerStream = null;
let scannerRAF = null;


// ============================================
// OPFS
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

  console.log('[ME] nickname:', myIdentity.nickname,
              'codePoints:', [...myIdentity.nickname].map(c => c.codePointAt(0).toString(16)));

  document.getElementById('meName').textContent = myIdentity.nickname;
  document.getElementById('meFp').textContent = myIdentity.fingerprint;

  contacts = await loadContacts();
  chatHistory = await loadChats();
  purgeExpiredChats();

  renderContacts();
  listenIncoming();
  bindUI();

  setInterval(purgeExpiredChats, 60 * 1000);
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
// РЕНДЕР КОНТАКТОВ
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
    const hasHistory = chatHistory[fp] && chatHistory[fp].messages.length > 0;
    const badge = hasHistory ? ' <span style="color: var(--blue); font-size: 11px;">●</span>' : '';
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
// МОЯ КАРТОЧКА (QR)
// ============================================
async function showMyCard() {
  const card = buildMyCard();
  const json = JSON.stringify(card);
  document.getElementById('myCardJson').value = json;

  const qrBox = document.getElementById('qrBox');
  qrBox.innerHTML = '';

  try {
    if (typeof qrcode !== 'function') throw new Error('QR-библиотека не загружена');

    // UTF-8 friendly: qrcode-generator сам умеет с UTF-8 если передать строку
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
          ctx.fillRect(
            margin + col * cellSize,
            margin + row * cellSize,
            cellSize,
            cellSize
          );
        }
      }
    }

    canvas.style.maxWidth = '100%';
    canvas.style.height = 'auto';
    canvas.style.display = 'block';
    qrBox.appendChild(canvas);

  } catch (e) {
    console.error('QR generation error:', e);
    qrBox.innerHTML = '<div style="color: #333; font-size: 12px; padding: 10px;">QR недоступен — используйте JSON</div>';
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
    console.error('Camera error:', e);
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
    console.error('QR parse error:', e);
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
    const nameChanged = existing.nickname !== card.nickname;

    if (keysChanged) {
      const ok = confirm(
        `Ключи контакта "${card.nickname}" изменились.\n` +
        `Собеседник пересоздал профиль.\n\n` +
        `Обновить контакт? Старая переписка будет удалена.`
      );
      if (!ok) return;
      delete chatHistory[card.fingerprint];
      await saveChats();
    } else if (nameChanged) {
      console.log(`[UPDATE] ${existing.nickname} → ${card.nickname}`);
    } else {
      console.log('[UPDATE] без изменений');
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
// МОДАЛКА ДОБАВЛЕНИЯ — ВКЛАДКИ
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
  delete chatHistory[fp];
  saveChats();

  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
  activeChat = null;

  renderContacts();
  renderChat();
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

  const payload = JSON.stringify({ id: msgId, text, ts });
  const blob = await encryptMessage(payload, activeChat.sharedKey);
  const signature = await signBlob(blob.ciphertext, myIdentity.ed25519.private);

  const toHash = await hashPubkey(activeChat.peerCard.x25519);
  const fromHash = await hashPubkey(myIdentity.x25519.public);

  // ГЛАВНЫЙ ФИКС: карточка передаётся как JSON-строка (UTF-8 в base64),
  // чтобы Firestore не ломал кириллицу при сериализации объекта.
  const senderCard = buildMyCard();
  const senderCardStr = JSON.stringify(senderCard);
  const senderCardB64 = btoa(unescape(encodeURIComponent(senderCardStr)));

  console.log('[SEND] my nickname:', senderCard.nickname,
              'codePoints:', [...senderCard.nickname].map(c => c.codePointAt(0).toString(16)));

  try {
    await addDoc(collection(db, 'relay'), {
      to: toHash,
      from: fromHash,
      iv: blob.iv,
      ciphertext: blob.ciphertext,
      signature: signature,
      senderEd25519: myIdentity.ed25519.public,
      senderCardB64: senderCardB64,         // НОВОЕ: карточка как base64-строка
      senderCard: senderCard,               // оставили для совместимости
      ttl: Date.now() + RELAY_TTL_MS
    });
  } catch (e) {
    console.error('Не удалось отправить:', e);
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
  const myHash = await hashPubkey(myIdentity.x25519.public);

  const q = query(collection(db, 'relay'), where('to', '==', myHash));

  unsubscribeIncoming = onSnapshot(q, async (snapshot) => {
    for (const change of snapshot.docChanges()) {
      if (change.type !== 'added') continue;

      const data = change.doc.data();
      const docId = change.doc.id;

      try { await deleteDoc(doc(db, 'relay', docId)); } catch (e) {}

      if (data.ttl && data.ttl < Date.now()) continue;

      // ГЛАВНЫЙ ФИКС: сначала пробуем достать карточку из base64-строки
      let senderCard = null;
      if (typeof data.senderCardB64 === 'string') {
        try {
          const json = decodeURIComponent(escape(atob(data.senderCardB64)));
          senderCard = JSON.parse(json);
          console.log('[RECV] senderCard from B64:', senderCard.nickname,
                      'codePoints:', [...senderCard.nickname].map(c => c.codePointAt(0).toString(16)));
        } catch (e) {
          console.warn('Не удалось распарсить senderCardB64:', e);
        }
      }
      // Fallback на старый формат
      if (!senderCard && data.senderCard && typeof data.senderCard === 'object') {
        senderCard = data.senderCard;
        console.log('[RECV] senderCard from object (fallback):', senderCard.nickname);
      }

      let peerFp = null;
      for (const fp in contacts) {
        const h = await hashPubkey(contacts[fp].x25519);
        if (h === data.from) { peerFp = fp; break; }
      }

      if (!peerFp && senderCard) {
        try {
          const card = senderCard;
          if (!card.x25519 || !card.fingerprint || !card.ed25519) continue;
          const cardHash = await hashPubkey(card.x25519);
          if (cardHash !== data.from) continue;
          if (data.senderEd25519 !== card.ed25519) continue;
          contacts[card.fingerprint] = card;
          await saveContacts();
          peerFp = card.fingerprint;
          console.log('✅ Авто-добавлен контакт:', card.nickname);
          renderContacts();
        } catch (e) {
          console.error('Авто-handshake ошибка:', e);
          continue;
        }
      }

      if (!peerFp) continue;

      if (data.signature && data.senderEd25519) {
        const valid = await verifyBlob(data.ciphertext, data.signature, data.senderEd25519);
        if (!valid) continue;
        if (data.senderEd25519 !== contacts[peerFp].ed25519) continue;
      } else continue;

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
// УСТРОЙСТВА (экспорт identity)
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
  if (pw.length < 6) {
    alert('Пароль минимум 6 символов');
    return;
  }

  try {
    const exportObj = await exportIdentity(myIdentity, pw);
    const json = JSON.stringify(exportObj);
    document.getElementById('exportJson').value = json;

    // Рисуем QR
    const qrBox = document.getElementById('exportQrBox');
    qrBox.innerHTML = '';

    if (typeof qrcode === 'function') {
      const qr = qrcode(0, 'L');   // L — минимальная коррекция, больше данных влезет
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
            ctx.fillRect(
              margin + col * cellSize,
              margin + row * cellSize,
              cellSize,
              cellSize
            );
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
// СТАРТ
// ============================================
init();