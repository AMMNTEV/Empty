// ============================================
// messenger.js — contacts, chats, E2EE, relay
// Scheme: users/{hashHex}/inbox/{blobId}
// Contacts and chats files are per-account
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

// ============================================
// UTF-8 for QR (qrcode-generator doesn't support it by default)
// ============================================
if (typeof qrcode === 'function') {
  qrcode.stringToBytes = function (s) {
    const utf8 = unescape(encodeURIComponent(s));
    const bytes = new Array(utf8.length);
    for (let i = 0; i < utf8.length; i++) {
      bytes[i] = utf8.charCodeAt(i);
    }
    return bytes;
  };
}

const RELAY_TTL_MS = 25 * 60 * 60 * 1000;
const CHAT_TTL_MS = 24 * 60 * 60 * 1000;

// Proof-of-work: how many leading zero hex chars we require in SHA-256.
// 4 → on average ~65536 attempts, ~0.1–0.5 sec on a phone.
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
// CUSTOM DIALOGS
// ============================================
function showConfirm(text, title = 'Confirmation') {
  return new Promise((resolve) => {
    const modal = document.getElementById('modalConfirm');
    const titleEl = document.getElementById('confirmTitle');
    const textEl = document.getElementById('confirmText');
    const btnYes = document.getElementById('btnConfirmYes');
    const btnNo = document.getElementById('btnConfirmNo');

    titleEl.textContent = title;
    textEl.textContent = text;

    const close = (result) => {
      modal.classList.remove('active');
      btnYes.removeEventListener('click', onYes);
      btnNo.removeEventListener('click', onNo);
      resolve(result);
    };

    const onYes = () => close(true);
    const onNo = () => close(false);

    btnYes.addEventListener('click', onYes);
    btnNo.addEventListener('click', onNo);

    modal.classList.add('active');
  });
}

function showAlert(text, title = 'Notice') {
  return new Promise((resolve) => {
    const modal = document.getElementById('modalAlert');
    const titleEl = document.getElementById('alertTitle');
    const textEl = document.getElementById('alertText');
    const btnOk = document.getElementById('btnAlertOk');

    titleEl.textContent = title;
    textEl.textContent = text;

    const close = () => {
      modal.classList.remove('active');
      btnOk.removeEventListener('click', close);
      resolve();
    };

    btnOk.addEventListener('click', close);
    modal.classList.add('active');
  });
}


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
    console.error('[OPFS] contacts:', e);
    return {};
  }
}

// Debounced chats save (for frequent updates)
async function saveChats() {
  if (!myPassword || !CHATS_FILE) return;
  if (saveChatsTimer) clearTimeout(saveChatsTimer);
  saveChatsTimer = setTimeout(async () => {
    try {
      const encrypted = await encryptIdentity(chatHistory, myPassword);
      await opfsWrite(CHATS_FILE, encrypted);
    } catch (e) {
      console.error('[OPFS] chats:', e);
    }
  }, 500);
}

// Immediate save (for endChat — in case the user closes the tab)
async function saveChatsNow() {
  if (!myPassword || !CHATS_FILE) return;
  if (saveChatsTimer) { clearTimeout(saveChatsTimer); saveChatsTimer = null; }
  try {
    const encrypted = await encryptIdentity(chatHistory, myPassword);
    await opfsWrite(CHATS_FILE, encrypted);
  } catch (e) {
    console.error('[OPFS] chats:', e);
  }
}

async function loadChats() {
  if (!myPassword || !CHATS_FILE) return {};
  if (!await opfsExists(CHATS_FILE)) return {};
  try {
    const enc = await opfsRead(CHATS_FILE);
    return await decryptIdentity(enc, myPassword);
  } catch (e) {
    console.error('[OPFS] chats:', e);
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
      throw new Error('PoW did not converge in reasonable time');
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
// AUTO-CLEANUP
// ============================================
async function purgeExpiredChats() {
  const now = Date.now();
  let changed = false;

  for (const fp in chatHistory) {
    const h = chatHistory[fp];
    if (!h || !h.expiresAt) continue;

    if (h.expiresAt < now) {
      console.log(`[PURGE] Chat with "${h.peerNickname}" expired`);

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
      console.log(`[PURGE] Deleted blobs from "${peer.nickname}": ${toDelete.length}`);
    }
    return toDelete.length;
  } catch (e) {
    console.warn('[PURGE]', e);
    return 0;
  }
}


// ============================================
// INITIALIZATION
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
    if (!await opfsExists(path)) throw new Error('Account file not found');
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
// CARD
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
// CONTACTS
// ============================================
function renderContacts() {
  const list = document.getElementById('contactsList');
  const keys = Object.keys(contacts);

  if (keys.length === 0) {
    list.innerHTML = '<div class="empty-sidebar">No contacts.<br>Tap «+» at the bottom right.</div>';
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
          <div class="contact-name">${escapeHtml(c.nickname || 'No name')}</div>
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

// Превращает URL в кликабельные ссылки, экранируя HTML
function linkifyAndEscape(text) {
  const escaped = escapeHtml(text);
  // http(s)://..., www...., и просто домены типа example.com/path
  const urlRegex = /((?:https?:\/\/|www\.)[^\s<]+|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.?[a-z]{2,}(?:\/[^\s<]*)?)/gi;
  return escaped.replace(urlRegex, (match) => {
    let href = match;
    if (!/^https?:\/\//i.test(href)) href = 'http://' + href;
    return `<a href="${href}" target="_blank" rel="noopener noreferrer">${match}</a>`;
  });
}

// Форматирует timestamp в HH:MM
function formatTime(ts) {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
}


// ============================================
// QR: MY CARD (render only, no modal opening)
// ============================================
async function showMyCard() {
  const card = buildMyCard();
  const json = JSON.stringify(card);

  const qrBox = document.getElementById('qrBox');
  qrBox.innerHTML = '';

  try {
    if (typeof qrcode !== 'function') throw new Error('QR library not loaded');
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
    qrBox.innerHTML = '<div style="color:#666;font-size:11px;padding:10px;">QR unavailable</div>';
  }
}

// ============================================
// QR SCANNER
// ============================================
async function startScanner() {
  const video = document.getElementById('scannerVideo');
  const errEl = document.getElementById('scanError');
  const successEl = document.getElementById('scannerSuccess');
  errEl.textContent = '';
  successEl.style.display = 'none';

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
            // Decode binary data as UTF-8 (jsQR may return Latin-1)
            let text;
            if (code.binaryData && code.binaryData.length) {
              const bytes = new Uint8Array(code.binaryData);
              text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
            } else {
              text = code.data;
            }

            successEl.style.display = 'flex';

            if (scannerStream) {
              scannerStream.getTracks().forEach(t => t.stop());
              scannerStream = null;
            }
            video.srcObject = null;

            handleScannedQR(text);
            return;
          }
        }
      }
      scannerRAF = requestAnimationFrame(tick);
    };
    tick();
  } catch (e) {
    console.error('[SCAN]', e);
    errEl.textContent = 'Failed to access camera: ' + e.message;
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

  const successEl = document.getElementById('scannerSuccess');
  if (successEl) successEl.style.display = 'none';
}

async function handleScannedQR(text) {
  try {
    const card = JSON.parse(text);
    await addContactFromCard(card);

    setTimeout(() => {
      stopScanner();
      closeAddContactModal();
    }, 600);
  } catch (e) {
    console.error('[SCAN]', e);
    document.getElementById('scanError').textContent = 'Failed to recognize: ' + e.message;
    stopScanner();
    setTimeout(() => startScanner(), 500);
  }
}


// ============================================
// ADD CONTACT
// ============================================
async function addContactFromCard(card) {
  if (!card || !card.x25519 || !card.fingerprint || !card.ed25519) {
    throw new Error('Card has no keys');
  }
  if (card.fingerprint === myIdentity.fingerprint) {
    throw new Error('This is your own card');
  }

  const existing = contacts[card.fingerprint];
  if (existing) {
    const keysChanged = existing.x25519 !== card.x25519 || existing.ed25519 !== card.ed25519;
    if (keysChanged) {
      const ok = await showConfirm(
        `Contact "${card.nickname}" keys have changed.\n` +
        `Update contact? Old chat will be deleted.`,
        'Update Contact'
      );
      if (!ok) return;
      delete chatHistory[card.fingerprint];
      await saveChatsNow();
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


// ============================================
// ADD CONTACT / MY QR MODAL
// ============================================
function setAddContactTab(tab) {
  const isScan = tab === 'scan';

  document.getElementById('tabScan').classList.toggle('active', isScan);
  document.getElementById('tabMyQr').classList.toggle('active', !isScan);

  document.getElementById('paneScan').style.display = isScan ? 'block' : 'none';
  document.getElementById('paneMyQr').style.display = isScan ? 'none' : 'block';

  if (isScan) {
    document.getElementById('scanError').textContent = '';
    startScanner();
  } else {
    stopScanner();
    showMyCard();
  }
}

function openAddContactModal() {
  document.getElementById('modalAddContact').classList.add('active');
  setAddContactTab('scan');
}

function closeAddContactModal() {
  stopScanner();
  document.getElementById('modalAddContact').classList.remove('active');
}

// ============================================
// FAB VISIBILITY
// ============================================
function updateFabVisibility() {
  const fab = document.getElementById('fabAdd');
  if (!fab) return;

  const chatOpen = !!activeChat;
  fab.classList.toggle('hidden', chatOpen);
}


// ============================================
// OPEN CHAT
// ============================================
async function openChat(fingerprint) {
  const card = contacts[fingerprint];
  if (!card) return;

  const sharedKey = await deriveSharedKey(
    myIdentity.x25519.private,
    card.x25519
  );

  activeChat = { fingerprint, peerCard: card, sharedKey };

  // IMPORTANT: do NOT create chatHistory on open.
  // Chat is created only on the first sent or received message.

  renderContacts();
  renderChat();
  startTimer();
}


// ============================================
// RENDER CHAT
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
    document.getElementById('chatTimer').textContent = '';
    updateFabVisibility();
    return;
  }

  chatArea.classList.add('active');
  empty.style.display = 'none';
  header.classList.add('active');
  messages.classList.add('active');
  inputArea.classList.add('active');

  document.getElementById('chatTitle').textContent = activeChat.peerCard.nickname;

  const history = chatHistory[activeChat.fingerprint];

  if (!history) {
    messages.innerHTML = '<div style="text-align:center;color:#999;padding:20px;font-size:13px;">No messages. Be the first to write.</div>';
    document.getElementById('chatTimer').textContent = '';
    updateFabVisibility();
    return;
  }

  const msgs = history.messages || [];

  messages.innerHTML = msgs.map(m => {
    const cls = m.from === 'me' ? 'me' : 'other';
    return `<div class="msg ${cls}">${linkifyAndEscape(m.text)}<span class="msg-time">${formatTime(m.ts)}</span></div>`;
  }).join('');

  requestAnimationFrame(() => {
    messages.scrollTop = messages.scrollHeight;
  });

  updateFabVisibility();
}

// Instant append of a single message (no full re-render)
function appendMessage(msg) {
  const messages = document.getElementById('messages');
  if (!messages) return;

  // Remove "No messages" placeholder
  const placeholder = messages.querySelector('div[style*="text-align:center"]');
  if (placeholder && placeholder.textContent.includes('No messages')) {
    placeholder.remove();
  }

  const cls = msg.from === 'me' ? 'me' : 'other';
  const html = `<div class="msg ${cls}">${linkifyAndEscape(msg.text)}<span class="msg-time">${formatTime(msg.ts)}</span></div>`;
  messages.insertAdjacentHTML('beforeend', html);

  requestAnimationFrame(() => {
    messages.scrollTop = messages.scrollHeight;
  });
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);

  let lastTimerText = '';

  const updateTimer = () => {
    if (!activeChat) {
      if (lastTimerText !== '') {
        document.getElementById('chatTimer').textContent = '';
        lastTimerText = '';
      }
      return;
    }
    const history = chatHistory[activeChat.fingerprint];

    if (!history || !history.expiresAt) {
      if (lastTimerText !== '') {
        document.getElementById('chatTimer').textContent = '';
        lastTimerText = '';
      }
      return;
    }

    const left = history.expiresAt - Date.now();
    if (left <= 0) {
      endChat();
      return;
    }

    const h = Math.floor(left / 3600000);
    const min = Math.floor((left % 3600000) / 60000);
    const sec = Math.floor((left % 60000) / 1000);
    const newText = `⏱ ${h}:${String(min).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;

    if (newText !== lastTimerText) {
      document.getElementById('chatTimer').textContent = newText;
      lastTimerText = newText;
    }
  };

  updateTimer();
  timerInterval = setInterval(updateTimer, 1000);
}


// ============================================
// CHAT END SIGNAL
// ============================================
// Sends { end: true } signal for a specific fp.
// Uses contacts[fp] directly — does not depend on activeChat.
async function sendEndSignalForFp(fp) {
  const peerCard = contacts[fp];
  if (!peerCard) return;

  const toHashHex = await hashPubkeyHex(peerCard.x25519);
  const sharedKey = await deriveSharedKey(
    myIdentity.x25519.private,
    peerCard.x25519
  );

  const payload = JSON.stringify({
    id: uuid(),
    text: '',
    ts: Date.now(),
    from: myHashHex,
    to: toHashHex,
    end: true
  });

  const blob = await encryptMessage(payload, sharedKey);

  const signedData = JSON.stringify({
    ciphertext: blob.ciphertext,
    from: myHashHex,
    to: toHashHex
  });
  const signature = await signBlob(signedData, myIdentity.ed25519.private);

  const pow = await computePow(blob.ciphertext);

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

  console.log('[END] End signal sent');
}


// ============================================
// END CHAT (UI instantly, network in background)
// ============================================
function endChat() {
  if (!activeChat) return;
  const fp = activeChat.fingerprint;
  const peerNickname = activeChat.peerCard.nickname;

  // 1. INSTANTLY delete local history
  delete chatHistory[fp];

  // 2. INSTANTLY close chat in UI
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
  activeChat = null;

  renderContacts();
  renderChat();

  // 3. Background signal + cleanup + save
  endChatBackground(fp, peerNickname);

  console.log(`[END] Chat with "${peerNickname}" ended (UI)`);
}

async function endChatBackground(fp, peerNickname) {
  try {
    // Signal to peer
    try {
      await sendEndSignalForFp(fp);
    } catch (e) {
      console.warn('[END] signal failed:', e);
    }

    // Clean own inbox from peer's blobs
    try {
      await purgeRelayForContact(fp);
    } catch (e) {
      console.warn('[END] purge failed:', e);
    }

    // Save immediately — if the user closes the tab, chat is already deleted
    await saveChatsNow();

    console.log(`[END] Background cleanup of "${peerNickname}" done`);
  } catch (e) {
    console.warn('[END] background failed:', e);
  }
}

function exitChat() {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
  activeChat = null;
  renderContacts();
  renderChat();
}


// ============================================
// SEND MESSAGE (UI instantly, network in background)
// ============================================
function sendMessage() {
  const input = document.getElementById('msgInput');
  const text = input.value.trim();
  if (!text || !activeChat) return;

  // 1. INSTANTLY clear the input
  input.value = '';
  input.style.height = 'auto';

  const fp = activeChat.fingerprint;
  const msgId = uuid();
  const ts = Date.now();

  // 2. INSTANTLY create history if it doesn't exist
  if (!chatHistory[fp]) {
    chatHistory[fp] = {
      peerNickname: activeChat.peerCard.nickname,
      messages: [],
      lastActivity: ts,
      expiresAt: ts + CHAT_TTL_MS
    };
  }

  // 3. INSTANTLY add message to history
  chatHistory[fp].messages.push({ id: msgId, from: 'me', text, ts });
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  // 4. INSTANTLY render the message (append, no full re-render)
  appendMessage({ from: 'me', text, ts });
  startTimer();

  // 5. Background send
  sendMessageBackground({ fp, msgId, text, ts });
}

async function sendMessageBackground({ fp, msgId, text, ts }) {
  try {
    const peerCard = contacts[fp];
    if (!peerCard) return;

    const toHashHex = await hashPubkeyHex(peerCard.x25519);
    const sharedKey = await deriveSharedKey(
      myIdentity.x25519.private,
      peerCard.x25519
    );

    const payload = JSON.stringify({
      id: msgId,
      text,
      ts,
      from: myHashHex,
      to: toHashHex
    });

    const blob = await encryptMessage(payload, sharedKey);

    const signedData = JSON.stringify({
      ciphertext: blob.ciphertext,
      from: myHashHex,
      to: toHashHex
    });
    const signature = await signBlob(signedData, myIdentity.ed25519.private);

    const pow = await computePow(blob.ciphertext);

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

    // Save to OPFS in background
    saveChats();
  } catch (e) {
    console.error('[SEND]', e);
  }
}


// ============================================
// INCOMING LISTENER
// ============================================
async function listenIncoming() {
  const inboxRef = myInboxRef();

  unsubscribeIncoming = onSnapshot(inboxRef, async (snapshot) => {
    for (const change of snapshot.docChanges()) {
      if (change.type !== 'added') continue;

      const data = change.doc.data();
      const docId = change.doc.id;
      const docRef = doc(db, 'users', myHashHex, 'inbox', docId);

      // 1. Structural validation
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

      // 2. "to" must be us
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

      // 5. Find contact by "from"
      let peerFp = null;
      for (const fp in contacts) {
        const h = await hashPubkeyHex(contacts[fp].x25519);
        if (h === data.from) { peerFp = fp; break; }
      }
      if (!peerFp) {
        await deleteDoc(docRef); continue;
      }

      // 6. senderEd25519 must match the contact
      if (data.senderEd25519 !== contacts[peerFp].ed25519) {
        await deleteDoc(docRef); continue;
      }

      // 7. Signature over {ciphertext, from, to}
      const signedData = JSON.stringify({
        ciphertext: data.ciphertext,
        from: data.from,
        to: data.to
      });
      const valid = await verifyBlob(signedData, data.signature, data.senderEd25519);
      if (!valid) {
        await deleteDoc(docRef); continue;
      }

      // 8. Decrypt
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

      // 9. payload.from / payload.to must match
      if (payload.from !== data.from || payload.to !== myHashHex) {
        await deleteDoc(docRef); continue;
      }

      // 10. Chat end signal
      if (payload.end === true) {
        await deleteDoc(docRef);

        const peerNickname = contacts[peerFp].nickname;

        if (chatHistory[peerFp]) {
          delete chatHistory[peerFp];
          saveChatsNow();
        }

        if (activeChat && activeChat.fingerprint === peerFp) {
          if (timerInterval) clearInterval(timerInterval);
          timerInterval = null;
          activeChat = null;
          renderChat();
        }
        renderContacts();

        purgeRelayForContact(peerFp).catch(e => console.warn('[END] purge:', e));

        console.log(`[END] Peer "${peerNickname}" ended the chat`);
        continue;
      }

      // 11. Check for expired chat
      const existingChat = chatHistory[peerFp];
      const chatExpired = existingChat && existingChat.expiresAt && existingChat.expiresAt < Date.now();
      const isActiveWithPeer = activeChat && activeChat.fingerprint === peerFp;

      if (chatExpired && !isActiveWithPeer) {
        await deleteDoc(docRef); continue;
      }

      try { await deleteDoc(docRef); } catch (e) {}

      // 12. Instant render of incoming
      const isFirstMessage = !chatHistory[peerFp];

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
        if (isFirstMessage) {
          renderChat();
        } else {
          appendMessage({ from: 'peer', text: payload.text, ts: payload.ts });
        }
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
  document.getElementById('fabAdd').addEventListener('click', openAddContactModal);
  document.getElementById('tabScan').addEventListener('click', () => setAddContactTab('scan'));
  document.getElementById('tabMyQr').addEventListener('click', () => setAddContactTab('myqr'));

  document.getElementById('btnAccounts').addEventListener('click', openAccountsModal);
  document.getElementById('btnCloseAccounts').addEventListener('click', closeAccountsModal);
  document.getElementById('btnLogout').addEventListener('click', handleLogout);
  document.getElementById('btnAddAnotherAccount').addEventListener('click', handleAddAnotherAccount);

  document.getElementById('btnOpenDevices').addEventListener('click', () => {
    closeAccountsModal();
    openDevicesModal();
  });

  document.getElementById('btnCloseDevices').addEventListener('click', closeDevicesModal);
  document.getElementById('btnGenerateExport').addEventListener('click', generateExport);
  document.getElementById('btnCopyExport').addEventListener('click', copyExport);

  document.getElementById('btnCloseAddContact').addEventListener('click', closeAddContactModal);

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

  document.getElementById('btnEndChat').addEventListener('click', async () => {
    const ok = await showConfirm(
      'End chat? History will be permanently deleted for both participants.',
      'End Chat'
    );
    if (ok) endChat();
  });

  window.addEventListener('resize', updateFabVisibility);

  updateFabVisibility();
}


// ============================================
// DEVICES
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
    await showAlert('Password must be at least 6 characters', 'Error');
    return;
  }
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
    await showAlert('Error: ' + e.message, 'Error');
  }
}

async function copyExport() {
  const ta = document.getElementById('exportJson');
  ta.select();
  try {
    await navigator.clipboard.writeText(ta.value);
    const btn = document.getElementById('btnCopyExport');
    const prev = btn.textContent;
    btn.textContent = 'Copied ✓';
    setTimeout(() => { btn.textContent = prev; }, 1200);
  } catch {
    document.execCommand('copy');
  }
}


// ============================================
// ACCOUNTS
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
    list.innerHTML = '<div style="text-align:center;color:#666;font-size:13px;">No accounts</div>';
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
          <div class="acct-name">${escapeHtml(acc.nickname || 'No name')}${isCurrent ? ' (current)' : ''}</div>
          <div class="acct-fp">${acc.fingerprint}</div>
        </div>
        ${isCurrent ? '' : `<button class="acct-switch" data-switch="${acc.fingerprint}">Switch</button>`}
      </div>
    `;
  }).join('');

  list.querySelectorAll('.acct-switch').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const fp = btn.dataset.switch;
      const ok = await showConfirm(
        'Switch to another account? You will be asked for a password.',
        'Switch Account'
      );
      if (!ok) return;
      sessionStorage.removeItem('_pw');
      sessionStorage.removeItem('_fp');
      await setLastActive(fp);
      window.location.href = 'index.html';
    });
  });
}

async function handleLogout() {
  const ok = await showConfirm(
    'Sign out of the account? Data will remain on the device — you can return with the password.',
    'Sign Out'
  );
  if (!ok) return;
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
// START
// ============================================
init();