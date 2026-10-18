// ============================================
// messenger.js — contacts, chats, E2EE, relay
// Scheme: users/{hashHex}/inbox/{blobId}
// Contacts and chats files are per-account
// ============================================
import { db } from './firebase-init.js';
import {
  collection, addDoc, onSnapshot,
  deleteDoc, doc, getDocs, writeBatch,
  setDoc
} from "https://www.gstatic.com/firebasejs/10.8.1/firebase-firestore.js";

import {
  opfsWrite, opfsRead, opfsExists,
  decryptIdentity, encryptIdentity,
  deriveSharedKey, encryptMessage, decryptMessage,
  hashPubkeyHex,
  signBlob, verifyBlob, uuid,
  exportIdentity,
  listAccounts, setLastActive, identityFilePath,
  utf8Encode, utf8Decode, bufToBase64, base64ToBuf
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
const POW_DIFFICULTY = 4;
const TYPING_REFRESH_MS = 1000; // обновляем не чаще раза в секунду
const TYPING_VISIBLE_MS = 3000; // индикатор виден 3 сек после последнего сигнала
const TYPING_STOP_DELAY = 2500; // через 2.5 сек после последнего ввода считаем, что юзер перестал печатать

let myIdentity = null;
let myPassword = null;
let myHashHex = null;
let contacts = {};
let chatHistory = {};
let activeChat = null;
let unsubscribeIncoming = null;
let unsubscribeTyping = null;
let timerInterval = null;
let saveChatsTimer = null;
let scannerStream = null;
let scannerRAF = null;
let purgeCheckInterval = null;
let typingStopTimer = null;
let lastTypingSent = 0;
let typingHideTimer = null;

let CONTACTS_FILE = null;
let CHATS_FILE = null;

// Voice state
let mediaRecorder = null;
let mediaStream = null;
let recordedChunks = [];
let recordStartTs = 0;
let recordTimerInterval = null;
let recWaveInterval = null;
let audioContext = null;
let audioAnalyser = null;
let isPaused = false;
let isCancelled = false;
let pausedTime = 0;
const audioCache = new Map();
const fileCache = new Map(); // Для хранения blob-URL картинок
const pendingFiles = new Map(); // Для склейки чанков

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
// TYPING
// ============================================
function myEphemeralRef() {
  return collection(db, 'users', myHashHex, 'ephemeral');
}

async function sendTypingSignal(peerHash) {
  const now = Date.now();
  if (now - lastTypingSent < TYPING_REFRESH_MS) return;
  lastTypingSent = now;
  try {
    await setDoc(doc(db, 'users', peerHash, 'ephemeral', myHashHex), { typing: true, ts: now });
  } catch (e) {}
}

async function clearTypingSignal(peerHash) {
  try {
    await setDoc(doc(db, 'users', peerHash, 'ephemeral', myHashHex), { typing: false, ts: Date.now() });
  } catch (e) {}
}

function onTypingInput() {
  if (!activeChat) return;
  
  // Сбрасываем таймер остановки при каждом нажатии клавиши
  if (typingStopTimer) clearTimeout(typingStopTimer);
  
  const fp = activeChat.fingerprint;
  const peer = contacts[fp];
  if (!peer) return;
  
  hashPubkeyHex(peer.x25519).then(peerHash => {
    // Отправляем сигнал (внутри есть троттлинг на 1 сек)
    sendTypingSignal(peerHash);
    
    // Ставим таймер на "перестал печатать" через 2.5 сек после последнего ввода
    typingStopTimer = setTimeout(() => {
      clearTypingSignal(peerHash);
    }, TYPING_STOP_DELAY);
  });
}

function listenTyping() {
  if (unsubscribeTyping) unsubscribeTyping();
  unsubscribeTyping = onSnapshot(myEphemeralRef(), (snapshot) => {
    let newest = null;
    snapshot.forEach(d => {
      const data = d.data();
      if (!data || !data.typing || typeof data.ts !== 'number') return;
      if (Date.now() - data.ts > TYPING_VISIBLE_MS) return;
      if (!newest || data.ts > newest.ts) newest = { senderHash: d.id, ts: data.ts };
    });
    updateTypingIndicator(newest);
  }, (err) => { console.warn('[TYPING]', err); });
}

async function updateTypingIndicator(newest) {
  const el = document.getElementById('chatTyping');
  if (!el) return;
  if (typingHideTimer) { clearTimeout(typingHideTimer); typingHideTimer = null; }
  if (!newest || !activeChat) { el.classList.remove('visible'); el.textContent = ''; return; }
  let senderFp = null;
  for (const fp in contacts) {
    const h = await hashPubkeyHex(contacts[fp].x25519);
    if (h === newest.senderHash) { senderFp = fp; break; }
  }
  if (!senderFp || senderFp !== activeChat.fingerprint) {
    el.classList.remove('visible'); el.textContent = ''; return;
  }
  el.textContent = `${contacts[senderFp].nickname || 'Peer'} is typing…`;
  el.classList.add('visible');
  const age = Date.now() - newest.ts;
  typingHideTimer = setTimeout(() => {
    el.classList.remove('visible'); el.textContent = '';
  }, Math.max(1000, TYPING_VISIBLE_MS - age));
}

// ============================================
// PROOF-OF-WORK
// ============================================
async function computePow(ciphertextB64) {
  let nonce = 0;
  while (true) {
    const buf = new TextEncoder().encode(ciphertextB64 + ':' + nonce);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (hex.startsWith('0'.repeat(POW_DIFFICULTY))) return nonce;
    nonce++;
    if (nonce > 10_000_000) throw new Error('PoW did not converge in reasonable time');
  }
}

async function verifyPow(ciphertextB64, pow) {
  if (typeof pow !== 'number' || !Number.isInteger(pow) || pow < 0) return false;
  const buf = new TextEncoder().encode(ciphertextB64 + ':' + pow);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
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
  if (changed) { saveChats(); renderContacts(); renderChat(); }
}

async function purgeRelayForContact(peerFingerprint) {
  try {
    const peer = contacts[peerFingerprint];
    if (!peer) return 0;
    const peerHashHex = await hashPubkeyHex(peer.x25519);
    const snapshot = await getDocs(myInboxRef());
    const toDelete = [];
    snapshot.forEach(d => { if (d.data().from === peerHashHex) toDelete.push(d.ref); });
    for (let i = 0; i < toDelete.length; i += 500) {
      const batch = writeBatch(db);
      toDelete.slice(i, i + 500).forEach(ref => batch.delete(ref));
      await batch.commit();
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
  if (!myPassword || !myFp) { window.location.href = 'index.html'; return; }
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
  listenTyping();
  bindUI();
  if (purgeCheckInterval) clearInterval(purgeCheckInterval);
  purgeCheckInterval = setInterval(() => { purgeExpiredChats().catch(e => console.warn('[PURGE]', e)); }, 60 * 1000);
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
    return `<div class="contact ${active}" data-fp="${fp}">
      <div class="avatar">${initial}</div>
      <div class="contact-info">
        <div class="contact-name">${escapeHtml(c.nickname || 'No name')}</div>
        <div class="contact-fp">${fp}</div>
      </div>
    </div>`;
  }).join('');
  list.querySelectorAll('.contact').forEach(el => {
    el.addEventListener('click', () => openChat(el.dataset.fp));
  });
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function linkifyAndEscape(text) {
  const escaped = escapeHtml(text);
  const urlRegex = /((?:https?:\/\/|www\.)[^\s<]+|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.?[a-z]{2,}(?:\/[^\s<]*)?)/gi;
  return escaped.replace(urlRegex, (match) => {
    let href = match;
    if (!/^https?:\/\//i.test(href)) href = 'http://' + href;
    return `<a href="${href}" target="_blank" rel="noopener noreferrer">${match}</a>`;
  });
}

function formatTime(ts) {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
}

function formatDuration(ms) {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

// ============================================
// QR: MY CARD
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
    const cellSize = 6, margin = 4, count = qr.getModuleCount(), size = count * cellSize + margin * 2;
    const canvas = document.createElement('canvas');
    canvas.width = size; canvas.height = size;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (let row = 0; row < count; row++) for (let col = 0; col < count; col++)
      if (qr.isDark(row, col)) ctx.fillRect(margin + col * cellSize, margin + row * cellSize, cellSize, cellSize);
    canvas.style.maxWidth = '100%'; canvas.style.height = 'auto';
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
    scannerStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } } });
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
          const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
          if (code && code.data) {
            let text;
            if (code.binaryData && code.binaryData.length) {
              text = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(code.binaryData));
            } else { text = code.data; }
            successEl.style.display = 'flex';
            if (scannerStream) { scannerStream.getTracks().forEach(t => t.stop()); scannerStream = null; }
            video.srcObject = null;
            handleScannedQR(text); return;
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
  if (scannerStream) { scannerStream.getTracks().forEach(t => t.stop()); scannerStream = null; }
  const video = document.getElementById('scannerVideo');
  if (video) video.srcObject = null;
  const successEl = document.getElementById('scannerSuccess');
  if (successEl) successEl.style.display = 'none';
}

async function handleScannedQR(text) {
  try {
    const card = JSON.parse(text);
    await addContactFromCard(card);
    setTimeout(() => { stopScanner(); closeAddContactModal(); }, 600);
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
  if (!card || !card.x25519 || !card.fingerprint || !card.ed25519) throw new Error('Card has no keys');
  if (card.fingerprint === myIdentity.fingerprint) throw new Error('This is your own card');
  const existing = contacts[card.fingerprint];
  if (existing) {
    const keysChanged = existing.x25519 !== card.x25519 || existing.ed25519 !== card.ed25519;
    if (keysChanged) {
      const ok = await showConfirm(`Contact "${card.nickname}" keys have changed.\nUpdate contact? Old chat will be deleted.`, 'Update Contact');
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
  if (isScan) { document.getElementById('scanError').textContent = ''; startScanner(); }
  else { stopScanner(); showMyCard(); }
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
  fab.classList.toggle('hidden', !!activeChat);
}

// ============================================
// OPEN CHAT
// ============================================
async function openChat(fingerprint) {
  const card = contacts[fingerprint];
  if (!card) return;
  const sharedKey = await deriveSharedKey(myIdentity.x25519.private, card.x25519);
  activeChat = { fingerprint, peerCard: card, sharedKey };
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
    document.getElementById('chatTyping').classList.remove('visible');
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
  for (const [id, url] of audioCache.entries()) { URL.revokeObjectURL(url); audioCache.delete(id); }
    for (const [id, url] of fileCache.entries()) { URL.revokeObjectURL(url); fileCache.delete(id); }
  messages.innerHTML = msgs.map(m => renderMessageHtml(m)).join('');
    messages.querySelectorAll('.msg-image-el').forEach(img => {
    img.addEventListener('click', () => {
      document.getElementById('imageViewer').src = img.src;
      document.getElementById('modalImage').classList.add('active');
    });
  });
  messages.querySelectorAll('.file-download-btn').forEach(btn => {
    btn.addEventListener('click', () => downloadFile(btn.dataset.fileId));
  });
  messages.querySelectorAll('.voice-play-btn').forEach(btn => {
    btn.addEventListener('click', () => toggleVoicePlayback(btn.dataset.msgId));
  });
  requestAnimationFrame(() => { messages.scrollTop = messages.scrollHeight; });
  updateFabVisibility();
}

function renderMessageHtml(m) {
  const cls = m.from === 'me' ? 'me' : 'other';
  const time = `<span class="msg-time">${formatTime(m.ts)}</span>`;

  // Голосовые
  if (m.type === 'voice') {
    const duration = formatDuration(m.duration || 0);
    const bars = renderWaveBars(m.id);
    return `<div class="msg voice ${cls}" data-msg-id="${m.id}">
      <div class="voice-main">
        <button class="voice-play-btn" data-msg-id="${m.id}" aria-label="Play voice">
          <svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
        </button>
        <div class="voice-wave" data-msg-id="${m.id}">${bars}</div>
        <div class="voice-duration" data-msg-id="${m.id}">${duration}</div>
      </div>
      <div class="voice-footer">
        <div class="voice-progress"><div class="voice-progress-bar" data-msg-id="${m.id}"></div></div>
        ${time}
      </div>
    </div>`;
  }

  // Фото
  if (m.type === 'image') {
    let imgSrc = m._imgUrl;
    
    // Если нет локального URL (например, после перезагрузки), но есть b64 — создаем URL
    if (!imgSrc && m.b64) {
      try {
        const bytes = base64ToBuf(m.b64);
        const blob = new Blob([bytes], { type: m.fileMime });
        imgSrc = URL.createObjectURL(blob);
        m._imgUrl = imgSrc;
        fileCache.set(m.id, imgSrc);
      } catch (e) { imgSrc = ''; }
    }
    
    // Если вообще ничего нет (например, фото еще грузится), показываем плейсхолдер
    if (!imgSrc) {
      return `<div class="msg image ${cls}" data-msg-id="${m.id}"><div style="padding:10px; color:#666; font-size:10px;">Loading...</div>${time}</div>`;
    }
    
    return `<div class="msg image ${cls}" data-msg-id="${m.id}">
      <img src="${imgSrc}" alt="${escapeHtml(m.fileName)}" data-msg-id="${m.id}" class="msg-image-el">
      ${time}
    </div>`;
  }

  // Файл
  if (m.type === 'file') {
    const sizeKb = m.fileSize ? (m.fileSize / 1024).toFixed(1) + ' KB' : '';
    const ext = (m.fileName || '').split('.').pop().toUpperCase();
    return `<div class="msg file ${cls}" data-msg-id="${m.id}">
      <div class="file-icon">
        <svg viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
      </div>
      <div class="file-info">
        <div class="file-name">${escapeHtml(m.fileName || 'File')}</div>
        <div class="file-size">${ext} • ${sizeKb}</div>
      </div>
      <button class="file-download-btn" data-file-id="${m.id}" title="Download">
        <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
      </button>
      ${time}
    </div>`;
  }

  // Текст
  return `<div class="msg ${cls}" data-msg-id="${m.id}">${linkifyAndEscape(m.text || '')}${time}</div>`;
}

function renderWaveBars(msgId) {
  let h = 0;
  for (let i = 0; i < msgId.length; i++) h = ((h << 5) - h + msgId.charCodeAt(i)) | 0;
  const bars = [];
  for (let i = 0; i < 24; i++) {
    h = ((h << 5) - h + i) | 0;
    bars.push(`<span style="height:${4 + (Math.abs(h) % 16)}px"></span>`);
  }
  return bars.join('');
}

function appendMessage(msg) {
  const messages = document.getElementById('messages');
  if (!messages) return;
  const placeholder = messages.querySelector('div[style*="text-align:center"]');
  if (placeholder && placeholder.textContent.includes('No messages')) placeholder.remove();
  
  messages.insertAdjacentHTML('beforeend', renderMessageHtml(msg));
  const newEl = messages.lastElementChild;
  
  if (newEl && newEl.classList.contains('voice')) {
    const btn = newEl.querySelector('.voice-play-btn');
    if (btn) btn.addEventListener('click', () => toggleVoicePlayback(btn.dataset.msgId));
  }
  
  if (newEl && newEl.classList.contains('image')) {
    const img = newEl.querySelector('.msg-image-el');
    if (img) {
      img.addEventListener('click', () => {
        document.getElementById('imageViewer').src = img.src;
        document.getElementById('modalImage').classList.add('active');
      });
    }
  }
  
  if (newEl && newEl.classList.contains('file')) {
    const btn = newEl.querySelector('.file-download-btn');
    if (btn) {
      btn.addEventListener('click', () => downloadFile(btn.dataset.fileId));
    }
  }
  
  requestAnimationFrame(() => { messages.scrollTop = messages.scrollHeight; });
}

function downloadFile(msgId) {
  if (!activeChat) return;
  const history = chatHistory[activeChat.fingerprint];
  if (!history) return;
  const msg = (history.messages || []).find(m => m.id === msgId);
  if (!msg || msg.type !== 'file' || !msg.fileB64) {
    showAlert('File data not available yet.', 'Notice');
    return;
  }
  try {
    const bytes = base64ToBuf(msg.fileB64);
    const blob = new Blob([bytes], { type: msg.fileMime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = msg.fileName || 'file';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    console.error('[DOWNLOAD]', e);
  }
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);
  let lastTimerText = '';
  const updateTimer = () => {
    if (!activeChat) {
      if (lastTimerText !== '') { document.getElementById('chatTimer').textContent = ''; lastTimerText = ''; }
      return;
    }
    const history = chatHistory[activeChat.fingerprint];
    if (!history || !history.expiresAt) {
      if (lastTimerText !== '') { document.getElementById('chatTimer').textContent = ''; lastTimerText = ''; }
      return;
    }
    const left = history.expiresAt - Date.now();
    if (left <= 0) { endChat(); return; }
    const h = Math.floor(left / 3600000);
    const min = Math.floor((left % 3600000) / 60000);
    const sec = Math.floor((left % 60000) / 1000);
    const newText = `⏱ ${h}:${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
    if (newText !== lastTimerText) {
      document.getElementById('chatTimer').textContent = newText;
      lastTimerText = newText;
    }
  };
  updateTimer();
  timerInterval = setInterval(updateTimer, 1000);
}

// ============================================
// VOICE PLAYBACK
// ============================================
async function toggleVoicePlayback(msgId) {
  const history = activeChat ? chatHistory[activeChat.fingerprint] : null;
  if (!history) return;
  const msg = (history.messages || []).find(m => m.id === msgId);
  if (!msg || msg.type !== 'voice' || !msg.audioB64 || !msg.mime) return;

  const messagesEl = document.getElementById('messages');
  const btn = messagesEl.querySelector(`.voice-play-btn[data-msg-id="${msgId}"]`);
  const wave = messagesEl.querySelector(`.voice-wave[data-msg-id="${msgId}"]`);
  const bar = messagesEl.querySelector(`.voice-progress-bar[data-msg-id="${msgId}"]`);
  const durEl = messagesEl.querySelector(`.voice-duration[data-msg-id="${msgId}"]`);

  const existing = audioCache.get(msgId);
  if (existing) {
    existing.audio.pause();
    existing.audio.currentTime = 0;
    URL.revokeObjectURL(existing.url);
    audioCache.delete(msgId);
    if (btn) btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
    if (wave) wave.classList.remove('playing');
    if (bar) bar.style.width = '0%';
    if (durEl) durEl.textContent = formatDuration(msg.duration || 0);
    return;
  }

  try {
    const bytes = base64ToBuf(msg.audioB64);
    const blob = new Blob([bytes], { type: msg.mime });
    const url = URL.createObjectURL(blob);
    const audio = new Audio(url);
    
    audio.addEventListener('timeupdate', () => {
      // В webm/opus на iOS/Android audio.duration может быть NaN.
      // Берем длительность из сообщения (msg.duration) для расчета прогресса.
      const totalMs = (audio.duration && isFinite(audio.duration)) 
        ? audio.duration * 1000 
        : (msg.duration || 0);
      
      if (totalMs > 0 && bar) {
        const currentMs = audio.currentTime * 1000;
        const pct = Math.min(100, (currentMs / totalMs) * 100);
        bar.style.width = pct + '%';
        
        // Показываем время прослушивания (вместо общей длительности)
        if (durEl) durEl.textContent = formatDuration(currentMs);
      }
    });

    audio.addEventListener('ended', () => {
      URL.revokeObjectURL(url);
      audioCache.delete(msgId);
      if (btn) btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
      if (wave) wave.classList.remove('playing');
      if (bar) bar.style.width = '0%';
      if (durEl) durEl.textContent = formatDuration(msg.duration || 0); // возвращаем общую длительность
    });

    audio.addEventListener('error', () => { URL.revokeObjectURL(url); audioCache.delete(msgId); });
    audioCache.set(msgId, { audio, url });
    await audio.play();
    if (btn) btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M6 6h4v12H6zM14 6h4v12h-4z"/></svg>';
    if (wave) wave.classList.add('playing');
  } catch (e) {
    console.error('[VOICE] play failed:', e);
  }
}
// ============================================
// VOICE RECORDING
// ============================================
function pickMimeType() {
  const candidates = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/webm', 'audio/mp4'];
  for (const c of candidates) {
    if (window.MediaRecorder && MediaRecorder.isTypeSupported(c)) return c;
  }
  return '';
}

async function toggleRecording() {
  if (mediaRecorder && mediaRecorder.state === 'recording') {
    await stopRecordingAndSend();
    return;
  }
  await startRecording();
}

async function startRecording() {
  if (!activeChat) return;
  const mime = pickMimeType();
  if (!mime) { await showAlert('Voice recording is not supported in this browser.', 'Error'); return; }
  try {
    mediaStream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
  } catch (e) { await showAlert('Microphone access denied: ' + e.message, 'Error'); return; }

  audioContext = new (window.AudioContext || window.webkitAudioContext)();
  const source = audioContext.createMediaStreamSource(mediaStream);
  audioAnalyser = audioContext.createAnalyser();
  audioAnalyser.fftSize = 64;
  source.connect(audioAnalyser);

  const recWave = document.getElementById('recWave');
  recWave.innerHTML = '';
  for (let i = 0; i < 24; i++) recWave.appendChild(document.createElement('span'));

  const dataArray = new Uint8Array(audioAnalyser.frequencyBinCount);
  recWaveInterval = setInterval(() => {
    if (isPaused) return;
    audioAnalyser.getByteFrequencyData(dataArray);
    const spans = recWave.querySelectorAll('span');
    for (let i = 0; i < spans.length; i++) {
      const val = dataArray[i] || 0;
      spans[i].style.height = Math.max(2, (val / 255) * 24) + 'px';
      spans[i].style.opacity = 0.4 + (val / 255) * 0.6;
    }
  }, 100);

  recordedChunks = [];
  recordStartTs = Date.now() - pausedTime;
  isPaused = false;
  isCancelled = false;
  pausedTime = 0;

  try {
    mediaRecorder = new MediaRecorder(mediaStream, { mimeType: mime, audioBitsPerSecond: 16000 });
  } catch (e) {
    if (mediaStream) mediaStream.getTracks().forEach(t => t.stop());
    if (audioContext) audioContext.close();
    await showAlert('Failed to start recorder: ' + e.message, 'Error');
    return;
  }

  mediaRecorder.addEventListener('dataavailable', (ev) => {
    if (ev.data && ev.data.size > 0) recordedChunks.push(ev.data);
  });

  mediaRecorder.addEventListener('stop', async () => {
    await finalizeRecordingAndSend(mime);
  });

  mediaRecorder.start(250);

  document.getElementById('recordingUi').classList.add('active');
  document.getElementById('btnVoice').style.display = 'none';
  document.getElementById('msgInput').style.display = 'none';
  document.getElementById('btnSend').style.display = 'none';
  document.getElementById('recTimer').textContent = '0:00';
  updateRecPauseIcon();

  recordTimerInterval = setInterval(() => {
    if (isPaused) return;
    const elapsed = Date.now() - recordStartTs;
    document.getElementById('recTimer').textContent = formatDuration(elapsed);
    if (elapsed >= 5 * 60 * 1000) stopRecordingAndSend();
  }, 200);
}

async function stopRecordingAndSend() {
  if (!mediaRecorder) return;
  if (mediaRecorder.state !== 'inactive') mediaRecorder.stop();
}

async function finalizeRecordingAndSend(mime) {
  if (isCancelled) return; // Если корзина нажата - выходим сразу

  if (recordTimerInterval) { clearInterval(recordTimerInterval); recordTimerInterval = null; }
  if (recWaveInterval) { clearInterval(recWaveInterval); recWaveInterval = null; }
  if (audioContext) { audioContext.close(); audioContext = null; }

  document.getElementById('recordingUi').classList.remove('active');
  document.getElementById('btnVoice').style.display = '';
  document.getElementById('msgInput').style.display = '';
  document.getElementById('btnSend').style.display = '';

  if (mediaStream) { mediaStream.getTracks().forEach(t => t.stop()); mediaStream = null; }
  mediaRecorder = null;

  const duration = Date.now() - recordStartTs;
  recordStartTs = 0;

  if (!recordedChunks.length || duration < 500) {
    recordedChunks = [];
    return;
  }

  const blob = new Blob(recordedChunks, { type: mime.split(';')[0] || 'audio/webm' });
  recordedChunks = [];

  const arrayBuf = await blob.arrayBuffer();
  const bytes = new Uint8Array(arrayBuf);
  if (!activeChat) return;

  const fp = activeChat.fingerprint;
  const msgId = uuid();
  const ts = Date.now();
  const mimeClean = mime.split(';')[0] || 'audio/webm';
  const b64 = bufToBase64(bytes);

  if (!chatHistory[fp]) {
    chatHistory[fp] = { peerNickname: activeChat.peerCard.nickname, messages: [], lastActivity: ts, expiresAt: ts + CHAT_TTL_MS };
  }

  chatHistory[fp].messages.push({ id: msgId, from: 'me', type: 'voice', audioB64: b64, mime: mimeClean, duration, ts });
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  appendMessage({ id: msgId, from: 'me', type: 'voice', audioB64: b64, mime: mimeClean, duration, ts });
  startTimer();

  sendVoiceBackground({ fp, msgId, b64, mime: mimeClean, duration, ts }).catch(e => console.error('[VOICE SEND]', e));
}

function togglePauseRecord() {
  if (!mediaRecorder) return;
  if (isPaused) {
    mediaRecorder.resume();
    recordStartTs = Date.now() - pausedTime;
    isPaused = false;
  } else {
    mediaRecorder.pause();
    pausedTime = Date.now() - recordStartTs;
    isPaused = true;
    const spans = document.querySelectorAll('#recWave span');
    spans.forEach(s => { s.style.height = '2px'; s.style.opacity = '0.4'; });
  }
  updateRecPauseIcon();
}

function updateRecPauseIcon() {
  const icon = document.getElementById('recPauseIcon');
  if (!icon) return;
  if (isPaused) icon.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"></polygon>';
  else icon.innerHTML = '<rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect>';
}

// ============================================
// SEND VOICE
// ============================================
async function sendVoiceBackground({ fp, msgId, b64, mime, duration, ts }) {
  const peerCard = contacts[fp];
  if (!peerCard) return;
  const toHashHex = await hashPubkeyHex(peerCard.x25519);
  const sharedKey = await deriveSharedKey(myIdentity.x25519.private, peerCard.x25519);

  const CHUNK = 650_000;
  const totalChunks = Math.max(1, Math.ceil(b64.length / CHUNK));

  for (let i = 0; i < totalChunks; i++) {
    const chunkData = b64.slice(i * CHUNK, (i + 1) * CHUNK);
    const payload = JSON.stringify({
      id: msgId, text: '', ts, from: myHashHex, to: toHashHex,
      type: 'voice', voice: { chunk: i, total: totalChunks, mime, duration, data: chunkData }
    });
    const blob = await encryptMessage(payload, sharedKey);
    const signedData = JSON.stringify({ ciphertext: blob.ciphertext, from: myHashHex, to: toHashHex });
    const signature = await signBlob(signedData, myIdentity.ed25519.private);
    const pow = await computePow(blob.ciphertext);
    await addDoc(collection(db, 'users', toHashHex, 'inbox'), {
      from: myHashHex, to: toHashHex, iv: blob.iv, ciphertext: blob.ciphertext,
      signature, senderEd25519: myIdentity.ed25519.public, pow, ttl: Date.now() + RELAY_TTL_MS
    });
  }
  saveChats();
}

// ============================================
// CHAT END SIGNAL
// ============================================
async function sendEndSignalForFp(fp) {
  const peerCard = contacts[fp];
  if (!peerCard) return;
  const toHashHex = await hashPubkeyHex(peerCard.x25519);
  const sharedKey = await deriveSharedKey(myIdentity.x25519.private, peerCard.x25519);
  const payload = JSON.stringify({ id: uuid(), text: '', ts: Date.now(), from: myHashHex, to: toHashHex, end: true });
  const blob = await encryptMessage(payload, sharedKey);
  const signedData = JSON.stringify({ ciphertext: blob.ciphertext, from: myHashHex, to: toHashHex });
  const signature = await signBlob(signedData, myIdentity.ed25519.private);
  const pow = await computePow(blob.ciphertext);
  await addDoc(collection(db, 'users', toHashHex, 'inbox'), {
    from: myHashHex, to: toHashHex, iv: blob.iv, ciphertext: blob.ciphertext,
    signature, senderEd25519: myIdentity.ed25519.public, pow, ttl: Date.now() + RELAY_TTL_MS
  });
}

// ============================================
// END CHAT
// ============================================
function endChat() {
  if (!activeChat) return;
  const fp = activeChat.fingerprint;
  const peerNickname = activeChat.peerCard.nickname;
  delete chatHistory[fp];
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = null;
  activeChat = null;
  renderContacts();
  renderChat();
  endChatBackground(fp, peerNickname);
}

async function endChatBackground(fp, peerNickname) {
  try {
    try { await sendEndSignalForFp(fp); } catch (e) { console.warn('[END] signal failed:', e); }
    try { await purgeRelayForContact(fp); } catch (e) { console.warn('[END] purge failed:', e); }
    await saveChatsNow();
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
// SEND TEXT MESSAGE
// ============================================
function sendMessage() {
  const input = document.getElementById('msgInput');
  const text = input.value.trim();
  if (!text || !activeChat) return;
  input.value = '';
  input.style.height = 'auto';
  const fp = activeChat.fingerprint;
  const msgId = uuid();
  const ts = Date.now();
  if (!chatHistory[fp]) {
    chatHistory[fp] = { peerNickname: activeChat.peerCard.nickname, messages: [], lastActivity: ts, expiresAt: ts + CHAT_TTL_MS };
  }
  chatHistory[fp].messages.push({ id: msgId, from: 'me', text, ts });
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;
  appendMessage({ from: 'me', text, ts });
  startTimer();
  const peer = contacts[fp];
  if (peer) hashPubkeyHex(peer.x25519).then(h => clearTypingSignal(h)).catch(() => {});
  sendMessageBackground({ fp, msgId, text, ts });
}

async function sendMessageBackground({ fp, msgId, text, ts }) {
  try {
    const peerCard = contacts[fp];
    if (!peerCard) return;
    const toHashHex = await hashPubkeyHex(peerCard.x25519);
    const sharedKey = await deriveSharedKey(myIdentity.x25519.private, peerCard.x25519);
    const payload = JSON.stringify({ id: msgId, text, ts, from: myHashHex, to: toHashHex });
    const blob = await encryptMessage(payload, sharedKey);
    const signedData = JSON.stringify({ ciphertext: blob.ciphertext, from: myHashHex, to: toHashHex });
    const signature = await signBlob(signedData, myIdentity.ed25519.private);
    const pow = await computePow(blob.ciphertext);
    await addDoc(collection(db, 'users', toHashHex, 'inbox'), {
      from: myHashHex, to: toHashHex, iv: blob.iv, ciphertext: blob.ciphertext,
      signature, senderEd25519: myIdentity.ed25519.public, pow, ttl: Date.now() + RELAY_TTL_MS
    });
    saveChats();
  } catch (e) { console.error('[SEND]', e); }
}

// ============================================
// INCOMING
// ============================================
async function listenIncoming() {
  const inboxRef = myInboxRef();
  unsubscribeIncoming = onSnapshot(inboxRef, async (snapshot) => {
    for (const change of snapshot.docChanges()) {
      if (change.type !== 'added') continue;
      const data = change.doc.data();
      const docId = change.doc.id;
      const docRef = doc(db, 'users', myHashHex, 'inbox', docId);

      if (
        typeof data.from !== 'string' || typeof data.to !== 'string' ||
        typeof data.iv !== 'string' || typeof data.ciphertext !== 'string' ||
        typeof data.signature !== 'string' || typeof data.senderEd25519 !== 'string' ||
        typeof data.pow !== 'number' || typeof data.ttl !== 'number'
      ) { await deleteDoc(docRef); continue; }

      if (data.to !== myHashHex) { await deleteDoc(docRef); continue; }
      if (data.ttl < Date.now()) { await deleteDoc(docRef); continue; }
      if (!await verifyPow(data.ciphertext, data.pow)) { await deleteDoc(docRef); continue; }

      let peerFp = null;
      for (const fp in contacts) {
        const h = await hashPubkeyHex(contacts[fp].x25519);
        if (h === data.from) { peerFp = fp; break; }
      }
      if (!peerFp) { await deleteDoc(docRef); continue; }
      if (data.senderEd25519 !== contacts[peerFp].ed25519) { await deleteDoc(docRef); continue; }

      const signedData = JSON.stringify({ ciphertext: data.ciphertext, from: data.from, to: data.to });
      const valid = await verifyBlob(signedData, data.signature, data.senderEd25519);
      if (!valid) { await deleteDoc(docRef); continue; }

      const sharedKey = await deriveSharedKey(myIdentity.x25519.private, contacts[peerFp].x25519);
      let payload;
      try {
        const plain = await decryptMessage({ iv: data.iv, ciphertext: data.ciphertext }, sharedKey);
        payload = JSON.parse(plain);
      } catch (e) { await deleteDoc(docRef); continue; }

      if (payload.from !== data.from || payload.to !== myHashHex) { await deleteDoc(docRef); continue; }

      if (payload.end === true) {
        await deleteDoc(docRef);
        if (chatHistory[peerFp]) { delete chatHistory[peerFp]; saveChatsNow(); }
        if (activeChat && activeChat.fingerprint === peerFp) {
          if (timerInterval) clearInterval(timerInterval);
          timerInterval = null;
          activeChat = null;
          renderChat();
        }
        renderContacts();
        purgeRelayForContact(peerFp).catch(e => console.warn('[END] purge:', e));
        continue;
      }

      const existingChat = chatHistory[peerFp];
      const chatExpired = existingChat && existingChat.expiresAt && existingChat.expiresAt < Date.now();
      const isActiveWithPeer = activeChat && activeChat.fingerprint === peerFp;
      if (chatExpired && !isActiveWithPeer) { await deleteDoc(docRef); continue; }
      try { await deleteDoc(docRef); } catch (e) {}

      if (payload.type === 'voice' && payload.voice) {
        await handleIncomingVoice(payload, peerFp); continue;
      }

           if ((payload.type === 'file' || payload.type === 'image') && payload.file) {
        await handleIncomingFile(payload, peerFp); continue;
      }

      const isFirstMessage = !chatHistory[peerFp];
      if (!chatHistory[peerFp]) {
        chatHistory[peerFp] = { peerNickname: contacts[peerFp].nickname, messages: [], lastActivity: payload.ts, expiresAt: payload.ts + CHAT_TTL_MS };
      }
      chatHistory[peerFp].messages.push({ id: payload.id, from: 'peer', text: payload.text, ts: payload.ts });
      chatHistory[peerFp].lastActivity = payload.ts;
      chatHistory[peerFp].expiresAt = payload.ts + CHAT_TTL_MS;
      saveChats();

      if (activeChat && activeChat.fingerprint === peerFp) {
        if (isFirstMessage) renderChat();
        else appendMessage({ from: 'peer', text: payload.text, ts: payload.ts });
        startTimer();
      } else {
        renderContacts();
      }
    }
  }, (error) => { console.error('[LISTEN]', error); });
}

const pendingVoice = new Map();
async function handleIncomingVoice(payload, peerFp) {
  const v = payload.voice;
  if (typeof v.chunk !== 'number' || typeof v.total !== 'number' || typeof v.data !== 'string' || typeof v.mime !== 'string') return;
  const msgId = payload.id;
  let entry = pendingVoice.get(msgId);
  if (!entry) {
    entry = { total: v.total, chunks: new Map(), meta: { ts: payload.ts, mime: v.mime, duration: v.duration } };
    pendingVoice.set(msgId, entry);
  }
  entry.chunks.set(v.chunk, v.data);
  if (entry.chunks.size < entry.total) return;

  const parts = [];
  for (let i = 0; i < entry.total; i++) {
    const c = entry.chunks.get(i);
    if (!c) return;
    parts.push(c);
  }
  const fullB64 = parts.join('');
  pendingVoice.delete(msgId);

  const isFirstMessage = !chatHistory[peerFp];
  if (!chatHistory[peerFp]) {
    chatHistory[peerFp] = { peerNickname: contacts[peerFp].nickname, messages: [], lastActivity: payload.ts, expiresAt: payload.ts + CHAT_TTL_MS };
  }
  chatHistory[peerFp].messages.push({ id: msgId, from: 'peer', type: 'voice', audioB64: fullB64, mime: entry.meta.mime, duration: entry.meta.duration || 0, ts: payload.ts });
  chatHistory[peerFp].lastActivity = payload.ts;
  chatHistory[peerFp].expiresAt = payload.ts + CHAT_TTL_MS;
  saveChats();

  if (activeChat && activeChat.fingerprint === peerFp) {
    if (isFirstMessage) renderChat();
    else appendMessage({ id: msgId, from: 'peer', type: 'voice', audioB64: fullB64, mime: entry.meta.mime, duration: entry.meta.duration || 0, ts: payload.ts });
    startTimer();
  } else {
    renderContacts();
  }
}

// ============================================
// UI BINDINGS
// ============================================
function bindUI() {
  document.getElementById('fabAdd').addEventListener('click', openAddContactModal);
  document.getElementById('tabScan').addEventListener('click', () => setAddContactTab('scan'));
  document.getElementById('tabMyQr').addEventListener('click', () => setAddContactTab('myqr'));
  document.getElementById('btnAccounts').addEventListener('click', openAccountsModal);
  document.getElementById('btnCloseAccounts').addEventListener('click', closeAccountsModal);
  document.getElementById('btnLogout').addEventListener('click', handleLogout);
  document.getElementById('btnAddAnotherAccount').addEventListener('click', handleAddAnotherAccount);
  document.getElementById('btnOpenDevices').addEventListener('click', () => { closeAccountsModal(); openDevicesModal(); });
  document.getElementById('btnCloseDevices').addEventListener('click', closeDevicesModal);
  document.getElementById('btnGenerateExport').addEventListener('click', generateExport);
  document.getElementById('btnCopyExport').addEventListener('click', copyExport);
  document.getElementById('btnCloseAddContact').addEventListener('click', closeAddContactModal);
  document.getElementById('btnSend').addEventListener('click', sendMessage);
  document.getElementById('btnVoice').addEventListener('click', toggleRecording);
  document.getElementById('btnAttach').addEventListener('click', () => document.getElementById('fileInput').click());
  document.getElementById('fileInput').addEventListener('change', handleFileSelect);
  document.getElementById('btnCloseImage').addEventListener('click', () => {
    document.getElementById('modalImage').classList.remove('active');
  });
  document.getElementById('modalImage').addEventListener('click', (e) => {
    if (e.target.id === 'modalImage') document.getElementById('modalImage').classList.remove('active');
  });

  document.getElementById('recBtnDelete').addEventListener('click', async () => {
    isCancelled = true; 
    
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
      mediaRecorder.stop();
    }
    
    // Принудительно всё чистим
    if (recordTimerInterval) { clearInterval(recordTimerInterval); recordTimerInterval = null; }
    if (recWaveInterval) { clearInterval(recWaveInterval); recWaveInterval = null; }
    if (audioContext) { audioContext.close(); audioContext = null; }
    if (mediaStream) { mediaStream.getTracks().forEach(t => t.stop()); mediaStream = null; }
    
    mediaRecorder = null;
    recordedChunks = [];
    isPaused = false; 
    pausedTime = 0;
    
    document.getElementById('recordingUi').classList.remove('active');
    document.getElementById('btnVoice').style.display = '';
    document.getElementById('msgInput').style.display = '';
    document.getElementById('btnSend').style.display = '';
  });

  document.getElementById('recBtnPause').addEventListener('click', togglePauseRecord);
  document.getElementById('recBtnSend').addEventListener('click', stopRecordingAndSend);

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
    onTypingInput();
  });

  document.getElementById('btnMobileBack').addEventListener('click', exitChat);
  document.getElementById('btnEndChat').addEventListener('click', async () => {
    const ok = await showConfirm('End chat? History will be permanently deleted for both participants.', 'End Chat');
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
  if (pw.length < 6) { await showAlert('Password must be at least 6 characters', 'Error'); return; }
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
      const cellSize = 4, margin = 4, count = qr.getModuleCount(), size = count * cellSize + margin * 2;
      const canvas = document.createElement('canvas');
      canvas.width = size; canvas.height = size;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = '#000000';
      for (let row = 0; row < count; row++) for (let col = 0; col < count; col++)
        if (qr.isDark(row, col)) ctx.fillRect(margin + col * cellSize, margin + row * cellSize, cellSize, cellSize);
      canvas.style.maxWidth = '100%'; canvas.style.height = 'auto';
      qrBox.appendChild(canvas);
    }
    document.getElementById('exportResult').style.display = 'block';
  } catch (e) { console.error(e); await showAlert('Error: ' + e.message, 'Error'); }
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
  } catch { document.execCommand('copy'); }
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
    return `<div class="acct-item ${isCurrent ? 'current' : ''}">
      <div class="acct-avatar">${initial}</div>
      <div class="acct-info">
        <div class="acct-name">${escapeHtml(acc.nickname || 'No name')}${isCurrent ? ' (current)' : ''}</div>
        <div class="acct-fp">${acc.fingerprint}</div>
      </div>
      ${isCurrent ? '' : `<button class="acct-switch" data-switch="${acc.fingerprint}">Switch</button>`}
    </div>`;
  }).join('');
  list.querySelectorAll('.acct-switch').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const fp = btn.dataset.switch;
      const ok = await showConfirm('Switch to another account? You will be asked for a password.', 'Switch Account');
      if (!ok) return;
      sessionStorage.removeItem('_pw');
      sessionStorage.removeItem('_fp');
      await setLastActive(fp);
      window.location.href = 'index.html';
    });
  });
}

async function handleLogout() {
  const ok = await showConfirm('Sign out of the account? Data will remain on the device — you can return with the password.', 'Sign Out');
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
// FILE & IMAGE HANDLING
// ============================================
const MAX_FILE_SIZE = 40 * 1024 * 1024; // 40 MB
const FILE_CHUNK_SIZE = 650_000; // bytes of base64 per chunk

async function compressImage(file) {
  return new Promise(async (resolve, reject) => {
    try {
      const img = await createImageBitmap(file);
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      let width = img.width;
      let height = img.height;
      let quality = 0.8;
      const MAX_DIMENSION = 1600; // Уменьшили с 1920 до 1600 для скорости
      const MAX_SIZE_BYTES = 2 * 1024 * 1024; // 2 МБ — максимум для фото

      if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
        if (width > height) {
          height = Math.round((height * MAX_DIMENSION) / width);
          width = MAX_DIMENSION;
        } else {
          width = Math.round((width * MAX_DIMENSION) / height);
          height = MAX_DIMENSION;
        }
      }

      const tryCompress = () => {
        canvas.width = width;
        canvas.height = height;
        ctx.drawImage(img, 0, 0, width, height);
        
        canvas.toBlob((blob) => {
          if (!blob) {
            reject(new Error('Canvas toBlob failed'));
            return;
          }
          // Если фото больше 2 МБ — уменьшаем качество или разрешение
          if (blob.size > MAX_SIZE_BYTES && quality > 0.3) {
            quality -= 0.15;
            tryCompress();
          } else if (blob.size > MAX_SIZE_BYTES && width > 800) {
            width = Math.floor(width * 0.8);
            height = Math.floor(height * 0.8);
            quality = 0.7;
            tryCompress();
          } else {
            resolve(new File([blob], file.name.replace(/\.[^/.]+$/, "") + ".jpg", { type: 'image/jpeg' }));
          }
        }, 'image/jpeg', quality);
      };
      
      tryCompress();
    } catch (err) {
      reject(err);
    }
  });
}

async function handleFileSelect(e) {
  const file = e.target.files[0];
  e.target.value = ''; 
  if (!file || !activeChat) return;

  if (file.size > 40 * 1024 * 1024) {
    await showAlert('File is too large. Maximum size is 40 MB.', 'Error');
    return;
  }

  await sendFile(file);
}

async function sendFile(file) {
  if (!activeChat) return;
  const fp = activeChat.fingerprint;
  const msgId = uuid();
  const ts = Date.now();
  const isImage = file.type.startsWith('image/');
  const mime = file.type || 'application/octet-stream';
  const name = file.name || 'file';

  if (!chatHistory[fp]) {
    chatHistory[fp] = { peerNickname: activeChat.peerCard.nickname, messages: [], lastActivity: ts, expiresAt: ts + CHAT_TTL_MS };
  }

  // Для фото делаем превью сразу, но НЕ держим в b64
  let imgUrl = null;
  if (isImage) {
    imgUrl = URL.createObjectURL(file);
    fileCache.set(msgId, imgUrl);
  }

  const msgRecord = {
    id: msgId, from: 'me', type: isImage ? 'image' : 'file',
    fileName: name, fileMime: mime, fileSize: file.size,
    _imgUrl: imgUrl,
    ts
  };
  
  chatHistory[fp].messages.push(msgRecord);
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  appendMessage(msgRecord);
  
  // Добавляем индикатор загрузки
  const el = document.querySelector(`[data-msg-id="${msgId}"]`);
  if (el) {
    el.classList.add('uploading');
    const progressSpan = document.createElement('span');
    progressSpan.className = 'upload-progress';
    progressSpan.innerHTML = `<span class="upload-spinner"></span>0%`;
    el.appendChild(progressSpan);
  }

  startTimer();

  // Шлем файл (порезанный на куски)
  sendFileBackground({ fp, msgId, file, mime, name, isImage, ts })
    .then(() => {
      const el2 = document.querySelector(`[data-msg-id="${msgId}"]`);
      if (el2) {
        el2.classList.remove('uploading');
        const p = el2.querySelector('.upload-progress');
        if (p) p.remove();
      }
    })
    .catch(e => console.error('[FILE SEND]', e));
}

async function sendFileBackground({ fp, msgId, file, mime, name, isImage, ts }) {
  const peerCard = contacts[fp];
  if (!peerCard) return;
  const toHashHex = await hashPubkeyHex(peerCard.x25519);
  const sharedKey = await deriveSharedKey(myIdentity.x25519.private, peerCard.x25519);

  // 500 КБ бинарных данных на чанк
  const CHUNK_SIZE = 500 * 1024; 
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBlob = file.slice(start, end); // Читаем только кусок

    const arrayBuf = await chunkBlob.arrayBuffer();
    const chunkBytes = new Uint8Array(arrayBuf);
    const chunkData = bufToBase64(chunkBytes);

    const payload = JSON.stringify({
      id: msgId, text: '', ts, from: myHashHex, to: toHashHex,
      type: isImage ? 'image' : 'file',
      file: {
        chunk: i, total: totalChunks,
        mime, name, size: file.size, isImage,
        data: chunkData
      }
    });
    
    const blob = await encryptMessage(payload, sharedKey);
    const signedData = JSON.stringify({ ciphertext: blob.ciphertext, from: myHashHex, to: toHashHex });
    const signature = await signBlob(signedData, myIdentity.ed25519.private);
    const pow = await computePow(blob.ciphertext);
    
    await addDoc(collection(db, 'users', toHashHex, 'inbox'), {
      from: myHashHex, to: toHashHex, iv: blob.iv, ciphertext: blob.ciphertext,
      signature, senderEd25519: myIdentity.ed25519.public, pow, ttl: Date.now() + RELAY_TTL_MS
    });

    // Обновляем прогресс
    const percent = Math.round(((i + 1) / totalChunks) * 100);
    const el = document.querySelector(`[data-msg-id="${msgId}"]`);
    if (el) {
      const p = el.querySelector('.upload-progress');
      if (p) p.innerHTML = `<span class="upload-spinner"></span>${percent}%`;
    }

    // Даем браузеру отдышаться
    await new Promise(r => setTimeout(r, 10));
  }
  saveChats();
}

async function handleIncomingFile(payload, peerFp) {
  const f = payload.file;
  if (typeof f.chunk !== 'number' || typeof f.total !== 'number' || typeof f.data !== 'string') return;
  
  const msgId = payload.id;
  let entry = pendingFiles.get(msgId);
  if (!entry) {
    entry = {
      total: f.total, chunks: new Map(),
      meta: { ts: payload.ts, mime: f.mime, name: f.name, size: f.size, isImage: f.isImage }
    };
    pendingFiles.set(msgId, entry);
  }
  
  entry.chunks.set(f.chunk, f.data);
  if (entry.chunks.size < entry.total) return;

  const parts = [];
  for (let i = 0; i < entry.total; i++) {
    const c = entry.chunks.get(i);
    if (!c) return;
    parts.push(c);
  }
  const fullB64 = parts.join('');
  pendingFiles.delete(msgId);

  const isFirstMessage = !chatHistory[peerFp];
  if (!chatHistory[peerFp]) {
    chatHistory[peerFp] = { peerNickname: contacts[peerFp].nickname, messages: [], lastActivity: payload.ts, expiresAt: payload.ts + CHAT_TTL_MS };
  }
  
  const fileMsg = {
    id: msgId, from: 'peer', type: entry.meta.isImage ? 'image' : 'file',
    fileName: entry.meta.name, fileMime: entry.meta.mime, fileSize: entry.meta.size,
    b64: entry.meta.isImage ? fullB64 : null, // Для фото
    fileB64: !entry.meta.isImage ? fullB64 : null, // Для файлов
    ts: payload.ts
  };
  
  chatHistory[peerFp].messages.push(fileMsg);
  chatHistory[peerFp].lastActivity = payload.ts;
  chatHistory[peerFp].expiresAt = payload.ts + CHAT_TTL_MS;
  saveChats();

  if (activeChat && activeChat.fingerprint === peerFp) {
    if (isFirstMessage) renderChat();
    else appendMessage(fileMsg);
    startTimer();
  } else {
    renderContacts();
  }
}
// ============================================
// START
// ============================================
init();