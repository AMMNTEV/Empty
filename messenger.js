// ============================================
// messenger.js — contacts, chats, E2EE, relay
// Scheme: users/{hashHex}/inbox/{blobId}
//         users/{hashHex}/ephemeral/{peerHash}  (typing)
// Contacts and chats files are per-account
// ============================================
import { db } from './firebase-init.js';
import {
  collection, addDoc, onSnapshot,
  deleteDoc, doc, getDocs, writeBatch,
  setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.8.1/firebase-firestore.js";

import {
  opfsWrite, opfsRead, opfsExists,
  decryptIdentity, encryptIdentity,
  deriveSharedKey, encryptMessage, decryptMessage, decryptMessageText,
  hashPubkeyHex,
  signBlob, verifyBlob, uuid,
  exportIdentity,
  listAccounts, setLastActive, identityFilePath,
  utf8Encode, utf8Decode, bufToBase64, base64ToBuf,
  padBytes, unpadBytes
} from './crypto.js';

// ============================================
// UTF-8 for QR
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

// Voice: Firestore document hard limit is 1 MiB.
// Base64 overhead ~33%, plus JSON wrapper → keep payload under ~700 KB base64.
const VOICE_CHUNK_MAX_B64 = 650_000;   // bytes of base64 per chunk
const VOICE_MAX_DURATION_MS = 5 * 60 * 1000; // 5 min hard cap

// Typing: ephemeral doc refreshed every 3s, considered active if <5s old
const TYPING_REFRESH_MS = 3000;
const TYPING_VISIBLE_MS = 5000;

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

// voice state
let mediaRecorder = null;
let mediaStream = null;
let recordedChunks = [];
let recordStartTs = 0;
let recordTimerInterval = null;
let recWaveInterval = null;
let audioContext = null;
let audioAnalyser = null;
let isPaused = false;
let pausedTime = 0;
let previewAudio = null;

// voice reassembly: { [msgId]: { total, chunks: Map, meta } }
const pendingVoice = new Map();

// active audio players per message id (to revoke object URLs)
const audioCache = new Map();

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
// TYPING (idea 9 — ephemeral, auto-expires)
// Doc: users/{peerHash}/ephemeral/{myHash}  (sender's view)
// We write to peer's ephemeral collection, subscribe to our own.
// ============================================
function myEphemeralRef() {
  return collection(db, 'users', myHashHex, 'ephemeral');
}

async function sendTypingSignal(peerHash) {
  const now = Date.now();
  if (now - lastTypingSent < TYPING_REFRESH_MS) return;
  lastTypingSent = now;
  try {
    const ref = doc(db, 'users', peerHash, 'ephemeral', myHashHex);
    await setDoc(ref, {
      typing: true,
      ts: now
    });
  } catch (e) {
    // silently ignore — typing is non-critical
  }
}

async function clearTypingSignal(peerHash) {
  try {
    const ref = doc(db, 'users', peerHash, 'ephemeral', myHashHex);
    await setDoc(ref, { typing: false, ts: Date.now() });
  } catch (e) {}
}

function onTypingInput() {
  if (!activeChat) return;
  if (typingStopTimer) clearTimeout(typingStopTimer);
  const fp = activeChat.fingerprint;
  const peer = contacts[fp];
  if (!peer) return;

  hashPubkeyHex(peer.x25519).then(peerHash => {
    sendTypingSignal(peerHash);
    typingStopTimer = setTimeout(() => {
      clearTypingSignal(peerHash);
    }, TYPING_REFRESH_MS + 500);
  });
}

function listenTyping() {
  if (unsubscribeTyping) unsubscribeTyping();

  const ref = myEphemeralRef();
  unsubscribeTyping = onSnapshot(ref, (snapshot) => {
    // Find newest typing signal from any contact
    let newest = null;
    snapshot.forEach(d => {
      const data = d.data();
      if (!data || !data.typing) return;
      if (typeof data.ts !== 'number') return;
      if (Date.now() - data.ts > TYPING_VISIBLE_MS) return;
      if (!newest || data.ts > newest.ts) {
        newest = { senderHash: d.id, ts: data.ts };
      }
    });

    updateTypingIndicator(newest);
  }, (err) => {
    console.warn('[TYPING]', err);
  });
}

async function updateTypingIndicator(newest) {
  const el = document.getElementById('chatTyping');
  if (!el) return;

  if (typingHideTimer) { clearTimeout(typingHideTimer); typingHideTimer = null; }

  if (!newest || !activeChat) {
    el.classList.remove('visible');
    el.textContent = '';
    return;
  }

  // Resolve senderHash → contact fp
  let senderFp = null;
  for (const fp in contacts) {
    const h = await hashPubkeyHex(contacts[fp].x25519);
    if (h === newest.senderHash) { senderFp = fp; break; }
  }

  if (!senderFp || senderFp !== activeChat.fingerprint) {
    el.classList.remove('visible');
    el.textContent = '';
    return;
  }

  const name = contacts[senderFp].nickname || 'Peer';
  el.textContent = `${name} is typing…`;
  el.classList.add('visible');

  // Auto-hide after TYPING_VISIBLE_MS if no refresh
  const age = Date.now() - newest.ts;
  const remaining = Math.max(1000, TYPING_VISIBLE_MS - age);
  typingHideTimer = setTimeout(() => {
    el.classList.remove('visible');
    el.textContent = '';
  }, remaining);
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
  listenTyping();
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

  // Clean up any old audio URLs
  for (const [id, url] of audioCache.entries()) {
    URL.revokeObjectURL(url);
    audioCache.delete(id);
  }

  messages.innerHTML = msgs.map(m => renderMessageHtml(m)).join('');

  // Wire up voice players
  messages.querySelectorAll('.voice-play-btn').forEach(btn => {
    const id = btn.dataset.msgId;
    btn.addEventListener('click', () => toggleVoicePlayback(id));
  });

  requestAnimationFrame(() => {
    messages.scrollTop = messages.scrollHeight;
  });

  updateFabVisibility();
}

// Renders one message to HTML (handles text and voice)
function renderMessageHtml(m) {
  const cls = m.from === 'me' ? 'me' : 'other';
  const time = `<span class="msg-time">${formatTime(m.ts)}</span>`;

  if (m.type === 'voice') {
    const duration = formatDuration(m.duration || 0);
    const bars = renderWaveBars(m.id);
    return `<div class="msg voice ${cls}" data-msg-id="${m.id}">
      <div class="voice-row">
        <button class="voice-play-btn" data-msg-id="${m.id}" aria-label="Play voice">
          <svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
        </button>
        <div class="voice-wave" data-msg-id="${m.id}">${bars}</div>
        <div class="voice-duration" data-msg-id="${m.id}">${duration}</div>
      </div>
      <div class="voice-progress"><div class="voice-progress-bar" data-msg-id="${m.id}"></div></div>
      ${time}
    </div>`;
  }

  return `<div class="msg ${cls}" data-msg-id="${m.id}">${linkifyAndEscape(m.text || '')}${time}</div>`;
}

// Deterministic pseudo-waveform from message id (so it's stable across renders)
function renderWaveBars(msgId) {
  let h = 0;
  for (let i = 0; i < msgId.length; i++) {
    h = ((h << 5) - h + msgId.charCodeAt(i)) | 0;
  }
  const bars = [];
  for (let i = 0; i < 24; i++) {
    h = ((h << 5) - h + i) | 0;
    const v = 4 + (Math.abs(h) % 16);
    bars.push(`<span style="height:${v}px"></span>`);
  }
  return bars.join('');
}

// Instant append of a single message (no full re-render)
function appendMessage(msg) {
  const messages = document.getElementById('messages');
  if (!messages) return;

  const placeholder = messages.querySelector('div[style*="text-align:center"]');
  if (placeholder && placeholder.textContent.includes('No messages')) {
    placeholder.remove();
  }

  messages.insertAdjacentHTML('beforeend', renderMessageHtml(msg));

  // Wire up the newly added voice player (if any)
  const newEl = messages.lastElementChild;
  if (newEl && newEl.classList.contains('voice')) {
    const btn = newEl.querySelector('.voice-play-btn');
    if (btn) {
      const id = btn.dataset.msgId;
      btn.addEventListener('click', () => toggleVoicePlayback(id));
    }
  }

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

  // Toggle stop if already playing
  const existing = audioCache.get(msgId);
  if (existing) {
    const audio = existing.audio;
    audio.pause();
    audio.currentTime = 0;
    URL.revokeObjectURL(existing.url);
    audioCache.delete(msgId);
    if (btn) btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
    if (wave) wave.classList.remove('playing');
    if (bar) bar.style.width = '0%';
    if (durEl) durEl.textContent = formatDuration(msg.duration || 0);
    return;
  }

  // Create new audio
  try {
    const bytes = base64ToBuf(msg.audioB64);
    const blob = new Blob([bytes], { type: msg.mime });
    const url = URL.createObjectURL(blob);
    const audio = new Audio(url);

    audio.addEventListener('timeupdate', () => {
      if (!audio.duration || !isFinite(audio.duration)) return;
      const pct = (audio.currentTime / audio.duration) * 100;
      if (bar) bar.style.width = pct + '%';
      if (durEl) durEl.textContent = formatDuration(audio.currentTime * 1000);
    });

    audio.addEventListener('ended', () => {
      URL.revokeObjectURL(url);
      audioCache.delete(msgId);
      if (btn) btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
      if (wave) wave.classList.remove('playing');
      if (bar) bar.style.width = '0%';
      if (durEl) durEl.textContent = formatDuration(msg.duration || 0);
    });

    audio.addEventListener('error', () => {
      console.error('[VOICE] audio error');
      URL.revokeObjectURL(url);
      audioCache.delete(msgId);
    });

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
  const candidates = [
    'audio/webm;codecs=opus',
    'audio/ogg;codecs=opus',
    'audio/webm',
    'audio/mp4'
  ];
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
  if (!mime) {
    await showAlert('Voice recording is not supported in this browser.', 'Error');
    return;
  }

  try {
    mediaStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        channelCount: 1,
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true
      }
    });
  } catch (e) {
    await showAlert('Microphone access denied: ' + e.message, 'Error');
    return;
  }

  // Настройка визуализации (волн)
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
  pausedTime = 0;

  try {
    mediaRecorder = new MediaRecorder(mediaStream, {
      mimeType: mime,
      audioBitsPerSecond: 16000
    });
  } catch (e) {
    console.error('[VOICE] MediaRecorder failed:', e);
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

  // UI
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
    if (elapsed >= VOICE_MAX_DURATION_MS) {
      stopRecordingAndSend();
    }
  }, 200);
}

async function stopRecordingAndSend() {
  if (!mediaRecorder) return;
  if (mediaRecorder.state === 'recording') {
    mediaRecorder.stop();
  }
}

async function finalizeRecordingAndSend(mime) {
  if (recordTimerInterval) { clearInterval(recordTimerInterval); recordTimerInterval = null; }
  if (recWaveInterval) { clearInterval(recWaveInterval); recWaveInterval = null; }
  if (audioContext) { audioContext.close(); audioContext = null; }
  if (previewAudio) { previewAudio.pause(); previewAudio = null; }

  // Restore UI
  const btnVoice = document.getElementById('btnVoice');
  const msgInput = document.getElementById('msgInput');
  const btnSend = document.getElementById('btnSend');
  if (btnVoice) btnVoice.style.display = '';
  if (msgInput) msgInput.style.display = '';
  if (btnSend) btnSend.style.display = '';
  document.getElementById('recordingUi').classList.remove('active');

  // Stop tracks
  if (mediaStream) {
    mediaStream.getTracks().forEach(t => t.stop());
    mediaStream = null;
  }
  const mr = mediaRecorder;
  mediaRecorder = null;

  const duration = Date.now() - recordStartTs;
  recordStartTs = 0;

  if (!recordedChunks.length) return;
  if (duration < 500) {
    recordedChunks = [];
    await showAlert('Recording too short.', 'Notice');
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
    chatHistory[fp] = {
      peerNickname: activeChat.peerCard.nickname,
      messages: [],
      lastActivity: ts,
      expiresAt: ts + CHAT_TTL_MS
    };
  }

  const msgRecord = {
    id: msgId,
    from: 'me',
    type: 'voice',
    audioB64: b64,
    mime: mimeClean,
    duration,
    ts
  };

  chatHistory[fp].messages.push(msgRecord);
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  appendMessage(msgRecord);
  startTimer();

  sendVoiceBackground({ fp, msgId, b64, mime: mimeClean, duration, ts })
    .catch(e => console.error('[VOICE SEND]', e));
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
  if (isPaused) {
    icon.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"></polygon>';
  } else {
    icon.innerHTML = '<rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect>';
  }
}


// ============================================
// SEND VOICE (with chunking if too large)
// ============================================
async function sendVoiceBackground({ fp, msgId, b64, mime, duration, ts }) {
  const peerCard = contacts[fp];
  if (!peerCard) return;

  const toHashHex = await hashPubkeyHex(peerCard.x25519);
  const sharedKey = await deriveSharedKey(
    myIdentity.x25519.private,
    peerCard.x25519
  );

  const totalChunks = Math.max(1, Math.ceil(b64.length / VOICE_CHUNK_MAX_B64));

  for (let i = 0; i < totalChunks; i++) {
    const chunkData = b64.slice(i * VOICE_CHUNK_MAX_B64, (i + 1) * VOICE_CHUNK_MAX_B64);

    const payloadObj = {
      id: msgId,
      text: '',
      ts,
      from: myHashHex,
      to: toHashHex,
      type: 'voice',
      voice: {
        chunk: i,
        total: totalChunks,
        mime,
        duration,
        data: chunkData
      }
    };

    const payload = JSON.stringify(payloadObj);
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
      pow,
      ttl: Date.now() + RELAY_TTL_MS
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
    signature,
    senderEd25519: myIdentity.ed25519.public,
    pow,
    ttl: Date.now() + RELAY_TTL_MS
  });

  console.log('[END] End signal sent');
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

  console.log(`[END] Chat with "${peerNickname}" ended (UI)`);
}

async function endChatBackground(fp, peerNickname) {
  try {
    try { await sendEndSignalForFp(fp); } catch (e) { console.warn('[END] signal failed:', e); }
    try { await purgeRelayForContact(fp); } catch (e) { console.warn('[END] purge failed:', e); }
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
    chatHistory[fp] = {
      peerNickname: activeChat.peerCard.nickname,
      messages: [],
      lastActivity: ts,
      expiresAt: ts + CHAT_TTL_MS
    };
  }

  const msgRecord = { id: msgId, from: 'me', type: 'text', text, ts };
  chatHistory[fp].messages.push(msgRecord);
  chatHistory[fp].lastActivity = ts;
  chatHistory[fp].expiresAt = ts + CHAT_TTL_MS;

  appendMessage(msgRecord);
  startTimer();

  const peer = contacts[fp];
  if (peer) {
    hashPubkeyHex(peer.x25519).then(h => clearTypingSignal(h)).catch(() => {});
  }

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
      to: toHashHex,
      type: 'text'
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
      signature,
      senderEd25519: myIdentity.ed25519.public,
      pow,
      ttl: Date.now() + RELAY_TTL_MS
    });

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

      if (
        typeof data.from !== 'string' ||
        typeof data.to !== 'string' ||
        typeof data.iv !== 'string' ||
        typeof data.ciphertext !== 'string' ||
        typeof data.signature !== 'string' ||
        typeof data.senderEd25519 !== 'string' ||
        typeof data.pow !== 'number' ||
        typeof data.ttl !== 'number'
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

      const signedData = JSON.stringify({
        ciphertext: data.ciphertext,
        from: data.from,
        to: data.to
      });
      const valid = await verifyBlob(signedData, data.signature, data.senderEd25519);
      if (!valid) { await deleteDoc(docRef); continue; }

      const sharedKey = await deriveSharedKey(
        myIdentity.x25519.private,
        contacts[peerFp].x25519
      );

      let payload;
      try {
        const bytes = await decryptMessage(
          { iv: data.iv, ciphertext: data.ciphertext },
          sharedKey
        );
        payload = JSON.parse(utf8Decode(bytes));
      } catch (e) { await deleteDoc(docRef); continue; }

      if (payload.from !== data.from || payload.to !== myHashHex) {
        await deleteDoc(docRef); continue;
      }

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

      const existingChat = chatHistory[peerFp];
      const chatExpired = existingChat && existingChat.expiresAt && existingChat.expiresAt < Date.now();
      const isActiveWithPeer = activeChat && activeChat.fingerprint === peerFp;
      if (chatExpired && !isActiveWithPeer) {
        await deleteDoc(docRef); continue;
      }

      try { await deleteDoc(docRef); } catch (e) {}

      if (payload.type === 'voice' && payload.voice) {
        await handleIncomingVoice(payload, peerFp);
        continue;
      }

      const isFirstMessage = !chatHistory[peerFp];

      if (!chatHistory[peerFp]) {
        chatHistory[peerFp] = {
          peerNickname: contacts[peerFp].nickname,
          messages: [],
          lastActivity: payload.ts,
          expiresAt: payload.ts + CHAT_TTL_MS
        };
      }

      const textMsg = {
        id: payload.id,
        from: 'peer',
        type: 'text',
        text: payload.text || '',
        ts: payload.ts
      };
      chatHistory[peerFp].messages.push(textMsg);
      chatHistory[peerFp].lastActivity = payload.ts;
      chatHistory[peerFp].expiresAt = payload.ts + CHAT_TTL_MS;

      saveChats();

      if (activeChat && activeChat.fingerprint === peerFp) {
        if (isFirstMessage) {
          renderChat();
        } else {
          appendMessage(textMsg);
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
// INCOMING VOICE (chunk reassembly)
// ============================================
async function handleIncomingVoice(payload, peerFp) {
  const v = payload.voice;
  if (
    typeof v.chunk !== 'number' ||
    typeof v.total !== 'number' ||
    typeof v.data !== 'string' ||
    typeof v.mime !== 'string'
  ) return;

  const msgId = payload.id;
  let entry = pendingVoice.get(msgId);
  if (!entry) {
    entry = { total: v.total, chunks: new Map(), meta: { ts: payload.ts, mime: v.mime, duration: v.duration } };
    pendingVoice.set(msgId, entry);
  }

  entry.chunks.set(v.chunk, v.data);

  if (entry.chunks.size < entry.total) {
    return;
  }

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
    chatHistory[peerFp] = {
      peerNickname: contacts[peerFp].nickname,
      messages: [],
      lastActivity: payload.ts,
      expiresAt: payload.ts + CHAT_TTL_MS
    };
  }

  const voiceMsg = {
    id: msgId,
    from: 'peer',
    type: 'voice',
    audioB64: fullB64,
    mime: entry.meta.mime,
    duration: entry.meta.duration || 0,
    ts: payload.ts
  };

  chatHistory[peerFp].messages.push(voiceMsg);
  chatHistory[peerFp].lastActivity = payload.ts;
  chatHistory[peerFp].expiresAt = payload.ts + CHAT_TTL_MS;

  saveChats();

  if (activeChat && activeChat.fingerprint === peerFp) {
    if (isFirstMessage) {
      renderChat();
    } else {
      appendMessage(voiceMsg);
    }
    startTimer();
  } else {
    renderContacts();
  }
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
  document.getElementById('btnVoice').addEventListener('click', toggleRecording);

  // Кнопки управления записью
  document.getElementById('recBtnDelete').addEventListener('click', () => stopRecording('delete'));
  document.getElementById('recBtnPause').addEventListener('click', togglePauseRecord);
  document.getElementById('recBtnSend').addEventListener('click', () => stopRecording('send'));

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