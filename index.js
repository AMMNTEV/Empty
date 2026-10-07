// ============================================
// index.js — multi-account: list, create, unlock, import
// ============================================
import {
  opfsWrite, opfsRead, opfsExists, opfsDelete,
  generateIdentity, encryptIdentity, decryptIdentity,
  importIdentity,
  listAccounts, saveAccounts, addAccountToIndex,
  removeAccountFromIndex, setLastActive,
  identityFilePath, deleteAccountFile
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

let selectedFingerprint = null;
let scannedImportJson = null;

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

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

// ---------- Nickname validation ----------
function sanitizeNickname(raw) {
  let s = (raw || '').normalize('NFC').trim();
  s = s.replace(/[^\p{L}\p{N} _\-.]+/gu, '');
  s = s.replace(/\s+/g, ' ');
  if (s.length > 24) s = s.slice(0, 24).trim();
  return s;
}

// ---------- Render account list ----------
async function renderAccountsList() {
  const data = await listAccounts();
  const list = document.getElementById('accountList');

  if (data.accounts.length === 0) {
    list.innerHTML = '<div style="text-align:center; color:#666; font-size:13px; padding:20px 0;">No accounts yet</div>';
    return;
  }

  const sorted = [...data.accounts].sort((a, b) => {
    if (a.fingerprint === data.lastActive) return -1;
    if (b.fingerprint === data.lastActive) return 1;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });

  list.innerHTML = sorted.map(acc => {
    const initial = (acc.nickname || '?').charAt(0).toUpperCase();
    const isCurrent = acc.fingerprint === data.lastActive ? 'current' : '';
    return `
      <div class="account-item ${isCurrent}" data-fp="${acc.fingerprint}">
        <div class="account-avatar">${initial}</div>
        <div class="account-info">
          <div class="account-name">${escapeHtml(acc.nickname || 'No name')}</div>
          <div class="account-fp">${acc.fingerprint}</div>
        </div>
        <button class="account-delete" data-delete="${acc.fingerprint}" title="Delete">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
      </div>
    `;
  }).join('');

  // Click on account — open unlock screen
  list.querySelectorAll('.account-item').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.account-delete')) return;
      const fp = el.dataset.fp;
      const acc = sorted.find(a => a.fingerprint === fp);
      openUnlockScreen(acc);
    });
  });

  // Delete account
  list.querySelectorAll('.account-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const fp = btn.dataset.delete;
      const acc = data.accounts.find(a => a.fingerprint === fp);
      if (!acc) return;

      const ok = await showConfirm(
        `Delete account "${acc.nickname}"?\n\n` +
        `All contacts, chats and keys will be permanently deleted.\n` +
        `This action cannot be undone.`,
        'Delete Account'
      );
      if (!ok) return;

      await deleteAccountFile(fp);
      await removeAccountFromIndex(fp);
      await renderAccountsList();
    });
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------- Unlock screen ----------
function openUnlockScreen(account) {
  selectedFingerprint = account.fingerprint;
  document.getElementById('unlockSubtitle').textContent = `Enter password for "${account.nickname}"`;
  document.getElementById('unlockPassword').value = '';
  document.getElementById('unlockError').textContent = '';

  const backBtn = document.getElementById('linkBackFromUnlock');
  if (backBtn) backBtn.style.display = '';

  showScreen('screen-unlock');
  setTimeout(() => document.getElementById('unlockPassword').focus(), 100);
}

// ---------- Create ----------
async function handleCreate() {
  const rawNickname = document.getElementById('nickname').value;
  const nickname = sanitizeNickname(rawNickname);
  const password = document.getElementById('password').value;
  const password2 = document.getElementById('password2').value;
  const errEl = document.getElementById('createError');
  const btn = document.getElementById('createBtn');

  errEl.textContent = '';
  if (!nickname) { errEl.textContent = 'Enter a nickname'; return; }
  if (nickname.length < 2) { errEl.textContent = 'Nickname must be at least 2 characters'; return; }
  if (password.length < 6) { errEl.textContent = 'Password must be at least 6 characters'; return; }
  if (password !== password2) { errEl.textContent = 'Passwords do not match'; return; }

  btn.disabled = true;
  btn.textContent = 'Generating keys...';

  try {
    const identity = await generateIdentity(nickname);
    const encrypted = await encryptIdentity(identity, password);
    await opfsWrite(identityFilePath(identity.fingerprint), encrypted);
    await addAccountToIndex(identity);

    sessionStorage.setItem('_pw', password);
    sessionStorage.setItem('_fp', identity.fingerprint);

    window.location.href = 'messenger.html';
  } catch (e) {
    console.error('❌', e);
    errEl.textContent = 'Error: ' + e.message;
    btn.disabled = false;
    btn.textContent = 'Create';
  }
}

// ---------- Unlock ----------
async function handleUnlock() {
  const password = document.getElementById('unlockPassword').value;
  const errEl = document.getElementById('unlockError');
  const btn = document.getElementById('unlockBtn');
  const backBtn = document.getElementById('linkBackFromUnlock');

  if (!selectedFingerprint) {
    errEl.textContent = 'No account selected';
    return;
  }

  errEl.textContent = '';

  btn.disabled = true;
  btn.textContent = 'Decrypting...';
  backBtn.style.display = 'none';

  try {
    const path = identityFilePath(selectedFingerprint);
    if (!await opfsExists(path)) {
      throw new Error('Account file not found');
    }
    const encrypted = await opfsRead(path);
    const identity = await decryptIdentity(encrypted, password);

    await setLastActive(identity.fingerprint);
    sessionStorage.setItem('_pw', password);
    sessionStorage.setItem('_fp', identity.fingerprint);

    window.location.href = 'messenger.html';
  } catch (e) {
    console.error(e);
    errEl.textContent = 'Wrong password';
    btn.disabled = false;
    btn.textContent = 'Sign In';
    backBtn.style.display = '';
  }
}

// ---------- Import ----------
async function handleImport() {
  const errEl = document.getElementById('importError');
  const btn = document.getElementById('importBtn');

  const json = scannedImportJson;
  const exportPassword = document.getElementById('importPassword').value;
  const newPassword = document.getElementById('importNewPassword').value;
  const newPassword2 = document.getElementById('importNewPassword2').value;

  errEl.textContent = '';
  if (!json) { errEl.textContent = 'Scan the QR code first'; return; }
  if (!exportPassword) { errEl.textContent = 'Enter the export password'; return; }
  if (newPassword.length < 6) { errEl.textContent = 'New password must be at least 6 characters'; return; }
  if (newPassword !== newPassword2) { errEl.textContent = 'New passwords do not match'; return; }

  btn.disabled = true;
  btn.textContent = 'Importing...';

  try {
    const exportObj = JSON.parse(json);
    const identity = await importIdentity(exportObj, exportPassword);

    const data = await listAccounts();
    const exists = data.accounts.find(a => a.fingerprint === identity.fingerprint);
    if (exists) {
      const overwrite = await showConfirm(
        `Account "${identity.nickname}" already exists on this device.\nOverwrite it?`,
        'Overwrite Account'
      );
      if (!overwrite) {
        btn.disabled = false;
        btn.textContent = 'Import';
        return;
      }
    }

    const encrypted = await encryptIdentity(identity, newPassword);
    await opfsWrite(identityFilePath(identity.fingerprint), encrypted);
    await addAccountToIndex(identity);

    sessionStorage.setItem('_pw', newPassword);
    sessionStorage.setItem('_fp', identity.fingerprint);

    window.location.href = 'messenger.html';
  } catch (e) {
    console.error('❌', e);
    errEl.textContent = 'Error: ' + e.message;
    btn.disabled = false;
    btn.textContent = 'Import';
  }
}

// ---------- Init ----------
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('createBtn').addEventListener('click', handleCreate);
  document.getElementById('unlockBtn').addEventListener('click', handleUnlock);
  document.getElementById('importBtn').addEventListener('click', handleImport);

  document.getElementById('btnAddAccount').addEventListener('click', () => {
    document.getElementById('nickname').value = '';
    document.getElementById('password').value = '';
    document.getElementById('password2').value = '';
    document.getElementById('createError').textContent = '';
    showScreen('screen-create');
  });

  document.getElementById('btnImportAccount').addEventListener('click', () => {
    showScreen('screen-import');
    setTimeout(() => startImportScanner(), 100);
  });

  document.getElementById('linkBackFromCreate').addEventListener('click', async () => {
    await renderAccountsList();
    showScreen('screen-accounts');
  });

  document.getElementById('linkBackFromUnlock').addEventListener('click', async () => {
    selectedFingerprint = null;
    await renderAccountsList();
    showScreen('screen-accounts');
  });

  document.getElementById('linkBackFromImport').addEventListener('click', async () => {
    stopImportScanner();
    await renderAccountsList();
    showScreen('screen-accounts');
  });

  document.getElementById('unlockPassword').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const btn = document.getElementById('unlockBtn');
    if (btn.disabled) return;
    handleUnlock();
  });

  // About
  document.getElementById('btnAbout').addEventListener('click', () => {
    document.getElementById('modalAbout').classList.add('active');
  });

  document.getElementById('btnCloseAbout').addEventListener('click', () => {
    document.getElementById('modalAbout').classList.remove('active');
  });

  const data = await listAccounts();
  if (data.accounts.length === 0) {
    showScreen('screen-create');
  } else {
    await renderAccountsList();
    showScreen('screen-accounts');
  }
});

// ============================================
// QR SCANNER FOR IMPORT
// ============================================
let importScannerStream = null;
let importScannerRAF = null;

async function startImportScanner() {
  const video = document.getElementById('importScannerVideo');
  const errEl = document.getElementById('importScanError');
  const successEl = document.getElementById('importScannerSuccess');
  errEl.textContent = '';
  successEl.style.display = 'none';

  if (importScannerStream) return;

  try {
    importScannerStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } }
    });
    video.srcObject = importScannerStream;
    await video.play();

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    const tick = () => {
      if (!importScannerStream) return;
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

            scannedImportJson = text;
            successEl.style.display = 'flex';

            if (importScannerStream) {
              importScannerStream.getTracks().forEach(t => t.stop());
              importScannerStream = null;
            }
            video.srcObject = null;

            document.getElementById('importBtn').disabled = false;
            return;
          }
        }
      }
      importScannerRAF = requestAnimationFrame(tick);
    };
    tick();
  } catch (e) {
    console.error('Camera error:', e);
    errEl.textContent = 'Failed to access camera: ' + e.message;
  }
}

function stopImportScanner() {
  if (importScannerRAF) { cancelAnimationFrame(importScannerRAF); importScannerRAF = null; }
  if (importScannerStream) {
    importScannerStream.getTracks().forEach(t => t.stop());
    importScannerStream = null;
  }
  const video = document.getElementById('importScannerVideo');
  if (video) video.srcObject = null;

  const successEl = document.getElementById('importScannerSuccess');
  if (successEl) successEl.style.display = 'none';

  scannedImportJson = null;
  const btn = document.getElementById('importBtn');
  if (btn) btn.disabled = true;
}