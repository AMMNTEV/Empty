// ============================================
// index.js — мультиаккаунт: список, создание, вход, импорт
// ============================================
import {
  opfsWrite, opfsRead, opfsExists, opfsDelete,
  generateIdentity, encryptIdentity, decryptIdentity,
  importIdentity,
  listAccounts, saveAccounts, addAccountToIndex,
  removeAccountFromIndex, setLastActive,
  identityFilePath, deleteAccountFile
} from './crypto.js';

let selectedFingerprint = null;   // для экрана разблокировки

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

// ---------- Валидация ника ----------
function sanitizeNickname(raw) {
  let s = (raw || '').normalize('NFC').trim();
  s = s.replace(/[^\p{L}\p{N} _\-.]+/gu, '');
  s = s.replace(/\s+/g, ' ');
  if (s.length > 24) s = s.slice(0, 24).trim();
  return s;
}

// ---------- Рендер списка аккаунтов ----------
async function renderAccountsList() {
  const data = await listAccounts();
  const list = document.getElementById('accountList');

  if (data.accounts.length === 0) {
    list.innerHTML = '<div style="text-align:center; color:#666; font-size:13px; padding:20px 0;">Пока нет аккаунтов</div>';
    return;
  }

  // Сортируем: сначала lastActive, потом по дате создания (новые выше)
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
          <div class="account-name">${escapeHtml(acc.nickname || 'Без имени')}</div>
          <div class="account-fp">${acc.fingerprint}</div>
        </div>
        <button class="account-delete" data-delete="${acc.fingerprint}" title="Удалить">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
      </div>
    `;
  }).join('');

  // Клик по аккаунту — открыть экран входа
  list.querySelectorAll('.account-item').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.account-delete')) return;
      const fp = el.dataset.fp;
      const acc = sorted.find(a => a.fingerprint === fp);
      openUnlockScreen(acc);
    });
  });

  // Удалить аккаунт
  list.querySelectorAll('.account-delete').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const fp = btn.dataset.delete;
      const acc = data.accounts.find(a => a.fingerprint === fp);
      if (!acc) return;
      const ok = confirm(
        `Удалить аккаунт "${acc.nickname}"?\n\n` +
        `Все контакты, чаты и ключи будут удалены безвозвратно.\n` +
        `Это действие нельзя отменить.`
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

// ---------- Экран входа в аккаунт ----------
function openUnlockScreen(account) {
  selectedFingerprint = account.fingerprint;
  document.getElementById('unlockSubtitle').textContent = `Введите пароль для "${account.nickname}"`;
  document.getElementById('unlockPassword').value = '';
  document.getElementById('unlockError').textContent = '';
  showScreen('screen-unlock');
  setTimeout(() => document.getElementById('unlockPassword').focus(), 100);
}

// ---------- Создание ----------
async function handleCreate() {
  const rawNickname = document.getElementById('nickname').value;
  const nickname = sanitizeNickname(rawNickname);
  const password = document.getElementById('password').value;
  const password2 = document.getElementById('password2').value;
  const errEl = document.getElementById('createError');
  const btn = document.getElementById('createBtn');

  errEl.textContent = '';
  if (!nickname) { errEl.textContent = 'Введите никнейм'; return; }
  if (nickname.length < 2) { errEl.textContent = 'Ник минимум 2 символа'; return; }
  if (password.length < 6) { errEl.textContent = 'Пароль минимум 6 символов'; return; }
  if (password !== password2) { errEl.textContent = 'Пароли не совпадают'; return; }

  btn.disabled = true;
  btn.textContent = 'Генерация ключей...';

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
    errEl.textContent = 'Ошибка: ' + e.message;
    btn.disabled = false;
    btn.textContent = 'Создать';
  }
}

// ---------- Разблокировка ----------
async function handleUnlock() {
  const password = document.getElementById('unlockPassword').value;
  const errEl = document.getElementById('unlockError');
  const btn = document.getElementById('unlockBtn');

  if (!selectedFingerprint) {
    errEl.textContent = 'Аккаунт не выбран';
    return;
  }

  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Расшифровка...';

  try {
    const path = identityFilePath(selectedFingerprint);
    if (!await opfsExists(path)) {
      throw new Error('Файл аккаунта не найден');
    }
    const encrypted = await opfsRead(path);
    const identity = await decryptIdentity(encrypted, password);

    await setLastActive(identity.fingerprint);
    sessionStorage.setItem('_pw', password);
    sessionStorage.setItem('_fp', identity.fingerprint);

    window.location.href = 'messenger.html';
  } catch (e) {
    console.error(e);
    errEl.textContent = 'Неверный пароль';
    btn.disabled = false;
    btn.textContent = 'Войти';
  }
}

// ---------- Импорт ----------
async function handleImport() {
  const json = document.getElementById('importJson').value.trim();
  const exportPassword = document.getElementById('importPassword').value;
  const newPassword = document.getElementById('importNewPassword').value;
  const newPassword2 = document.getElementById('importNewPassword2').value;
  const errEl = document.getElementById('importError');
  const btn = document.getElementById('importBtn');

  errEl.textContent = '';
  if (!json) { errEl.textContent = 'Вставьте данные экспорта'; return; }
  if (!exportPassword) { errEl.textContent = 'Введите пароль экспорта'; return; }
  if (newPassword.length < 6) { errEl.textContent = 'Новый пароль минимум 6 символов'; return; }
  if (newPassword !== newPassword2) { errEl.textContent = 'Новые пароли не совпадают'; return; }

  btn.disabled = true;
  btn.textContent = 'Импорт...';

  try {
    const exportObj = JSON.parse(json);
    const identity = await importIdentity(exportObj, exportPassword);

    // Проверим, нет ли уже такого аккаунта
    const data = await listAccounts();
    const exists = data.accounts.find(a => a.fingerprint === identity.fingerprint);
    if (exists) {
      const overwrite = confirm(
        `Аккаунт "${identity.nickname}" уже есть на этом устройстве.\nПерезаписать его?`
      );
      if (!overwrite) {
        btn.disabled = false;
        btn.textContent = 'Импортировать';
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
    errEl.textContent = 'Ошибка: ' + e.message;
    btn.disabled = false;
    btn.textContent = 'Импортировать';
  }
}

// ---------- Инициализация ----------
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('createBtn').addEventListener('click', handleCreate);
  document.getElementById('unlockBtn').addEventListener('click', handleUnlock);
  document.getElementById('importBtn').addEventListener('click', handleImport);

  // Навигация
  document.getElementById('btnAddAccount').addEventListener('click', () => {
    document.getElementById('nickname').value = '';
    document.getElementById('password').value = '';
    document.getElementById('password2').value = '';
    document.getElementById('createError').textContent = '';
    showScreen('screen-create');
  });
  document.getElementById('btnImportAccount').addEventListener('click', () => {
    showScreen('screen-import');
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

  // Enter на поле пароля в экране разблокировки
  document.getElementById('unlockPassword').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleUnlock();
  });
    document.getElementById('btnScanImport').addEventListener('click', startImportScanner);
  document.getElementById('btnStopImportScan').addEventListener('click', stopImportScanner);

  // Стартовый экран
  const data = await listAccounts();
  if (data.accounts.length === 0) {
    showScreen('screen-create');
  } else {
    await renderAccountsList();
    showScreen('screen-accounts');
  }
});

// ============================================
// QR-СКАНЕР ДЛЯ ИМПОРТА
// ============================================
let importScannerStream = null;
let importScannerRAF = null;

async function startImportScanner() {
  const wrap = document.getElementById('importScannerWrap');
  const video = document.getElementById('importScannerVideo');
  const errEl = document.getElementById('importScanError');
  errEl.textContent = '';
  wrap.style.display = 'block';

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
            document.getElementById('importJson').value = code.data;
            stopImportScanner();
            return;
          }
        }
      }
      importScannerRAF = requestAnimationFrame(tick);
    };
    tick();
  } catch (e) {
    console.error('Camera error:', e);
    errEl.textContent = 'Не удалось получить доступ к камере: ' + e.message;
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
  const wrap = document.getElementById('importScannerWrap');
  if (wrap) wrap.style.display = 'none';
}