// ============================================
// index.js — создание / разблокировка / импорт identity
// ============================================
import {
  opfsWrite, opfsRead, opfsExists,
  generateIdentity, encryptIdentity, decryptIdentity,
  importIdentity
} from './crypto.js';

const IDENTITY_FILE = 'identity.enc';

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

// ---------- Создание ----------
async function handleCreate() {
  const rawNickname = document.getElementById('nickname').value;
  const nickname = sanitizeNickname(rawNickname);
  const password = document.getElementById('password').value;
  const password2 = document.getElementById('password2').value;
  const errEl = document.getElementById('createError');
  const btn = document.getElementById('createBtn');

  errEl.textContent = '';
  if (!nickname) { errEl.textContent = 'Введите никнейм (буквы, цифры, пробел, _ - .)'; return; }
  if (nickname.length < 2) { errEl.textContent = 'Ник минимум 2 символа'; return; }
  if (password.length < 6) { errEl.textContent = 'Пароль минимум 6 символов'; return; }
  if (password !== password2) { errEl.textContent = 'Пароли не совпадают'; return; }

  btn.disabled = true;
  btn.textContent = 'Генерация ключей...';

  try {
    const identity = await generateIdentity(nickname);
    const encrypted = await encryptIdentity(identity, password);
    await opfsWrite(IDENTITY_FILE, encrypted);
    sessionStorage.setItem('_pw', password);
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

  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Расшифровка...';

  try {
    const encrypted = await opfsRead(IDENTITY_FILE);
    const identity = await decryptIdentity(encrypted, password);
    sessionStorage.setItem('_pw', password);
    window.location.href = 'messenger.html';
  } catch (e) {
    console.error(e);
    errEl.textContent = 'Неверный пароль';
    btn.disabled = false;
    btn.textContent = 'Войти';
  }
}

// ---------- Импорт с другого устройства ----------
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
    console.log('✅ импортирована identity:', identity.fingerprint);

    // Сохраняем локально уже с НОВЫМ паролем пользователя
    const encrypted = await encryptIdentity(identity, newPassword);
    await opfsWrite(IDENTITY_FILE, encrypted);
    sessionStorage.setItem('_pw', newPassword);

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

  // Ссылки на экраны
  document.getElementById('linkToImport').addEventListener('click', (e) => {
    e.preventDefault();
    showScreen('screen-import');
  });
  document.getElementById('linkBackToCreate').addEventListener('click', (e) => {
    e.preventDefault();
    showScreen('screen-create');
  });

  const exists = await opfsExists(IDENTITY_FILE);
  showScreen(exists ? 'screen-unlock' : 'screen-create');
});