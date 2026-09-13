// ============================================
// index.js — создание / разблокировка identity
// ============================================
import {
  opfsWrite, opfsRead, opfsExists,
  generateIdentity, encryptIdentity, decryptIdentity
} from './crypto.js';

const IDENTITY_FILE = 'identity.enc';

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

// ---------- Валидация ника ----------
function sanitizeNickname(raw) {
  // NFC нормализация — й, ё, é приводятся к каноническому виду
  let s = (raw || '').normalize('NFC').trim();

  // Разрешены: буквы (любые Unicode), цифры, пробел, _ - .
  s = s.replace(/[^\p{L}\p{N} _\-.]+/gu, '');

  // Схлопываем множественные пробелы
  s = s.replace(/\s+/g, ' ');

  // Обрезаем до 24
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
    console.log('▶ generateIdentity:', nickname);
    const identity = await generateIdentity(nickname);
    console.log('✅ identity ok:', identity.fingerprint);
    console.log('   nickname codePoints:', [...identity.nickname].map(c => c.codePointAt(0).toString(16)));

    const encrypted = await encryptIdentity(identity, password);
    await opfsWrite(IDENTITY_FILE, encrypted);
    console.log('✅ записано в OPFS');

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
    console.log('✅ разблокировано:', identity.fingerprint);
    console.log('   nickname codePoints:', [...identity.nickname].map(c => c.codePointAt(0).toString(16)));
    sessionStorage.setItem('_pw', password);
    window.location.href = 'messenger.html';
  } catch (e) {
    console.error(e);
    errEl.textContent = 'Неверный пароль';
    btn.disabled = false;
    btn.textContent = 'Войти';
  }
}

// ---------- Инициализация ----------
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('createBtn').addEventListener('click', handleCreate);
  document.getElementById('unlockBtn').addEventListener('click', handleUnlock);

  const exists = await opfsExists(IDENTITY_FILE);
  showScreen(exists ? 'screen-unlock' : 'screen-create');
});