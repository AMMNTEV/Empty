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

// ---------- Создание ----------
async function handleCreate() {
  const nickname = document.getElementById('nickname').value.trim();
  const password = document.getElementById('password').value;
  const password2 = document.getElementById('password2').value;
  const errEl = document.getElementById('createError');
  const btn = document.getElementById('createBtn');

  errEl.textContent = '';

  if (!nickname) { errEl.textContent = 'Введите никнейм'; return; }
  if (password.length < 6) { errEl.textContent = 'Пароль минимум 6 символов'; return; }
  if (password !== password2) { errEl.textContent = 'Пароли не совпадают'; return; }

  btn.disabled = true;
  btn.textContent = 'Генерация ключей...';

  try {
    const identity = await generateIdentity(nickname);
    const encrypted = await encryptIdentity(identity, password);
    await opfsWrite(IDENTITY_FILE, encrypted);

    // Пароль кладём в sessionStorage, чтобы messenger.html мог расшифровать
    // (живёт до закрытия вкладки — норм для нашей модели)
    sessionStorage.setItem('_pw', password);

    console.log('✅ Identity создана:', identity.fingerprint);
    window.location.href = 'messenger.html';
  } catch (e) {
    console.error(e);
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
    console.log('✅ Identity разблокирована:', identity.fingerprint);
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