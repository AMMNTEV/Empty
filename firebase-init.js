import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-firestore.js";
import { initializeAppCheck, ReCaptchaV3Provider } from "https://www.gstatic.com/firebasejs/10.8.1/firebase-app-check.js";

const firebaseConfig = {
  apiKey: "AIzaSyB1YuKyaW5FY8tvXhJ9jxlqTz4JaffeSOU",
  authDomain: "emptychatss.firebaseapp.com",
  projectId: "emptychatss",
  storageBucket: "emptychatss.firebasestorage.app",
  messagingSenderId: "984092776074",
  appId: "1:984092776074:web:5908fb32b1596fa5f1bf73",
  measurementId: "G-YL2PJPJ56T"
};

const app = initializeApp(firebaseConfig);

// Debug-токен для локальной разработки
if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
  self.FIREBASE_APPCHECK_DEBUG_TOKEN = true;
}

initializeAppCheck(app, {
  provider: new ReCaptchaV3Provider('6LdJo7wtAAAAAMP2S3syQAdd1gj7Rowa9e-q_gI_'),
  isTokenAutoRefreshEnabled: true
});

const auth = getAuth(app);
const db = getFirestore(app);

export { app, auth, db };