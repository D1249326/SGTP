import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-auth.js";
import { getStorage } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-storage.js";

const firebaseConfig = {
  apiKey: "AIzaSyAPeE8wvB5dhpe0f3UEbqPrpp8jhL7dat4",
  authDomain: "sgtp-ed89d.firebaseapp.com",
  projectId: "sgtp-ed89d",
  storageBucket: "sgtp-ed89d.appspot.com",   // ★ 一定是 appspot.com
  messagingSenderId: "381788847156",
  appId: "1:381788847156:web:e48e67ad57015fdfd75e61",
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);

export { app };
