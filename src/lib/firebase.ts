import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
  apiKey: "AIzaSyCD0tI0VQ8uctbfmXEbTJgbM3HXIWQ-LRk",
  authDomain: "qrypto-f0d20.firebaseapp.com",
  projectId: "qrypto-f0d20",
  storageBucket: "qrypto-f0d20.firebasestorage.app",
  messagingSenderId: "626916596664",
  appId: "1:626916596664:web:d89e1abdad167859a74d4d",
  measurementId: "G-NM16PVQ6M0"
};

const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app);

export { app, analytics, auth };
