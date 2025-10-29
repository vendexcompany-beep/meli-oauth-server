import express from "express";
import axios from "axios";
import crypto from "crypto";
import { google } from "googleapis";

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Mercado Livre =====
const ML_CLIENT_ID = process.env.ML_CLIENT_ID;
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;              // ex.: https://meli-oauth-server.onrender.com
const REDIRECT_PATH = process.env.REDIRECT_PATH || "/callback";

// ===== Google Sheets =====
const GOOGLE_CLIENT_EMAIL = process.env.GOOGLE_CLIENT_EMAIL;
const GOOGLE_PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
const SPREADSHEET_ID = process.env.SPREADSHEET_ID;

// ===== PKCE store =====
const verifierStore = new Map();
const b64url = buf => buf.toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const genVerifier = (len=64) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from({length: len}, () => chars[Math.floor(Math.random()*chars.length)]).join("");
};
const challengeS256 = v => b64url(crypto.createHash("sha256").update(v).digest());

// ===== Helpers =====
async function getSheets() {
  const auth = new google.auth.GoogleAuth({
    credentials: {
      client_email: GOOGLE_CLIENT_EMAIL,
      private_key: GOOGLE_PRIVATE_KEY,
    },
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
  return google.sheets({ version: "v4", auth });
}

/** Grava no Sheets: timestamp | user_id | nickname | access_token | refresh_token */
async function appendToSheet({ user_id, nickname, access_token, refresh_token }) {
  if (!GOOGLE_CLIENT_EMAIL || !GOOGLE_PRIVATE_KEY || !SPREADSHEET_ID) {
    console.warn("⚠️ Variáveis do Google ausentes; pulando escrita.");
    return;
  }

  const sheets = await getSheets();
  const nowIso = new Date().toISOString();
  const range = "A:E"; // ajuste para sua aba se necessário

  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range,
    valueInputOption: "RAW",
    requestBody: {
      values: [[nowIso, String(user_id), nickname || "", access_token, refresh_token]],
    },
  });

  console.log("✅ Gravado no Sheets:", { user_id, nickname });
}

// ===== Rotas =====

// Tela inicial
app.get("/", (_req, res) => {
  res.send(`
    <h1>Servidor ativo 🚀</h1>
    <p><a href="/start">Iniciar OAuth Mercado Livre</a></p>
  `);
});

// Inicia o OAuth com PKCE
app.get("/start", (_req, res) => {
  const redirect_uri = `${BASE_URL}${REDIRECT_PATH}`;
  const state = crypto.randomBytes(16).toString("hex");
  const code_verifier = genVerifier();
  const code_challenge = challengeS256(code_verifier);

  verifierStore.set(state, code_verifier);

  const auth = new URL("https://auth.mercadolivre.com.br/authorization");
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("client_id", ML_CLIENT_ID);
  auth.searchParams.set("redirect_uri", redirect_uri);
  auth.searchParams.set("state", state);
  auth.searchParams.set("code_challenge_method", "S256");
  auth.searchParams.set("code_challenge", code_challenge);

  res.redirect(auth.toString());
});

// Callback Mercado Livre → Tokens → Nickname → Grava → Redireciona ao Mercado Livre
app.get(REDIRECT_PATH, async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Faltou code/state");

    const code_verifier = verifierStore.get(state);
    verifierStore.delete(state);

    if (!code_verifier) {
      return res.status(400).send("state inválido/expirado (hibernação?)");
    }

    const tokenUrl = "https://api.mercadolibre.com/oauth/token";
    const redirect_uri = `${BASE_URL}${REDIRECT_PATH}`;

    const body = new URLSearchParams();
    body.append("grant_type", "authorization_code");
    body.append("client_id", ML_CLIENT_ID);
    body.append("client_secret", ML_CLIENT_SECRET);
    body.append("code", code);
    body.append("redirect_uri", redirect_uri);
    body.append("code_verifier", code_verifier);

    const { data: token } = await axios.post(tokenUrl, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    // Puxar nickname
    let nickname = "";
    try {
      const { data: me } = await axios.get("https://api.mercadolibre.com/users/me", {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });
      nickname = me?.nickname || "";
    } catch (e) {
      console.warn("⚠️ Falha ao ler /users/me:", e?.response?.data || e.message);
    }

    // Gravar na planilha
    appendToSheet({
      user_id: token.user_id,
      nickname,
      access_token: token.access_token,
      refresh_token: token.refresh_token,
    }).catch(err => console.error("❌ Falha ao gravar no Sheets:", err?.response?.data || err));

    // ✅ Depois de tudo, redireciona o usuário para o Mercado Livre
    return res.redirect("https://www.mercadolivre.com.br/");

  } catch (err) {
    console.error(err?.response?.data || err.message);
    return res.status(500).send("Falha ao processar o callback.");
  }
});

app.listen(PORT, () => console.log(`✅ Servidor rodando em http://localhost:${PORT}`));
