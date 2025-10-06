// server.js (PKCE + grava no Google Sheets)
import express from "express";
import axios from "axios";
import crypto from "crypto";
import { google } from "googleapis";

const app = express();
const PORT = process.env.PORT || 3000;

// Mercado Livre
const ML_CLIENT_ID = process.env.ML_CLIENT_ID;
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;           // ex.: https://meli-oauth-server.onrender.com
const REDIRECT_PATH = process.env.REDIRECT_PATH || "/callback";

// Google Sheets
const GOOGLE_CLIENT_EMAIL = process.env.GOOGLE_CLIENT_EMAIL;
const GOOGLE_PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
const SPREADSHEET_ID = process.env.SPREADSHEET_ID; // 1fPjwsYeMK3lOo1c7MCUWgwJLEM1EsvJAMgWKVdM5oHQ

// guarda code_verifier por state (em memória)
const verifierStore = new Map();

const b64url = buf => buf.toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const genVerifier = (len=64) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from({length: len}, () => chars[Math.floor(Math.random()*chars.length)]).join("");
};
const challengeS256 = v => b64url(crypto.createHash("sha256").update(v).digest());

// ----- Google Sheets helper -----
async function appendToSheet({ user_id, access_token, refresh_token, expires_in }) {
  if (!GOOGLE_CLIENT_EMAIL || !GOOGLE_PRIVATE_KEY || !SPREADSHEET_ID) {
    console.warn("Google env vars ausentes; pulando escrita na planilha.");
    return;
  }

  const auth = new google.auth.JWT({
    email: GOOGLE_CLIENT_EMAIL,
    key: GOOGLE_PRIVATE_KEY,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });

  const sheets = google.sheets({ version: "v4", auth });

  const nowIso = new Date().toISOString();
  const expiresAtEpoch = Math.floor(Date.now() / 1000) + Number(expires_in || 21600);

  // Ajuste o range conforme sua aba: 'Página1' ou 'Sheet1'. Aqui uso a primeira aba com A:D.
  const range = "A:D"; // Timestamp | user_id | access_token | refresh_token

  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range,
    valueInputOption: "RAW",
    requestBody: {
      values: [[nowIso, String(user_id), access_token, refresh_token]],
    },
  });

  console.log("✅ Tokens gravados na planilha:", SPREADSHEET_ID);
}

// ----- Rotas -----
app.get("/", (_req, res) => {
  // Página simples; pode servir 'public/index.html' se preferir
  res.send(`<h1>Servidor ativo 🚀</h1>
    <p><a href="/start">Iniciar OAuth Mercado Livre</a></p>`);
});

// Início do fluxo (gera PKCE)
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

// Callback: troca code -> tokens e grava na planilha
app.get(REDIRECT_PATH, async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Faltou code/state");

    const code_verifier = verifierStore.get(state);
    verifierStore.delete(state);
    if (!code_verifier) return res.status(400).send("state inválido/expirado (instância hibernou?)");

    const tokenUrl = "https://api.mercadolibre.com/oauth/token";
    const redirect_uri = `${BASE_URL}${REDIRECT_PATH}`;

    const body = new URLSearchParams();
    body.append("grant_type", "authorization_code");
    body.append("client_id", ML_CLIENT_ID);
    body.append("client_secret", ML_CLIENT_SECRET);
    body.append("code", code);
    body.append("redirect_uri", redirect_uri);
    body.append("code_verifier", code_verifier);

    const { data } = await axios.post(tokenUrl, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    // Grava na planilha (não aguarda na resposta do usuário)
    appendToSheet({
      user_id: data.user_id,
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
    }).catch(e => console.error("Falha ao escrever na planilha:", e?.response?.data || e));

    // Mostra algo amigável para o cliente
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`
      <h2>Autorização concluída ✅</h2>
      <p>Tokens recebidos e salvos. Você já pode fechar esta janela.</p>
    `);
  } catch (err) {
    console.error(err?.response?.data || err.message);
    res.status(500).send("Falha ao trocar code por token.");
  }
});

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
