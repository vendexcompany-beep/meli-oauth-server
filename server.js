import express from "express";
import axios from "axios";
import crypto from "crypto";
import { google } from "googleapis";

const app = express();
const PORT = process.env.PORT || 3000;

// ======= Mercado Livre =======
const ML_CLIENT_ID = process.env.ML_CLIENT_ID;
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_PATH = process.env.REDIRECT_PATH || "/callback";

// ======= Google Sheets =======
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI; // ex: https://meli-oauth-server.onrender.com/google-callback
const SPREADSHEET_ID = process.env.SPREADSHEET_ID;

const oAuth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

const SHEET_NAME = "Tokens";

// PKCE para Mercado Livre
const verifierStore = new Map();
const b64url = buf => buf.toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const genVerifier = (len=64) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from({length: len}, () => chars[Math.floor(Math.random()*chars.length)]).join("");
};
const challengeS256 = v => b64url(crypto.createHash("sha256").update(v).digest());

// ====================
// ROTAS GOOGLE SHEETS
// ====================

// Página inicial só para teste
app.get("/", (_req, res) => {
  res.send(`
    <h2>Servidor ativo 🚀</h2>
    <p><a href="/google-auth">Autorizar Google Sheets</a></p>
    <p><a href="/start">Iniciar OAuth Mercado Livre</a></p>
  `);
});

// Passo 1 - Gerar URL de autorização do Google
app.get("/google-auth", (req, res) => {
  const scopes = ["https://www.googleapis.com/auth/spreadsheets"];
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes,
  });
  res.redirect(url);
});

// Passo 2 - Receber callback do Google
app.get("/google-callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Nenhum código recebido do Google.");

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    // Confirma que funcionou
    res.send(`<h3>✅ Google autorizado com sucesso!</h3>
              <p>Agora já posso escrever na planilha.</p>`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao obter tokens do Google.");
  }
});

// ========================
// ROTAS MERCADO LIVRE
// ========================
app.get("/start", (req, res) => {
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

app.get(REDIRECT_PATH, async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Faltou code/state");

    const code_verifier = verifierStore.get(state);
    verifierStore.delete(state);
    if (!code_verifier) return res.status(400).send("state inválido/expirado");

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

    // ==== Salvar tokens ML no Sheets ====
    try {
      const sheets = google.sheets({ version: "v4", auth: oAuth2Client });
      await sheets.spreadsheets.values.append({
        spreadsheetId: SPREADSHEET_ID,
        range: `${SHEET_NAME}!A:C`,
        valueInputOption: "RAW",
        requestBody: {
          values: [[new Date().toISOString(), data.access_token, data.refresh_token]]
        }
      });
      console.log("Tokens ML salvos no Google Sheets.");
    } catch (sheetErr) {
      console.error("Erro ao salvar na planilha:", sheetErr.message);
    }

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(err?.response?.data || err.message);
    res.status(500).send("Falha ao trocar code por token.");
  }
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
