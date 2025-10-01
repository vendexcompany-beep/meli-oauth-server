// server.js  (Node 18+)
import express from "express";
import axios from "axios";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

const ML_CLIENT_ID = process.env.ML_CLIENT_ID;
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;           // ex.: https://meli-oauth-server.onrender.com
const REDIRECT_PATH = process.env.REDIRECT_PATH || "/callback";

// Armazena code_verifier por state (volátil em memória; suficiente para o fluxo)
const verifierStore = new Map();

// Helpers PKCE
const b64url = buf => buf.toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const genVerifier = (len=64) => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from({length: len}, () => chars[Math.floor(Math.random()*chars.length)]).join("");
};
const challengeS256 = v => b64url(crypto.createHash("sha256").update(v).digest());

app.get("/", (_req, res) => res.send("OK - ML OAuth PKCE server up"));

/** 1) Início do fluxo: gera code_challenge e redireciona para o ML */
app.get("/start", (req, res) => {
  const redirect_uri = `${BASE_URL}${REDIRECT_PATH}`;
  const state = crypto.randomBytes(16).toString("hex");
  const code_verifier = genVerifier();
  const code_challenge = challengeS256(code_verifier);

  // guarda temporariamente para usar no callback
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

/** 2) Callback: troca code -> tokens enviando o code_verifier */
app.get(REDIRECT_PATH, async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Faltou code/state");

    const code_verifier = verifierStore.get(state);
    verifierStore.delete(state);
    if (!code_verifier) return res.status(400).send("state inválido ou expirado");

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

    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(data, null, 2)); // << copie o refresh_token daqui
  } catch (err) {
    console.error(err?.response?.data || err.message);
    res.status(500).send("Falha ao trocar code por token (veja logs).");
  }
});

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
