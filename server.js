import express from "express";
import axios from "axios";

const app = express();
const PORT = process.env.PORT || 3000;

const ML_CLIENT_ID = process.env.ML_CLIENT_ID;
const ML_CLIENT_SECRET = process.env.ML_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL;
const REDIRECT_PATH = "/callback";

app.get("/", (_req, res) => {
  res.send("Servidor de OAuth Mercado Livre ativo!");
});

app.get(REDIRECT_PATH, async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send("Faltou o parâmetro code na URL");

    const tokenUrl = "https://api.mercadolibre.com/oauth/token";
    const redirect_uri = `${BASE_URL}${REDIRECT_PATH}`;

    const params = new URLSearchParams();
    params.append("grant_type", "authorization_code");
    params.append("client_id", ML_CLIENT_ID);
    params.append("client_secret", ML_CLIENT_SECRET);
    params.append("code", code);
    params.append("redirect_uri", redirect_uri);

    const { data } = await axios.post(tokenUrl, params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    res.json(data);
  } catch (err) {
    res.status(500).json(err.response?.data || { error: err.message });
  }
});

app.listen(PORT, () => console.log(`Rodando em http://localhost:${PORT}`));
