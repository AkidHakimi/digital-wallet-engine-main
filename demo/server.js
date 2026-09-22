import 'dotenv/config';
import express from 'express';
import {fileURLToPath} from 'url';
import {dirname, join} from 'path';

const app  = express();
const PORT = process.env.DEMO_PORT || 3004;

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.static(join(__dirname, 'public')));

app.get('/demo/config', (req, res) => {
  res.json({
    clientId:    process.env.DEFAULT_CLIENT_ID  || 'default-client',
    apiKey:      process.env.DEFAULT_API_KEY    || '',
    issuerUrl:   process.env.ISSUER_BASE_URL    || 'http://localhost:3001',
    holderUrl:   process.env.HOLDER_BASE_URL    || 'http://localhost:3002',
    verifierUrl: process.env.VERIFIER_BASE_URL  || 'http://localhost:3003',
    registryUrl: process.env.REGISTRY_BASE_URL  || 'http://localhost:3005',
    demoUrl:     process.env.DEMO_BASE_URL      || `http://localhost:${PORT}`,
  });
});

app.listen(PORT, () => console.log(`[Demo UI] running on http://localhost:${PORT}`));
