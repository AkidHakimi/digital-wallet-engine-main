import 'dotenv/config';
import express from 'express';
import {fileURLToPath} from 'url';
import {dirname, join} from 'path';
import {requireScope} from '../shared/tenant-auth.js';
import {
  listDids, listSchemas, listRevocations,
  listAccreditations, createAccreditation, revokeAccreditation,
  verifyIssuer
} from './routes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const app  = express();
const PORT = process.env.REGISTRY_PORT || 3005;

app.use(express.json());
app.use(express.urlencoded({extended: false}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-client, x-api-key');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.static(join(__dirname, 'public')));

// ── Public endpoints ──────────────────────────────────────────────────────
app.get('/registry/dids',           listDids);
app.get('/registry/schemas',        listSchemas);
app.get('/registry/cred-revocations', listRevocations);
app.get('/registry/accreditations', listAccreditations);
app.get('/registry/verify',         verifyIssuer);

// ── Authenticated endpoints (registry scope) ──────────────────────────────
app.post('/registry/accreditations',        requireScope('registry'), createAccreditation);
app.delete('/registry/accreditations/:id',  requireScope('registry'), revokeAccreditation);

app.listen(PORT, () => console.log(`[Registry] running on http://localhost:${PORT}`));
