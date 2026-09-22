import 'dotenv/config';
import express from 'express';
import {requireScope} from '../shared/tenant-auth.js';
import {
  getDids, getDidDocument, getDidWebDocument, createDid,
  issueCredential, revokeCredential,
  getStatusList,
  getKeys, rotateKey, revokeKey, getAuditLog,
  registerSchema, getSchemaBySlug, listSchemas,
  delegateCapability
} from './routes.js';
import {createOid4vciRouter} from './oid4vci.js';

const app  = express();
const PORT = process.env.ISSUER_PORT || 3001;
app.use(express.json());
app.use(express.urlencoded({extended: false}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-client, x-api-key, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(createOid4vciRouter());

// ── Public endpoints (no auth) ────────────────────────────────────────────
app.get('/did/:did',                     getDidDocument);
app.get('/issuers/:domain/did.json',     getDidWebDocument);
app.get('/status/:listId',               getStatusList);
app.get('/schemas/:slug',                getSchemaBySlug);

// ── Authenticated endpoints (issuer scope) ────────────────────────────────
app.get('/dids',                         requireScope('issuer'), getDids);
app.post('/create',                      requireScope('issuer'), createDid);
app.post('/issue',                       requireScope('issuer'), issueCredential);
app.post('/credentials/revoke',          requireScope('issuer'), revokeCredential);

app.get('/keys',                         requireScope('issuer'), getKeys);
app.post('/keys/rotate',                 requireScope('issuer'), rotateKey);
app.post('/keys/revoke',                 requireScope('issuer'), revokeKey);
app.get('/keys/audit',                   requireScope('issuer'), getAuditLog);

app.post('/schemas',                     requireScope('issuer'), registerSchema);
app.get('/schemas',                      requireScope('issuer'), listSchemas);

app.post('/delegate',                    requireScope('issuer'), delegateCapability);

app.listen(PORT, () => console.log(`[Issuer] running on http://localhost:${PORT}`));
