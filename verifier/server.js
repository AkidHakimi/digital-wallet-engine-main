import 'dotenv/config';
import express from 'express';
import {requireScope} from '../shared/tenant-auth.js';
import {getDids, createDid, issueChallenge, verifyPresentation} from './routes.js';
import {createOid4vpRouter} from './oid4vp.js';

const app  = express();
const PORT = process.env.VERIFIER_PORT || 3003;
app.use(express.json());
app.use(express.urlencoded({extended: false}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-client, x-api-key, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(createOid4vpRouter());

app.get('/dids',       requireScope('verifier'), getDids);
app.post('/create',    requireScope('verifier'), createDid);

app.post('/challenge', requireScope('verifier'), issueChallenge);
app.post('/verify',    requireScope('verifier'), verifyPresentation);

app.listen(PORT, () => console.log(`[Verifier] running on http://localhost:${PORT}`));
