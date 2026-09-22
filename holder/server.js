import 'dotenv/config';
import express from 'express';
import {requireScope} from '../shared/tenant-auth.js';
import {getDids, createDid, receiveCredential, listCredentials, getCredential, createPresentation, getKeys, rotateKey} from './routes.js';
import {createOid4vciClientRouter} from './oid4vci.js';
import {createOid4vpClientRouter} from './oid4vp.js';

const app  = express();
const PORT = process.env.HOLDER_PORT || 3002;
app.use(express.json());
app.use(express.urlencoded({extended: false}));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-client, x-api-key, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/dids',          requireScope('holder'), getDids);
app.post('/create',       requireScope('holder'), createDid);

app.post('/credentials',       requireScope('holder'), receiveCredential);
app.get('/credentials',        requireScope('holder'), listCredentials);
app.get('/credentials/:id',    requireScope('holder'), getCredential);
app.post('/present',      requireScope('holder'), createPresentation);
app.get('/keys',          requireScope('holder'), getKeys);
app.post('/keys/rotate',  requireScope('holder'), rotateKey);

app.use(createOid4vciClientRouter());
app.use(createOid4vpClientRouter());

app.listen(PORT, () => console.log(`[Holder] running on http://localhost:${PORT}`));
