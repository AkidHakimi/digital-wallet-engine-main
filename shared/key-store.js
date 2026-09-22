import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {getPool} from './db.js';
import {encryptPrivateKey, decryptPrivateKey} from './crypto-utils.js';
import {generateKeyForPurpose} from './did-utils.js';
import {getIdentityById} from './identity-store.js';

// ── In-process TTL cache ──────────────────────────────────────────────────
const _cache   = new Map();
const CACHE_TTL = 60_000; // 60 seconds

function cacheKey(identityId, purpose) { return `${identityId}:${purpose}`; }

function getCached(identityId, purpose) {
  const entry = _cache.get(cacheKey(identityId, purpose));
  if (!entry) return null;
  if (Date.now() - entry.cachedAt > CACHE_TTL) {
    _cache.delete(cacheKey(identityId, purpose));
    return null;
  }
  return entry;
}

function setCached(identityId, purpose, value) {
  _cache.set(cacheKey(identityId, purpose), {...value, cachedAt: Date.now()});
}

function evictCache(identityId, purpose) {
  _cache.delete(cacheKey(identityId, purpose));
}

// ── Helpers ───────────────────────────────────────────────────────────────

// For did:key the stored DID string is also the controller.
// For did:web the stored DID is 'did:web:domain' and key.id uses the fragment.
function buildKeyId(row) {
  if (row.key_fragment) {
    return `${row.did}#${row.key_fragment}`;
  }
  // did:key: fragment = the multibase key string (last component of DID)
  const multibase = row.did.split(':')[2];
  return `${row.did}#${multibase}`;
}

async function hydrateKeyPair(row) {
  const jwk     = decryptPrivateKey(row.enc_private_key, buildKeyId(row));
  const keyPair = await Ed25519Multikey.from(jwk);
  keyPair.id         = buildKeyId(row);
  keyPair.controller = row.did;
  return keyPair;
}

// ── Exports ───────────────────────────────────────────────────────────────

export async function saveKey({identityId, did, keyFragment = null, purpose, version = 1, didDocument, keyPair}) {
  const pool     = getPool();
  const keyId    = keyFragment ? `${did}#${keyFragment}` : buildKeyId({did, key_fragment: keyFragment});
  const exported = await keyPair.export({publicKey: true, secretKey: true});
  const enc      = encryptPrivateKey(exported, keyId);

  const publicKeyJwk = {
    type:             exported.type,
    publicKeyMultibase: exported.publicKeyMultibase
  };

  const [result] = await pool.query(
    `INSERT INTO did_keys
      (identity_id, did, key_fragment, purpose, key_version, did_document,
       enc_private_key, public_key_jwk, status, activated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW())`,
    [identityId, did, keyFragment, purpose, version,
     JSON.stringify(didDocument), enc, JSON.stringify(publicKeyJwk)]
  );
  evictCache(identityId, purpose);
  return result.insertId;
}

export async function loadActiveKey(identityId, purpose) {
  const cached = getCached(identityId, purpose);
  if (cached) return cached;

  const pool = getPool();
  const [rows] = await pool.query(
    `SELECT * FROM did_keys
     WHERE identity_id = ? AND purpose = ? AND status = 'active'
     ORDER BY key_version DESC LIMIT 1`,
    [identityId, purpose]
  );
  if (rows.length === 0) return null;

  const row     = rows[0];
  const keyPair = await hydrateKeyPair(row);
  const result  = {
    id:          row.id,
    did:         row.did,
    keyFragment: row.key_fragment,
    purpose:     row.purpose,
    version:     row.key_version,
    didDocument: JSON.parse(row.did_document),
    keyPair
  };
  setCached(identityId, purpose, result);
  return result;
}

export async function loadOrCreateKey(identityId, purpose, identityRow) {
  const isDidWeb = identityRow?.did_method === 'did:web' && identityRow?.domain;
  // did:key encodes one key in the DID itself — all purposes share it.
  // did:web gets a named fragment per purpose.
  const storagePurpose = isDidWeb ? purpose : 'assertionMethod';

  const existing = await loadActiveKey(identityId, storagePurpose);
  if (existing) return existing;

  const {did: keyDid, didDocument, keyPair} = await generateKeyForPurpose(storagePurpose);

  let storeDid    = keyDid;
  let keyFragment = null;
  let version     = 1;

  if (isDidWeb) {
    const domain  = identityRow.domain;
    storeDid      = `did:web:${domain}`;
    keyFragment   = `${purpose}-key-v${version}`;
    keyPair.id         = `${storeDid}#${keyFragment}`;
    keyPair.controller = storeDid;
  }

  const keyId = await saveKey({
    identityId, did: storeDid, keyFragment, purpose: storagePurpose, version,
    didDocument, keyPair
  });

  await auditLog('KEY_CREATED', {
    identityId, didKeyId: keyId,
    did: keyPair.controller, actor: 'system'
  });

  return loadActiveKey(identityId, storagePurpose);
}

export async function loadKeyByDid(did) {
  const pool = getPool();
  const base  = did.split('#')[0];
  const frag  = did.includes('#') ? did.split('#')[1] : null;

  let rows;
  if (frag) {
    [rows] = await pool.query(
      'SELECT * FROM did_keys WHERE did = ? AND key_fragment = ? LIMIT 1',
      [base, frag]
    );
    if (rows.length === 0) {
      // did:key — fragment matches the DID's multibase component
      [rows] = await pool.query('SELECT * FROM did_keys WHERE did = ? LIMIT 1', [base]);
    }
  } else {
    [rows] = await pool.query('SELECT * FROM did_keys WHERE did = ? LIMIT 1', [base]);
  }

  if (rows.length === 0) return null;
  const row     = rows[0];
  const keyPair = await hydrateKeyPair(row);
  return {
    id:         row.id,
    did:        row.did,
    keyFragment: row.key_fragment,
    purpose:    row.purpose,
    status:     row.status,
    revokedAt:  row.revoked_at,
    keyPair
  };
}

export async function listKeys(identityId) {
  const pool = getPool();
  const [rows] = await pool.query(
    `SELECT id, did, key_fragment, purpose, key_version, status,
            activated_at, expires_at, revoked_at, created_at
     FROM did_keys WHERE identity_id = ? ORDER BY purpose, key_version ASC`,
    [identityId]
  );
  return rows.map(r => ({
    id:          r.id,
    did:         r.did,
    keyId:       r.key_fragment ? `${r.did}#${r.key_fragment}` : `${r.did}#${r.did.split(':')[2]}`,
    purpose:     r.purpose,
    version:     r.key_version,
    status:      r.status,
    activatedAt: r.activated_at,
    expiresAt:   r.expires_at,
    revokedAt:   r.revoked_at,
    createdAt:   r.created_at
  }));
}

export async function rotateKey(identityId, purpose) {
  const pool     = getPool();
  const identity = await getIdentityById(identityId);

  // Get current active key version
  const [existing] = await pool.query(
    "SELECT id, key_version FROM did_keys WHERE identity_id = ? AND purpose = ? AND status = 'active' ORDER BY key_version DESC LIMIT 1",
    [identityId, purpose]
  );

  const newVersion = (existing[0]?.key_version ?? 0) + 1;
  const oldKeyId   = existing[0]?.id ?? null;

  const {did: keyDid, didDocument, keyPair} = await generateKeyForPurpose(purpose);

  let storeDid    = keyDid;
  let keyFragment = null;

  if (identity?.did_method === 'did:web' && identity?.domain) {
    storeDid    = `did:web:${identity.domain}`;
    keyFragment = `${purpose}-key-v${newVersion}`;
    keyPair.id         = `${storeDid}#${keyFragment}`;
    keyPair.controller = storeDid;
  }

  const newKeyId = await saveKey({
    identityId, did: storeDid, keyFragment, purpose,
    version: newVersion, didDocument, keyPair
  });

  if (oldKeyId) {
    await pool.query(
      "UPDATE did_keys SET status = 'inactive' WHERE id = ?",
      [oldKeyId]
    );
  }

  evictCache(identityId, purpose);

  await auditLog('KEY_ROTATED', {
    identityId, didKeyId: newKeyId,
    did: keyPair.controller, actor: 'api',
    meta: {oldKeyId, newVersion}
  });

  return {newKeyId, oldKeyId, did: storeDid, keyFragment, version: newVersion};
}

export async function revokeKey(keyId) {
  const pool = getPool();
  const [rows] = await pool.query('SELECT * FROM did_keys WHERE id = ?', [keyId]);
  if (rows.length === 0) throw new Error(`Key not found: ${keyId}`);

  const row = rows[0];
  await pool.query(
    "UPDATE did_keys SET status = 'revoked', revoked_at = NOW() WHERE id = ?",
    [keyId]
  );
  evictCache(row.identity_id, row.purpose);

  await auditLog('KEY_REVOKED', {
    identityId: row.identity_id, didKeyId: keyId,
    did: row.did, actor: 'api'
  });
}

export async function auditLog(eventType, {tenantId = null, identityId = null, didKeyId = null, did = null, actor = null, credentialId = null, meta = null} = {}) {
  try {
    const pool = getPool();
    await pool.query(
      `INSERT INTO key_audit_log
        (tenant_id, event_type, identity_id, did_key_id, did, actor, credential_id, meta)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [tenantId, eventType, identityId, didKeyId, did, actor, credentialId,
       meta ? JSON.stringify(meta) : null]
    );
  } catch {
    // Audit log failures must never crash the main flow
  }
}
