import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {v4 as uuidv4} from 'uuid';
import {requireScope} from '../shared/tenant-auth.js';
import {documentLoader} from '../shared/document-loader.js';
import {getPool} from '../shared/db.js';
import {
  getIssuerKeys, createIssuerDid, getAllIssuerDids,
  getIssuerDidWebDocument, rotateIssuerKey, revokeIssuerKey, listIssuerKeys
} from './keys.js';
import {assignStatusIndex, revokeCredentialStatus, getStatusListVc} from '../shared/status-list.js';
import {loadSchema, validateCredentialSubject, saveSchema} from '../shared/schema-validator.js';
import {issueSDJWT} from '../shared/sd-jwt.js';
import {auditLog} from '../shared/key-store.js';
import {resolveExpiration} from '../shared/expiry.js';

function buildContext() {
  return {'@vocab': 'https://example.org/vocab#'};
}

function baseUrl(req) {
  return process.env.ISSUER_BASE_URL || `${req.protocol}://${req.get('host')}`;
}

// ── DID endpoints ─────────────────────────────────────────────────────────

export async function getDids(req, res) {
  try {
    const tenantId = req.tenant?.id ?? parseInt(process.env.DEFAULT_TENANT_ID || '1');
    const dids     = await getAllIssuerDids(tenantId);
    res.json({dids});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function getDidDocument(req, res) {
  try {
    const {did} = req.params;
    const pool   = getPool();
    const [rows] = await pool.query(
      "SELECT i.id, i.domain, i.did_method FROM identity i WHERE i.did = ? LIMIT 1",
      [did]
    );
    if (rows.length === 0) return res.status(404).json({error: 'DID not found'});

    if (rows[0].did_method === 'did:web') {
      const doc = await getIssuerDidWebDocument(rows[0].domain);
      return res.json(doc);
    }

    // did:key — resolve from key store
    const [keyRows] = await pool.query(
      "SELECT did_document FROM did_keys WHERE identity_id = ? AND status = 'active' LIMIT 1",
      [rows[0].id]
    );
    if (keyRows.length === 0) return res.status(404).json({error: 'No active keys for DID'});
    res.json(JSON.parse(keyRows[0].did_document));
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// GET /issuers/:domain/did.json  — public did:web DID document endpoint
export async function getDidWebDocument(req, res) {
  try {
    const doc = await getIssuerDidWebDocument(req.params.domain);
    if (!doc) return res.status(404).json({error: 'did:web identity not found for domain'});
    res.setHeader('Content-Type', 'application/did+ld+json');
    res.json(doc);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// POST /create
export async function createDid(req, res) {
  try {
    const tenantId  = req.tenant.id;
    const name      = req.body?.name?.trim();
    const domain    = req.body?.domain?.trim() || null;
    const didMethod = req.body?.didMethod === 'did:web' ? 'did:web' : 'did:key';

    if (!name) return res.status(400).json({error: 'name is required'});
    if (didMethod === 'did:web' && !domain) {
      return res.status(400).json({error: 'domain is required for did:web identities'});
    }

    const result = await createIssuerDid(tenantId, name, {domain, didMethod});
    res.status(201).json(result);
  } catch (err) {
    console.error('[Issuer] Create DID error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── Credential issuance ───────────────────────────────────────────────────

export async function issueCredential(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {
      holderDid, issuerDid: requestedIssuerDid = null, format = 'vc-ld', disclosableClaims = [],
      schemaSlug = null, schemaVersion = null, credentialType = null,
      expiresInDays = null, expirationDate: requestedExpirationDate = null
    } = req.body;
    const subject = req.body.subject || req.body.employee;

    if (!holderDid || !subject || !Object.keys(subject).length) {
      return res.status(400).json({error: 'holderDid and subject data are required'});
    }

    let expiration;
    try {
      expiration = resolveExpiration({expiresInDays, expirationDate: requestedExpirationDate});
    } catch (err) {
      return res.status(400).json({error: err.message});
    }

    const {did: issuerDid, assertionKey, identityId: resolvedIdentityId} = await getIssuerKeys(tenantId, requestedIssuerDid);

    // Schema validation
    let credentialSchemaField = undefined;
    if (schemaSlug) {
      const schemaRow = await loadSchema(tenantId, schemaSlug, schemaVersion);
      const {valid, errors} = validateCredentialSubject(schemaRow, subject);
      if (!valid) return res.status(400).json({error: 'Schema validation failed', errors});
      credentialSchemaField = {id: schemaRow.schema_id, type: 'JsonSchema'};
    }

    // SD-JWT path
    if (format === 'sd-jwt') {
      const {statusListId, statusListIndex, statusListVcUrl} =
        await assignStatusIndex(tenantId, resolvedIdentityId, issuerDid, baseUrl(req));
      const sdJwt = await issueSDJWT({
        claims:           subject,
        holderDid,
        assertionKey,
        disclosableClaims,
        credentialSchema: credentialSchemaField ?? null,
        expirationDate:   expiration,
      });
      const credentialId = `${baseUrl(req)}/credentials/${uuidv4()}`;
      const pool         = getPool();
      await pool.query(
        `INSERT INTO credentials
          (credential_id, credential, issuer_did, subject_did, issuance_date, expiration_date,
           tenant_id, signing_key_did, credential_format, sd_jwt, schema_id,
           status_list_id, status_list_index)
         VALUES (?, ?, ?, ?, NOW(), ?, ?, ?, 'sd-jwt', ?, ?, ?, ?)`,
        [credentialId, '{}', issuerDid, holderDid, expiration, tenantId,
         assertionKey.id, sdJwt, credentialSchemaField?.id ?? null,
         statusListId, statusListIndex]
      );
      await auditLog('SIGN_VC', {tenantId, identityId: resolvedIdentityId, did: issuerDid, actor: req.apiClient, credentialId});
      return res.json({credentialId, sdJwt, format: 'sd-jwt'});
    }

    // VC-LD path
    const {statusListId, statusListIndex, statusListVcUrl} =
      await assignStatusIndex(tenantId, resolvedIdentityId, issuerDid, baseUrl(req));

    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/vc/status-list/2021/v1',
        buildContext()
      ],
      id:             `${baseUrl(req)}/credentials/${uuidv4()}`,
      type:           ['VerifiableCredential', ...(credentialType ? [credentialType] : [])],
      issuer:         issuerDid,
      issuanceDate:   new Date().toISOString(),
      expirationDate: expiration.toISOString(),
      credentialStatus: {
        id:                   `${statusListVcUrl}#${statusListIndex}`,
        type:                 'StatusList2021Entry',
        statusPurpose:        'revocation',
        statusListIndex:      String(statusListIndex),
        statusListCredential: statusListVcUrl
      },
      credentialSubject: {
        id: holderDid,
        ...Object.fromEntries(Object.entries(subject).filter(([k]) => k !== 'id'))
      }
    };

    if (credentialSchemaField) credential.credentialSchema = credentialSchemaField;

    const suite              = new Ed25519Signature2020({key: assertionKey});
    const verifiableCredential = await vc.issue({credential, suite, documentLoader});

    const pool       = getPool();
    const storageId  = `vc-ld:${Date.now()}:${Math.random().toString(36).slice(2)}`;
    await pool.query(
      `INSERT INTO credentials
        (credential_id, credential, issuer_did, subject_did, issuance_date, expiration_date,
         tenant_id, signing_key_did, status_list_id, status_list_index, schema_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        storageId,
        JSON.stringify(verifiableCredential),
        issuerDid, holderDid,
        new Date(credential.issuanceDate), new Date(credential.expirationDate),
        tenantId, assertionKey.id,
        statusListId, statusListIndex,
        credentialSchemaField?.id ?? null
      ]
    );

    await auditLog('SIGN_VC', {tenantId, identityId: resolvedIdentityId, did: issuerDid, actor: req.apiClient, credentialId: credential.id});
    console.log(`[Issuer] Issued VC ${verifiableCredential.id} to ${holderDid}`);
    res.json({verifiableCredential});
  } catch (err) {
    console.error('[Issuer] Issue error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── Credential revocation ─────────────────────────────────────────────────

export async function revokeCredential(req, res) {
  try {
    const tenantId     = req.tenant.id;
    const {credentialId} = req.body;
    if (!credentialId) return res.status(400).json({error: 'credentialId is required'});
    const pool         = getPool();
    // credentialId may be the wallet's opaque storage key, or the VC's own
    // embedded `id` (a dereferenceable URL) — the value users see and copy
    // from the Issue Credential result.
    const [rows]       = await pool.query(
      `SELECT * FROM credentials
       WHERE (credential_id = ? OR JSON_UNQUOTE(JSON_EXTRACT(credential, '$.id')) = ?)
         AND tenant_id = ?`,
      [credentialId, credentialId, tenantId]
    );
    if (rows.length === 0) return res.status(404).json({error: 'Credential not found'});

    const cred = rows[0];
    if (!cred.status_list_id) return res.status(400).json({error: 'Credential has no status list entry'});

    const {assertionKey, did: issuerDid} = await getIssuerKeys(tenantId);

    await revokeCredentialStatus(cred.status_list_id, cred.status_list_index, assertionKey, issuerDid);
    await pool.query('UPDATE credentials SET credential = JSON_SET(credential, "$.revoked", TRUE) WHERE credential_id = ?', [cred.credential_id]);

    res.json({revoked: true, credentialId});
  } catch (err) {
    console.error('[Issuer] Revoke error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── Status list endpoint (public) ─────────────────────────────────────────

export async function getStatusList(req, res) {
  try {
    const statusVc = await getStatusListVc(req.params.listId);
    if (!statusVc) return res.status(404).json({error: 'Status list not found'});
    res.json(statusVc);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// ── Key management endpoints ──────────────────────────────────────────────

export async function getKeys(req, res) {
  try {
    const keys = await listIssuerKeys(req.tenant.id);
    res.json({keys});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function rotateKey(req, res) {
  try {
    const {purpose} = req.body;
    const valid = ['assertionMethod','authentication','capabilityDelegation','capabilityInvocation'];
    if (!valid.includes(purpose)) return res.status(400).json({error: `purpose must be one of: ${valid.join(', ')}`});
    const result = await rotateIssuerKey(req.tenant.id, purpose);
    res.json(result);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function revokeKey(req, res) {
  try {
    const {keyId} = req.body;
    if (!keyId) return res.status(400).json({error: 'keyId is required'});
    await revokeIssuerKey(keyId);
    res.json({revoked: true, keyId});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function getAuditLog(req, res) {
  try {
    const pool      = getPool();
    const tenantId  = req.tenant.id;
    const limit     = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset    = parseInt(req.query.offset) || 0;
    const eventType = req.query.eventType || null;

    const params = [tenantId];
    let where    = 'WHERE tenant_id = ?';
    if (eventType) { where += ' AND event_type = ?'; params.push(eventType); }

    const [rows] = await pool.query(
      `SELECT * FROM key_audit_log ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    res.json({events: rows});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// ── Schema management endpoints ────────────────────────────────────────────

export async function registerSchema(req, res) {
  try {
    const tenantId   = req.tenant.id;
    const {slug, version = '1.0.0', schemaJson} = req.body;
    if (!slug || !schemaJson) return res.status(400).json({error: 'slug and schemaJson are required'});
    const schemaId = await saveSchema(tenantId, slug, version, schemaJson, baseUrl(req));
    res.status(201).json({schemaId, slug, version});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function getSchemaBySlug(req, res) {
  try {
    const pool  = getPool();
    const {version} = req.query;
    const query  = version
      ? 'SELECT schema_json FROM credential_schemas WHERE slug = ? AND version = ? ORDER BY created_at DESC LIMIT 1'
      : 'SELECT schema_json FROM credential_schemas WHERE slug = ? ORDER BY created_at DESC LIMIT 1';
    const params = version ? [req.params.slug, version] : [req.params.slug];
    const [rows] = await pool.query(query, params);
    if (rows.length === 0) return res.status(404).json({error: 'Schema not found'});
    res.json(typeof rows[0].schema_json === 'string' ? JSON.parse(rows[0].schema_json) : rows[0].schema_json);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function listSchemas(req, res) {
  try {
    const pool   = getPool();
    const [rows] = await pool.query(
      'SELECT id, slug, schema_id, version, created_at FROM credential_schemas WHERE tenant_id = ? ORDER BY slug ASC',
      [req.tenant.id]
    );
    res.json({schemas: rows});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// Stub delegation endpoint (Phase 2)
export async function delegateCapability(req, res) {
  res.status(501).json({error: 'Capability delegation not yet implemented (Phase 2)'});
}

// ── Route exporter ────────────────────────────────────────────────────────
export {requireScope};
