import express from 'express';
import {SignJWT, jwtVerify, importJWK, decodeProtectedHeader} from 'jose';
import {v4 as uuidv4} from 'uuid';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import QRCode from 'qrcode';
import {requireScope} from '../shared/tenant-auth.js';
import {keypairToJWK, issueSDJWT} from '../shared/sd-jwt.js';
import {getIssuerKeys} from './keys.js';
import {documentLoader} from '../shared/document-loader.js';
import {assignStatusIndex} from '../shared/status-list.js';
import {auditLog} from '../shared/key-store.js';
import {getPool} from '../shared/db.js';
import {loadSchema, validateCredentialSubject} from '../shared/schema-validator.js';
import {credentialTypeFor} from '../shared/schema-registry.js';
import {resolveExpiration} from '../shared/expiry.js';

// ── In-memory state (POC — single process) ────────────────────────────────
const offers       = new Map(); // offerId  → { tenantId, employee, preAuthCode, format, disclosableClaims, expiresAt }
const preAuthCodes = new Map(); // preAuthCode → offerId  (reverse index)
const tokens       = new Map(); // accessToken → { tenantId, employee, cNonce, format, disclosableClaims, expiresAt }

const OFFER_TTL_MS = 10 * 60 * 1000;
const TOKEN_TTL_MS =  5 * 60 * 1000;

function buildContext() {
  return {'@vocab': 'https://example.org/vocab#'};
}

function baseUrl(req) {
  return process.env.ISSUER_BASE_URL || `${req.protocol}://${req.get('host')}`;
}

// ── GET /.well-known/openid-credential-issuer ─────────────────────────────
async function handleMetadata(req, res) {
  const base = baseUrl(req);
  res.json({
    credential_issuer: base,
    credential_endpoint: `${base}/oid4vci/credential`,
    token_endpoint: `${base}/oid4vci/token`,
    credential_configurations_supported: {
      EmployeeBadgeCredential: {
        format: 'ldp_vc',
        scope: 'EmployeeBadgeCredential',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['EdDSA'],
        proof_types_supported: {
          jwt: {proof_signing_alg_values_supported: ['EdDSA']}
        },
        display: [{name: 'Employee Badge', locale: 'en-US'}],
        credential_definition: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'EmployeeBadgeCredential']
        }
      },
      EmployeeBadgeCredentialSdJwt: {
        format: 'vc+sd-jwt',
        scope: 'EmployeeBadgeCredential',
        vct: 'EmployeeBadgeCredential',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['EdDSA'],
        proof_types_supported: {
          jwt: {proof_signing_alg_values_supported: ['EdDSA']}
        },
        display: [{name: 'Employee Badge (SD-JWT)', locale: 'en-US'}],
        claims: {
          name:        {display: [{name: 'Full Name',     locale: 'en-US'}]},
          department:  {display: [{name: 'Department',    locale: 'en-US'}]},
          position:    {display: [{name: 'Job Title',     locale: 'en-US'}]},
          startDate:   {display: [{name: 'Start Date',    locale: 'en-US'}]},
          accessLevel: {display: [{name: 'Access Level',  locale: 'en-US'}]}
        }
      }
    }
  });
}

// ── POST /oid4vci/offer  (auth: issuer scope) ─────────────────────────────
async function handleCreateOffer(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {
      format = 'ldp_vc', disclosableClaims = [], schemaSlug = null, schemaVersion = null,
      credentialType: requestedCredentialType = null, offerTtlMs = OFFER_TTL_MS, issuerDid = null,
      expiresInDays = null, expirationDate = null
    } = req.body;
    const subject = req.body.subject || req.body.employee;

    if (!subject || !Object.keys(subject).length) {
      return res.status(400).json({error: 'subject data is required'});
    }
    if (!['ldp_vc', 'vc+sd-jwt'].includes(format)) {
      return res.status(400).json({error: 'format must be ldp_vc or vc+sd-jwt'});
    }

    // Schema validation + credential type must tally with the schema
    let credentialType = requestedCredentialType;
    if (schemaSlug) {
      const schemaRow = await loadSchema(tenantId, schemaSlug, schemaVersion);
      const {valid, errors} = validateCredentialSubject(schemaRow, subject);
      if (!valid) return res.status(400).json({error: 'Schema validation failed', errors});

      const expectedType = credentialTypeFor(schemaRow.slug, schemaRow.schema_json);
      if (credentialType && credentialType !== expectedType) {
        return res.status(400).json({
          error:   'credential_type_schema_mismatch',
          details: `Schema "${schemaRow.slug}" defines credential type "${expectedType}", not "${credentialType}"`,
          expectedCredentialType: expectedType
        });
      }
      credentialType = expectedType;
    }

    // Fail fast on a bad expiry so the caller doesn't get a valid-looking
    // offer that fails later at credential issuance.
    try {
      resolveExpiration({expiresInDays, expirationDate});
    } catch (err) {
      return res.status(400).json({error: err.message});
    }

    // Fail fast if the caller picked a specific issuer DID that doesn't exist
    if (issuerDid) await getIssuerKeys(tenantId, issuerDid);

    const offerId     = uuidv4();
    const preAuthCode = uuidv4();

    // holderDid is intentionally absent — the holder proves their DID via the
    // binding proof JWT in the credential request (OID4VCI §7.2.1)
    offers.set(offerId, {
      tenantId, subject, preAuthCode, format, disclosableClaims, schemaSlug, credentialType, issuerDid,
      expiresInDays, expirationDate,
      expiresAt: Date.now() + offerTtlMs
    });
    preAuthCodes.set(preAuthCode, offerId);

    const offerUri           = `${baseUrl(req)}/oid4vci/offer/${offerId}`;
    const credentialOfferUri = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
    const qrcode             = await QRCode.toString(credentialOfferUri, {type: 'svg', width: 300});

    console.log(`[Issuer OID4VCI] Created offer ${offerId} (holderDid resolved at credential request)`);
    res.status(201).json({offerId, offerUri, credentialOfferUri, qrcode});
  } catch (err) {
    console.error('[Issuer OID4VCI] Create offer error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── GET /oid4vci/offer/:id  (public) ─────────────────────────────────────
async function handleGetOffer(req, res) {
  const entry = offers.get(req.params.id);
  if (!entry) return res.status(404).json({error: 'Offer not found'});
  if (entry.expiresAt <= Date.now()) return res.status(410).json({error: 'Offer expired'});

  res.json({
    credential_issuer: baseUrl(req),
    credential_configuration_ids: ['EmployeeBadgeCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': entry.preAuthCode,
        user_pin_required: false
      }
    }
  });
}

// ── POST /oid4vci/token  (public, urlencoded) ─────────────────────────────
async function handleToken(req, res) {
  try {
    const grantType   = req.body?.grant_type;
    const preAuthCode = req.body?.['pre-authorized_code'];

    if (grantType !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      return res.status(400).json({error: 'unsupported_grant_type'});
    }
    if (!preAuthCode) {
      return res.status(400).json({error: 'invalid_request', error_description: 'pre-authorized_code required'});
    }

    const offerId = preAuthCodes.get(preAuthCode);
    if (!offerId) return res.status(400).json({error: 'invalid_grant'});

    const entry = offers.get(offerId);
    if (!entry) return res.status(400).json({error: 'invalid_grant'});
    if (entry.expiresAt <= Date.now()) {
      offers.delete(offerId);
      preAuthCodes.delete(preAuthCode);
      return res.status(400).json({error: 'invalid_grant', error_description: 'Offer expired'});
    }

    // Single-use: remove offer
    offers.delete(offerId);
    preAuthCodes.delete(preAuthCode);

    const accessToken = uuidv4();
    const cNonce      = uuidv4();

    tokens.set(accessToken, {
      tenantId:          entry.tenantId,
      subject:           entry.subject,
      credentialType:    entry.credentialType,
      format:            entry.format,
      disclosableClaims: entry.disclosableClaims,
      issuerDid:         entry.issuerDid,
      expiresInDays:     entry.expiresInDays,
      expirationDate:    entry.expirationDate,
      cNonce,
      expiresAt: Date.now() + TOKEN_TTL_MS
    });

    console.log(`[Issuer OID4VCI] Issued token for offer ${offerId}`);
    res.json({
      access_token:        accessToken,
      token_type:          'Bearer',
      expires_in:          300,
      c_nonce:             cNonce,
      c_nonce_expires_in:  300
    });
  } catch (err) {
    console.error('[Issuer OID4VCI] Token error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── POST /oid4vci/credential  (Bearer token) ─────────────────────────────
async function handleCredential(req, res) {
  try {
    // Extract Bearer token
    const authHeader  = req.headers.authorization ?? '';
    const accessToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!accessToken) return res.status(401).json({error: 'invalid_token'});

    const tokenEntry = tokens.get(accessToken);
    if (!tokenEntry) return res.status(401).json({error: 'invalid_token'});
    if (tokenEntry.expiresAt <= Date.now()) {
      tokens.delete(accessToken);
      return res.status(401).json({error: 'invalid_token', error_description: 'Token expired'});
    }

    // Validate format + proof
    const requestedFormat = req.body?.format;
    if (!['ldp_vc', 'vc+sd-jwt'].includes(requestedFormat)) {
      return res.status(400).json({error: 'unsupported_credential_format'});
    }
    if (requestedFormat !== tokenEntry.format) {
      return res.status(400).json({
        error: 'unsupported_credential_format',
        error_description: `Offer was for ${tokenEntry.format}, not ${requestedFormat}`
      });
    }
    if (req.body?.proof?.proof_type !== 'jwt') {
      return res.status(400).json({error: 'invalid_proof', error_description: 'proof_type must be jwt'});
    }

    // Verify proof JWT  (holder embeds public key in header.jwk)
    const proofJwt = req.body.proof.jwt;
    let proofPayload;
    try {
      const header    = decodeProtectedHeader(proofJwt);
      if (!header.jwk) throw new Error('Missing jwk in proof header');
      const publicKey = await importJWK(header.jwk, 'EdDSA');
      const {payload} = await jwtVerify(proofJwt, publicKey, {
        audience:   baseUrl(req),
        algorithms: ['EdDSA']
      });
      proofPayload = payload;
    } catch (err) {
      return res.status(400).json({error: 'invalid_proof', error_description: err.message});
    }

    if (tokenEntry.cNonce && proofPayload.nonce !== tokenEntry.cNonce) {
      return res.status(400).json({error: 'invalid_proof', error_description: 'Nonce mismatch'});
    }

    // Extract holder DID from the proof JWT — this is how the issuer learns who
    // the credential should be bound to (OID4VCI §7.2.1)
    const holderDid = proofPayload.iss;
    if (!holderDid) {
      return res.status(400).json({error: 'invalid_proof', error_description: 'Missing iss claim in proof JWT'});
    }

    // Single-use: remove token
    tokens.delete(accessToken);

    const {tenantId, subject, credentialType, format: credFormat, disclosableClaims} = tokenEntry;
    const {did: issuerDid, assertionKey, identityId} = await getIssuerKeys(tenantId, tokenEntry.issuerDid);
    const expiration = resolveExpiration({expiresInDays: tokenEntry.expiresInDays, expirationDate: tokenEntry.expirationDate});

    // ── SD-JWT path ───────────────────────────────────────────────────────
    if (credFormat === 'vc+sd-jwt') {
      const {statusListId, statusListIndex} =
        await assignStatusIndex(tenantId, identityId, issuerDid, baseUrl(req));
      const sdJwt = await issueSDJWT({
        claims:          subject,
        holderDid,
        assertionKey,
        disclosableClaims,
        credentialType,
        expirationDate:  expiration
      });
      const credentialId = `${baseUrl(req)}/credentials/${uuidv4()}`;
      const pool         = getPool();
      await pool.query(
        `INSERT INTO credentials
          (credential_id, credential, issuer_did, subject_did, issuance_date, expiration_date,
           tenant_id, signing_key_did, credential_format, sd_jwt,
           status_list_id, status_list_index)
         VALUES (?, ?, ?, ?, NOW(), ?, ?, ?, 'sd-jwt', ?, ?, ?)`,
        [credentialId, '{}', issuerDid, holderDid, expiration, tenantId, assertionKey.id, sdJwt,
         statusListId, statusListIndex]
      );
      await auditLog('SIGN_VC', {tenantId, identityId, did: issuerDid, actor: 'oid4vci', credentialId});
      console.log(`[Issuer OID4VCI] Issued SD-JWT ${credentialId}`);
      return res.json({format: 'vc+sd-jwt', credential: sdJwt});
    }

    // ── VC-LD path ────────────────────────────────────────────────────────
    const {statusListId, statusListIndex, statusListVcUrl} =
      await assignStatusIndex(tenantId, identityId, issuerDid, baseUrl(req));

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

    const suite              = new Ed25519Signature2020({key: assertionKey});
    const verifiableCredential = await vc.issue({credential, suite, documentLoader});

    const pool      = getPool();
    const storageId = `vc-ld:${Date.now()}:${Math.random().toString(36).slice(2)}`;
    await pool.query(
      `INSERT INTO credentials
        (credential_id, credential, issuer_did, subject_did, issuance_date, expiration_date,
         tenant_id, signing_key_did, status_list_id, status_list_index)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        storageId,
        JSON.stringify(verifiableCredential),
        issuerDid, holderDid,
        new Date(credential.issuanceDate), new Date(credential.expirationDate),
        tenantId, assertionKey.id,
        statusListId, statusListIndex
      ]
    );

    await auditLog('SIGN_VC', {tenantId, identityId, did: issuerDid, actor: 'oid4vci', credentialId: credential.id});
    console.log(`[Issuer OID4VCI] Issued VC ${credential.id} via OID4VCI`);

    res.json({
      format:     'ldp_vc',
      credential: verifiableCredential,
      c_nonce:    uuidv4(),
      c_nonce_expires_in: 300
    });
  } catch (err) {
    console.error('[Issuer OID4VCI] Credential error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── Router factory ────────────────────────────────────────────────────────
export function createOid4vciRouter() {
  const router = express.Router();
  router.get('/.well-known/openid-credential-issuer', handleMetadata);
  router.post('/oid4vci/offer',      requireScope('issuer'), handleCreateOffer);
  router.get('/oid4vci/offer/:id',   handleGetOffer);
  router.post('/oid4vci/token',      handleToken);
  router.post('/oid4vci/credential', handleCredential);
  return router;
}
