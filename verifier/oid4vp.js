import express from 'express';
import {SignJWT, decodeJwt} from 'jose';
import {v4 as uuidv4} from 'uuid';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import QRCode from 'qrcode';
import {requireScope} from '../shared/tenant-auth.js';
import {keypairToJWK, verifySDJWT} from '../shared/sd-jwt.js';
import {getVerifierKeys} from './keys.js';
import {documentLoader} from '../shared/document-loader.js';
import {decodeList, getBit} from '../shared/status-list.js';
import {auditLog} from '../shared/key-store.js';

const REGISTRY_URL = process.env.REGISTRY_BASE_URL || 'http://localhost:3005';

async function checkTrustRegistry(issuerDid, schemaSlug) {
  if (!issuerDid || !schemaSlug) return null;
  try {
    const res = await fetch(
      `${REGISTRY_URL}/registry/verify?issuerDid=${encodeURIComponent(issuerDid)}&schemaSlug=${encodeURIComponent(schemaSlug)}`
    );
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function schemaSlugFromUrl(url) {
  if (!url) return null;
  return url.split('/').pop() || null;
}

// ── In-memory state (POC — single process) ────────────────────────────────
const requestJwts = new Map(); // requestId → signedJwt:string
const requests    = new Map(); // state → { tenantId, verifierDid, nonce, requestId, used, expiresAt, presentationDefinition }
const results     = new Map(); // state → { status, verified?, holder?, credential?, error?, verifiedAt? }

const REQUEST_TTL_MS = 10 * 60 * 1000;

// ── Presentation Definition builder ──────────────────────────────────────
// Builds a DIF Presentation Exchange v1 presentation_definition from
// individual constraint params. Any param can be omitted.
function buildPresentationDefinition({
  id, credentialType, issuerDid, credentialFormat,
  requiredClaims = [], schemaUrl
} = {}) {
  const fields = [];

  if (credentialType) {
    fields.push({
      path:   ['$.type'],
      filter: {type: 'array', contains: {const: credentialType}}
    });
  }
  if (issuerDid) {
    // handles both plain-string issuer and {id: "..."} object issuer
    fields.push({
      path:   ['$.issuer', '$.issuer.id'],
      filter: {type: 'string', const: issuerDid}
    });
  }
  if (schemaUrl) {
    fields.push({
      path:   ['$.credentialSchema.id', '$.credentialSchema[0].id'],
      filter: {type: 'string', const: schemaUrl}
    });
  }
  for (const claim of requiredClaims) {
    // assert the claim exists in credentialSubject — no value constraint
    fields.push({path: [`$.credentialSubject.${claim}`]});
  }

  const descriptor = {
    id:      `${credentialType ?? 'credential'}-descriptor`,
    name:    credentialType ?? 'Credential',
    purpose: `Provide your ${credentialType ?? 'credential'}`,
    constraints: {fields}
  };

  if (credentialFormat === 'vc+sd-jwt') {
    descriptor.format = {'vc+sd-jwt': {alg: ['EdDSA']}};
    descriptor.constraints.limit_disclosure = 'required';
  } else if (credentialFormat === 'ldp_vc') {
    descriptor.format = {ldp_vc: {proof_type: ['Ed25519Signature2020']}};
  }

  return {
    id:      id ?? uuidv4(),
    name:    credentialType ? `${credentialType} Presentation` : 'Credential Presentation',
    purpose: credentialType ? `Verify ${credentialType}` : 'Credential verification',
    input_descriptors: [descriptor]
  };
}

// ── Post-verification constraint check ───────────────────────────────────
// Validates that the resolved credential satisfies every field constraint
// declared in the presentation_definition. Returns {satisfied, failures[]}.
function assertSatisfiesDefinition(credentialClaims, definition) {
  const failures = [];
  if (!definition?.input_descriptors?.length) return {satisfied: true, failures};

  for (const descriptor of definition.input_descriptors) {
    const fields = descriptor.constraints?.fields ?? [];

    for (const field of fields) {
      if (!field.filter) continue; // existence-only field (no filter = just must exist)

      // Resolve field value from first matching path
      const value = resolveFieldValue(credentialClaims, field.path);

      if (value === undefined) {
        failures.push(`Field not found: ${field.path.join(' | ')}`);
        continue;
      }

      const filter = field.filter;

      // type: array + contains: {const: X}
      if (filter.type === 'array' && filter.contains?.const !== undefined) {
        const arr = Array.isArray(value) ? value : [value];
        if (!arr.includes(filter.contains.const)) {
          failures.push(`$.type must contain "${filter.contains.const}", got: [${arr.join(', ')}]`);
        }
        continue;
      }

      // type: string + const: X
      if (filter.type === 'string' && filter.const !== undefined) {
        if (value !== filter.const) {
          failures.push(`Expected "${filter.const}", got "${value}" at ${field.path[0]}`);
        }
        continue;
      }
    }

    // Existence-only fields (no filter) — just check path resolves
    for (const field of fields) {
      if (field.filter) continue;
      const value = resolveFieldValue(credentialClaims, field.path);
      if (value === undefined) {
        failures.push(`Required claim not present: ${field.path.join(' | ')}`);
      }
    }

    // SD-JWT limit_disclosure enforcement
    if (descriptor.constraints?.limit_disclosure === 'required') {
      if (!credentialClaims._isSDJWT) {
        failures.push('Descriptor requires vc+sd-jwt format (limit_disclosure: required)');
      }
    }
  }

  return {satisfied: failures.length === 0, failures};
}

// Resolves the first matching JSON path from a simple set of dotted paths.
// Only handles flat paths like $.issuer, $.issuer.id, $.credentialSubject.name.
function resolveFieldValue(obj, paths) {
  for (const path of paths) {
    const parts = path.replace(/^\$\./, '').split('.');
    let val = obj;
    for (const part of parts) {
      if (val == null || typeof val !== 'object') { val = undefined; break; }
      val = val[part];
    }
    if (val !== undefined) return val;
  }
  return undefined;
}

function baseUrl(req) {
  return process.env.VERIFIER_BASE_URL || `${req.protocol}://${req.get('host')}`;
}

// ── GET /.well-known/openid-configuration ─────────────────────────────────
async function handleMetadata(req, res) {
  const base = baseUrl(req);
  res.json({
    issuer:                   base,
    authorization_endpoint:   `${base}/oid4vp/authorize`,
    response_types_supported: ['vp_token'],
    response_modes_supported: ['direct_post'],
    vp_formats_supported: {
      ldp_vp:      {proof_type: ['Ed25519Signature2020']},
      'vc+sd-jwt': {alg: ['EdDSA']}
    },
    request_object_signing_alg_values_supported: ['EdDSA'],
    presentation_definition_uri_supported:       false
  });
}

// ── POST /oid4vp/request  (auth: verifier scope) ──────────────────────────
// Body can supply:
//   A) presentationDefinition — full PD object (takes precedence)
//   B) credentialType, issuerDid, credentialFormat, requiredClaims, schemaUrl
//   C) empty — defaults to EmployeeBadgeCredential (backward-compat)
async function handleCreateRequest(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {did: verifierDid, authKey} = await getVerifierKeys(tenantId);
    const {privateKey} = await keypairToJWK(authKey);

    const {
      presentationDefinition,
      credentialType,
      issuerDid:       constraintIssuer,
      credentialFormat,
      requiredClaims,
      schemaUrl
    } = req.body ?? {};

    const definition = presentationDefinition ?? buildPresentationDefinition({
      credentialType,
      issuerDid:       constraintIssuer,
      credentialFormat,
      requiredClaims:  requiredClaims ?? [],
      schemaUrl
    });

    const requestId  = uuidv4();
    const nonce      = uuidv4();
    const state      = uuidv4();
    const responseUri = `${baseUrl(req)}/oid4vp/response`;
    const requestUri  = `${baseUrl(req)}/oid4vp/request/${requestId}`;

    const requestJwt = await new SignJWT({
      iss: verifierDid,
      aud: 'https://self-issued.me/v2',
      response_type: 'vp_token',
      response_mode: 'direct_post',
      response_uri:   responseUri,
      nonce,
      state,
      presentation_definition: definition
    })
      .setProtectedHeader({alg: 'EdDSA', typ: 'oauth-authz-req+jwt', kid: authKey.id})
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(privateKey);

    requestJwts.set(requestId, requestJwt);
    requests.set(state, {
      tenantId, verifierDid, nonce, requestId,
      used:                 false,
      expiresAt:            Date.now() + REQUEST_TTL_MS,
      presentationDefinition: definition
    });
    results.set(state, {status: 'pending'});

    const openid4vpUri = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(verifierDid)}`;
    const qrcode       = await QRCode.toString(openid4vpUri, {type: 'svg', width: 300});

    console.log(`[Verifier OID4VP] Created request ${requestId}, state ${state}`);
    res.status(201).json({requestId, state, requestUri, openid4vpUri, qrcode});
  } catch (err) {
    console.error('[Verifier OID4VP] Create request error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── GET /oid4vp/request/:id  (public — wallet fetches this) ───────────────
async function handleGetRequest(req, res) {
  const jwt = requestJwts.get(req.params.id);
  if (!jwt) return res.status(404).json({error: 'Request not found'});
  res.setHeader('Content-Type', 'application/oauth-authz-req+jwt');
  res.send(jwt);
}

// ── POST /oid4vp/response  (public — wallet direct_post) ─────────────────
async function handleResponse(req, res) {
  try {
    const {state, vp_token: vpTokenStr, presentation_submission: submissionStr} = req.body;

    if (!state || !vpTokenStr) {
      return res.status(400).json({error: 'invalid_request', error_description: 'state and vp_token are required'});
    }

    const reqEntry = requests.get(state);
    if (!reqEntry) {
      return res.status(400).json({error: 'invalid_request', error_description: 'Unknown state'});
    }
    if (reqEntry.expiresAt <= Date.now()) {
      return res.status(400).json({error: 'invalid_request', error_description: 'Request expired'});
    }
    if (reqEntry.used) {
      return res.status(400).json({error: 'invalid_request', error_description: 'Request already used'});
    }
    reqEntry.used = true;

    const definition = reqEntry.presentationDefinition;

    // ── Detect SD-JWT vs VC-LD VP ─────────────────────────────────────────
    const isSdJwt = vpTokenStr.includes('~') && !vpTokenStr.trimStart().startsWith('{');

    if (isSdJwt) {
      // ── SD-JWT path ─────────────────────────────────────────────────────
      const sdResult = await verifySDJWT(vpTokenStr);
      if (!sdResult.valid) {
        console.warn('[Verifier OID4VP] SD-JWT verification failed:', sdResult.error);
        results.set(state, {status: 'error', verified: false, error: sdResult.error});
        return res.status(400).json({error: 'vp_verification_failed', details: sdResult.error});
      }

      // Validate credential claims against presentation definition
      const claims = {
        ...sdResult.payload,
        type:              sdResult.payload?.vc?.type ?? [],
        issuer:            sdResult.issuer,
        credentialSubject: sdResult.disclosedClaims,
        _isSDJWT:          true
      };
      const {satisfied, failures} = assertSatisfiesDefinition(claims, definition);
      if (!satisfied) {
        console.warn('[Verifier OID4VP] SD-JWT constraint check failed:', failures);
        results.set(state, {status: 'error', verified: false, error: failures.join('; ')});
        return res.status(400).json({error: 'presentation_definition_not_satisfied', details: failures});
      }

      const sdSchemaSlug = schemaSlugFromUrl(sdResult.payload?.credentialSchema?.id);
      const sdTrust      = await checkTrustRegistry(sdResult.issuer, sdSchemaSlug);

      results.set(state, {
        status:          'complete',
        verified:        true,
        format:          'sd-jwt',
        issuer:          sdResult.issuer,
        holder:          sdResult.subject,
        disclosedClaims: sdResult.disclosedClaims,
        allClaims:       sdResult.payload,
        verifiedAt:      new Date().toISOString(),
        ...(sdTrust && !sdTrust.trusted && {
          trustWarning: `Issuer is not accredited in the trust registry for schema "${sdSchemaSlug}"`
        }),
        ...(sdTrust && {trustRegistry: sdTrust}),
      });
      await auditLog('VERIFY_VP', {tenantId: reqEntry.tenantId, did: sdResult.subject, actor: 'oid4vp-sdjwt'});
      console.log(`[Verifier OID4VP] Verified SD-JWT for state ${state}`);
      return res.json({redirect_uri: null});
    }

    // ── VC-LD VP path ────────────────────────────────────────────────────
    let verifiablePresentation;
    try {
      verifiablePresentation = JSON.parse(vpTokenStr);
    } catch {
      return res.status(400).json({error: 'invalid_vp_token', error_description: 'vp_token must be valid JSON'});
    }

    const suite  = new Ed25519Signature2020();
    const result = await vc.verify({
      presentation: verifiablePresentation,
      challenge:    reqEntry.nonce,
      domain:       'verifier.example.org',
      suite,
      documentLoader,
      checkStatus: async ({credential}) => {
        const status = credential?.credentialStatus;
        if (!status?.statusListCredential) return {verified: true};
        try {
          const listRes = await fetch(status.statusListCredential);
          if (!listRes.ok) return {verified: true};
          const listVc  = await listRes.json();
          const encoded = listVc?.credentialSubject?.encodedList;
          if (!encoded) return {verified: true};
          const buffer  = decodeList(encoded);
          const bit     = getBit(buffer, parseInt(status.statusListIndex));
          if (bit === 1) {
            return {verified: false, error: new Error('Credential has been revoked by issuer')};
          }
        } catch {
          // non-fatal — treat as unrevoked if status list unreachable
        }
        return {verified: true};
      }
    });

    if (!result.verified) {
      const errMsg = result.error?.message
        ?? result.credentialResults?.find(r => !r.verified)?.error?.message
        ?? JSON.stringify(result);
      console.warn('[Verifier OID4VP] VP verification failed:', errMsg);
      results.set(state, {status: 'error', verified: false, error: errMsg});
      return res.status(400).json({error: 'vp_verification_failed', details: errMsg});
    }

    const credential = verifiablePresentation.verifiableCredential?.[0];

    // Validate credential claims against presentation definition
    const credClaims = {
      type:              credential?.type,
      issuer:            credential?.issuer,
      credentialSchema:  credential?.credentialSchema,
      credentialSubject: credential?.credentialSubject
    };
    const {satisfied, failures} = assertSatisfiesDefinition(credClaims, definition);
    if (!satisfied) {
      console.warn('[Verifier OID4VP] VC-LD constraint check failed:', failures);
      results.set(state, {status: 'error', verified: false, error: failures.join('; ')});
      return res.status(400).json({error: 'presentation_definition_not_satisfied', details: failures});
    }

    const issuerDid  = typeof credential?.issuer === 'string' ? credential.issuer : credential?.issuer?.id;
    const schemaSlug = schemaSlugFromUrl(credential?.credentialSchema?.id);
    const trust      = await checkTrustRegistry(issuerDid, schemaSlug);

    results.set(state, {
      status:     'complete',
      verified:   true,
      format:     'ldp_vc',
      holder:     verifiablePresentation.holder,
      credential: {
        id:                credential?.id,
        type:              credential?.type,
        issuer:            credential?.issuer,
        issuanceDate:      credential?.issuanceDate,
        credentialSubject: credential?.credentialSubject
      },
      verifiedAt: new Date().toISOString(),
      ...(trust && !trust.trusted && {
        trustWarning: `Issuer is not accredited in the trust registry for schema "${schemaSlug}"`
      }),
      ...(trust && {trustRegistry: trust}),
    });

    await auditLog('VERIFY_VP', {tenantId: reqEntry.tenantId, did: verifiablePresentation.holder, actor: 'oid4vp-ldp'});
    console.log(`[Verifier OID4VP] Verified VC-LD VP for state ${state}`);

    res.json({redirect_uri: null});
  } catch (err) {
    console.error('[Verifier OID4VP] Response error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── GET /oid4vp/result/:state  (auth: verifier scope) ────────────────────
async function handleResult(req, res) {
  const result = results.get(req.params.state);
  if (!result) return res.status(404).json({error: 'Result not found'});
  res.json(result);
}

// ── Router factory ────────────────────────────────────────────────────────
export function createOid4vpRouter() {
  const router = express.Router();
  router.get('/.well-known/openid-configuration', handleMetadata);
  router.post('/oid4vp/request',      requireScope('verifier'), handleCreateRequest);
  router.get('/oid4vp/request/:id',   handleGetRequest);
  router.post('/oid4vp/response',     handleResponse);
  router.get('/oid4vp/result/:state', requireScope('verifier'), handleResult);
  return router;
}
