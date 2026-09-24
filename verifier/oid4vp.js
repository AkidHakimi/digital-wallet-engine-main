import express from 'express';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import {SignJWT, decodeJwt, importJWK, jwtVerify} from 'jose';
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

// ════════════════════════════════════════════════════════════════════════════
//  OID4VP verifier
//
//  A) Verifier-initiated  (verifier shows QR, wallet scans)
//       POST /oid4vp/request            create signed request + QR
//       GET  /oid4vp/request/:id        wallet fetches request object
//       POST /oid4vp/response           wallet direct_post (vp_token | error)
//       GET  /oid4vp/result/:state      poll result
//
//  B) Holder-initiated  (wallet shows QR, verifier scans)
//       POST /oid4vp/scan               {qr, ...same options as /oid4vp/request}
//         → creates the SAME signed request as (A), pushes it to the wallet's
//           share endpoint (Bearer share_token); the wallet answers via
//           POST /oid4vp/response, so verification is identical for A and B.
//       POST /oid4vp/receive            backward-compatible alias: if the body
//                                       carries a holder QR it delegates to /scan
// ════════════════════════════════════════════════════════════════════════════

const isProd       = process.env.NODE_ENV === 'production';
const envFlag      = (name, dflt) => (process.env[name] === undefined ? dflt : process.env[name] === 'true');
const REGISTRY_URL = process.env.REGISTRY_BASE_URL || 'http://localhost:3005';

const CONFIG = Object.freeze({
  verifierName:        process.env.VERIFIER_DISPLAY_NAME || 'Verifier',
  // OID4VP: LD-proof domain = client_id. Override only for legacy wallets.
  ldpExpectedDomain:   process.env.OID4VP_LDP_EXPECTED_DOMAIN || null,
  // Holder-bound SD-JWT (cnf) without KB-JWT: always rejected in the holder-initiated
  // flow; in the original verifier-initiated flow only when this is true (default off
  // so existing wallets keep working). A KB-JWT that IS present is always verified.
  requireKeyBinding:   envFlag('OID4VP_REQUIRE_KEY_BINDING', false),
  // Original LD-proof domain; accepted alongside client_id
  legacyLdpDomain:     'verifier.example.org',
  // Optional cleanup of old sessions (minutes). 0 = keep forever (original behaviour).
  sessionRetentionMin: Number(process.env.OID4VP_SESSION_RETENTION_MINUTES ?? 0),
  kbMaxAge:            process.env.OID4VP_KB_MAX_AGE || '5m',
  // Holder QR scanning (outbound call to the wallet)
  allowInsecureHttp:   envFlag('OID4VP_ALLOW_INSECURE_HTTP', !isProd),
  blockPrivateNetworks: envFlag('OID4VP_BLOCK_PRIVATE_NETWORKS', isProd),
  trustedWalletHosts:  (process.env.OID4VP_TRUSTED_WALLET_HOSTS ?? '').split(',').map(s => s.trim()).filter(Boolean),
  walletTimeoutMs:     Number(process.env.OID4VP_WALLET_TIMEOUT_MS ?? 15_000),
  holderQrScheme:      'openid4vp-share:'
});

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
                               //   (+ clientId, flow — added for the holder-initiated flow)
const results     = new Map(); // state → { status, verified?, holder?, credential?, error?, verifiedAt? }
                               //   (+ flow, walletStatus?, keyBinding? — added)

const REQUEST_TTL_MS = 10 * 60 * 1000;

// Optional: drop old sessions (off unless OID4VP_SESSION_RETENTION_MINUTES > 0)
if (CONFIG.sessionRetentionMin > 0) {
  setInterval(() => {
    const now = Date.now();
    for (const [state, entry] of requests) {
      if (entry.expiresAt + CONFIG.sessionRetentionMin * 60_000 < now) {
        requests.delete(state);
        requestJwts.delete(entry.requestId);
        results.delete(state);
      }
    }
  }, 60_000).unref();
}

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

// ════════════════════════════════════════════════════════════════════════════
//  SD-JWT Key Binding (KB-JWT) verification
//  vp_token = <issuer-jwt>~<disclosures>~<kb-jwt>
//  KB-JWT must be signed by the credential's cnf key and carry
//  {aud = our client_id, nonce = session nonce, sd_hash, iat}.
// ════════════════════════════════════════════════════════════════════════════
const b64url = data => Buffer.from(data).toString('base64url');
const sha256 = data => crypto.createHash('sha256').update(data).digest();

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(str) {
  const bytes = [];
  for (const ch of str) {
    let carry = B58.indexOf(ch);
    if (carry < 0) throw new Error('Invalid base58 character');
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  for (const ch of str) { if (ch === '1') bytes.push(0); else break; }
  return Uint8Array.from(bytes.reverse());
}

// did:key:z6Mk… → Ed25519 JWK
function didKeyToJwk(did) {
  const bytes = base58Decode(did.slice('did:key:z'.length));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error('Only Ed25519 did:key is supported');
  return {kty: 'OKP', crv: 'Ed25519', x: b64url(bytes.slice(2))};
}

function splitKeyBinding(vpToken) {
  const parts = vpToken.split('~');
  const last  = parts.at(-1);
  if (parts.length > 1 && last && last.split('.').length === 3) {
    return {sdJwt: `${parts.slice(0, -1).join('~')}~`, kbJwt: last};
  }
  return {sdJwt: vpToken, kbJwt: null};
}

function algForJwk(jwk) {
  if (jwk.alg) return jwk.alg;
  if (jwk.kty === 'OKP') return 'EdDSA';
  return {'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512'}[jwk.crv] ?? 'ES256';
}

async function verifyKeyBinding({sdJwt, kbJwt, nonce, audience, required = CONFIG.requireKeyBinding}) {
  const cnf = decodeJwt(sdJwt.split('~')[0]).cnf;
  if (!kbJwt) {
    if (cnf && required) {
      return {ok: false, error: 'Credential is holder-bound (cnf) but no KB-JWT was presented'};
    }
    return {ok: true, status: cnf ? 'absent' : 'not_bound'};
  }
  if (!cnf) return {ok: false, error: 'KB-JWT presented but credential has no cnf key'};

  let jwk = cnf.jwk;
  if (!jwk && typeof cnf.kid === 'string' && cnf.kid.startsWith('did:key:')) jwk = didKeyToJwk(cnf.kid.split('#')[0]);
  if (!jwk) return {ok: false, error: 'Unsupported cnf key type'};

  try {
    const key = await importJWK(jwk, algForJwk(jwk));
    const {payload} = await jwtVerify(kbJwt, key, {
      typ:            'kb+jwt',
      audience,
      maxTokenAge:    CONFIG.kbMaxAge,
      clockTolerance: 60
    });
    if (payload.nonce !== nonce) return {ok: false, error: 'KB-JWT nonce mismatch (possible replay)'};
    if (payload.sd_hash !== b64url(sha256(sdJwt))) return {ok: false, error: 'KB-JWT sd_hash does not match presented SD-JWT'};
    return {ok: true, status: 'verified'};
  } catch (err) {
    return {ok: false, error: `KB-JWT invalid: ${err.message}`};
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  Authorization request creation (shared by verifier-initiated & holder-initiated)
// ════════════════════════════════════════════════════════════════════════════
async function createAuthorizationRequest({tenantId, base, options = {}, flow = 'verifier-initiated'}) {
  const {did: verifierDid, authKey} = await getVerifierKeys(tenantId);
  const {privateKey} = await keypairToJWK(authKey);

  const {
    presentationDefinition,
    credentialType,
    issuerDid:       constraintIssuer,
    credentialFormat,
    requiredClaims,
    schemaUrl
  } = options;

  const definition = presentationDefinition ?? buildPresentationDefinition({
    credentialType,
    issuerDid:       constraintIssuer,
    credentialFormat,
    requiredClaims:  requiredClaims ?? [],
    schemaUrl
  });

  const requestId   = uuidv4();
  const nonce       = uuidv4();
  const state       = uuidv4();
  const clientId    = verifierDid;                     // client_id scheme: did
  const responseUri = `${base}/oid4vp/response`;
  const requestUri  = `${base}/oid4vp/request/${requestId}`;

  const requestJwt = await new SignJWT({
    iss:              verifierDid,
    aud:              'https://self-issued.me/v2',
    client_id:        clientId,
    client_id_scheme: 'did',
    client_metadata: {
      client_name: CONFIG.verifierName,
      vp_formats: {
        ldp_vp:      {proof_type: ['Ed25519Signature2020']},
        'vc+sd-jwt': {'sd-jwt_alg_values': ['EdDSA'], 'kb-jwt_alg_values': ['EdDSA', 'ES256']}
      }
    },
    response_type:  'vp_token',
    response_mode:  'direct_post',
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
    tenantId, verifierDid, clientId, nonce, requestId, flow,
    used:                   false,
    expiresAt:              Date.now() + REQUEST_TTL_MS,
    presentationDefinition: definition
  });
  results.set(state, {status: 'pending', flow});

  const openid4vpUri = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  return {requestId, state, nonce, requestUri, openid4vpUri, definition};
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
    client_id_schemes_supported:                 ['did'],
    request_object_signing_alg_values_supported: ['EdDSA'],
    presentation_definition_uri_supported:       false,
    holder_initiated_scan_endpoint:              `${base}/oid4vp/scan`
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
      // added: lets wallets authenticate this verifier (client_id scheme: did)
      client_id:        verifierDid,
      client_id_scheme: 'did',
      client_metadata:  {client_name: CONFIG.verifierName},
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
      clientId:             verifierDid,            // added
      flow:                 'verifier-initiated',   // added
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
  res.setHeader('Cache-Control', 'no-store');
  res.send(jwt);
}

// ── POST /oid4vp/response  (public — wallet direct_post) ─────────────────
async function handleResponse(req, res) {
  try {
    const {
      state,
      vp_token: vpTokenStr,
      presentation_submission: submissionStr,
      error:    walletError,
      error_description: walletErrorDescription
    } = req.body ?? {};

    // ── Wallet error response (holder declined / cancelled / timed out) ──
    if (walletError) {
      const entry = state && requests.get(state);
      if (!entry) return res.status(400).json({error: 'invalid_request', error_description: 'Unknown state'});
      if (entry.used) return res.status(400).json({error: 'invalid_request', error_description: 'Request already used'});
      entry.used = true;
      results.set(state, {
        status:           'error',
        flow:             entry.flow,
        verified:         false,
        error:            walletError,
        errorDescription: walletErrorDescription ?? null
      });
      await auditLog('VERIFY_VP_DECLINED', {tenantId: entry.tenantId, actor: 'oid4vp', error: walletError});
      console.log(`[Verifier OID4VP] Wallet returned ${walletError} for state ${state}`);
      return res.json({});
    }

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
    const flow       = reqEntry.flow;

    // ── Detect SD-JWT vs VC-LD VP ─────────────────────────────────────────
    const isSdJwt = vpTokenStr.includes('~') && !vpTokenStr.trimStart().startsWith('{');

    if (isSdJwt) {
      // ── SD-JWT path ─────────────────────────────────────────────────────
      const {sdJwt, kbJwt} = splitKeyBinding(vpTokenStr);
      const sdResult = await verifySDJWT(sdJwt);
      if (!sdResult.valid) {
        console.warn('[Verifier OID4VP] SD-JWT verification failed:', sdResult.error);
        results.set(state, {status: 'error', flow, verified: false, error: sdResult.error});
        return res.status(400).json({error: 'vp_verification_failed', details: sdResult.error});
      }

      // Holder binding + replay protection (nonce / audience / sd_hash)
      const kb = await verifyKeyBinding({
        sdJwt, kbJwt, nonce: reqEntry.nonce, audience: reqEntry.clientId,
        required: flow === 'holder-initiated' || CONFIG.requireKeyBinding
      });
      if (!kb.ok) {
        console.warn('[Verifier OID4VP] Key binding failed:', kb.error);
        results.set(state, {status: 'error', flow, verified: false, error: kb.error});
        return res.status(400).json({error: 'key_binding_failed', details: kb.error});
      }

      // Validate credential claims against presentation definition
      const claims = {
        ...sdResult.payload,
        type:              sdResult.payload?.vc?.type ?? (sdResult.payload?.vct ? [sdResult.payload.vct] : []),
        issuer:            sdResult.issuer,
        credentialSubject: sdResult.disclosedClaims,
        _isSDJWT:          true
      };
      const {satisfied, failures} = assertSatisfiesDefinition(claims, definition);
      if (!satisfied) {
        console.warn('[Verifier OID4VP] SD-JWT constraint check failed:', failures);
        results.set(state, {status: 'error', flow, verified: false, error: failures.join('; ')});
        return res.status(400).json({error: 'presentation_definition_not_satisfied', details: failures});
      }

      const sdSchemaSlug = schemaSlugFromUrl(sdResult.payload?.credentialSchema?.id);
      const sdTrust      = await checkTrustRegistry(sdResult.issuer, sdSchemaSlug);

      results.set(state, {
        status:          'complete',
        flow,
        verified:        true,
        format:          'sd-jwt',
        keyBinding:      kb.status,
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
      await auditLog('VERIFY_VP', {tenantId: reqEntry.tenantId, did: sdResult.subject, actor: 'oid4vp-sdjwt', flow});
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

    // domain: OID4VP uses client_id; original wallets used 'verifier.example.org' — accept either
    const proofDomain    = [].concat(verifiablePresentation?.proof ?? [])[0]?.domain;
    const acceptedDomains = CONFIG.ldpExpectedDomain
      ? [CONFIG.ldpExpectedDomain]
      : [reqEntry.clientId, CONFIG.legacyLdpDomain].filter(Boolean);
    const expectedDomain = acceptedDomains.includes(proofDomain) ? proofDomain : acceptedDomains[0];

    const suite  = new Ed25519Signature2020();
    const result = await vc.verify({
      presentation: verifiablePresentation,
      challenge:    reqEntry.nonce,
      domain:       expectedDomain,
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
      results.set(state, {status: 'error', flow, verified: false, error: errMsg});
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
      results.set(state, {status: 'error', flow, verified: false, error: failures.join('; ')});
      return res.status(400).json({error: 'presentation_definition_not_satisfied', details: failures});
    }

    const issuerDid  = typeof credential?.issuer === 'string' ? credential.issuer : credential?.issuer?.id;
    const schemaSlug = schemaSlugFromUrl(credential?.credentialSchema?.id);
    const trust      = await checkTrustRegistry(issuerDid, schemaSlug);

    results.set(state, {
      status:     'complete',
      flow,
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

    await auditLog('VERIFY_VP', {tenantId: reqEntry.tenantId, did: verifiablePresentation.holder, actor: 'oid4vp-ldp', flow});
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

// ════════════════════════════════════════════════════════════════════════════
//  B) Holder-initiated — verifier scans the wallet's QR
//
//  QR: openid4vp-share://share?v=1&share_uri=<https wallet url>&share_token=<secret>
// ════════════════════════════════════════════════════════════════════════════
class ScanError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}

function isHolderShareQr(text) {
  return typeof text === 'string' && text.trim().toLowerCase().startsWith(CONFIG.holderQrScheme);
}

function parseHolderShareQr(text) {
  let u;
  try { u = new URL(String(text ?? '').trim()); } catch {
    throw new ScanError('invalid_qr', 'QR content is not a URI');
  }
  if (u.protocol !== CONFIG.holderQrScheme) throw new ScanError('invalid_qr', `Unsupported QR scheme ${u.protocol}`);

  const version    = u.searchParams.get('v') ?? '1';
  const shareUri   = u.searchParams.get('share_uri');
  const shareToken = u.searchParams.get('share_token');
  if (version !== '1')          throw new ScanError('invalid_qr', `Unsupported share QR version ${version}`);
  if (!shareUri || !shareToken) throw new ScanError('invalid_qr', 'QR is missing share_uri or share_token');
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(shareToken)) throw new ScanError('invalid_qr', 'Malformed share_token');

  let su;
  try { su = new URL(shareUri); } catch { throw new ScanError('invalid_qr', 'share_uri is not a URL'); }
  if (su.protocol !== 'https:' && !(su.protocol === 'http:' && CONFIG.allowInsecureHttp)) {
    throw new ScanError('invalid_qr', 'share_uri must use https');
  }
  if (su.username || su.password) throw new ScanError('invalid_qr', 'share_uri must not contain credentials');
  if (!/\/oid4vp\/share\/[0-9a-f-]{36}\/?$/i.test(su.pathname)) throw new ScanError('invalid_qr', 'Unexpected share_uri path');
  if (CONFIG.trustedWalletHosts.length && !CONFIG.trustedWalletHosts.includes(su.host)) {
    throw new ScanError('untrusted_wallet', `Wallet ${su.host} is not trusted`, 403);
  }
  return {shareUri: su.toString().replace(/\/$/, ''), shareToken};
}

// SSRF guard: a scanned QR must not make the verifier call its own internal network
const privateRanges = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16], ['224.0.0.0', 4]]) {
  privateRanges.addSubnet(a, p, 'ipv4');
}
for (const [a, p] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]]) privateRanges.addSubnet(a, p, 'ipv6');

async function assertPublicHost(url) {
  if (!CONFIG.blockPrivateNetworks) return;
  const host  = new URL(url).hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{address: host}] : await dns.lookup(host, {all: true}).catch(() => []);
  if (!addrs.length) throw new ScanError('invalid_qr', `Cannot resolve wallet host ${host}`);
  for (const {address} of addrs) {
    const v4 = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)?.[1];
    const blocked = v4 ? privateRanges.check(v4, 'ipv4') : privateRanges.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4');
    if (blocked) throw new ScanError('invalid_qr', `Wallet host ${host} resolves to a private address`, 403);
  }
}

async function pushRequestToHolder({shareUri, shareToken, authorizationRequest}) {
  const url = `${shareUri}/request`;
  await assertPublicHost(url);
  let res;
  try {
    res = await fetch(url, {
      method:   'POST',
      redirect: 'error',
      signal:   AbortSignal.timeout(CONFIG.walletTimeoutMs),
      headers:  {'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${shareToken}`},
      body:     JSON.stringify({authorization_request: authorizationRequest})
    });
  } catch (err) {
    throw new ScanError('wallet_unreachable', `Could not reach wallet: ${err.message}`, 502);
  }
  const text = await res.text();
  if (text.length > 64 * 1024) throw new ScanError('wallet_error', 'Wallet response too large', 502);
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch {}
  return {httpStatus: res.status, ...body};
}

// Mark a holder-initiated session failed — but never overwrite a result the
// wallet already delivered via /oid4vp/response (auto mode posts synchronously).
function failSession(state, error, errorDescription) {
  const entry = requests.get(state);
  if (entry) entry.used = true;
  const current = results.get(state);
  if (current?.status === 'pending') {
    results.set(state, {status: 'error', flow: current.flow, verified: false, error, errorDescription: errorDescription ?? null});
  }
}

// ── POST /oid4vp/scan  (auth: verifier scope) ─────────────────────────────
// Body: {qr, presentationDefinition? | credentialType?, issuerDid?, credentialFormat?, requiredClaims?, schemaUrl?}
// Response 201: {state, walletStatus: 'submitted'|'pending_consent', status, result?}
//   → then poll GET /oid4vp/result/:state (same as the verifier-initiated flow)
async function handleScanHolderQr(req, res) {
  let state;
  try {
    const tenantId = req.tenant.id;
    const {qr, shareUri: qrFromLegacyField, acceptableCredentialTypes, ...options} = req.body ?? {};
    const {shareUri, shareToken} = parseHolderShareQr(qr ?? qrFromLegacyField);

    // Map the legacy /oid4vp/receive body onto a presentation definition
    if (!options.presentationDefinition && !options.credentialType && acceptableCredentialTypes?.length === 1) {
      options.credentialType = acceptableCredentialTypes[0];
    }

    const created = await createAuthorizationRequest({tenantId, base: baseUrl(req), options, flow: 'holder-initiated'});
    state = created.state;

    const wallet = await pushRequestToHolder({shareUri, shareToken, authorizationRequest: created.openid4vpUri});
    console.log(`[Verifier OID4VP] Pushed request ${state} to holder → HTTP ${wallet.httpStatus} ${wallet.status ?? wallet.error ?? ''}`);

    if (wallet.httpStatus === 200 || wallet.httpStatus === 202) {
      const current = results.get(state);
      if (current?.status === 'pending') {
        results.set(state, {...current, walletStatus: wallet.status, walletExpiresIn: wallet.expires_in ?? null});
      }
      const now = results.get(state);
      await auditLog('OID4VP_HOLDER_QR_SCANNED', {tenantId, actor: 'oid4vp-scan', walletStatus: wallet.status});
      return res.status(201).json({
        state,
        requestId:    created.requestId,
        walletStatus: wallet.status,                     // 'submitted' | 'pending_consent'
        status:       now?.status,                       // 'complete' | 'error' | 'pending'
        expiresIn:    wallet.expires_in ?? null,
        ...(now?.status !== 'pending' && {result: now})
      });
    }

    failSession(state, wallet.error ?? 'wallet_error', wallet.error_description ?? `Wallet returned HTTP ${wallet.httpStatus}`);
    return res.status(wallet.httpStatus >= 500 ? 502 : wallet.httpStatus).json({
      state,
      error:             wallet.error ?? 'wallet_error',
      error_description: wallet.error_description ?? 'Wallet rejected the request'
    });
  } catch (err) {
    if (state) failSession(state, err.code ?? 'server_error', err.message);
    console.error('[Verifier OID4VP] Scan holder QR error:', err.message);
    res.status(err.status ?? 500).json({state: state ?? null, error: err.code ?? 'server_error', error_description: err.message});
  }
}

// ── POST /oid4vp/receive  (auth: verifier scope) ──────────────────────────
// Reverse flow: Verifier receives & verifies credential from holder-initiated share
// Body: {shareUri, acceptableCredentialTypes?, requiredClaims?}
//   NEW: if the body carries the holder's QR text ({qr} or shareUri = "openid4vp-share://…")
//   it is handled by the secure scan flow (handleScanHolderQr). An https shareUri keeps
//   the original download behaviour below, unchanged.
async function handleReceiveShare(req, res) {
  if (req.body?.qr || isHolderShareQr(req.body?.shareUri)) return handleScanHolderQr(req, res);

  try {
    const tenantId = req.tenant.id;
    const {did: verifierDid} = await getVerifierKeys(tenantId);
    const {shareUri, acceptableCredentialTypes = [], requiredClaims = []} = req.body ?? {};

    if (!shareUri) {
      return res.status(400).json({error: 'shareUri is required'});
    }

    // Fetch the credential from the holder's share
    console.log('[Verifier OID4VP] Fetching shared credential from:', shareUri);
    const shareRes = await fetch(shareUri);
    if (!shareRes.ok) {
      return res.status(502).json({
        error: 'Failed to fetch credential',
        details: `Holder returned ${shareRes.status}`
      });
    }

    const shareData = await shareRes.json();
    if (!shareData.format) {
      return res.status(400).json({error: 'Invalid share format'});
    }

    const state = uuidv4();
    results.set(state, {status: 'pending'});

    if (shareData.format === 'vc-ld') {
      // ── VC-LD verification ──────────────────────────────────────────────
      const verifiablePresentation = shareData.verifiablePresentation;

      const suite = new Ed25519Signature2020();
      const result = await vc.verify({
        presentation: verifiablePresentation,
        suite,
        documentLoader,
        checkStatus: async ({credential}) => {
          const status = credential?.credentialStatus;
          if (!status?.statusListCredential) return {verified: true};
          try {
            const listRes = await fetch(status.statusListCredential);
            if (!listRes.ok) return {verified: true};
            const listVc = await listRes.json();
            const encoded = listVc?.credentialSubject?.encodedList;
            if (!encoded) return {verified: true};
            const buffer = decodeList(encoded);
            const bit = getBit(buffer, parseInt(status.statusListIndex));
            if (bit === 1) {
              return {verified: false, error: new Error('Credential has been revoked by issuer')};
            }
          } catch {
            // non-fatal
          }
          return {verified: true};
        }
      });

      if (!result.verified) {
        const errMsg = result.error?.message ?? 'Verification failed';
        console.warn('[Verifier OID4VP] VP verification failed:', errMsg);
        results.set(state, {status: 'error', verified: false, error: errMsg});
        return res.status(400).json({error: 'vp_verification_failed', details: errMsg});
      }

      const credential = verifiablePresentation.verifiableCredential?.[0];

      // Validate credential type if specified
      if (acceptableCredentialTypes.length > 0) {
        const credTypes = Array.isArray(credential?.type) ? credential.type : [];
        const typeMatch = acceptableCredentialTypes.some(t => credTypes.includes(t));
        if (!typeMatch) {
          const errMsg = `Credential type not accepted. Expected: ${acceptableCredentialTypes.join(', ')}, got: ${credTypes.join(', ')}`;
          results.set(state, {status: 'error', verified: false, error: errMsg});
          return res.status(400).json({error: 'credential_type_mismatch', details: errMsg});
        }
      }

      // Validate required claims if specified
      if (requiredClaims.length > 0) {
        const subject = credential?.credentialSubject ?? {};
        const missingClaims = requiredClaims.filter(claim => subject[claim] === undefined);
        if (missingClaims.length > 0) {
          const errMsg = `Missing required claims: ${missingClaims.join(', ')}`;
          results.set(state, {status: 'error', verified: false, error: errMsg});
          return res.status(400).json({error: 'missing_required_claims', details: errMsg});
        }
      }

      const issuerDid = typeof credential?.issuer === 'string' ? credential.issuer : credential?.issuer?.id;
      const schemaSlug = schemaSlugFromUrl(credential?.credentialSchema?.id);
      const trust = await checkTrustRegistry(issuerDid, schemaSlug);

      results.set(state, {
        status: 'complete',
        verified: true,
        format: 'ldp_vc',
        holder: verifiablePresentation.holder,
        credential: {
          id: credential?.id,
          type: credential?.type,
          issuer: credential?.issuer,
          issuanceDate: credential?.issuanceDate,
          credentialSubject: credential?.credentialSubject
        },
        verifiedAt: new Date().toISOString(),
        ...(trust && !trust.trusted && {
          trustWarning: `Issuer is not accredited in the trust registry for schema "${schemaSlug}"`
        }),
        ...(trust && {trustRegistry: trust})
      });

      await auditLog('VERIFY_VP', {tenantId, did: verifiablePresentation.holder, actor: 'oid4vp-share-vcld'});
      console.log(`[Verifier OID4VP] Verified VC-LD from holder share, state: ${state}`);
      return res.status(201).json({state, status: 'verified', format: 'vc-ld'});
    }

    if (shareData.format === 'sd-jwt') {
      // ── SD-JWT verification ─────────────────────────────────────────────
      const {verifySDJWT} = await import('../shared/sd-jwt.js');
      const sdResult = await verifySDJWT(shareData.sdJwt);

      if (!sdResult.valid) {
        console.warn('[Verifier OID4VP] SD-JWT verification failed:', sdResult.error);
        results.set(state, {status: 'error', verified: false, error: sdResult.error});
        return res.status(400).json({error: 'vp_verification_failed', details: sdResult.error});
      }

      // Validate credential type if specified
      if (acceptableCredentialTypes.length > 0) {
        const credTypes = sdResult.payload?.vc?.type ?? [];
        const typeMatch = acceptableCredentialTypes.some(t => credTypes.includes(t));
        if (!typeMatch) {
          const errMsg = `Credential type not accepted. Expected: ${acceptableCredentialTypes.join(', ')}, got: ${credTypes.join(', ')}`;
          results.set(state, {status: 'error', verified: false, error: errMsg});
          return res.status(400).json({error: 'credential_type_mismatch', details: errMsg});
        }
      }

      // Validate required claims if specified
      if (requiredClaims.length > 0) {
        const missingClaims = requiredClaims.filter(claim => sdResult.disclosedClaims[claim] === undefined);
        if (missingClaims.length > 0) {
          const errMsg = `Missing required claims: ${missingClaims.join(', ')}`;
          results.set(state, {status: 'error', verified: false, error: errMsg});
          return res.status(400).json({error: 'missing_required_claims', details: errMsg});
        }
      }

      const sdSchemaSlug = schemaSlugFromUrl(sdResult.payload?.credentialSchema?.id);
      const sdTrust = await checkTrustRegistry(sdResult.issuer, sdSchemaSlug);

      results.set(state, {
        status: 'complete',
        verified: true,
        format: 'sd-jwt',
        issuer: sdResult.issuer,
        holder: sdResult.subject,
        disclosedClaims: sdResult.disclosedClaims,
        allClaims: sdResult.payload,
        verifiedAt: new Date().toISOString(),
        ...(sdTrust && !sdTrust.trusted && {
          trustWarning: `Issuer is not accredited in the trust registry for schema "${sdSchemaSlug}"`
        }),
        ...(sdTrust && {trustRegistry: sdTrust})
      });

      await auditLog('VERIFY_VP', {tenantId, did: sdResult.subject, actor: 'oid4vp-share-sdjwt'});
      console.log(`[Verifier OID4VP] Verified SD-JWT from holder share, state: ${state}`);
      return res.status(201).json({state, status: 'verified', format: 'sd-jwt'});
    }

    return res.status(400).json({error: 'Unsupported credential format', format: shareData.format});
  } catch (err) {
    console.error('[Verifier OID4VP] Receive share error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// ── Router factory ────────────────────────────────────────────────────────
export function createOid4vpRouter() {
  const router = express.Router();
  router.get('/.well-known/openid-configuration', handleMetadata);
  router.post('/oid4vp/request',      requireScope('verifier'), handleCreateRequest);
  router.get('/oid4vp/request/:id',   handleGetRequest);
  router.post('/oid4vp/response',     handleResponse);
  router.post('/oid4vp/receive',      requireScope('verifier'), handleReceiveShare);
  router.get('/oid4vp/result/:state', requireScope('verifier'), handleResult);

  // added: holder-initiated flow (verifier scans the wallet's QR)
  router.post('/oid4vp/scan',         requireScope('verifier'), express.json({limit: '256kb'}), handleScanHolderQr);
  return router;
}