// ════════════════════════════════════════════════════════════════════════════
//  holder/oid4vp.js — OID4VP wallet (holder) endpoints, single-file build
//
//  Sections
//    1. Config & errors
//    2. Outbound safety (SSRF-safe fetch)
//    3. Verifier authentication (request object: did / x509_san_dns / redirect_uri)
//    4. Share session store (holder-initiated QR state machine)
//    5. Credential matching (Presentation Exchange + DCQL)
//    6. Presentation building (LDP VP / SD-JWT + KB-JWT) and direct_post
//    7. A) Verifier-initiated handlers  (/oid4vp/initiate, /oid4vp/initiate-sdjwt)
//    8. B) Holder-initiated handlers    (/oid4vp/share …)
//    9. Router
// ════════════════════════════════════════════════════════════════════════════
import express from 'express';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import net from 'node:net';
import {EventEmitter} from 'node:events';
import {v4 as uuidv4} from 'uuid';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {decodeJwt, decodeProtectedHeader, importJWK, jwtVerify} from 'jose';
import QRCode from 'qrcode';
import {requireScope} from '../shared/tenant-auth.js';
import {presentSDJWT} from '../shared/sd-jwt.js';
import {getHolderKeys, getHolderKeysByDid} from './keys.js';
import {list} from './store.js';
import {documentLoader} from '../shared/document-loader.js';
import {auditLog} from '../shared/key-store.js';

const isProd = process.env.NODE_ENV === 'production';

// ════════════════════════════════════════════════════════════════════════════
//  1–3. Config, outbound safety, verifier authentication
// ════════════════════════════════════════════════════════════════════════════
// ── OID4VP authorization-request loading & verification + outbound safety ──
// Used by the holder wallet for BOTH directions:
//   • verifier-initiated  (holder scans verifier QR  → /oid4vp/initiate*)
//   • holder-initiated    (verifier scans holder QR  → /oid4vp/share/:id/request)
//
// Responsibilities
//   1. Resolve a request (by value, by reference, or openid4vp:// URI)
//   2. Authenticate the verifier (client_id prefix: decentralized_identifier / did,
//      x509_san_dns, redirect_uri) and bind response_uri to that identity
//   3. Protect the wallet against SSRF when it talks to verifier-supplied URLs

const flag = (name, dflt) => (process.env[name] === undefined ? dflt : process.env[name] === 'true');
const csv  = v => (v ?? '').split(',').map(s => s.trim()).filter(Boolean);

const OID4VP_CONFIG = Object.freeze({
  // strict  → unsigned / unverifiable request objects are rejected
  // lenient → accepted but flagged verified:false (wallet then forces holder consent)
  verification:         process.env.OID4VP_REQUEST_VERIFICATION ?? (isProd ? 'strict' : 'lenient'),
  allowInsecureHttp:    flag('OID4VP_ALLOW_INSECURE_HTTP', !isProd),
  blockPrivateNetworks: flag('OID4VP_BLOCK_PRIVATE_NETWORKS', isProd),
  allowUntrustedX509:   flag('OID4VP_ALLOW_UNTRUSTED_X509', !isProd),
  trustedVerifiers:     csv(process.env.OID4VP_TRUSTED_VERIFIERS),       // optional client_id allow-list
  trustAnchorFile:      process.env.OID4VP_TRUSTED_CA_PEM_FILE ?? null,  // PEM bundle for x509_san_dns
  fetchTimeoutMs:       Number(process.env.OID4VP_FETCH_TIMEOUT_MS ?? 8000),
  maxResponseBytes:     256 * 1024,
  clockToleranceSec:    60
});

const ALLOWED_ALGS = ['EdDSA', 'ES256', 'ES384', 'ES512', 'PS256', 'RS256'];

class Oid4vpError extends Error {
  constructor(code, description, status = 400, extra = {}) {
    super(description);
    this.code   = code;
    this.status = status;
    Object.assign(this, extra);
  }
}

// ── Outbound safety (SSRF) ────────────────────────────────────────────────
const privateRanges = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16], ['224.0.0.0', 4], ['240.0.0.0', 4]]) {
  privateRanges.addSubnet(a, p, 'ipv4');
}
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]]) {
  privateRanges.addSubnet(a, p, 'ipv6');
}

function isPrivateAddress(address) {
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return privateRanges.check(mapped[1], 'ipv4');
  return privateRanges.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4');
}

async function assertSafeOutboundUrl(url) {
  let u;
  try { u = new URL(url); } catch {
    throw new Oid4vpError('invalid_request', `Invalid URL: ${url}`);
  }
  const httpOk = u.protocol === 'http:' && OID4VP_CONFIG.allowInsecureHttp;
  if (u.protocol !== 'https:' && !httpOk) {
    throw new Oid4vpError('invalid_request', `Only https URLs are allowed (${u.origin})`);
  }
  if (u.username || u.password) throw new Oid4vpError('invalid_request', 'Credentials in URL are not allowed');

  if (OID4VP_CONFIG.blockPrivateNetworks) {
    const host  = u.hostname.replace(/^\[|\]$/g, '');
    const addrs = net.isIP(host) ? [{address: host}] : await dns.lookup(host, {all: true}).catch(() => []);
    if (!addrs.length) throw new Oid4vpError('invalid_request', `Cannot resolve host ${host}`);
    if (addrs.some(a => isPrivateAddress(a.address))) {
      throw new Oid4vpError('invalid_request', `Host ${host} resolves to a private network address`);
    }
  }
  return u;
}

// fetch() with SSRF guard, no redirects, timeout and response-size cap.
async function safeFetch(url, init = {}) {
  await assertSafeOutboundUrl(url);
  let res;
  try {
    res = await fetch(url, {
      ...init,
      redirect: 'error',
      signal:   AbortSignal.timeout(OID4VP_CONFIG.fetchTimeoutMs)
    });
  } catch (err) {
    throw new Oid4vpError('server_error', `Request to ${new URL(url).host} failed: ${err.message}`, 502);
  }
  const chunks = [];
  let size = 0;
  if (res.body) {
    for await (const chunk of res.body) {
      size += chunk.byteLength;
      if (size > OID4VP_CONFIG.maxResponseBytes) {
        throw new Oid4vpError('server_error', `Response from ${new URL(url).host} too large`, 502);
      }
      chunks.push(chunk);
    }
  }
  return {ok: res.ok, status: res.status, headers: res.headers, text: Buffer.concat(chunks).toString('utf8')};
}

// ── Key helpers ───────────────────────────────────────────────────────────
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

// z6Mk… (multicodec 0xed01 + 32 bytes) → Ed25519 OKP JWK
function multibaseEd25519ToJwk(multibase) {
  if (typeof multibase !== 'string' || !multibase.startsWith('z')) throw new Error('Unsupported multibase encoding');
  const bytes = base58Decode(multibase.slice(1));
  if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
    return {kty: 'OKP', crv: 'Ed25519', x: Buffer.from(bytes.slice(2)).toString('base64url')};
  }
  throw new Error('Only Ed25519 multikeys are supported');
}

async function resolveDidKey(kidUrl) {
  const [did, fragment] = kidUrl.split('#');
  if (did.startsWith('did:key:')) return multibaseEd25519ToJwk(did.slice('did:key:'.length));
  if (did.startsWith('did:jwk:')) return JSON.parse(Buffer.from(did.slice('did:jwk:'.length), 'base64url').toString('utf8'));
  if (did.startsWith('did:web:')) {
    const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
    const path  = parts.length > 1 ? `/${parts.slice(1).join('/')}/did.json` : '/.well-known/did.json';
    const r     = await safeFetch(`https://${parts[0]}${path}`, {headers: {accept: 'application/did+json, application/json'}});
    if (!r.ok) throw new Error(`did:web resolution failed (HTTP ${r.status})`);
    const doc = JSON.parse(r.text);
    const vm  = (doc.verificationMethod ?? []).find(v => v.id === kidUrl || v.id === `#${fragment}`);
    if (!vm) throw new Error(`Verification method ${kidUrl} not found`);
    if (vm.publicKeyJwk) return vm.publicKeyJwk;
    if (vm.publicKeyMultibase) return multibaseEd25519ToJwk(vm.publicKeyMultibase);
    throw new Error('Verification method has no usable public key');
  }
  throw new Error(`Unsupported DID method: ${did.split(':').slice(0, 2).join(':')}`);
}

let trustAnchors;
function loadTrustAnchors() {
  if (trustAnchors) return trustAnchors;
  trustAnchors = [];
  if (OID4VP_CONFIG.trustAnchorFile) {
    const pem = fs.readFileSync(OID4VP_CONFIG.trustAnchorFile, 'utf8');
    for (const block of pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []) {
      trustAnchors.push(new crypto.X509Certificate(block));
    }
  }
  return trustAnchors;
}

// ── client_id parsing (OID4VP 1.0 prefixes + draft client_id_scheme) ──────
const CLIENT_ID_PREFIXES = ['x509_san_dns', 'x509_hash', 'decentralized_identifier', 'redirect_uri',
  'verifier_attestation', 'openid_federation', 'pre-registered'];

function parseClientId(clientId, legacyScheme) {
  if (!clientId) return {scheme: null, identifier: null};
  for (const p of CLIENT_ID_PREFIXES) {
    if (clientId.startsWith(`${p}:`)) return {scheme: p, identifier: clientId.slice(p.length + 1)};
  }
  if (legacyScheme) return {scheme: legacyScheme === 'did' ? 'decentralized_identifier' : legacyScheme, identifier: clientId};
  if (clientId.startsWith('did:'))      return {scheme: 'decentralized_identifier', identifier: clientId};
  if (/^https?:\/\//.test(clientId))    return {scheme: 'redirect_uri', identifier: clientId};
  return {scheme: 'pre-registered', identifier: clientId};
}

// ── Request object signature verification ────────────────────────────────
async function verifyWithDid(jwt, header, did) {
  if (!header.kid) throw new Error('kid header is required for DID-signed request objects');
  const kid = header.kid.startsWith('#') ? `${did}${header.kid}` : header.kid;
  if (kid.split('#')[0] !== did) throw new Error('kid does not belong to the client_id DID');
  const jwk = await resolveDidKey(kid);
  const key = await importJWK(jwk, header.alg);
  await jwtVerify(jwt, key, {algorithms: ALLOWED_ALGS, clockTolerance: OID4VP_CONFIG.clockToleranceSec});
}

async function verifyWithX509(jwt, header, dnsName) {
  if (!Array.isArray(header.x5c) || !header.x5c.length) throw new Error('x5c header is required');
  const chain = header.x5c.map(c => new crypto.X509Certificate(Buffer.from(c, 'base64')));
  const now   = new Date();
  for (const c of chain) {
    if (new Date(c.validFrom) > now || new Date(c.validTo) < now) throw new Error('Certificate is not currently valid');
  }
  if (!chain[0].checkHost(dnsName, {subject: 'never'})) throw new Error(`Certificate SAN does not contain ${dnsName}`);
  for (let i = 0; i < chain.length - 1; i++) {
    if (!chain[i].checkIssued(chain[i + 1]) || !chain[i].verify(chain[i + 1].publicKey)) {
      throw new Error('Certificate chain is broken');
    }
  }
  const anchors = loadTrustAnchors();
  const top = chain.at(-1);
  if (anchors.length) {
    const trusted = anchors.some(a => a.fingerprint256 === top.fingerprint256 || (top.checkIssued(a) && top.verify(a.publicKey)));
    if (!trusted) throw new Error('Certificate chain does not end in a trusted anchor');
  } else if (!OID4VP_CONFIG.allowUntrustedX509) {
    throw new Error('No X.509 trust anchors configured (OID4VP_TRUSTED_CA_PEM_FILE)');
  }
  await jwtVerify(jwt, chain[0].publicKey, {algorithms: ALLOWED_ALGS, clockTolerance: OID4VP_CONFIG.clockToleranceSec});
}

async function verifyRequestObject(jwt) {
  let header, payload;
  try {
    header  = decodeProtectedHeader(jwt);
    payload = decodeJwt(jwt);
  } catch {
    throw new Oid4vpError('invalid_request_object', 'Request object is not a valid JWT');
  }
  const {scheme, identifier} = parseClientId(payload.client_id, payload.client_id_scheme);

  if (!header.alg || header.alg === 'none') {
    return {header, payload, verification: {verified: false, scheme, reason: 'request object is unsigned'}};
  }
  try {
    if (scheme === 'x509_san_dns') await verifyWithX509(jwt, header, identifier);
    else if (scheme === 'decentralized_identifier') await verifyWithDid(jwt, header, identifier);
    else throw new Error(`client_id scheme "${scheme}" cannot be verified by this wallet`);
    return {header, payload, verification: {verified: true, scheme}};
  } catch (err) {
    return {header, payload, verification: {verified: false, scheme, reason: err.message}};
  }
}

// ── Public entry point ────────────────────────────────────────────────────
// input: string (openid4vp://… URI or https URL of the request object)
//     or {authorization_request?, request?, request_uri?, client_id?}
async function loadAuthorizationRequest(input) {
  const src = typeof input === 'string' ? {authorization_request: input} : {...(input ?? {})};
  let requestJwt    = src.request;
  let requestUri    = src.request_uri;
  let outerClientId = src.client_id;
  let byValue       = null;

  if (src.authorization_request) {
    const raw = String(src.authorization_request).trim();
    if (/^https?:\/\//i.test(raw)) {
      requestUri = raw;                                 // legacy: direct link to the request object
    } else {
      const params  = new URLSearchParams(raw.split('?')[1] ?? '');
      requestUri    = params.get('request_uri') ?? requestUri;
      requestJwt    = params.get('request') ?? requestJwt;
      outerClientId = params.get('client_id') ?? outerClientId;
      if (!requestUri && !requestJwt) byValue = Object.fromEntries(params);
    }
  }

  if (!requestJwt && requestUri) {
    console.log('[OID4VP] Fetching request object from:', requestUri);
    const r = await safeFetch(requestUri, {headers: {accept: 'application/oauth-authz-req+jwt, application/jwt'}});
    if (!r.ok) throw new Oid4vpError('invalid_request_uri', `Failed to fetch request object: HTTP ${r.status}`, 502);
    requestJwt = r.text.trim();
  }

  let payload, verification;
  if (requestJwt) {
    ({payload, verification} = await verifyRequestObject(requestJwt));
  } else if (byValue && Object.keys(byValue).length) {
    payload = {...byValue};
    for (const k of ['presentation_definition', 'dcql_query', 'client_metadata']) {
      if (typeof payload[k] === 'string') {
        try { payload[k] = JSON.parse(payload[k]); } catch {
          throw new Oid4vpError('invalid_request', `${k} is not valid JSON`);
        }
      }
    }
    verification = {verified: false, reason: 'request passed by value (unsigned)'};
  } else {
    throw new Oid4vpError('invalid_request', 'No request, request_uri or authorization request supplied');
  }

  if (outerClientId && payload.client_id && outerClientId !== payload.client_id) {
    throw new Oid4vpError('invalid_request_object', 'client_id in URI does not match request object');
  }
  return normalizeRequest(payload, verification);
}

async function normalizeRequest(payload, verification) {
  const strict = OID4VP_CONFIG.verification === 'strict';
  const {nonce} = payload;
  const responseUri = payload.response_uri;

  if (!nonce || !responseUri) {
    throw new Oid4vpError('invalid_request_object', 'Missing nonce or response_uri in request object');
  }
  if (payload.response_type && !String(payload.response_type).split(' ').includes('vp_token')) {
    throw new Oid4vpError('unsupported_response_type', 'Only response_type=vp_token is supported');
  }
  if (payload.response_mode && payload.response_mode !== 'direct_post') {
    throw new Oid4vpError('invalid_request', `Unsupported response_mode: ${payload.response_mode}`);
  }
  if (payload.exp && payload.exp * 1000 < Date.now() - OID4VP_CONFIG.clockToleranceSec * 1000) {
    throw new Oid4vpError('invalid_request_object', 'Request object has expired');
  }

  let clientId = payload.client_id;
  if (!clientId) {
    if (strict) throw new Oid4vpError('invalid_request_object', 'client_id is required');
    clientId     = new URL(responseUri).origin;       // legacy verifiers: fall back to response_uri origin
    verification = {verified: false, reason: 'client_id missing'};
  }
  const {scheme, identifier} = parseClientId(clientId, payload.client_id_scheme);

  // Bind response_uri to the authenticated verifier identity
  if (scheme === 'redirect_uri' && responseUri !== identifier) {
    throw new Oid4vpError('invalid_request_object', 'response_uri must equal client_id for the redirect_uri scheme');
  }
  if (scheme === 'x509_san_dns' && verification.verified && new URL(responseUri).hostname !== identifier) {
    verification = {verified: false, reason: 'response_uri host does not match certificate DNS name'};
  }

  if (strict && !verification.verified) {
    throw new Oid4vpError('invalid_request_object', `Verifier could not be authenticated: ${verification.reason}`, 401);
  }
  if (OID4VP_CONFIG.trustedVerifiers.length && !OID4VP_CONFIG.trustedVerifiers.includes(clientId)) {
    throw new Oid4vpError('access_denied', `Verifier ${clientId} is not on the trusted list`, 403);
  }
  await assertSafeOutboundUrl(responseUri);

  return {
    clientId,
    clientIdScheme:         scheme,
    verified:               Boolean(verification.verified),
    verificationNote:       verification.reason ?? null,
    verifierName:           payload.client_metadata?.client_name ?? identifier ?? clientId,
    verifierLogoUri:        payload.client_metadata?.logo_uri ?? null,
    nonce,
    state:                  payload.state ?? null,
    responseUri,
    presentationDefinition: payload.presentation_definition ?? null,
    dcqlQuery:              payload.dcql_query ?? null,
    expiresAt:              payload.exp ? payload.exp * 1000 : null
  };
}

// ════════════════════════════════════════════════════════════════════════════
//  4. Share session store
// ════════════════════════════════════════════════════════════════════════════
// ── Holder-initiated share sessions: state machine + storage ──────────────
//
//   created ──(verifier POST /request, valid token)──► request_received
//   request_received ──(needs consent)──► pending_consent ──(approve)──► submitting ──► submitted
//                    └─(auto mode)──────────────────────────────────────► submitting ──► failed
//   pending_consent ──(decline)──► rejected
//   any non-terminal ──(deadline)──► expired      created|pending_consent ──(holder)──► cancelled
//   any non-terminal ──(too many bad tokens)──► locked
//
// Store contract (implement the same 6 methods on Redis / Postgres for multi-instance):
//   create(share) · get(id) · update(id, patch) · transition(id, from[], to, patch) — MUST be atomic CAS
//   expireIfDue(id) · events: 'change' (share, previousStatus)
// Redis hint: keep the share as a JSON value with PX TTL and do transition() in a Lua script
// (GET → compare status → SET); publish changes on a channel for SSE fan-out.

const S = Object.freeze({
  CREATED:          'created',
  REQUEST_RECEIVED: 'request_received',
  PENDING_CONSENT:  'pending_consent',
  SUBMITTING:       'submitting',
  SUBMITTED:        'submitted',
  REJECTED:         'rejected',
  FAILED:           'failed',
  EXPIRED:          'expired',
  CANCELLED:        'cancelled',
  LOCKED:           'locked'
});

const TERMINAL_STATUSES = new Set([S.SUBMITTED, S.REJECTED, S.FAILED, S.EXPIRED, S.CANCELLED, S.LOCKED]);
const ACTIVE_STATUSES   = Object.values(S).filter(s => !TERMINAL_STATUSES.has(s));

// ── Share token: 256-bit bearer secret carried only in the QR ────────────
// Only its SHA-256 is stored, so a store dump cannot be used to claim a share.
const generateShareToken = () => crypto.randomBytes(32).toString('base64url');
const hashShareToken     = token => crypto.createHash('sha256').update(token).digest('base64url');

function verifyShareToken(token, expectedHash) {
  if (typeof token !== 'string' || !token || typeof expectedHash !== 'string') return false;
  const a = Buffer.from(hashShareToken(token));
  const b = Buffer.from(expectedHash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── In-memory implementation (single instance / dev) ─────────────────────
class MemoryShareStore extends EventEmitter {
  #shares = new Map();
  #retentionMs;

  constructor({sweepIntervalMs = 15_000, retentionMs = 10 * 60_000} = {}) {
    super();
    this.setMaxListeners(0);
    this.#retentionMs = retentionMs;
    setInterval(() => this.sweep(), sweepIntervalMs).unref();
  }

  #publish(share, previousStatus) {
    this.emit('change', structuredClone(share), previousStatus);
  }

  async create(share) {
    if (this.#shares.has(share.id)) throw new Error(`Share ${share.id} already exists`);
    this.#shares.set(share.id, structuredClone(share));
    this.#publish(share, null);
    return structuredClone(share);
  }

  async get(id) {
    const s = this.#shares.get(id);
    return s ? structuredClone(s) : null;
  }

  // Non-status fields only (e.g. failedAttempts)
  async update(id, patch) {
    const s = this.#shares.get(id);
    if (!s) return null;
    const {status, ...rest} = patch;
    Object.assign(s, rest, {updatedAt: Date.now()});
    return structuredClone(s);
  }

  // Atomic compare-and-set on status. Returns the updated share, or null if the
  // current status is not in `from` (someone else won the race).
  async transition(id, from, to, patch = {}) {
    const s = this.#shares.get(id);
    if (!s) return null;
    const allowed = Array.isArray(from) ? from : [from];
    if (!allowed.includes(s.status)) return null;
    const previous = s.status;
    Object.assign(s, patch, {status: to, updatedAt: Date.now()});
    if (TERMINAL_STATUSES.has(to)) s.deadlineAt = null;
    this.#publish(s, previous);
    return structuredClone(s);
  }

  async expireIfDue(id, now = Date.now()) {
    const s = this.#shares.get(id);
    if (!s) return null;
    if (!TERMINAL_STATUSES.has(s.status) && s.deadlineAt && now > s.deadlineAt) {
      return this.transition(id, s.status, S.EXPIRED, {error: {code: 'expired', message: `Expired while ${s.status}`}});
    }
    return structuredClone(s);
  }

  sweep(now = Date.now()) {
    for (const [id, s] of this.#shares) {
      if (!TERMINAL_STATUSES.has(s.status)) {
        if (s.deadlineAt && now > s.deadlineAt) this.expireIfDue(id, now);
      } else if (now - s.updatedAt > this.#retentionMs) {
        this.#shares.delete(id);                   // keep terminal state briefly for status polling
      }
    }
  }
}

const shareStore = new MemoryShareStore();

// ════════════════════════════════════════════════════════════════════════════
//  5–9. Matching, presentations, handlers, router
// ════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
//  OID4VP holder (wallet) endpoints
//
//  A) Verifier-initiated — holder scans the verifier's QR
//       POST /oid4vp/initiate               (VC-LD)
//       POST /oid4vp/initiate-sdjwt         (SD-JWT)
//
//  B) Holder-initiated — holder shows a QR, verifier scans it
//       POST   /oid4vp/share                       holder  create share + QR
//       POST   /oid4vp/share/:id/request           PUBLIC  verifier pushes its signed OID4VP request
//       GET    /oid4vp/share/:id/status            holder  poll state / what the verifier asked for
//       GET    /oid4vp/share/:id/events            holder  same, as Server-Sent Events
//       POST   /oid4vp/share/:id/consent           holder  approve (optionally narrow fields) / decline
//       DELETE /oid4vp/share/:id                   holder  cancel
//
//  In flow B the verifier still authors a normal OID4VP request (nonce, client_id,
//  response_uri, presentation_definition | dcql_query). The wallet answers with
//  response_mode=direct_post to the verifier's response_uri, so the verifier's
//  existing response endpoint and VP verification are reused unchanged.
// ════════════════════════════════════════════════════════════════════════════

const SHARE_CONFIG = Object.freeze({
  defaultTtlSec:     Number(process.env.OID4VP_SHARE_TTL_SECONDS ?? 180),   // time for verifier to scan
  minTtlSec:         30,
  maxTtlSec:         600,
  consentTtlSec:     Number(process.env.OID4VP_CONSENT_TTL_SECONDS ?? 120),
  inFlightTtlSec:    60,                                                    // guard for stuck submissions
  maxTokenFailures:  5,
  qrScheme:          'openid4vp-share',
  legacyGet:         process.env.OID4VP_LEGACY_SHARE_GET === 'true',
  // Some verifiers still expect a fixed LD-proof domain; OID4VP says domain = client_id.
  ldpDomainOverride: process.env.OID4VP_LDP_DOMAIN_OVERRIDE ?? null
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SD_JWT_RESERVED = new Set(['iss', 'sub', 'iat', 'nbf', 'exp', 'cnf', 'vct', 'status', '_sd', '_sd_alg', 'jti', 'aud']);

// ── Small helpers ───────────────────────────────────────────────────────────
function baseUrl(req) {
  return process.env.HOLDER_BASE_URL || `${req.protocol}://${req.get('host')}`;
}
const b64url        = data => Buffer.from(data).toString('base64url');
const sha256        = data => crypto.createHash('sha256').update(data).digest();
const isStringArray = v => Array.isArray(v) && v.every(x => typeof x === 'string' && x.length > 0);
const errInfo       = err => ({code: err.code ?? 'server_error', message: err.message});

function sendError(res, err, {expose = true} = {}) {
  if (err instanceof Oid4vpError) {
    const body = {error: err.code, error_description: err.message};
    if (err.details) body.details = err.details;
    return res.status(err.status).json(body);
  }
  console.error('[Holder OID4VP]', err);
  return res.status(500).json({
    error:             'server_error',
    error_description: expose && !isProd ? err.message : 'Internal error'
  });
}

async function audit(event, data) {
  try { await auditLog(event, data); } catch (err) {
    console.error(`[Holder OID4VP] audit log failed for ${event}:`, err.message);
  }
}

// ── SD-JWT helpers ──────────────────────────────────────────────────────────
function sdJwtDisclosureNames(sdJwt) {
  const names = new Set();
  for (const enc of sdJwt.split('~').slice(1).filter(Boolean)) {
    if (enc.split('.').length === 3) continue;                     // KB-JWT, not a disclosure
    try {
      const arr = JSON.parse(Buffer.from(enc, 'base64url').toString('utf8'));
      if (Array.isArray(arr) && arr.length === 3 && typeof arr[1] === 'string') names.add(arr[1]);
    } catch {}
  }
  return names;
}

// What a holder can choose to reveal from a credential
function describeClaims(credential) {
  if (credential.format === 'sd-jwt') {
    const payload = decodeJwt(credential.sdJwt.split('~')[0]);
    return {
      selectable:      [...sdJwtDisclosureNames(credential.sdJwt)],
      alwaysDisclosed: Object.keys(payload).filter(k => !SD_JWT_RESERVED.has(k))
    };
  }
  const subject = credential.vc?.credentialSubject ?? {};
  return {selectable: [], alwaysDisclosed: Object.keys(subject).filter(k => k !== 'id')};
}

// ── Constraint extraction (Presentation Exchange input_descriptor) ─────────
function extractConstraints(descriptor) {
  const fields          = descriptor?.constraints?.fields ?? [];
  const requiredTypes   = [];            // all must be present   ($.type contains)
  const acceptedTypes   = [];            // any may be present    ($.vct const/enum, DCQL vct_values)
  const requiredClaims  = [];
  const optionalClaims  = [];
  let   issuerDid       = null;
  const limitDisclosure = descriptor?.constraints?.limit_disclosure === 'required';

  for (const field of fields) {
    const paths = field.path ?? [];

    if (paths.some(p => p === '$.type' || p === '$.vc.type')) {
      const c = field.filter?.contains?.const ?? field.filter?.const;
      if (c) requiredTypes.push(c);
      continue;
    }
    if (paths.includes('$.vct')) {
      if (field.filter?.const) acceptedTypes.push(field.filter.const);
      if (Array.isArray(field.filter?.enum)) acceptedTypes.push(...field.filter.enum);
      continue;
    }
    if (paths.some(p => ['$.issuer', '$.issuer.id', '$.iss', '$.vc.issuer'].includes(p))) {
      if (field.filter?.const) issuerDid = field.filter.const;
      continue;
    }
    // $.credentialSubject.x | $.vc.credentialSubject.x | $.x (SD-JWT top-level) | $['x']
    for (const p of paths) {
      const m = p.match(/^\$(?:\.vc)?(?:\.credentialSubject)?(?:\.([A-Za-z0-9_]+)|\['([^']+)'\])/);
      const name = m?.[1] ?? m?.[2];
      if (name && !['credentialSubject', 'vc', 'type'].includes(name)) {
        (field.optional ? optionalClaims : requiredClaims).push(name);
        break;
      }
    }
  }

  const formatKeys = Object.keys(descriptor?.format ?? {});
  const sdKey      = formatKeys.find(k => k === 'dc+sd-jwt' || k === 'vc+sd-jwt');
  const ldpKey     = formatKeys.find(k => k === 'ldp_vc' || k === 'ldp_vp');
  const formatHint = sdKey ? 'sd-jwt' : ldpKey ? 'vc-ld' : formatKeys.length ? 'unsupported' : null;

  return {
    requiredTypes, acceptedTypes, issuerDid, formatHint, requestedFormat: sdKey ?? ldpKey ?? null,
    limitDisclosure, requiredClaims, optionalClaims
  };
}

// DCQL (OID4VP 1.0) → PE-shaped descriptor so one matcher handles both.
// Supports the first credential query; claim_sets / multi-credential are not handled.
function dcqlToDescriptor(dcqlQuery) {
  const q = dcqlQuery?.credentials?.[0];
  if (!q) return null;
  const fields = [];
  for (const t of q.meta?.type_values?.[0] ?? []) fields.push({path: ['$.type'], filter: {contains: {const: t}}});
  if (q.meta?.vct_values?.length) fields.push({path: ['$.vct'], filter: {enum: q.meta.vct_values}});
  for (const c of q.claims ?? []) {
    const path = c.path ?? [];
    const name = path[0] === 'credentialSubject' ? path[1] : path[0];
    if (typeof name === 'string') fields.push({path: [`$.credentialSubject.${name}`]});
  }
  return {id: q.id, format: {[q.format]: {}}, constraints: {fields, limit_disclosure: 'required'}};
}

function descriptorFor(request) {
  if (request.dcqlQuery) return dcqlToDescriptor(request.dcqlQuery);
  const pd = request.presentationDefinition;
  const d  = pd?.input_descriptors?.[0];
  if (!d) return null;
  return !d.format && pd.format ? {...d, format: pd.format} : d;
}

// ── Credential matcher ──────────────────────────────────────────────────────
// Returns {credential, format, requestedFormat, requestedClaims, disclosedFields} or null.
function matchCredentialToDescriptor(credentials, descriptor) {
  if (!descriptor) {
    const fallback = credentials.find(c => c.format === 'vc-ld');
    return fallback
      ? {credential: fallback, format: 'vc-ld', requestedFormat: 'ldp_vc', requestedClaims: [], disclosedFields: []}
      : null;
  }

  const {requiredTypes, acceptedTypes, issuerDid, formatHint, requestedFormat, requiredClaims} =
    extractConstraints(descriptor);
  if (formatHint === 'unsupported') return null;          // e.g. mso_mdoc, jwt_vc_json

  const typesOk = credTypes =>
    (!requiredTypes.length || requiredTypes.every(t => credTypes.includes(t))) &&
    (!acceptedTypes.length || acceptedTypes.some(t => credTypes.includes(t)));

  if (formatHint !== 'sd-jwt') {
    for (const cred of credentials) {
      if (cred.format !== 'vc-ld' || !cred.vc) continue;
      const credTypes = Array.isArray(cred.vc.type) ? cred.vc.type : [cred.vc.type].filter(Boolean);
      if (!typesOk(credTypes)) continue;
      const credIssuer = typeof cred.vc.issuer === 'string' ? cred.vc.issuer : cred.vc.issuer?.id;
      if (issuerDid && credIssuer !== issuerDid) continue;
      const subject = cred.vc.credentialSubject ?? {};
      if (requiredClaims.length && !requiredClaims.every(c => subject[c] !== undefined)) continue;
      return {credential: cred, format: 'vc-ld', requestedFormat: 'ldp_vc', requestedClaims: requiredClaims, disclosedFields: []};
    }
  }

  if (formatHint !== 'vc-ld') {
    for (const cred of credentials) {
      if (cred.format !== 'sd-jwt' || !cred.sdJwt) continue;
      let payload;
      try { payload = decodeJwt(cred.sdJwt.split('~')[0]); } catch { continue; }

      // Only enforce type when the SD-JWT actually carries type info (vc.type / vct)
      const credTypes = payload?.vc?.type ?? (payload?.vct ? [payload.vct] : []);
      if (credTypes.length && !typesOk(credTypes)) continue;
      if (issuerDid && payload.iss !== issuerDid) continue;

      if (requiredClaims.length) {
        const allKeys = new Set([
          ...Object.keys(payload),
          ...Object.keys(payload?.vc?.credentialSubject ?? {}),
          ...sdJwtDisclosureNames(cred.sdJwt)
        ]);
        if (!requiredClaims.every(c => allKeys.has(c))) continue;
      }
      return {
        credential:      cred,
        format:          'sd-jwt',
        requestedFormat: requestedFormat ?? 'vc+sd-jwt',
        requestedClaims: requiredClaims,
        disclosedFields: requiredClaims
      };
    }
  }
  return null;
}

// ── Presentation builders (always nonce- and audience-bound) ───────────────
async function buildLdpVp({tenantId, credential, nonce, audience}) {
  const subjectDid = credential.vc?.credentialSubject?.id;
  const {did, authKey, identityId} = subjectDid
    ? await getHolderKeysByDid(tenantId, subjectDid)
    : await getHolderKeys(tenantId);

  const presentation = vc.createPresentation({
    verifiableCredential: [credential.vc],
    id:     `urn:uuid:${uuidv4()}`,
    holder: did
  });
  const vp = await vc.signPresentation({
    presentation,
    suite:     new Ed25519Signature2020({key: authKey}),
    challenge: nonce,
    domain:    SHARE_CONFIG.ldpDomainOverride ?? audience,
    documentLoader
  });
  return {presentation: vp, holderDid: did, identityId};
}

// Compact JWS signed with a @digitalbazaar key object (Ed25519VerificationKey2020)
async function signCompactJwt(authKey, header, payload) {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig   = await authKey.signer().sign({data: new TextEncoder().encode(input)});
  return `${input}.${b64url(sig)}`;
}

function assertCnfMatchesKey(cnf, authKey) {
  if (cnf?.jwk?.crv === 'Ed25519' && authKey.publicKeyMultibase) {
    const ours = multibaseEd25519ToJwk(authKey.publicKeyMultibase);
    if (ours.x !== cnf.jwk.x) {
      throw new Oid4vpError('server_error', 'Holder key does not match the credential cnf key', 500);
    }
  }
}

// SD-JWT VP = <issuer-jwt>~<selected disclosures>~<KB-JWT>
// KB-JWT {iat, aud=client_id, nonce, sd_hash} proves possession and prevents replay.
async function buildSdJwtVp({tenantId, credential, disclosedFields, nonce, audience}) {
  const issuerPayload = decodeJwt(credential.sdJwt.split('~')[0]);

  let sdJwt = presentSDJWT(credential.sdJwt, disclosedFields);
  const last = sdJwt.split('~').at(-1);
  const alreadyBound = sdJwt.includes('~') && last && last.split('.').length === 3;
  if (!alreadyBound && !sdJwt.endsWith('~')) sdJwt += '~';

  const cnfKid = issuerPayload.cnf?.kid;
  const cnfDid = typeof cnfKid === 'string' && cnfKid.startsWith('did:') ? cnfKid.split('#')[0] : null;
  const subDid = typeof issuerPayload.sub === 'string' && issuerPayload.sub.startsWith('did:') ? issuerPayload.sub : null;

  let keys;
  try {
    keys = (cnfDid ?? subDid) ? await getHolderKeysByDid(tenantId, cnfDid ?? subDid) : await getHolderKeys(tenantId);
  } catch (err) {
    if (cnfDid) throw new Oid4vpError('server_error', `Holder key for ${cnfDid} not found`, 500);
    keys = await getHolderKeys(tenantId);
  }

  let keyBound = alreadyBound;
  if (!alreadyBound && issuerPayload.cnf) {
    assertCnfMatchesKey(issuerPayload.cnf, keys.authKey);
    const kbJwt = await signCompactJwt(
      keys.authKey,
      {alg: 'EdDSA', typ: 'kb+jwt'},
      {iat: Math.floor(Date.now() / 1000), aud: audience, nonce, sd_hash: b64url(sha256(sdJwt))}
    );
    sdJwt   += kbJwt;
    keyBound = true;
  }
  return {presentation: sdJwt, holderDid: keys.did, identityId: keys.identityId, keyBound};
}

// ── Authorization response (direct_post) ────────────────────────────────────
function buildResponseFields({request, match, presentation}) {
  const fields = {};
  if (request.dcqlQuery) {
    // OID4VP 1.0: vp_token is a JSON object keyed by DCQL credential query id
    const queryId   = request.dcqlQuery.credentials?.[0]?.id ?? 'credential';
    fields.vp_token = JSON.stringify({[queryId]: [presentation]});
  } else {
    fields.vp_token = typeof presentation === 'string' ? presentation : JSON.stringify(presentation);
    const pd = request.presentationDefinition;
    const descriptorId = pd?.input_descriptors?.[0]?.id ?? 'credential-descriptor';
    const entry = match.format === 'vc-ld'
      ? {id: descriptorId, format: 'ldp_vp', path: '$', path_nested: {format: 'ldp_vc', path: '$.verifiableCredential[0]'}}
      : {id: descriptorId, format: match.requestedFormat ?? 'vc+sd-jwt', path: '$'};
    fields.presentation_submission = JSON.stringify({
      id:             uuidv4(),
      definition_id:  pd?.id ?? 'credential-presentation',
      descriptor_map: [entry]
    });
  }
  if (request.state) fields.state = request.state;
  return fields;
}

async function postToResponseUri(responseUri, fields) {
  const r = await safeFetch(responseUri, {
    method:  'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json'},
    body:    new URLSearchParams(fields).toString()
  });
  let data = {};
  try { data = r.text ? JSON.parse(r.text) : {}; } catch { data = {raw: r.text.slice(0, 300)}; }
  if (!r.ok) {
    throw new Oid4vpError('verifier_rejected', `Verifier responded with HTTP ${r.status}`, 502, {details: data});
  }
  return data;                                              // may carry redirect_uri
}

// Best-effort OID4VP error response (e.g. access_denied) so the verifier session ends cleanly
async function notifyVerifierError(request, error, description) {
  if (!request?.responseUri) return;
  try {
    const fields = {error, error_description: description};
    if (request.state) fields.state = request.state;
    await postToResponseUri(request.responseUri, fields);
  } catch (err) {
    console.warn(`[Holder OID4VP] Could not deliver ${error} to verifier:`, err.message);
  }
}

async function presentAndSubmit({tenantId, request, credential, match, disclosedFields, actor}) {
  const common = {tenantId, credential, nonce: request.nonce, audience: request.clientId};
  const built  = match.format === 'vc-ld'
    ? await buildLdpVp(common)
    : await buildSdJwtVp({...common, disclosedFields});

  const verifierResponse = await postToResponseUri(
    request.responseUri,
    buildResponseFields({request, match, presentation: built.presentation})
  );

  await audit('SIGN_VP', {
    tenantId, identityId: built.identityId, did: built.holderDid, actor,
    verifier: request.clientId, verifierAuthenticated: request.verified,
    credentialId: credential.id, disclosedFields: match.format === 'sd-jwt' ? disclosedFields : 'all'
  });
  return {holderDid: built.holderDid, keyBound: built.keyBound ?? null, verifierResponse};
}

// ════════════════════════════════════════════════════════════════════════════
//  A) Verifier-initiated
// ════════════════════════════════════════════════════════════════════════════

// POST /oid4vp/initiate  {requestUri, credentialId?}
async function handleInitiate(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {requestUri, credentialId} = req.body ?? {};
    if (!requestUri) return res.status(400).json({error: 'requestUri is required'});

    const request     = await loadAuthorizationRequest(requestUri);
    const credentials = await list(tenantId);
    let match;

    if (credentialId) {
      const found = credentials.find(c => c.id === credentialId && c.format === 'vc-ld');
      if (!found) {
        throw new Oid4vpError('no_matching_credential', `VC-LD credential not found: ${credentialId}`, 404);
      }
      match = {credential: found, format: 'vc-ld', requestedFormat: 'ldp_vc', requestedClaims: [], disclosedFields: []};
    } else {
      match = matchCredentialToDescriptor(credentials, descriptorFor(request));
      if (!match || match.format !== 'vc-ld') {
        const wanted = request.presentationDefinition?.input_descriptors?.[0]?.name ?? 'VC-LD';
        throw new Oid4vpError('no_matching_credential', `No matching VC-LD credential found in wallet (wanted: ${wanted})`, 404);
      }
    }

    const {holderDid, verifierResponse} = await presentAndSubmit({
      tenantId, request, credential: match.credential, match, actor: 'oid4vp-initiate'
    });
    console.log(`[Holder OID4VP] Submitted VP for state: ${request.state}`);
    res.json({
      submitted: true, state: request.state, holder: holderDid,
      verifier: request.clientId, verifierAuthenticated: request.verified,
      redirectUri: verifierResponse.redirect_uri ?? null
    });
  } catch (err) {
    sendError(res, err);
  }
}

// POST /oid4vp/initiate-sdjwt  {requestUri, credentialId?, disclosedFields?}
async function handleInitiateSdJwt(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {requestUri, disclosedFields: callerFields, credentialId} = req.body ?? {};
    if (!requestUri) return res.status(400).json({error: 'requestUri is required'});
    if (callerFields !== undefined && !isStringArray(callerFields)) {
      return res.status(400).json({error: 'disclosedFields must be an array of strings'});
    }

    const request     = await loadAuthorizationRequest(requestUri);
    const credentials = await list(tenantId);
    let match;

    if (credentialId) {
      const found = credentials.find(c => c.id === credentialId && c.format === 'sd-jwt');
      if (!found) throw new Oid4vpError('no_matching_credential', `SD-JWT credential not found: ${credentialId}`, 404);
      const requested = extractConstraints(descriptorFor(request)).requiredClaims;
      match = {credential: found, format: 'sd-jwt', requestedFormat: 'vc+sd-jwt', requestedClaims: requested, disclosedFields: requested};
    } else {
      match = matchCredentialToDescriptor(credentials, descriptorFor(request));
      if (!match || match.format !== 'sd-jwt') {
        throw new Oid4vpError('no_matching_credential', 'No matching SD-JWT credential found in wallet', 404);
      }
    }

    // Caller-supplied fields override auto-derived fields from the descriptor
    const disclosedFields = callerFields ?? match.disclosedFields;
    const {verifierResponse, keyBound} = await presentAndSubmit({
      tenantId, request, credential: match.credential, match, disclosedFields, actor: 'oid4vp-sdjwt'
    });
    console.log(`[Holder OID4VP] Submitted SD-JWT presentation (${disclosedFields.length} fields) for state: ${request.state}`);
    res.json({
      submitted: true, state: request.state, disclosedFields, keyBound,
      verifier: request.clientId, verifierAuthenticated: request.verified,
      redirectUri: verifierResponse.redirect_uri ?? null
    });
  } catch (err) {
    sendError(res, err);
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  B) Holder-initiated (wallet shows QR → verifier scans)
// ════════════════════════════════════════════════════════════════════════════

function publicView(share) {
  const p = share.pending;
  return {
    shareId:     share.id,
    status:      share.status,
    mode:        share.mode,
    format:      share.format,
    credentialId: share.credentialId,
    createdAt:   new Date(share.createdAt).toISOString(),
    expiresAt:   new Date(share.expiresAt).toISOString(),
    verifier: p ? {
      clientId:       p.request.clientId,
      name:           p.request.verifierName,
      logoUri:        p.request.verifierLogoUri,
      clientIdScheme: p.request.clientIdScheme,
      authenticated:  p.request.verified,
      note:           p.request.verificationNote
    } : null,
    request: p ? {
      requestedClaims:  p.requestedClaims,
      proposedFields:   p.proposedFields,
      missingClaims:    p.missing,               // requested but not pre-approved by holder
      fullDisclosure:   p.fullDisclosure,        // VC-LD: whole credential is revealed
      consentExpiresAt: new Date(p.consentExpiresAt).toISOString()
    } : null,
    result: share.result ?? null,
    error:  share.error ?? null
  };
}

async function getOwnedShare(req) {
  const {shareId} = req.params;
  if (!UUID_RE.test(shareId)) throw new Oid4vpError('not_found', 'Share not found', 404);
  const share = await shareStore.expireIfDue(shareId);
  if (!share || share.tenantId !== req.tenant.id) throw new Oid4vpError('not_found', 'Share not found', 404);
  return share;
}

function bearerToken(req) {
  const m = (req.get('authorization') ?? '').match(/^Bearer\s+(.+)$/i);
  return m?.[1]?.trim() ?? null;
}

// Decide which SD-JWT claims to reveal: verifier's request ∩ holder's pre-approved set
function planDisclosure({share, match}) {
  const requested = match.requestedClaims ?? [];
  if (match.format === 'vc-ld') {
    return {requestedClaims: requested, proposedFields: [], missing: [], fullDisclosure: true};
  }
  const allowed  = share.disclosedFields;          // null → holder accepts whatever the verifier asks
  const proposed = allowed
    ? (requested.length ? requested.filter(c => allowed.includes(c)) : [...allowed])
    : [...requested];
  const missing  = requested.filter(c => !proposed.includes(c));
  return {requestedClaims: requested, proposedFields: proposed, missing, fullDisclosure: false};
}

// POST /oid4vp/share  (holder)
// Body: {credentialId, format?, disclosedFields?, mode?: 'confirm'|'auto', allowedVerifiers?, ttlSeconds?}
async function handleShare(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {credentialId, format: reqFormat, disclosedFields, mode = 'confirm', allowedVerifiers, ttlSeconds} = req.body ?? {};

    if (!credentialId) throw new Oid4vpError('invalid_request', 'credentialId is required');
    if (!['confirm', 'auto'].includes(mode)) throw new Oid4vpError('invalid_request', "mode must be 'confirm' or 'auto'");
    if (allowedVerifiers !== undefined && !isStringArray(allowedVerifiers)) {
      throw new Oid4vpError('invalid_request', 'allowedVerifiers must be an array of client_id strings');
    }

    const credential = (await list(tenantId)).find(c => c.id === credentialId);
    if (!credential) throw new Oid4vpError('not_found', 'Credential not found', 404);

    const format = reqFormat ?? credential.format;
    if (!['vc-ld', 'sd-jwt'].includes(format)) throw new Oid4vpError('invalid_request', `Unsupported format: ${format}`);
    if (format !== credential.format) {
      throw new Oid4vpError('invalid_request', `Credential is not ${format === 'vc-ld' ? 'VC-LD' : 'SD-JWT'} format`);
    }

    if (disclosedFields !== undefined) {
      if (format !== 'sd-jwt') throw new Oid4vpError('invalid_request', 'disclosedFields is only supported for SD-JWT credentials');
      if (!isStringArray(disclosedFields)) throw new Oid4vpError('invalid_request', 'disclosedFields must be an array of strings');
      const {selectable} = describeClaims(credential);
      const unknown = disclosedFields.filter(f => !selectable.includes(f));
      if (unknown.length) throw new Oid4vpError('invalid_request', `Not selectively disclosable: ${unknown.join(', ')}`);
    }

    const ttlRaw = Number(ttlSeconds ?? SHARE_CONFIG.defaultTtlSec);
    const ttlSec = Math.min(SHARE_CONFIG.maxTtlSec, Math.max(SHARE_CONFIG.minTtlSec, Number.isFinite(ttlRaw) ? ttlRaw : SHARE_CONFIG.defaultTtlSec));

    const shareId    = uuidv4();
    const shareToken = generateShareToken();
    const now        = Date.now();
    const expiresAt  = now + ttlSec * 1000;
    const shareUri   = `${baseUrl(req)}/oid4vp/share/${shareId}`;

    await shareStore.create({
      id: shareId, tenantId, credentialId, format, mode,
      disclosedFields:  disclosedFields ?? null,
      allowedVerifiers: allowedVerifiers ?? null,
      tokenHash:        hashShareToken(shareToken),
      status:           S.CREATED,
      failedAttempts:   0,
      createdAt: now, updatedAt: now, expiresAt, deadlineAt: expiresAt
    });

    // The token lives only in the QR — never logged, never stored in clear
    const qrPayload = `${SHARE_CONFIG.qrScheme}://share?` +
      new URLSearchParams({v: '1', share_uri: shareUri, share_token: shareToken});
    const qrOpts = {errorCorrectionLevel: 'M', margin: 2, width: 300};
    const [qrCode, qrCodeDataUrl] = await Promise.all([
      QRCode.toString(qrPayload, {...qrOpts, type: 'svg'}),
      QRCode.toDataURL(qrPayload, qrOpts)
    ]);

    await audit('OID4VP_SHARE_CREATED', {tenantId, credentialId, shareId, mode, actor: 'oid4vp-share'});
    console.log(`[Holder OID4VP] Created share ${shareId} (${mode}) for credential ${credentialId}`);

    res.set('Cache-Control', 'no-store').status(201).json({
      shareId,
      shareUri,
      qrPayload,
      qrCode,
      qrCodeDataUrl,
      format,
      mode,
      status:    S.CREATED,
      expiresAt: new Date(expiresAt).toISOString(),
      statusUri: `${shareUri}/status`,
      eventsUri: `${shareUri}/events`
    });
  } catch (err) {
    sendError(res, err);
  }
}

// POST /oid4vp/share/:shareId/request  (PUBLIC — called by the verifier after scanning)
// Header: Authorization: Bearer <share_token>
// Body (JSON or form): {authorization_request: "openid4vp://…"} | {request_uri} | {request: <JWT>}
async function handleVerifierRequest(req, res) {
  res.set('Cache-Control', 'no-store');
  const {shareId} = req.params;
  let claimed = false;

  try {
    if (!UUID_RE.test(shareId)) throw new Oid4vpError('invalid_share', 'Share not found', 404);
    let share = await shareStore.expireIfDue(shareId);
    if (!share) throw new Oid4vpError('invalid_share', 'Share not found', 404);

    const token = bearerToken(req);
    if (!token) throw new Oid4vpError('invalid_token', 'Missing share token (Authorization: Bearer <share_token>)', 401);
    if (share.status === S.LOCKED) throw new Oid4vpError('invalid_share', 'Share is locked', 410);

    if (!verifyShareToken(token, share.tokenHash)) {
      const failures = (share.failedAttempts ?? 0) + 1;
      await shareStore.update(shareId, {failedAttempts: failures});
      if (failures >= SHARE_CONFIG.maxTokenFailures) {
        await shareStore.transition(shareId, ACTIVE_STATUSES, S.LOCKED, {error: {code: 'locked', message: 'Too many invalid tokens'}});
        await audit('OID4VP_SHARE_LOCKED', {tenantId: share.tenantId, shareId, actor: 'oid4vp-share'});
      }
      throw new Oid4vpError('invalid_token', 'Invalid share token', 401);
    }
    if (share.status === S.EXPIRED) throw new Oid4vpError('expired_share', 'Share has expired', 410);

    // Atomic claim: first valid verifier wins, the QR is single-use
    share = await shareStore.transition(shareId, S.CREATED, S.REQUEST_RECEIVED, {
      deadlineAt: Date.now() + SHARE_CONFIG.inFlightTtlSec * 1000
    });
    if (!share) throw new Oid4vpError('share_already_used', 'This QR code has already been used', 409);
    claimed = true;

    const request = await loadAuthorizationRequest(req.body ?? {});

    if (share.allowedVerifiers?.length && !share.allowedVerifiers.includes(request.clientId)) {
      throw new Oid4vpError('access_denied', 'Verifier is not permitted by the holder for this share', 403);
    }

    // Re-load the credential now (it may have been deleted/revoked since the QR was made)
    const credential = (await list(share.tenantId)).find(c => c.id === share.credentialId);
    if (!credential) throw new Oid4vpError('credential_unavailable', 'Shared credential is no longer available', 410);

    const match = matchCredentialToDescriptor([credential], descriptorFor(request));
    if (!match) {
      throw new Oid4vpError('no_matching_credential', 'The shared credential does not satisfy the verifier request', 422);
    }

    const plan = planDisclosure({share, match});
    const now  = Date.now();
    const consentExpiresAt = Math.min(now + SHARE_CONFIG.consentTtlSec * 1000, request.expiresAt ?? Infinity);
    const pending = {
      request,
      match:           {format: match.format, requestedFormat: match.requestedFormat, requestedClaims: match.requestedClaims},
      requestedClaims: plan.requestedClaims,
      proposedFields:  plan.proposedFields,
      missing:         plan.missing,
      fullDisclosure:  plan.fullDisclosure,
      consentExpiresAt
    };

    // Auto-release only when: holder chose 'auto', verifier is authenticated,
    // and nothing beyond the holder's pre-approved claims is requested.
    const needsConsent = share.mode === 'confirm' || !request.verified || plan.missing.length > 0;

    await audit('OID4VP_SHARE_REQUESTED', {
      tenantId: share.tenantId, shareId, verifier: request.clientId,
      verifierAuthenticated: request.verified, needsConsent, actor: 'oid4vp-share'
    });

    if (needsConsent) {
      await shareStore.transition(shareId, S.REQUEST_RECEIVED, S.PENDING_CONSENT, {pending, deadlineAt: consentExpiresAt});
      return res.status(202).json({
        status:     S.PENDING_CONSENT,
        expires_in: Math.max(0, Math.round((consentExpiresAt - now) / 1000))
      });
    }

    await shareStore.transition(shareId, S.REQUEST_RECEIVED, S.SUBMITTING, {pending});
    const result = await presentAndSubmit({
      tenantId: share.tenantId, request, credential, match,
      disclosedFields: plan.proposedFields, actor: 'oid4vp-share-auto'
    });
    await shareStore.transition(shareId, S.SUBMITTING, S.SUBMITTED, {
      result: {disclosedFields: plan.proposedFields, holder: result.holderDid, submittedAt: new Date().toISOString()}
    });
    console.log(`[Holder OID4VP] Share ${shareId} auto-submitted to ${request.clientId}`);
    return res.json({status: S.SUBMITTED, redirect_uri: result.verifierResponse.redirect_uri ?? null});
  } catch (err) {
    if (claimed) {
      await shareStore.transition(shareId, [S.REQUEST_RECEIVED, S.SUBMITTING], S.FAILED, {error: errInfo(err)});
    }
    console.warn(`[Holder OID4VP] Share ${shareId} request failed: ${err.code ?? ''} ${err.message}`);
    return sendError(res, err, {expose: false});
  }
}

// GET /oid4vp/share/:shareId/status  (holder)
async function handleStatus(req, res) {
  try {
    res.set('Cache-Control', 'no-store').json(publicView(await getOwnedShare(req)));
  } catch (err) {
    sendError(res, err);
  }
}

// GET /oid4vp/share/:shareId/events  (holder, Server-Sent Events)
async function handleEvents(req, res) {
  let share;
  try { share = await getOwnedShare(req); } catch (err) { return sendError(res, err); }

  res.set({'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no'});
  res.flushHeaders();
  const send = s => res.write(`event: status\ndata: ${JSON.stringify(publicView(s))}\n\n`);
  send(share);
  if (TERMINAL_STATUSES.has(share.status)) return res.end();

  const ping = setInterval(() => res.write(': ping\n\n'), 15_000);
  const cleanup = end => {
    clearInterval(ping);
    shareStore.off('change', onChange);
    if (end) res.end();
  };
  const onChange = s => {
    if (s.id !== share.id) return;
    send(s);
    if (TERMINAL_STATUSES.has(s.status)) cleanup(true);
  };
  shareStore.on('change', onChange);
  req.on('close', () => cleanup(false));
}

// POST /oid4vp/share/:shareId/consent  (holder)  {approve: boolean, disclosedFields?: string[]}
async function handleConsent(req, res) {
  let submitting = false;
  const {shareId} = req.params;
  try {
    const share = await getOwnedShare(req);
    const {approve, disclosedFields} = req.body ?? {};
    if (typeof approve !== 'boolean') throw new Oid4vpError('invalid_request', 'approve (boolean) is required');
    if (share.status === S.EXPIRED) throw new Oid4vpError('expired_share', 'The consent window has expired', 410);
    if (share.status !== S.PENDING_CONSENT) throw new Oid4vpError('invalid_state', `Share is ${share.status}`, 409);

    const {pending} = share;

    if (!approve) {
      const updated = await shareStore.transition(shareId, S.PENDING_CONSENT, S.REJECTED, {});
      if (!updated) throw new Oid4vpError('invalid_state', 'Share state changed, retry', 409);
      await audit('OID4VP_SHARE_REJECTED', {tenantId: share.tenantId, shareId, verifier: pending.request.clientId, actor: 'holder'});
      return res.json({status: S.REJECTED});
    }

    const credential = (await list(share.tenantId)).find(c => c.id === share.credentialId);
    if (!credential) throw new Oid4vpError('credential_unavailable', 'Credential is no longer available', 410);

    let fields = pending.proposedFields;
    if (disclosedFields !== undefined) {
      if (share.format !== 'sd-jwt') throw new Oid4vpError('invalid_request', 'disclosedFields is only supported for SD-JWT');
      if (!isStringArray(disclosedFields)) {
        throw new Oid4vpError('invalid_request', 'disclosedFields must be an array of strings');
      }
      const {selectable} = describeClaims(credential);
      const unknown = disclosedFields.filter(f => !selectable.includes(f));
      if (unknown.length) throw new Oid4vpError('invalid_request', `Not selectively disclosable: ${unknown.join(', ')}`);
      fields = disclosedFields;
    }

    const claimed = await shareStore.transition(shareId, S.PENDING_CONSENT, S.SUBMITTING, {
      deadlineAt: Date.now() + SHARE_CONFIG.inFlightTtlSec * 1000
    });
    if (!claimed) throw new Oid4vpError('invalid_state', 'Share state changed, retry', 409);
    submitting = true;

    const result = await presentAndSubmit({
      tenantId: share.tenantId,
      request:  pending.request,
      credential,
      match:    {...pending.match, credential},
      disclosedFields: fields,
      actor:    'oid4vp-share-consent'
    });
    await shareStore.transition(shareId, S.SUBMITTING, S.SUBMITTED, {
      result: {disclosedFields: fields, holder: result.holderDid, submittedAt: new Date().toISOString()}
    });
    console.log(`[Holder OID4VP] Share ${shareId} approved and submitted to ${pending.request.clientId}`);
    res.json({
      status: S.SUBMITTED,
      disclosedFields: share.format === 'sd-jwt' ? fields : 'all',
      redirectUri: result.verifierResponse.redirect_uri ?? null
    });
  } catch (err) {
    if (submitting) await shareStore.transition(shareId, S.SUBMITTING, S.FAILED, {error: errInfo(err)});
    sendError(res, err);
  }
}

// DELETE /oid4vp/share/:shareId  (holder)
async function handleCancel(req, res) {
  try {
    const share   = await getOwnedShare(req);
    const updated = await shareStore.transition(share.id, [S.CREATED, S.PENDING_CONSENT], S.CANCELLED, {});
    if (!updated) throw new Oid4vpError('invalid_state', `Share is ${share.status} and cannot be cancelled`, 409);
    await audit('OID4VP_SHARE_CANCELLED', {tenantId: share.tenantId, shareId: share.id, actor: 'holder'});
    res.json({status: S.CANCELLED});
  } catch (err) {
    sendError(res, err);
  }
}

// GET /oid4vp/share/:shareId — legacy bearer-download flow (disabled by default).
// Kept only for migrating old verifiers: no verifier auth, wallet-chosen challenge.
async function handleLegacyGetShare(req, res) {
  res.set('Cache-Control', 'no-store');
  if (!SHARE_CONFIG.legacyGet) {
    return res.status(410).json({
      error: 'deprecated',
      error_description: 'Scan the QR with an OID4VP verifier: POST a signed request to /oid4vp/share/:shareId/request'
    });
  }
  try {
    const {shareId} = req.params;
    if (!UUID_RE.test(shareId)) return res.status(404).json({error: 'Share not found or expired'});
    const share = await shareStore.expireIfDue(shareId);
    if (!share) return res.status(404).json({error: 'Share not found or expired'});
    if (share.status === S.EXPIRED) return res.status(410).json({error: 'Share expired'});
    const claimed = await shareStore.transition(shareId, S.CREATED, S.SUBMITTING, {});
    if (!claimed) return res.status(409).json({error: 'Share already used'});

    const credential = (await list(share.tenantId)).find(c => c.id === share.credentialId);
    if (!credential) {
      await shareStore.transition(shareId, S.SUBMITTING, S.FAILED, {});
      return res.status(410).json({error: 'Credential no longer available'});
    }
    let body;
    if (share.format === 'vc-ld') {
      const {presentation} = await buildLdpVp({tenantId: share.tenantId, credential, nonce: uuidv4(), audience: 'legacy-share'});
      body = {format: 'vc-ld', verifiablePresentation: presentation, shareId};
    } else {
      body = {format: 'sd-jwt', sdJwt: presentSDJWT(credential.sdJwt, share.disclosedFields ?? []), shareId};
    }
    await shareStore.transition(shareId, S.SUBMITTING, S.SUBMITTED, {result: {legacy: true}});
    console.warn(`[Holder OID4VP] LEGACY share ${shareId} downloaded without verifier authentication`);
    res.json(body);
  } catch (err) {
    sendError(res, err);
  }
}

// Tell the verifier when a pending request ends without a presentation
// (holder declined, cancelled, or the consent window expired).
let listenerInstalled = false;
function installVerifierNotifier() {
  if (listenerInstalled) return;
  listenerInstalled = true;
  shareStore.on('change', (share, previous) => {
    if (previous !== S.PENDING_CONSENT) return;
    const reason = {
      [S.REJECTED]:  'The holder declined the request',
      [S.CANCELLED]: 'The holder cancelled the share',
      [S.EXPIRED]:   'The holder did not respond in time'
    }[share.status];
    if (reason) notifyVerifierError(share.pending?.request, 'access_denied', reason);
  });
}

export function createOid4vpClientRouter() {
  installVerifierNotifier();
  const router    = express.Router();
  const parseBody = [express.json({limit: '64kb'}), express.urlencoded({extended: false, limit: '64kb'})];

  // A) Verifier-initiated
  router.post('/oid4vp/initiate',       requireScope('holder'), handleInitiate);
  router.post('/oid4vp/initiate-sdjwt', requireScope('holder'), handleInitiateSdJwt);

  // B) Holder-initiated
  router.post('/oid4vp/share',                    requireScope('holder'), handleShare);
  router.get('/oid4vp/share/:shareId/status',     requireScope('holder'), handleStatus);
  router.get('/oid4vp/share/:shareId/events',     requireScope('holder'), handleEvents);
  router.post('/oid4vp/share/:shareId/consent',   requireScope('holder'), handleConsent);
  router.delete('/oid4vp/share/:shareId',         requireScope('holder'), handleCancel);
  router.post('/oid4vp/share/:shareId/request',   ...parseBody, handleVerifierRequest);   // public, token-protected
  router.get('/oid4vp/share/:shareId',            handleLegacyGetShare);
  return router;
}

// Exported for unit tests
export const _internals = {
  extractConstraints, dcqlToDescriptor, matchCredentialToDescriptor, planDisclosure, buildResponseFields,
  loadAuthorizationRequest, multibaseEd25519ToJwk, base58Decode, shareStore, OID4VP_CONFIG
};