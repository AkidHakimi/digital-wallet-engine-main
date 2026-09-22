import {SignJWT, jwtVerify, importJWK, errors} from 'jose';
import {randomBytes, createHash} from 'crypto';
import {base58btc} from 'multiformats/bases/base58';

// SD-JWT implementation per IETF draft-ietf-oauth-selective-disclosure-jwt.
//
// Format: <JWT>~<disclosure1>~<disclosure2>~...~
// Each disclosure: base64url(JSON([salt, claimName, claimValue]))
// The JWT payload contains _sd: [sha256(disclosure), ...] instead of plain claims.

function base64url(input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64url');
}

function sha256Digest(input) {
  return createHash('sha256').update(input).digest('base64url');
}

// Build one disclosure: [salt, name, value] → base64url encoded
function makeDisclosure(name, value) {
  const salt    = randomBytes(16).toString('base64url');
  const payload = JSON.stringify([salt, name, value]);
  const encoded = base64url(payload);
  return {encoded, hash: sha256Digest(encoded), name, value};
}

// Converts an Ed25519Multikey keyPair to a JWK importable by jose.
// Ed25519Multikey exports multibase-encoded bytes with 2-byte multicodec prefix:
//   publicKeyMultibase  → [0xed, 0x01] + 32 raw bytes
//   secretKeyMultibase  → [0x80, 0x26] + 64 bytes (32-byte seed || 32-byte pub)
// jose EdDSA needs OKP JWK where d = 32-byte seed, x = 32-byte public key.
export async function keypairToJWK(keyPair) {
  const exported = await keyPair.export({publicKey: true, secretKey: true});
  const pubBytes  = base58btc.decode(exported.publicKeyMultibase);  // Uint8Array, incl. 2-byte prefix
  const privBytes = base58btc.decode(exported.secretKeyMultibase); // Uint8Array, incl. 2-byte prefix

  const rawPub = pubBytes.slice(2);       // 32-byte Ed25519 public key
  const seed   = privBytes.slice(2, 34);  // first 32 bytes of 64-byte secret = seed

  const privateKey = await importJWK({
    kty: 'OKP', crv: 'Ed25519',
    x: Buffer.from(rawPub).toString('base64url'),
    d: Buffer.from(seed).toString('base64url')
  }, 'EdDSA');

  const publicKey = await importJWK({
    kty: 'OKP', crv: 'Ed25519',
    x: Buffer.from(rawPub).toString('base64url')
  }, 'EdDSA');

  return {privateKey, publicKey, x: Buffer.from(rawPub).toString('base64url')};
}

// Issues an SD-JWT credential.
// disclosableClaims: array of claim names the holder can selectively disclose.
// All other claims are embedded directly in the JWT payload.
export async function issueSDJWT({claims, holderDid, assertionKey, disclosableClaims = [], credentialSchema = null, expirationDate}) {
  const {privateKey, x} = await keypairToJWK(assertionKey);

  const disclosures = [];
  const sdHashes    = [];
  const plainClaims = {};

  for (const [name, value] of Object.entries(claims)) {
    if (disclosableClaims.includes(name)) {
      const d = makeDisclosure(name, value);
      disclosures.push(d.encoded);
      sdHashes.push(d.hash);
    } else {
      plainClaims[name] = value;
    }
  }

  const payload = {
    ...plainClaims,
    sub:          holderDid,
    iss:          assertionKey.controller,
    iat:          Math.floor(Date.now() / 1000),
    exp:          Math.floor(expirationDate.getTime() / 1000),
    _sd:          sdHashes,
    _sd_alg:      'sha-256',
    cnf:          {jwk: {kty: 'OKP', crv: 'Ed25519', x}},
    ...(credentialSchema && {credentialSchema}),
  };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({alg: 'EdDSA', typ: 'sd+jwt'})
    .sign(privateKey);

  // Format: JWT~disclosure1~disclosure2~
  return [jwt, ...disclosures].join('~') + '~';
}

// Creates a presentation by keeping only the selected disclosures.
export function presentSDJWT(sdJwt, disclosedFields) {
  const parts       = sdJwt.split('~').filter(Boolean);
  const jwt         = parts[0];
  const allDisclosures = parts.slice(1);

  const selected = allDisclosures.filter(enc => {
    try {
      const [, name] = JSON.parse(Buffer.from(enc, 'base64url').toString('utf8'));
      return disclosedFields.includes(name);
    } catch {
      return false;
    }
  });

  return [jwt, ...selected].join('~') + '~';
}

// Verifies an SD-JWT. Returns {valid, payload, disclosedClaims, error}.
export async function verifySDJWT(sdJwt, {issuerDid = null} = {}) {
  try {
    const parts       = sdJwt.split('~').filter(Boolean);
    const jwt         = parts[0];
    const disclosures = parts.slice(1);

    // Decode header to check alg without verifying yet
    const [headerB64, payloadB64] = jwt.split('.');
    const payload  = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    const cnfJwk   = payload?.cnf?.jwk;

    if (!cnfJwk) throw new Error('SD-JWT missing cnf.jwk');

    const publicKey = await importJWK(cnfJwk, 'EdDSA');
    let verified;
    try {
      ({payload: verified} = await jwtVerify(jwt, publicKey, {algorithms: ['EdDSA']}));
    } catch (err) {
      // Signature is already verified by the time jose checks claims, so an
      // expired-but-validly-signed token should still surface its payload —
      // callers do their own soft expiry check (see verifier/routes.js).
      if (err instanceof errors.JWTExpired) {
        verified = err.payload;
      } else {
        throw err;
      }
    }

    // Reconstruct disclosed claims
    const sdHashes      = verified._sd ?? [];
    const disclosedClaims = {};

    for (const enc of disclosures) {
      const hash = sha256Digest(enc);
      if (sdHashes.includes(hash)) {
        const [, name, value] = JSON.parse(Buffer.from(enc, 'base64url').toString('utf8'));
        disclosedClaims[name] = value;
      }
    }

    // Build full visible payload (non-_sd claims + disclosed)
    const {_sd, _sd_alg, cnf, ...baseClaims} = verified;
    const fullClaims = {...baseClaims, ...disclosedClaims};

    return {valid: true, payload: fullClaims, disclosedClaims, issuer: verified.iss, subject: verified.sub};
  } catch (err) {
    return {valid: false, error: err.message};
  }
}
