import express from 'express';
import {SignJWT, decodeJwt} from 'jose';
import {requireScope} from '../shared/tenant-auth.js';
import {keypairToJWK} from '../shared/sd-jwt.js';
import {getHolderKeys, getHolderKeysByDid} from './keys.js';
import {save, saveSDJwt} from './store.js';
import {auditLog} from '../shared/key-store.js';

// ── POST /oid4vci/receive  (auth: holder scope) ───────────────────────────
// Executes the full OID4VCI pre-authorized code flow:
//   1. Parse offer URI (openid-credential-offer:// or direct HTTPS URL)
//   2. Fetch credential offer → extract issuerUrl + preAuthCode
//   3. Exchange pre-auth code for access token
//   4. Build holder-binding proof JWT (holder's key in header.jwk)
//   5. Request credential from issuer
//   6. Store received VC in holder wallet
async function handleReceive(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {offerUri} = req.body;

    const requestedDid = req.body.holderDid ?? null;

    if (!offerUri) return res.status(400).json({error: 'offerUri is required'});

    // Resolve fetch URL from openid-credential-offer:// scheme or use directly
    let fetchUrl = offerUri;
    if (offerUri.startsWith('openid-credential-offer://')) {
      const params = new URLSearchParams(offerUri.split('?')[1] ?? '');
      fetchUrl = params.get('credential_offer_uri');
      if (!fetchUrl) return res.status(400).json({error: 'credential_offer_uri not found in offerUri'});
    }

    // Fetch the offer object
    console.log('[Holder OID4VCI] Fetching offer from:', fetchUrl);
    const offerRes = await fetch(fetchUrl);
    if (!offerRes.ok) {
      return res.status(502).json({error: `Failed to fetch offer: ${offerRes.status} ${offerRes.statusText}`});
    }
    const offer = await offerRes.json();

    const issuerUrl   = offer.credential_issuer;
    const preAuthCode = offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'];

    if (!issuerUrl || !preAuthCode) {
      return res.status(400).json({error: 'Invalid offer: missing credential_issuer or pre-authorized_code'});
    }

    // Load holder keys — use the requested DID if specified, else the default identity
    const {did: holderDid, authKey, identityId} = requestedDid
      ? await getHolderKeysByDid(tenantId, requestedDid)
      : await getHolderKeys(tenantId);

    // Request access token
    const tokenBody = new URLSearchParams({
      grant_type:          'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': preAuthCode
    });
    const tokenRes = await fetch(`${issuerUrl}/oid4vci/token`, {
      method:  'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body:    tokenBody.toString()
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(502).json({error: 'Token request failed', details: tokenData});
    }

    const {access_token: accessToken, c_nonce: cNonce} = tokenData;

    // Build proof JWT — holder embeds public key directly in header.jwk
    const {privateKey, x} = await keypairToJWK(authKey);
    const proofJwt = await new SignJWT({
      iss:   holderDid,
      aud:   issuerUrl,
      nonce: cNonce ?? ''
    })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'openid4vci-proof+jwt',
        jwk: {kty: 'OKP', crv: 'Ed25519', x}
      })
      .setIssuedAt()
      .sign(privateKey);

    // Caller may specify the desired format; default to ldp_vc
    const offeredFormat = req.body.format ?? 'ldp_vc';

    // Request credential
    const credRes = await fetch(`${issuerUrl}/oid4vci/credential`, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        format: offeredFormat,
        proof:  {proof_type: 'jwt', jwt: proofJwt}
      })
    });
    const credData = await credRes.json();
    if (!credRes.ok) {
      return res.status(502).json({error: 'Credential request failed', details: credData});
    }

    // Store in wallet — branch by format
    let credentialId, storedFormat, credentialIssuer;
    if (credData.format === 'vc+sd-jwt') {
      credentialId     = await saveSDJwt(credData.credential, tenantId);
      storedFormat     = 'sd-jwt';
      const jwt        = credData.credential.split('~')[0];
      credentialIssuer = decodeJwt(jwt).iss;
    } else {
      credentialId     = await save(credData.credential, tenantId);
      storedFormat     = 'ldp_vc';
      credentialIssuer = credData.credential?.issuer;
    }
    await auditLog('SIGN_VP', {tenantId, identityId, actor: 'oid4vci-receive'});

    console.log(`[Holder OID4VCI] Received and stored ${storedFormat} credential: ${credentialId}`);
    res.json({
      stored:       true,
      credentialId,
      format:       storedFormat,
      issuer:       credentialIssuer
    });
  } catch (err) {
    console.error('[Holder OID4VCI] Receive error:', err.message, err.cause ?? '');
    res.status(500).json({error: err.message, cause: err.cause?.message ?? err.cause});
  }
}

export function createOid4vciClientRouter() {
  const router = express.Router();
  router.post('/oid4vci/receive', requireScope('holder'), handleReceive);
  return router;
}
