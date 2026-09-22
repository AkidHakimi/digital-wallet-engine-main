import express from 'express';
import {v4 as uuidv4} from 'uuid';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {decodeJwt} from 'jose';
import {requireScope} from '../shared/tenant-auth.js';
import {presentSDJWT} from '../shared/sd-jwt.js';
import {getHolderKeys, getHolderKeysByDid} from './keys.js';
import {list} from './store.js';
import {documentLoader} from '../shared/document-loader.js';
import {auditLog} from '../shared/key-store.js';

// ── Shared: fetch + decode the OID4VP request JWT ─────────────────────────
async function fetchRequestPayload(requestUri) {
  let fetchUrl = requestUri;
  if (requestUri.startsWith('openid4vp://')) {
    const params = new URLSearchParams(requestUri.split('?')[1] ?? '');
    fetchUrl = params.get('request_uri');
    if (!fetchUrl) throw Object.assign(new Error('request_uri not found in openid4vp:// URI'), {status: 400});
  }

  console.log('[Holder OID4VP] Fetching request JWT from:', fetchUrl);
  const jwtRes = await fetch(fetchUrl);
  if (!jwtRes.ok) throw Object.assign(new Error(`Failed to fetch request object: ${jwtRes.status}`), {status: 502});

  const requestJwt = await jwtRes.text();
  const payload    = decodeJwt(requestJwt);

  const {nonce, state, response_uri: responseUri, presentation_definition: presentationDefinition} = payload;
  if (!nonce || !state || !responseUri) {
    throw Object.assign(
      new Error('Missing nonce, state, or response_uri in request object'),
      {status: 400, code: 'invalid_request_object'}
    );
  }

  return {nonce, state, responseUri, presentationDefinition};
}

// ── Constraint extraction from a single input_descriptor ─────────────────
function extractConstraints(descriptor) {
  const fields          = descriptor?.constraints?.fields ?? [];
  const requiredTypes   = [];
  let   issuerDid       = null;
  const requiredClaims  = [];
  const limitDisclosure = descriptor?.constraints?.limit_disclosure === 'required';

  for (const field of fields) {
    const paths = field.path ?? [];

    if (paths.includes('$.type')) {
      const constVal = field.filter?.contains?.const;
      if (constVal) requiredTypes.push(constVal);
      continue;
    }

    if (paths.includes('$.issuer') || paths.includes('$.issuer.id')) {
      if (field.filter?.const) issuerDid = field.filter.const;
      continue;
    }

    // $.credentialSubject.* — extract the claim name
    for (const p of paths) {
      const m = p.match(/^\$\.credentialSubject\.(\w+)$/);
      if (m) { requiredClaims.push(m[1]); break; }
    }
  }

  // Determine format preference from descriptor.format keys
  const formatKeys = Object.keys(descriptor?.format ?? {});
  const formatHint = formatKeys.includes('vc+sd-jwt') ? 'vc+sd-jwt'
    : formatKeys.includes('ldp_vc')    ? 'ldp_vc'
    : null;

  return {requiredTypes, issuerDid, formatHint, limitDisclosure, requiredClaims};
}

// ── Rich credential matcher ───────────────────────────────────────────────
// Finds the best credential in the wallet that satisfies the descriptor.
// Returns { credential, format: 'vc-ld'|'sd-jwt', disclosedFields } or null.
function matchCredentialToDescriptor(credentials, descriptor) {
  if (!descriptor) {
    // No descriptor — fall back to first VC-LD credential
    const fallback = credentials.find(c => c.format === 'vc-ld');
    if (fallback) return {credential: fallback, format: 'vc-ld', disclosedFields: []};
    return null;
  }

  const {requiredTypes, issuerDid, formatHint, limitDisclosure, requiredClaims} =
    extractConstraints(descriptor);

  // Try VC-LD credentials first (unless format explicitly requires sd-jwt)
  if (formatHint !== 'vc+sd-jwt') {
    for (const cred of credentials) {
      if (cred.format !== 'vc-ld' || !cred.vc) continue;

      const credTypes = Array.isArray(cred.vc.type) ? cred.vc.type : [];
      if (requiredTypes.length && !requiredTypes.every(t => credTypes.includes(t))) continue;

      const credIssuer = typeof cred.vc.issuer === 'string'
        ? cred.vc.issuer
        : cred.vc.issuer?.id;
      if (issuerDid && credIssuer !== issuerDid) continue;

      const subject = cred.vc.credentialSubject ?? {};
      if (requiredClaims.length && !requiredClaims.every(c => subject[c] !== undefined)) continue;

      return {credential: cred, format: 'vc-ld', disclosedFields: []};
    }
  }

  // Try SD-JWT credentials (unless format explicitly requires ldp_vc)
  if (formatHint !== 'ldp_vc') {
    for (const cred of credentials) {
      if (cred.format !== 'sd-jwt' || !cred.sdJwt) continue;

      let payload;
      try {
        payload = decodeJwt(cred.sdJwt.split('~')[0]);
      } catch {
        continue;
      }

      // Type check — only enforce when the SD-JWT payload actually carries type info
      // (this implementation stores raw claims, not vc.type / vct)
      const credTypes = payload?.vc?.type ?? (payload?.vct ? [payload.vct] : []);
      if (credTypes.length && requiredTypes.length && !requiredTypes.every(t => credTypes.includes(t))) continue;

      // Issuer check
      if (issuerDid && payload.iss !== issuerDid) continue;

      // Required claims — check plain payload keys AND decoded disclosure claim names
      // (disclosable claims are hashed in _sd and not visible as plain keys)
      if (requiredClaims.length) {
        const disclosureNames = new Set();
        for (const enc of cred.sdJwt.split('~').slice(1).filter(Boolean)) {
          try {
            const arr = JSON.parse(Buffer.from(enc, 'base64url').toString('utf8'));
            if (Array.isArray(arr) && arr.length >= 2 && typeof arr[1] === 'string') {
              disclosureNames.add(arr[1]);
            }
          } catch {}
        }
        const allKeys = new Set([
          ...Object.keys(payload),
          ...Object.keys(payload?.vc?.credentialSubject ?? {}),
          ...disclosureNames
        ]);
        if (!requiredClaims.every(c => allKeys.has(c))) continue;
      }

      return {
        credential:      cred,
        format:          'sd-jwt',
        disclosedFields: requiredClaims
      };
    }
  }

  return null;
}

// ── POST /oid4vp/initiate  (auth: holder scope) ───────────────────────────
// Unified OID4VP response flow for VC-LD credentials.
// Parses the request URI, matches a credential via Presentation Definition,
// builds a signed VP, and POSTs to the verifier's response_uri.
async function handleInitiate(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {requestUri, credentialId} = req.body;

    if (!requestUri) return res.status(400).json({error: 'requestUri is required'});

    let parsed;
    try {
      parsed = await fetchRequestPayload(requestUri);
    } catch (err) {
      return res.status(err.status ?? 400).json({
        error: err.code ?? 'invalid_request_object',
        error_description: err.message
      });
    }
    const {nonce, state, responseUri, presentationDefinition} = parsed;

    const credentials = await list(tenantId);
    let match;

    if (credentialId) {
      const found = credentials.find(c => c.id === credentialId && c.format === 'vc-ld');
      if (!found) {
        return res.status(404).json({
          error:             'no_matching_credential',
          error_description: `VC-LD credential not found: ${credentialId}`
        });
      }
      match = {credential: found, format: 'vc-ld', disclosedFields: []};
    } else {
      const descriptor = presentationDefinition?.input_descriptors?.[0];
      match = matchCredentialToDescriptor(credentials, descriptor);
      if (!match || match.format !== 'vc-ld') {
        const wanted = presentationDefinition?.input_descriptors?.[0]?.name ?? 'VC-LD';
        return res.status(404).json({
          error:             'no_matching_credential',
          error_description: `No matching VC-LD credential found in wallet (wanted: ${wanted})`
        });
      }
    }

    const subjectDid = match.credential.vc?.credentialSubject?.id;
    const {did: holderDid, authKey, identityId} = subjectDid
      ? await getHolderKeysByDid(tenantId, subjectDid)
      : await getHolderKeys(tenantId);

    const presentation = vc.createPresentation({
      verifiableCredential: [match.credential.vc],
      id:     `https://example.org/presentations/${uuidv4()}`,
      holder: holderDid
    });
    const suite = new Ed25519Signature2020({key: authKey});
    const verifiablePresentation = await vc.signPresentation({
      presentation,
      suite,
      challenge:    nonce,
      domain:       'verifier.example.org',
      documentLoader
    });

    const defId        = presentationDefinition?.id ?? 'credential-presentation';
    const descriptorId = presentationDefinition?.input_descriptors?.[0]?.id ?? 'credential-descriptor';
    const presentationSubmission = {
      id:             uuidv4(),
      definition_id:  defId,
      descriptor_map: [
        {
          id:     descriptorId,
          format: 'ldp_vp',
          path:   '$',
          path_nested: {format: 'ldp_vc', path: '$.verifiableCredential[0]'}
        }
      ]
    };

    const formBody = new URLSearchParams({
      vp_token:                JSON.stringify(verifiablePresentation),
      presentation_submission: JSON.stringify(presentationSubmission),
      state
    });
    const postRes = await fetch(responseUri, {
      method:  'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body:    formBody.toString()
    });
    const postData = await postRes.json();
    if (!postRes.ok) {
      return res.status(502).json({error: 'Response submission failed', details: postData});
    }

    await auditLog('SIGN_VP', {tenantId, identityId, did: holderDid, actor: 'oid4vp-initiate'});
    console.log(`[Holder OID4VP] Submitted VP for state: ${state}`);
    res.json({submitted: true, state, holder: holderDid});
  } catch (err) {
    console.error('[Holder OID4VP] Initiate error:', err.message, err.cause ?? '');
    res.status(500).json({error: err.message, cause: err.cause?.message ?? err.cause});
  }
}

// ── POST /oid4vp/initiate-sdjwt  (auth: holder scope) ────────────────────
// Selective-disclosure SD-JWT presentation via OID4VP.
// Auto-derives disclosedFields from the Presentation Definition's field
// constraints; caller can override with an explicit disclosedFields array.
async function handleInitiateSdJwt(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {requestUri, disclosedFields: callerFields, credentialId} = req.body;

    if (!requestUri) return res.status(400).json({error: 'requestUri is required'});

    let parsed;
    try {
      parsed = await fetchRequestPayload(requestUri);
    } catch (err) {
      return res.status(err.status ?? 400).json({
        error: err.code ?? 'invalid_request_object',
        error_description: err.message
      });
    }
    const {state, responseUri, presentationDefinition} = parsed;

    const credentials = await list(tenantId);
    let match;

    if (credentialId) {
      const found = credentials.find(c => c.id === credentialId && c.format === 'sd-jwt');
      if (!found) {
        return res.status(404).json({
          error:             'no_matching_credential',
          error_description: `SD-JWT credential not found: ${credentialId}`
        });
      }
      match = {credential: found, format: 'sd-jwt', disclosedFields: []};
    } else {
      const descriptor = presentationDefinition?.input_descriptors?.[0];
      match = matchCredentialToDescriptor(credentials, descriptor);
      if (!match || match.format !== 'sd-jwt') {
        return res.status(404).json({
          error:             'no_matching_credential',
          error_description: 'No matching SD-JWT credential found in wallet'
        });
      }
    }

    // Caller-supplied fields override auto-derived fields from the descriptor
    const disclosedFields = callerFields ?? match.disclosedFields;

    const presentedSdJwt = presentSDJWT(match.credential.sdJwt, disclosedFields);

    const formBody = new URLSearchParams({
      vp_token: presentedSdJwt,
      state
    });
    const postRes = await fetch(responseUri, {
      method:  'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body:    formBody.toString()
    });
    const postData = await postRes.json();
    if (!postRes.ok) {
      return res.status(502).json({error: 'Response submission failed', details: postData});
    }

    const {identityId} = await getHolderKeys(tenantId);
    await auditLog('SIGN_VP', {tenantId, identityId, actor: 'oid4vp-sdjwt'});
    console.log(`[Holder OID4VP] Submitted SD-JWT presentation (${disclosedFields.length} fields) for state: ${state}`);
    res.json({submitted: true, state, disclosedFields});
  } catch (err) {
    console.error('[Holder OID4VP] SD-JWT initiate error:', err.message, err.cause ?? '');
    res.status(500).json({error: err.message, cause: err.cause?.message ?? err.cause});
  }
}

export function createOid4vpClientRouter() {
  const router = express.Router();
  router.post('/oid4vp/initiate',       requireScope('holder'), handleInitiate);
  router.post('/oid4vp/initiate-sdjwt', requireScope('holder'), handleInitiateSdJwt);
  return router;
}
