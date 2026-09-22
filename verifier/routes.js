import {createVerifierDid, getAllVerifierDids} from './keys.js';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {v4 as uuidv4} from 'uuid';
import {documentLoader} from '../shared/document-loader.js';
import {getPool} from '../shared/db.js';
import {loadKeyByDid, auditLog} from '../shared/key-store.js';
import {decodeList, getBit} from '../shared/status-list.js';
import {verifySDJWT} from '../shared/sd-jwt.js';

// GET /dids
export async function getDids(req, res) {
  try {
    const tenantId = req.tenant?.id ?? parseInt(process.env.DEFAULT_TENANT_ID || '1');
    const dids     = await getAllVerifierDids(tenantId);
    res.json({dids});
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

    const result = await createVerifierDid(tenantId, name, {domain, didMethod});
    res.status(201).json(result);
  } catch (err) {
    console.error('[Verifier] Create DID error:', err.message);
    res.status(500).json({error: err.message});
  }
}

const DOMAIN           = 'verifier.example.org';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const REGISTRY_URL     = process.env.REGISTRY_BASE_URL || 'http://localhost:3005';

async function checkTrustRegistry(issuerDid, schemaSlug) {
  if (!issuerDid || !schemaSlug) return null;
  try {
    const res = await fetch(
      `${REGISTRY_URL}/registry/verify?issuerDid=${encodeURIComponent(issuerDid)}&schemaSlug=${encodeURIComponent(schemaSlug)}`
    );
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null; // registry unreachable — non-fatal
  }
}

function schemaSlugFromUrl(url) {
  if (!url) return null;
  return url.split('/').pop() || null;
}

// POST /challenge
export async function issueChallenge(req, res) {
  const tenantId  = req.tenant.id;
  const challenge = uuidv4();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  const pool      = getPool();
  await pool.query(
    'INSERT INTO challenges (challenge, domain, expires_at, tenant_id) VALUES (?, ?, ?, ?)',
    [challenge, DOMAIN, expiresAt, tenantId]
  );
  console.log(`[Verifier] Issued challenge: ${challenge}`);
  res.json({challenge, domain: DOMAIN});
}

// POST /verify — handles both VC-LD VPs and SD-JWTs
export async function verifyPresentation(req, res) {
  try {
    const tenantId = req.tenant.id;

    // ── SD-JWT path ───────────────────────────────────────────────────────
    if (req.body.sdJwt) {
      const {sdJwt, challenge} = req.body;
      const result = await verifySDJWT(sdJwt);

      if (!result.valid) {
        return res.status(400).json({verified: false, error: result.error});
      }

      // Expiration check
      const exp = result.payload.exp;
      if (exp && exp < Math.floor(Date.now() / 1000)) {
        return res.json({verified: true, expired: true, warning: 'SD-JWT has expired'});
      }

      await auditLog('VERIFY_VP', {tenantId, did: result.issuer, actor: 'verifier'});

      const sdSchemaSlug = schemaSlugFromUrl(result.payload?.credentialSchema?.id);
      const sdTrust      = await checkTrustRegistry(result.issuer, sdSchemaSlug);

      return res.json({
        verified:        true,
        format:          'sd-jwt',
        issuer:          result.issuer,
        subject:         result.subject,
        disclosedClaims: result.disclosedClaims,
        ...(sdTrust && !sdTrust.trusted && {
          trustWarning: `Issuer is not accredited in the trust registry for schema "${sdSchemaSlug}"`
        }),
        ...(sdTrust && {trustRegistry: sdTrust}),
      });
    }

    // ── VC-LD path ────────────────────────────────────────────────────────
    const {verifiablePresentation} = req.body;
    if (!verifiablePresentation) {
      return res.status(400).json({error: 'verifiablePresentation or sdJwt is required'});
    }

    const challenge = verifiablePresentation.proof?.challenge;
    const pool      = getPool();
    const [rows]    = await pool.query(
      'SELECT * FROM challenges WHERE challenge = ? AND tenant_id = ? AND expires_at > NOW()',
      [challenge, tenantId]
    );

    if (!challenge || rows.length === 0) {
      return res.status(400).json({error: 'Unknown or expired challenge'});
    }
    if (rows[0].used) {
      return res.status(400).json({error: 'Challenge already used (replay prevented)'});
    }

    await pool.query('UPDATE challenges SET used = TRUE WHERE challenge = ?', [challenge]);

    const suite  = new Ed25519Signature2020();
    const result = await vc.verify({
      presentation: verifiablePresentation,
      challenge,
      domain: 'verifier.example.org',
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
      console.warn('[Verifier] Verification failed:', result.error ?? result);
      return res.status(400).json({
        verified: false,
        error:    result.error?.message ?? 'Verification failed',
        details:  result
      });
    }

    const credential = verifiablePresentation.verifiableCredential?.[0];
    const subject    = credential?.credentialSubject ?? {};
    const now        = new Date();

    // ── Expiration check ──────────────────────────────────────────────────
    const issuanceDate   = new Date(credential?.issuanceDate || credential?.validFrom);
    const expirationDate = credential?.expirationDate || credential?.validUntil;

    if (issuanceDate > now) {
      return res.json({
        verified: false,
        error:    'Credential is not yet valid',
        validFrom: issuanceDate
      });
    }
    if (expirationDate && new Date(expirationDate) < now) {
      return res.json({
        verified:   true,
        expired:    true,
        expiredAt:  expirationDate,
        warning:    'Credential has expired'
      });
    }

    // ── Key revocation check ──────────────────────────────────────────────
    const signingKeyDid = credential?.proof?.verificationMethod;
    if (signingKeyDid) {
      const keyRow = await loadKeyByDid(signingKeyDid);
      if (keyRow?.status === 'revoked') {
        await auditLog('VERIFY_VP', {tenantId, did: signingKeyDid, actor: 'verifier'});
        return res.json({
          verified:    true,
          keyRevoked:  true,
          revokedAt:   keyRow.revokedAt,
          warning:     'Credential signed with a revoked key'
        });
      }
    }

    await auditLog('VERIFY_VP', {tenantId, did: signingKeyDid, actor: 'verifier'});

    const issuerDid  = typeof credential?.issuer === 'string' ? credential.issuer : credential?.issuer?.id;
    const schemaSlug = schemaSlugFromUrl(credential?.credentialSchema?.id);
    const trust      = await checkTrustRegistry(issuerDid, schemaSlug);

    console.log(`[Verifier] Verified VP from holder: ${verifiablePresentation.holder}`);
    res.json({
      verified:   true,
      format:     'vc-ld',
      holder:     verifiablePresentation.holder,
      credential: {
        id:                credential?.id,
        type:              credential?.type,
        issuer:            credential?.issuer,
        issuanceDate:      credential?.issuanceDate,
        expirationDate:    credential?.expirationDate,
        credentialSubject: subject
      },
      ...(trust && !trust.trusted && {
        trustWarning: `Issuer is not accredited in the trust registry for schema "${schemaSlug}"`
      }),
      ...(trust && {trustRegistry: trust}),
    });
  } catch (err) {
    console.error('[Verifier] Verify error:', err.message);
    res.status(500).json({error: err.message});
  }
}
