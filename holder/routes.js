import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {save, saveSDJwt, load, list} from './store.js';
import {getHolderKeys, createHolderDid, getAllHolderDids, rotateHolderKey, listHolderKeys} from './keys.js';
import {documentLoader} from '../shared/document-loader.js';
import {presentSDJWT} from '../shared/sd-jwt.js';
import {auditLog} from '../shared/key-store.js';

// GET /dids
export async function getDids(req, res) {
  try {
    const tenantId = req.tenant?.id ?? parseInt(process.env.DEFAULT_TENANT_ID || '1');
    const dids     = await getAllHolderDids(tenantId);
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

    const result = await createHolderDid(tenantId, name, {domain, didMethod});
    res.status(201).json(result);
  } catch (err) {
    console.error('[Holder] Create DID error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// POST /credentials — receive a VC (vc-ld) or SD-JWT from an issuer
export async function receiveCredential(req, res) {
  try {
    const tenantId           = req.tenant.id;
    const {verifiableCredential, sdJwt} = req.body;

    if (sdJwt) {
      const id = await saveSDJwt(sdJwt, tenantId);
      console.log(`[Holder] Stored SD-JWT credential: ${id}`);
      return res.json({stored: true, id, format: 'sd-jwt'});
    }

    if (!verifiableCredential?.id) {
      return res.status(400).json({error: 'verifiableCredential or sdJwt is required'});
    }
    const id = await save(verifiableCredential, tenantId);
    console.log(`[Holder] Stored VC: ${id}`);
    res.json({stored: true, id, format: 'vc-ld'});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// GET /credentials — list all credentials in this tenant's wallet
export async function listCredentials(req, res) {
  const tenantId    = req.tenant.id;
  const credentials = await list(tenantId);
  res.json({credentials});
}

// GET /credentials/:id — retrieve a specific credential by ID
export async function getCredential(req, res) {
  try {
    const entry = await load(req.params.id, req.tenant.id);
    if (!entry) return res.status(404).json({error: `Credential not found: ${req.params.id}`});
    res.json({id: entry.id, format: entry.credential_format, vc: entry.vc, sdJwt: entry.sd_jwt});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// POST /present — create a signed VP (vc-ld) or selective-disclosure SD-JWT presentation
export async function createPresentation(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {credentialId, challenge, domain, disclosedFields = []} = req.body;

    if (!credentialId || !challenge) {
      return res.status(400).json({error: 'credentialId and challenge are required'});
    }

    const entry = await load(credentialId, tenantId);
    if (!entry) return res.status(404).json({error: `Credential not found: ${credentialId}`});

    // SD-JWT presentation
    if (entry.credential_format === 'sd-jwt') {
      if (disclosedFields.length === 0) {
        return res.status(400).json({error: 'disclosedFields required for SD-JWT presentation'});
      }
      const presentedSdJwt = presentSDJWT(entry.sd_jwt, disclosedFields);
      const {identityId}   = await getHolderKeys(tenantId);
      await auditLog('SIGN_VP', {tenantId, identityId, actor: req.apiClient});
      console.log(`[Holder] Created SD-JWT presentation for challenge: ${challenge}`);
      return res.json({sdJwt: presentedSdJwt, challenge, format: 'sd-jwt'});
    }

    // VC-LD presentation
    const {did: holderDid, authKey, identityId} = await getHolderKeys(tenantId);

    const presentation = vc.createPresentation({
      verifiableCredential: [entry.vc],
      id:     `https://example.org/presentations/${Date.now()}`,
      holder: holderDid
    });

    const suite = new Ed25519Signature2020({key: authKey});
    const verifiablePresentation = await vc.signPresentation({
      presentation,
      suite,
      challenge,
      domain: domain || 'verifier.example.org',
      documentLoader
    });

    await auditLog('SIGN_VP', {tenantId, identityId, did: holderDid, actor: req.apiClient});
    console.log(`[Holder] Created VP for challenge: ${challenge}`);
    res.json({verifiablePresentation, format: 'vc-ld'});
  } catch (err) {
    console.error('[Holder] Present error:', err.message);
    res.status(500).json({error: err.message});
  }
}

// GET /keys
export async function getKeys(req, res) {
  try {
    const keys = await listHolderKeys(req.tenant.id);
    res.json({keys});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

// POST /keys/rotate
export async function rotateKey(req, res) {
  try {
    const {purpose} = req.body;
    const valid = ['assertionMethod','authentication','capabilityDelegation','capabilityInvocation'];
    if (!valid.includes(purpose)) return res.status(400).json({error: `purpose must be one of: ${valid.join(', ')}`});
    const result = await rotateHolderKey(req.tenant.id, purpose);
    res.json(result);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}
