import {ensureIdentity, createIdentity, getIdentityById, updateIdentityDid, listIdentitiesByRole} from '../shared/identity-store.js';
import {loadOrCreateKey} from '../shared/key-store.js';
import {buildDidWebDocument} from '../shared/did-web.js';
import {getPool} from '../shared/db.js';

export async function createVerifierDid(tenantId, name, {domain = null, didMethod = 'did:key'} = {}) {
  const did        = didMethod === 'did:web' && domain ? `did:web:${domain}` : null;
  const identityId  = await createIdentity(tenantId, 'verifier', name, {didMethod, domain, did});
  const identityRow = await getIdentityById(identityId);

  const authEntry  = await loadOrCreateKey(identityId, 'authentication', identityRow);
  const controllerDid = authEntry.keyPair.controller;

  await updateIdentityDid(identityId, controllerDid);

  let didDocument;
  if (didMethod === 'did:web' && domain) {
    const pool = getPool();
    const [rows] = await pool.query(
      "SELECT * FROM did_keys WHERE identity_id = ? AND status = 'active'",
      [identityId]
    );
    didDocument = await buildDidWebDocument(domain, rows);
  } else {
    didDocument = authEntry.didDocument;
  }

  console.log(`[Verifier] Created identity '${name}': ${controllerDid}`);
  return {did: controllerDid, didDocument, identityId};
}

export async function getAllVerifierDids(tenantId) {
  return listIdentitiesByRole(tenantId, 'verifier');
}

// Verifier only needs authentication key for its own DID document.
// It never signs credentials — only verifies issuer/holder signatures.
export async function getVerifierKeys(tenantId) {
  const identityId  = await ensureIdentity(tenantId, 'verifier', 'Verifier Default');
  const identityRow = await getIdentityById(identityId);

  const authEntry     = await loadOrCreateKey(identityId, 'authentication', identityRow);
  const controllerDid = authEntry.keyPair.controller;

  if (!identityRow.did) await updateIdentityDid(identityId, controllerDid);

  return {
    did:         controllerDid,
    didDocument: authEntry.didDocument,
    authKey:     authEntry.keyPair,
    identityId
  };
}
