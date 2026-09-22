import {ensureIdentity, createIdentity, getIdentityById, updateIdentityDid, listIdentitiesByRole} from '../shared/identity-store.js';
import {getPool} from '../shared/db.js';
import {loadOrCreateKey, listKeys, rotateKey, auditLog} from '../shared/key-store.js';
import {buildDidWebDocument} from '../shared/did-web.js';

const PURPOSES = ['assertionMethod', 'authentication', 'capabilityDelegation', 'capabilityInvocation'];

// Loads or initialises all 4 purpose keys for the tenant's holder identity.
// Returns { did, didDocument, assertionKey, authKey, delegationKey, invocationKey }
export async function getHolderKeys(tenantId) {
  const identityId  = await ensureIdentity(tenantId, 'holder', 'Holder Default');
  const identityRow = await getIdentityById(identityId);

  const keys = {};
  for (const purpose of PURPOSES) {
    keys[purpose] = await loadOrCreateKey(identityId, purpose, identityRow);
  }

  const assertionEntry = keys.assertionMethod;
  const controllerDid  = assertionEntry.keyPair.controller;

  if (!identityRow.did) await updateIdentityDid(identityId, controllerDid);

  return {
    did:           controllerDid,
    didDocument:   assertionEntry.didDocument,
    assertionKey:  assertionEntry.keyPair,
    authKey:       keys.authentication.keyPair,
    delegationKey: keys.capabilityDelegation.keyPair,
    invocationKey: keys.capabilityInvocation.keyPair,
    identityId
  };
}

export async function createHolderDid(tenantId, name, {domain = null, didMethod = 'did:key'} = {}) {
  const did        = didMethod === 'did:web' && domain ? `did:web:${domain}` : null;
  const identityId  = await createIdentity(tenantId, 'holder', name, {didMethod, domain, did});
  const identityRow = await getIdentityById(identityId);

  const keys = {};
  for (const purpose of PURPOSES) {
    keys[purpose] = await loadOrCreateKey(identityId, purpose, identityRow);
  }

  const assertionEntry = keys.assertionMethod;
  const controllerDid  = assertionEntry.keyPair.controller;

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
    didDocument = assertionEntry.didDocument;
  }

  console.log(`[Holder] Created identity '${name}': ${controllerDid}`);
  return {did: controllerDid, didDocument, identityId};
}

export async function getHolderKeysByDid(tenantId, did) {
  const pool = getPool();
  const [rows] = await pool.query(
    "SELECT id FROM identity WHERE tenant_id = ? AND role = 'holder' AND did = ? LIMIT 1",
    [tenantId, did]
  );
  if (!rows.length) throw new Error(`Holder DID not found: ${did}`);
  const identityId  = rows[0].id;
  const identityRow = await getIdentityById(identityId);
  const keys = {};
  for (const purpose of PURPOSES) {
    keys[purpose] = await loadOrCreateKey(identityId, purpose, identityRow);
  }
  const assertionEntry = keys.assertionMethod;
  const controllerDid  = assertionEntry.keyPair.controller;
  return {
    did:           controllerDid,
    didDocument:   assertionEntry.didDocument,
    assertionKey:  assertionEntry.keyPair,
    authKey:       keys.authentication.keyPair,
    delegationKey: keys.capabilityDelegation.keyPair,
    invocationKey: keys.capabilityInvocation.keyPair,
    identityId
  };
}

export async function getAllHolderDids(tenantId) {
  return listIdentitiesByRole(tenantId, 'holder');
}

export async function rotateHolderKey(tenantId, purpose) {
  const identityId = await ensureIdentity(tenantId, 'holder', 'Holder Default');
  return rotateKey(identityId, purpose);
}

export async function listHolderKeys(tenantId) {
  const identityId = await ensureIdentity(tenantId, 'holder', 'Holder Default');
  return listKeys(identityId);
}
