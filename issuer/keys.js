import {ensureIdentity, createIdentity, getIdentityById, getIdentityByDid, getIdentityByDomain, updateIdentityDid, listIdentitiesByRole} from '../shared/identity-store.js';
import {loadOrCreateKey, loadActiveKey, listKeys, rotateKey, revokeKey, auditLog} from '../shared/key-store.js';
import {buildDidWebDocument} from '../shared/did-web.js';
import {getPool} from '../shared/db.js';

const PURPOSES = ['assertionMethod', 'authentication', 'capabilityDelegation', 'capabilityInvocation'];

// Loads or initialises all 4 purpose keys for the tenant's issuer identity.
// Pass issuerDid to select a specific identity by DID; omit to use the tenant default.
// Returns { did, didDocument, assertionKey, authKey, delegationKey, invocationKey }
export async function getIssuerKeys(tenantId, issuerDid = null) {
  let identityRow;
  if (issuerDid) {
    identityRow = await getIdentityByDid(tenantId, 'issuer', issuerDid);
    if (!identityRow) {
      throw Object.assign(new Error(`Issuer DID not found: ${issuerDid}`), {status: 404});
    }
  } else {
    const defaultId = await ensureIdentity(tenantId, 'issuer', 'Issuer Default');
    identityRow     = await getIdentityById(defaultId);
  }
  const resolvedIdentityId = identityRow.id;

  const keys = {};
  for (const purpose of PURPOSES) {
    keys[purpose] = await loadOrCreateKey(resolvedIdentityId, purpose, identityRow);
  }

  const assertionEntry = keys.assertionMethod;
  const did            = assertionEntry.keyPair.controller;

  if (!identityRow.did) await updateIdentityDid(resolvedIdentityId, did);

  let didDocument;
  if (identityRow?.did_method === 'did:web' && identityRow?.domain) {
    const pool = getPool();
    const [rows] = await pool.query(
      "SELECT * FROM did_keys WHERE identity_id = ? AND status = 'active'",
      [resolvedIdentityId]
    );
    didDocument = await buildDidWebDocument(identityRow.domain, rows);
  } else {
    didDocument = assertionEntry.didDocument;
  }

  return {
    did,
    didDocument,
    assertionKey:   assertionEntry.keyPair,
    authKey:        keys.authentication.keyPair,
    delegationKey:  keys.capabilityDelegation.keyPair,
    invocationKey:  keys.capabilityInvocation.keyPair,
    identityId:     resolvedIdentityId
  };
}

// Creates a new named issuer identity.
// Pass domain + didMethod:'did:web' for a did:web issuer.
export async function createIssuerDid(tenantId, name, {domain = null, didMethod = 'did:key'} = {}) {
  const did = didMethod === 'did:web' && domain ? `did:web:${domain}` : null;
  const identityId  = await createIdentity(tenantId, 'issuer', name, {didMethod, domain, did});
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

  console.log(`[Issuer] Created identity '${name}': ${controllerDid}`);
  return {did: controllerDid, didDocument, identityId};
}

export async function getAllIssuerDids(tenantId) {
  return listIdentitiesByRole(tenantId, 'issuer');
}

export async function getIssuerDidWebDocument(domain) {
  const identityRow = await getIdentityByDomain(domain);
  if (!identityRow) return null;

  const pool = getPool();
  const [keyRows] = await pool.query(
    "SELECT * FROM did_keys WHERE identity_id = ? AND status = 'active'",
    [identityRow.id]
  );
  return buildDidWebDocument(domain, keyRows);
}

export async function rotateIssuerKey(tenantId, purpose) {
  const identityId = await ensureIdentity(tenantId, 'issuer', 'Issuer Default');
  return rotateKey(identityId, purpose);
}

export async function revokeIssuerKey(keyId) {
  return revokeKey(keyId);
}

export async function listIssuerKeys(tenantId) {
  const identityId = await ensureIdentity(tenantId, 'issuer', 'Issuer Default');
  return listKeys(identityId);
}
