// did:web DID document builder, resolver, and key fragment helpers.
// did:key encodes exactly one key per DID; did:web can have many keys in one document.

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/multikey/v1'
];

// Fragment naming: {purpose}-key-v{version}
export function keyFragmentForPurpose(purpose, version) {
  return `${purpose}-key-v${version}`;
}

// Sets keyPair.id and keyPair.controller for a did:web identity.
// Must be called after Ed25519Multikey.generate() for each did:web key.
export function attachDidWebIdentity(keyPair, domain, purpose, version) {
  const controller = `did:web:${domain}`;
  const fragment   = keyFragmentForPurpose(purpose, version);
  keyPair.id         = `${controller}#${fragment}`;
  keyPair.controller = controller;
}

// Builds a W3C DID document from did_keys DB rows for a did:web identity.
// keyRows should be the active rows for this identity (all purposes).
export async function buildDidWebDocument(domain, keyRows) {
  const did = `did:web:${domain}`;
  const verificationMethod = [];
  const relationships = {
    assertionMethod:      [],
    authentication:       [],
    capabilityDelegation: [],
    capabilityInvocation: []
  };

  for (const row of keyRows) {
    if (!row.key_fragment) continue;
    const keyId      = `${did}#${row.key_fragment}`;
    const publicKey  = JSON.parse(typeof row.public_key_jwk === 'string' ? row.public_key_jwk : JSON.stringify(row.public_key_jwk));

    verificationMethod.push({
      id:                 keyId,
      type:               'Multikey',
      controller:         did,
      publicKeyMultibase: publicKey.publicKeyMultibase
    });

    if (row.status === 'active' && relationships[row.purpose] !== undefined) {
      relationships[row.purpose].push(keyId);
    }
  }

  const doc = {'@context': DID_CONTEXT, id: did, verificationMethod};
  for (const [rel, refs] of Object.entries(relationships)) {
    if (refs.length > 0) doc[rel] = refs;
  }
  return doc;
}

// Converts did:web DID to its HTTPS fetch URL.
// did:web:example.com        → https://example.com/.well-known/did.json
// did:web:example.com:a:b    → https://example.com/a/b/did.json
export function didWebToUrl(did) {
  const withoutScheme = did.slice('did:web:'.length);
  const parts         = withoutScheme.split(':');
  const domain        = parts[0];
  const path          = parts.slice(1).join('/');
  return path
    ? `https://${domain}/${path}/did.json`
    : `https://${domain}/.well-known/did.json`;
}

// Resolves a did:web DID by HTTPS fetch.
// Throws if the fetch fails or returns non-200.
export async function resolveDidWebHttp(did) {
  const url      = didWebToUrl(did);
  const response = await fetch(url, {headers: {Accept: 'application/json, application/did+ld+json'}});
  if (!response.ok) throw new Error(`did:web fetch failed for ${url}: ${response.status}`);
  return response.json();
}
