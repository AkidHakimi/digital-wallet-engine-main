import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {didKeyDriver} from './driver.js';

// Generates one independent Ed25519 keypair for a specific verification purpose.
// For did:key the DID is derived from the key bytes; id/controller are set here.
// For did:web callers must call attachDidWebIdentity() after this to override id/controller.
export async function generateKeyForPurpose(purpose) {
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument, methodFor} = await didKeyDriver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose});
  keyPair.id         = vm.id;
  keyPair.controller = didDocument.id;
  return {did: didDocument.id, didDocument, purpose, keyPair};
}

// Backward-compatible wrapper — returns the same shape as the original generateDid().
// Now generates two independent keypairs instead of aliasing one.
export async function generateDid() {
  const assertion = await generateKeyForPurpose('assertionMethod');
  const auth      = await generateKeyForPurpose('authentication');
  return {
    did:          assertion.did,
    didDocument:  assertion.didDocument,
    assertionKey: assertion.keyPair,
    authKey:      auth.keyPair
  };
}
