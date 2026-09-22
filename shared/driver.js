import {driver as keyDriver} from '@digitalbazaar/did-method-key';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';

// Singleton driver with Ed25519 Multikey registered.
// did:key:z6Mk... DIDs will produce DID documents with type:"Multikey" verification methods,
// which is what @digitalbazaar/ed25519-signature-2020 v5 requires for verification.
export const didKeyDriver = keyDriver();
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519Multikey.from
});
