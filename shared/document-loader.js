import {securityLoader} from '@digitalbazaar/security-document-loader';
import {contexts as multikeyContexts} from '@digitalbazaar/multikey-context';
import {didKeyDriver} from './driver.js';
import {buildDidWebDocument, resolveDidWebHttp} from './did-web.js';
import {getPool} from './db.js';

const STATUS_LIST_2021_CONTEXT_URL = 'https://w3id.org/vc/status-list/2021/v1';
const STATUS_LIST_2021_CONTEXT = {
  '@context': {
    '@protected': true,
    id: '@id',
    type: '@type',
    StatusList2021: {
      '@id': 'https://w3id.org/vc/status-list#StatusList2021',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        statusPurpose: 'https://w3id.org/vc/status-list#statusPurpose',
        encodedList: 'https://w3id.org/security#encodedList'
      }
    },
    StatusList2021Credential: {
      '@id': 'https://w3id.org/vc/status-list#StatusList2021Credential'
    },
    StatusList2021Entry: {
      '@id': 'https://w3id.org/vc/status-list#StatusList2021Entry',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        statusPurpose: 'https://w3id.org/vc/status-list#statusPurpose',
        statusListIndex: 'https://w3id.org/vc/status-list#statusListIndex',
        statusListCredential: {
          '@id': 'https://w3id.org/vc/status-list#statusListCredential',
          '@type': '@id'
        }
      }
    }
  }
};

const loader = securityLoader({useCache: true});
loader.addDocuments({documents: multikeyContexts});
const baseLoader = loader.build();

// Resolves a did:web DID: tries HTTPS first, falls back to local DB (dev/test).
async function resolveDidWebWithFallback(did) {
  try {
    return await resolveDidWebHttp(did);
  } catch {
    // Local fallback — query identity table by did column (no DNS needed in dev)
    const pool = getPool();
    const [rows] = await pool.query(
      "SELECT i.id, i.domain FROM identity i WHERE i.did = ? AND i.did_method = 'did:web' LIMIT 1",
      [did]
    );
    if (rows.length === 0) throw new Error(`Cannot resolve did:web DID (not found locally): ${did}`);

    const {id: identityId, domain} = rows[0];
    const [keyRows] = await pool.query(
      "SELECT * FROM did_keys WHERE identity_id = ? AND status IN ('active', 'inactive')",
      [identityId]
    );
    return buildDidWebDocument(domain, keyRows);
  }
}

export async function documentLoader(url) {
  // ── StatusList2021 context — served locally, no network call ─────────────
  if (url === STATUS_LIST_2021_CONTEXT_URL) {
    return {contextUrl: null, documentUrl: url, document: STATUS_LIST_2021_CONTEXT};
  }

  // ── did:key resolution ────────────────────────────────────────────────────
  if (url.startsWith('did:key:')) {
    const fragmentIdx = url.indexOf('#');
    const did         = fragmentIdx !== -1 ? url.slice(0, fragmentIdx) : url;
    const didDocument = await didKeyDriver.get({did, url: did});

    if (fragmentIdx !== -1) {
      const vm = didDocument.verificationMethod?.find(m => m.id === url);
      if (vm) return {contextUrl: null, documentUrl: url, document: vm};
    }
    return {contextUrl: null, documentUrl: url, document: didDocument};
  }

  // ── did:web resolution ────────────────────────────────────────────────────
  if (url.startsWith('did:web:')) {
    const fragmentIdx = url.indexOf('#');
    const did         = fragmentIdx !== -1 ? url.slice(0, fragmentIdx) : url;
    const didDocument = await resolveDidWebWithFallback(did);

    if (fragmentIdx !== -1) {
      const fragment = url.slice(fragmentIdx + 1);
      const vm       = didDocument.verificationMethod?.find(
        m => m.id === url || m.id.endsWith('#' + fragment)
      );
      if (vm) return {contextUrl: null, documentUrl: url, document: vm};
    }
    return {contextUrl: null, documentUrl: url, document: didDocument};
  }

  return baseLoader(url);
}
