import {gzipSync, gunzipSync} from 'zlib';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {documentLoader} from './document-loader.js';
import {getPool} from './db.js';
import {v4 as uuidv4} from 'uuid';

const MIN_SIZE = 131072; // W3C minimum: 131072 bits = 16KB

// ── Bitstring operations ──────────────────────────────────────────────────

export function createStatusList(size = MIN_SIZE) {
  const byteLen = Math.ceil(size / 8);
  const buffer  = Buffer.alloc(byteLen, 0);
  return {buffer, encodedList: encodeList(buffer)};
}

export function encodeList(buffer) {
  const compressed = gzipSync(buffer);
  return compressed.toString('base64url');
}

export function decodeList(encodedList) {
  const compressed = Buffer.from(encodedList, 'base64url');
  return gunzipSync(compressed);
}

export function getBit(buffer, index) {
  const byteIndex = Math.floor(index / 8);
  const bitIndex  = 7 - (index % 8);
  return (buffer[byteIndex] >> bitIndex) & 1;
}

export function setBit(buffer, index, value) {
  const byteIndex = Math.floor(index / 8);
  const bitIndex  = 7 - (index % 8);
  if (value) {
    buffer[byteIndex] |= (1 << bitIndex);
  } else {
    buffer[byteIndex] &= ~(1 << bitIndex);
  }
}

// ── Status list VC builder ─────────────────────────────────────────────────

export async function buildStatusListVc(listId, vcId, encodedList, issuerDid, assertionKey) {
  const credential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
      'https://w3id.org/vc/status-list/2021/v1'
    ],
    id:   vcId,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer:       issuerDid,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id:           `${vcId}#list`,
      type:         'StatusList2021',
      statusPurpose: 'revocation',
      encodedList
    }
  };

  const suite = new Ed25519Signature2020({key: assertionKey});
  return vc.issue({credential, suite, documentLoader});
}

// ── DB helpers ────────────────────────────────────────────────────────────

export async function getOrCreateStatusList(tenantId, identityId, issuerDid, baseUrl) {
  const pool = getPool();
  const [rows] = await pool.query(
    "SELECT * FROM status_lists WHERE identity_id = ? AND purpose = 'revocation' ORDER BY id DESC LIMIT 1",
    [identityId]
  );

  if (rows.length > 0 && rows[0].next_index < rows[0].list_size) {
    return rows[0];
  }

  // Create new list
  const listId      = uuidv4();
  const vcId        = `${baseUrl}/status/${listId}`;
  const {encodedList} = createStatusList(MIN_SIZE);

  const [result] = await pool.query(
    `INSERT INTO status_lists (tenant_id, identity_id, list_id, encoded_list, list_size, next_index, vc_id)
     VALUES (?, ?, ?, ?, ?, 0, ?)`,
    [tenantId, identityId, listId, encodedList, MIN_SIZE, vcId]
  );
  const [newRows] = await pool.query('SELECT * FROM status_lists WHERE id = ?', [result.insertId]);
  return newRows[0];
}

export async function assignStatusIndex(tenantId, identityId, issuerDid, baseUrl) {
  const pool = getPool();
  const list = await getOrCreateStatusList(tenantId, identityId, issuerDid, baseUrl);
  const index = list.next_index;

  await pool.query(
    'UPDATE status_lists SET next_index = next_index + 1 WHERE id = ?',
    [list.id]
  );

  return {
    statusListId:  list.id,
    statusListIndex: index,
    statusListVcUrl: list.vc_id,
    listId:        list.list_id
  };
}

export async function revokeCredentialStatus(statusListId, statusListIndex, assertionKey, issuerDid) {
  const pool  = getPool();
  const [rows] = await pool.query('SELECT * FROM status_lists WHERE id = ?', [statusListId]);
  if (rows.length === 0) throw new Error(`Status list not found: ${statusListId}`);

  const list   = rows[0];
  const buffer = decodeList(list.encoded_list);
  setBit(buffer, statusListIndex, 1);
  const newEncoded = encodeList(buffer);

  const signedVc = await buildStatusListVc(
    list.list_id, list.vc_id, newEncoded, issuerDid, assertionKey
  );

  await pool.query(
    'UPDATE status_lists SET encoded_list = ?, signed_vc = ? WHERE id = ?',
    [newEncoded, JSON.stringify(signedVc), statusListId]
  );
  return signedVc;
}

export async function getStatusListVc(listId) {
  const pool = getPool();
  const [rows] = await pool.query('SELECT * FROM status_lists WHERE list_id = ?', [listId]);
  if (rows.length === 0) return null;
  const list = rows[0];
  if (list.signed_vc) return JSON.parse(list.signed_vc);
  // Return an unsigned stub so verifiers can check the (all-zero) bitstring before first revocation
  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/vc/status-list/2021/v1'
    ],
    id:   list.vc_id,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    credentialSubject: {
      id:            `${list.vc_id}#list`,
      type:          'StatusList2021',
      statusPurpose: 'revocation',
      encodedList:   list.encoded_list
    }
  };
}
