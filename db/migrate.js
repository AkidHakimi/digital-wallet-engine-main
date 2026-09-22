/**
 * One-time migration script.
 * Run: node db/migrate.js
 *
 * - Seeds a default tenant and API key (scopes: issuer + holder + verifier)
 * - Back-fills identity + did_keys from old id_issuer / id_holder / id_verifier rows
 * - Re-encrypts private keys with AES-256-GCM
 * - Back-fills credentials.tenant_id and signing_key_did
 * - Creates initial status list for the default issuer identity
 * - Registers built-in EmployeeBadge JSON Schema
 */

import 'dotenv/config';
import {createHash, randomBytes} from 'crypto';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {getPool} from '../shared/db.js';
import {encryptPrivateKey} from '../shared/crypto-utils.js';
import {createStatusList, encodeList} from '../shared/status-list.js';
import {v4 as uuidv4} from 'uuid';

const BASE_URL = process.env.ISSUER_BASE_URL || 'http://localhost:3001';

function sha256(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

const EMPLOYEE_BADGE_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title:   'EmployeeBadgeCredentialSubject',
  type:    'object',
  required: ['name'],
  properties: {
    employeeId:  {type: 'string'},
    name:        {type: 'string'},
    department:  {type: 'string'},
    position:    {type: 'string'},
    startDate:   {type: 'string', format: 'date'},
    accessLevel: {type: 'string'}
  }
};

async function migrateParty(pool, tableName, role, tenantId) {
  const [rows] = await pool.query(`SELECT * FROM ${tableName} ORDER BY created_at ASC LIMIT 1`);
  if (rows.length === 0) {
    console.log(`  [${role}] No legacy rows — skipping`);
    return null;
  }

  const row = rows[0];
  const [idResult] = await pool.query(
    'INSERT INTO identity (tenant_id, role, name, did_method) VALUES (?, ?, ?, ?)',
    [tenantId, role, row.name ?? `${role} Default`, 'did:key']
  );
  const identityId = idResult.insertId;

  for (const [purpose, colName] of [['assertionMethod','assertion_key'],['authentication','auth_key']]) {
    const rawKey = typeof row[colName] === 'string' ? JSON.parse(row[colName]) : row[colName];
    const keyPair = await Ed25519Multikey.from(rawKey);
    const exported = await keyPair.export({publicKey: true, secretKey: true});

    // Re-derive key IDs from the existing did:key DID
    const multibase = row.did.split(':')[2];
    const keyId     = `${row.did}#${multibase}`;
    const enc       = encryptPrivateKey(exported, keyId);

    await pool.query(
      `INSERT INTO did_keys
        (identity_id, did, key_fragment, purpose, key_version, did_document,
         enc_private_key, public_key_jwk, status, activated_at)
       VALUES (?, ?, NULL, ?, 1, ?, ?, ?, 'active', NOW())`,
      [
        identityId, row.did, purpose,
        row.did_document,
        enc,
        JSON.stringify({type: exported.type, publicKeyMultibase: exported.publicKeyMultibase})
      ]
    );
    console.log(`  [${role}] Migrated ${purpose} key: ${keyId}`);
  }

  return {identityId, did: row.did};
}

async function run() {
  const pool = getPool();
  console.log('=== Digital Wallet Migration ===\n');

  // 1. Create default tenant
  const [existingTenants] = await pool.query("SELECT id FROM tenants WHERE name = 'Default Tenant' LIMIT 1");
  let tenantId;
  if (existingTenants.length > 0) {
    tenantId = existingTenants[0].id;
    console.log(`Default tenant already exists (id=${tenantId}) — skipping tenant creation`);
  } else {
    const [t] = await pool.query("INSERT INTO tenants (name) VALUES ('Default Tenant')");
    tenantId  = t.insertId;
    console.log(`Created default tenant (id=${tenantId})`);
  }

  // 2. Create default API key
  const [existingKeys] = await pool.query('SELECT id FROM tenant_api_keys WHERE tenant_id = ? LIMIT 1', [tenantId]);
  if (existingKeys.length > 0) {
    console.log('Default API key already exists — skipping');
  } else {
    const rawKey  = randomBytes(32).toString('hex');
    const keyHash = sha256(rawKey);
    await pool.query(
      "INSERT INTO tenant_api_keys (tenant_id, client_id, api_key_hash, scopes) VALUES (?, 'default-client', ?, ?)",
      [tenantId, keyHash, JSON.stringify(['issuer','holder','verifier'])]
    );
    console.log(`\n✓ Default API key created:`);
    console.log(`  client_id : default-client`);
    console.log(`  api_key   : ${rawKey}`);
    console.log(`\n  Add to .env:`);
    console.log(`  DEFAULT_CLIENT_ID=default-client`);
    console.log(`  DEFAULT_API_KEY=${rawKey}`);
    console.log(`  DEFAULT_TENANT_ID=${tenantId}\n`);
  }

  // 3. Migrate legacy identity tables
  console.log('Migrating legacy identity tables...');
  const issuerResult   = await migrateParty(pool, 'id_issuer',   'issuer',   tenantId);
  const holderResult   = await migrateParty(pool, 'id_holder',   'holder',   tenantId);
  const verifierResult = await migrateParty(pool, 'id_verifier', 'verifier', tenantId);

  // 4. Back-fill credentials
  const [creds] = await pool.query('SELECT credential_id, credential FROM credentials WHERE tenant_id IS NULL');
  if (creds.length > 0) {
    console.log(`\nBack-filling ${creds.length} credentials...`);
    for (const row of creds) {
      const credJson = typeof row.credential === 'string' ? JSON.parse(row.credential) : row.credential;
      const signingKeyDid = credJson?.proof?.verificationMethod ?? null;
      await pool.query(
        'UPDATE credentials SET tenant_id = ?, signing_key_did = ? WHERE credential_id = ?',
        [tenantId, signingKeyDid, row.credential_id]
      );
    }
    console.log(`  Back-filled ${creds.length} credentials`);
  }

  // 5. Back-fill challenges
  await pool.query('UPDATE challenges SET tenant_id = ? WHERE tenant_id IS NULL', [tenantId]);

  // 6. Create initial status list for issuer identity
  if (issuerResult) {
    const [existingList] = await pool.query(
      'SELECT id FROM status_lists WHERE identity_id = ? LIMIT 1',
      [issuerResult.identityId]
    );
    if (existingList.length === 0) {
      const listId        = uuidv4();
      const vcId          = `${BASE_URL}/status/${listId}`;
      const {encodedList} = createStatusList(131072);
      await pool.query(
        `INSERT INTO status_lists (tenant_id, identity_id, list_id, encoded_list, list_size, next_index, vc_id)
         VALUES (?, ?, ?, ?, 131072, 0, ?)`,
        [tenantId, issuerResult.identityId, listId, encodedList, vcId]
      );
      console.log(`\nCreated initial status list: ${listId}`);
    }
  }

  // 7. Create issuer_accreditations table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS issuer_accreditations (
      id             BIGINT        NOT NULL AUTO_INCREMENT,
      tenant_id      BIGINT        NOT NULL,
      identity_id    BIGINT        NOT NULL,
      schema_id      BIGINT        NOT NULL,
      trust_level    ENUM('self-asserted','accredited','government') NOT NULL DEFAULT 'self-asserted',
      accreditor_did VARCHAR(512),
      valid_from     DATETIME      NOT NULL DEFAULT (NOW()),
      valid_until    DATETIME,
      status         ENUM('active','revoked') NOT NULL DEFAULT 'active',
      created_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
      updated_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uniq_identity_schema (identity_id, schema_id),
      INDEX idx_tenant (tenant_id),
      INDEX idx_identity (identity_id),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (identity_id) REFERENCES identity(id),
      FOREIGN KEY (schema_id) REFERENCES credential_schemas(id)
    )
  `);
  console.log('issuer_accreditations table ready');

  // 8. Register EmployeeBadge schema
  const schemaId = `${BASE_URL}/schemas/employee-badge`;
  const [existingSchema] = await pool.query(
    "SELECT id FROM credential_schemas WHERE tenant_id = ? AND slug = 'employee-badge' LIMIT 1",
    [tenantId]
  );
  if (existingSchema.length === 0) {
    await pool.query(
      "INSERT INTO credential_schemas (tenant_id, slug, schema_id, version, schema_json) VALUES (?, 'employee-badge', ?, '1.0.0', ?)",
      [tenantId, schemaId, JSON.stringify(EMPLOYEE_BADGE_SCHEMA)]
    );
    console.log(`Registered EmployeeBadge schema: ${schemaId}`);
  }

  console.log('\n=== Migration complete ===');
  await pool.end();
}

run().catch(err => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
