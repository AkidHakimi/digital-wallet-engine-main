import {getPool} from './db.js';

export async function ensureIdentity(tenantId, role, name, {didMethod = 'did:key', domain = null, did = null} = {}) {
  const pool = getPool();
  const [existing] = await pool.query(
    'SELECT id FROM identity WHERE tenant_id = ? AND role = ? AND did IS NOT NULL LIMIT 1',
    [tenantId, role]
  );
  if (existing.length > 0) return existing[0].id;

  const [result] = await pool.query(
    'INSERT INTO identity (tenant_id, role, name, did_method, domain, did) VALUES (?, ?, ?, ?, ?, ?)',
    [tenantId, role, name, didMethod, domain, did]
  );
  return result.insertId;
}

export async function createIdentity(tenantId, role, name, {didMethod = 'did:key', domain = null, did = null} = {}) {
  const pool = getPool();
  const [result] = await pool.query(
    'INSERT INTO identity (tenant_id, role, name, did_method, domain, did) VALUES (?, ?, ?, ?, ?, ?)',
    [tenantId, role, name, didMethod, domain, did]
  );
  return result.insertId;
}

export async function updateIdentityDid(identityId, did) {
  const pool = getPool();
  await pool.query('UPDATE identity SET did = ? WHERE id = ?', [did, identityId]);
}

export async function getIdentity(tenantId, role) {
  const pool = getPool();
  const [rows] = await pool.query(
    'SELECT * FROM identity WHERE tenant_id = ? AND role = ? LIMIT 1',
    [tenantId, role]
  );
  return rows[0] ?? null;
}

export async function getIdentityById(identityId) {
  const pool = getPool();
  const [rows] = await pool.query('SELECT * FROM identity WHERE id = ?', [identityId]);
  return rows[0] ?? null;
}

export async function getIdentityByDomain(domain) {
  const pool = getPool();
  const [rows] = await pool.query(
    "SELECT * FROM identity WHERE domain = ? AND did_method = 'did:web' LIMIT 1",
    [domain]
  );
  return rows[0] ?? null;
}

export async function listIdentities(tenantId) {
  const pool = getPool();
  const [rows] = await pool.query(
    'SELECT id, role, name, did_method, domain, did, created_at FROM identity WHERE tenant_id = ? AND did IS NOT NULL ORDER BY created_at ASC',
    [tenantId]
  );
  return rows;
}

export async function getIdentityByDid(tenantId, role, did) {
  const pool = getPool();
  const [rows] = await pool.query(
    'SELECT * FROM identity WHERE tenant_id = ? AND role = ? AND did = ? LIMIT 1',
    [tenantId, role, did]
  );
  return rows[0] ?? null;
}

export async function listIdentitiesByRole(tenantId, role) {
  const pool = getPool();
  const [rows] = await pool.query(
    'SELECT id, role, name, did_method, domain, did, created_at FROM identity WHERE tenant_id = ? AND role = ? AND did IS NOT NULL ORDER BY created_at ASC',
    [tenantId, role]
  );
  return rows;
}
