import {createHash, randomBytes} from 'crypto';
import {getPool} from '../shared/db.js';

function sha256(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

// POST /tenants
export async function createTenant(req, res) {
  const {name} = req.body;
  if (!name?.trim()) return res.status(400).json({error: 'name is required'});

  const pool = getPool();
  const [result] = await pool.query(
    'INSERT INTO tenants (name) VALUES (?)',
    [name.trim()]
  );
  res.status(201).json({tenantId: result.insertId, name: name.trim()});
}

// GET /tenants
export async function listTenants(_req, res) {
  const pool = getPool();
  const [rows] = await pool.query('SELECT id, name, status, created_at FROM tenants ORDER BY id ASC');
  res.json({tenants: rows});
}

// PATCH /tenants/:id
export async function updateTenant(req, res) {
  const {status} = req.body;
  if (!['active','suspended'].includes(status)) {
    return res.status(400).json({error: "status must be 'active' or 'suspended'"});
  }
  const pool = getPool();
  const [result] = await pool.query('UPDATE tenants SET status = ? WHERE id = ?', [status, req.params.id]);
  if (result.affectedRows === 0) return res.status(404).json({error: 'Tenant not found'});
  res.json({updated: true, status});
}

// POST /tenants/:id/api-keys
export async function createApiKey(req, res) {
  const {clientId, scopes, expiresAt = null} = req.body;
  if (!clientId?.trim()) return res.status(400).json({error: 'clientId is required'});
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return res.status(400).json({error: 'scopes must be a non-empty array'});
  }
  const allowed = ['issuer','holder','verifier'];
  if (!scopes.every(s => allowed.includes(s))) {
    return res.status(400).json({error: `scopes must be subset of ${allowed.join(', ')}`});
  }

  const rawKey  = randomBytes(32).toString('hex');
  const keyHash = sha256(rawKey);
  const pool    = getPool();

  await pool.query(
    `INSERT INTO tenant_api_keys (tenant_id, client_id, api_key_hash, scopes, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    [req.params.id, clientId.trim(), keyHash, JSON.stringify(scopes), expiresAt]
  );

  // Raw key is shown exactly once — not stored
  res.status(201).json({clientId: clientId.trim(), apiKey: rawKey, scopes, expiresAt});
}

// DELETE /tenants/:id/api-keys/:keyId
export async function revokeApiKey(req, res) {
  const pool = getPool();
  const [result] = await pool.query(
    'UPDATE tenant_api_keys SET active = FALSE, revoked_at = NOW() WHERE id = ? AND tenant_id = ?',
    [req.params.keyId, req.params.id]
  );
  if (result.affectedRows === 0) return res.status(404).json({error: 'API key not found'});
  res.json({revoked: true});
}

// GET /tenants/:id/api-keys
export async function listApiKeys(req, res) {
  const pool = getPool();
  const [rows] = await pool.query(
    'SELECT id, client_id, scopes, active, expires_at, created_at, revoked_at FROM tenant_api_keys WHERE tenant_id = ? ORDER BY id ASC',
    [req.params.id]
  );
  res.json({apiKeys: rows.map(r => ({...r, scopes: typeof r.scopes === 'string' ? JSON.parse(r.scopes) : r.scopes}))});
}
