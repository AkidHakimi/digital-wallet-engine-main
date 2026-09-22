import {createHash, timingSafeEqual} from 'crypto';
import {getPool} from './db.js';

function sha256(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

// Attaches req.tenant = {id, name} and req.apiClient = clientId
// Validates scope; responds 401/403 on failure.
export function requireScope(scope) {
  return async (req, res, next) => {
    const clientId = req.headers['x-api-client'];
    const rawKey   = req.headers['x-api-key'];

    if (!clientId || !rawKey) {
      return res.status(401).json({error: 'Missing x-api-client / x-api-key headers'});
    }

    const pool = getPool();
    const [rows] = await pool.query(
      `SELECT k.id, k.tenant_id, k.api_key_hash, k.scopes, k.active, k.expires_at, k.revoked_at,
              t.name AS tenant_name, t.status AS tenant_status
       FROM tenant_api_keys k
       JOIN tenants t ON t.id = k.tenant_id
       WHERE k.client_id = ?
         AND k.active = TRUE
         AND (k.expires_at IS NULL OR k.expires_at > NOW())
         AND k.revoked_at IS NULL`,
      [clientId]
    );

    const keyHash = sha256(rawKey);
    const match   = rows.find(r => {
      try {
        return timingSafeEqual(
          Buffer.from(r.api_key_hash, 'hex'),
          Buffer.from(keyHash, 'hex')
        );
      } catch {
        return false;
      }
    });

    if (!match) {
      return res.status(401).json({error: 'Invalid or expired API key'});
    }

    if (match.tenant_status !== 'active') {
      return res.status(403).json({error: 'Tenant account is suspended'});
    }

    const scopes = Array.isArray(match.scopes)
      ? match.scopes
      : JSON.parse(match.scopes);

    if (!scopes.includes(scope)) {
      return res.status(403).json({error: `API key does not have '${scope}' scope`});
    }

    req.tenant    = {id: match.tenant_id, name: match.tenant_name};
    req.apiClient = clientId;
    next();
  };
}
