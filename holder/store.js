import {getPool} from '../shared/db.js';

export async function save(credential, tenantId) {
  const pool = getPool();
  const id   = `vc-ld:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  await pool.query(
    `INSERT INTO credentials
       (credential_id, credential, issuer_did, subject_did, issuance_date, expiration_date, tenant_id)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      JSON.stringify(credential),
      credential.issuer,
      credential.credentialSubject?.id ?? '',
      new Date(credential.issuanceDate),
      credential.expirationDate ? new Date(credential.expirationDate) : null,
      tenantId ?? null
    ]
  );
  return id;
}

export async function saveSDJwt(sdJwt, tenantId) {
  const pool = getPool();
  const id   = `sd-jwt:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  await pool.query(
    `INSERT INTO credentials
       (credential_id, credential, issuer_did, subject_did, issuance_date,
        tenant_id, credential_format, sd_jwt)
     VALUES (?, '{}', '', '', NOW(), ?, 'sd-jwt', ?)`,
    [id, tenantId ?? null, sdJwt]
  );
  return id;
}

export async function load(id, tenantId = null) {
  const pool  = getPool();
  const where = tenantId ? 'WHERE credential_id = ? AND tenant_id = ?' : 'WHERE credential_id = ?';
  const args  = tenantId ? [id, tenantId] : [id];
  const [rows] = await pool.query(
    `SELECT credential_id, credential, credential_format, sd_jwt FROM credentials ${where}`,
    args
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    id:                row.credential_id,
    credential_format: row.credential_format,
    vc:                row.credential_format === 'vc-ld' ? JSON.parse(row.credential) : null,
    sd_jwt:            row.sd_jwt ?? null
  };
}

export async function list(tenantId = null) {
  const pool  = getPool();
  const where = tenantId ? 'WHERE tenant_id = ?' : '';
  const [rows] = await pool.query(
    `SELECT credential_id, credential, credential_format, sd_jwt, stored_at
     FROM credentials ${where} ORDER BY stored_at DESC`,
    tenantId ? [tenantId] : []
  );
  return rows.map(r => ({
    id:     r.credential_id,
    format: r.credential_format,
    vc:     r.credential_format === 'vc-ld' ? JSON.parse(r.credential) : null,
    sdJwt:  r.sd_jwt ?? null,
    storedAt: r.stored_at
  }));
}
