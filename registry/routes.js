import {getPool} from '../shared/db.js';

export async function listDids(req, res) {
  try {
    const pool = getPool();
    const [rows] = await pool.query(
      `SELECT DISTINCT i.id, i.did, i.role, i.did_method, i.domain, i.created_at
       FROM identity i
       JOIN tenants t ON t.id = i.tenant_id
       JOIN issuer_accreditations a ON a.identity_id = i.id
       WHERE i.did IS NOT NULL
         AND i.role IN ('issuer', 'verifier')
         AND t.status = 'active'
         AND a.status = 'active'
         AND (a.valid_until IS NULL OR a.valid_until > NOW())
       ORDER BY i.role, i.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function listSchemas(req, res) {
  try {
    const pool = getPool();
    const [rows] = await pool.query(
      `SELECT DISTINCT cs.id, cs.slug, cs.schema_id, cs.version, cs.schema_json, cs.created_at
       FROM credential_schemas cs
       JOIN tenants t ON t.id = cs.tenant_id
       JOIN issuer_accreditations a ON a.schema_id = cs.id
       WHERE t.status = 'active'
         AND a.status = 'active'
         AND (a.valid_until IS NULL OR a.valid_until > NOW())
       ORDER BY cs.slug, cs.version DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function listRevocations(req, res) {
  try {
    const pool = getPool();
    const [rows] = await pool.query(
      `SELECT sl.id, sl.list_id, sl.purpose, sl.vc_id, sl.list_size,
              sl.next_index, sl.created_at, sl.updated_at,
              i.did AS issuer_did
       FROM status_lists sl
       JOIN identity i ON i.id = sl.identity_id
       JOIN tenants t ON t.id = sl.tenant_id
       WHERE t.status = 'active'
       ORDER BY sl.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function listAccreditations(req, res) {
  try {
    const pool = getPool();
    const [rows] = await pool.query(
      `SELECT a.id, a.trust_level, a.accreditor_did, a.valid_from, a.valid_until, a.status,
              i.did AS issuer_did, i.role,
              cs.slug AS schema_slug, cs.schema_id, cs.version
       FROM issuer_accreditations a
       JOIN identity i ON i.id = a.identity_id
       JOIN credential_schemas cs ON cs.id = a.schema_id
       JOIN tenants t ON t.id = a.tenant_id
       WHERE a.status = 'active'
         AND t.status = 'active'
         AND (a.valid_until IS NULL OR a.valid_until > NOW())
       ORDER BY i.did, cs.slug`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function createAccreditation(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {did, schema_id, trustLevel = 'self-asserted', accreditorDid, validUntil} = req.body;

    if (!did || !schema_id) {
      return res.status(400).json({error: 'did and schema_id are required'});
    }

    const pool = getPool();

    // Resolve issuer identity by DID, must belong to this tenant
    const [identRows] = await pool.query(
      `SELECT id FROM identity WHERE did = ? AND tenant_id = ? AND role = 'issuer'`,
      [did, tenantId]
    );
    if (identRows.length === 0) {
      return res.status(404).json({error: 'Issuer identity not found for this tenant'});
    }

    // Resolve schema by schema_id URL, must belong to this tenant
    const [schemaRows] = await pool.query(
      `SELECT id FROM credential_schemas WHERE schema_id = ? AND tenant_id = ?`,
      [schema_id, tenantId]
    );
    if (schemaRows.length === 0) {
      return res.status(404).json({error: 'Schema not found for this tenant'});
    }

    const identityId = identRows[0].id;
    const schemaDbId = schemaRows[0].id;

    const [result] = await pool.query(
      `INSERT INTO issuer_accreditations
         (tenant_id, identity_id, schema_id, trust_level, accreditor_did, valid_until)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [tenantId, identityId, schemaDbId, trustLevel, accreditorDid ?? null, validUntil ?? null]
    );

    res.status(201).json({id: result.insertId, created: true});
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({error: 'Accreditation already exists for this issuer and schema'});
    }
    res.status(500).json({error: err.message});
  }
}

export async function revokeAccreditation(req, res) {
  try {
    const tenantId = req.tenant.id;
    const {id}     = req.params;
    const pool     = getPool();

    const [result] = await pool.query(
      `UPDATE issuer_accreditations SET status = 'revoked' WHERE id = ? AND tenant_id = ?`,
      [id, tenantId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({error: 'Accreditation not found'});
    }
    res.json({revoked: true, id: Number(id)});
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}

export async function verifyIssuer(req, res) {
  try {
    const {issuerDid, schemaSlug} = req.query;

    if (!issuerDid || !schemaSlug) {
      return res.status(400).json({error: 'issuerDid and schemaSlug query params are required'});
    }

    const pool = getPool();
    const [rows] = await pool.query(
      `SELECT a.trust_level, a.accreditor_did, a.valid_from, a.valid_until
       FROM issuer_accreditations a
       JOIN identity i ON i.id = a.identity_id
       JOIN credential_schemas cs ON cs.id = a.schema_id
       JOIN tenants t ON t.id = a.tenant_id
       WHERE i.did = ?
         AND cs.slug = ?
         AND a.status = 'active'
         AND t.status = 'active'
         AND (a.valid_until IS NULL OR a.valid_until > NOW())
       LIMIT 1`,
      [issuerDid, schemaSlug]
    );

    if (rows.length === 0) {
      return res.json({trusted: false});
    }

    const row = rows[0];
    res.json({
      trusted:       true,
      trustLevel:    row.trust_level,
      accreditorDid: row.accreditor_did,
      validFrom:     row.valid_from,
      validUntil:    row.valid_until
    });
  } catch (err) {
    res.status(500).json({error: err.message});
  }
}
