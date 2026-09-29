import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import {getPool} from './db.js';

const ajv = new Ajv({allErrors: true});
addFormats(ajv);

// In-memory schema cache: Map<"tenantId:slug:version", compiledValidator>
const _schemaCache = new Map();

function cacheKey(tenantId, slug, version) {
  return `${tenantId}:${slug}:${version}`;
}

export async function loadSchema(tenantId, slug, version = null) {
  const pool = getPool();
  const query = version
    ? 'SELECT * FROM credential_schemas WHERE tenant_id = ? AND slug = ? AND version = ? LIMIT 1'
    : 'SELECT * FROM credential_schemas WHERE tenant_id = ? AND slug = ? ORDER BY id DESC LIMIT 1';
  const params = version ? [tenantId, slug, version] : [tenantId, slug];
  const [rows] = await pool.query(query, params);
  if (rows.length === 0) throw new Error(`Schema not found: ${slug}${version ? '@' + version : ''}`);
  return rows[0];
}

function getValidator(tenantId, slug, version, schemaJson) {
  const key = cacheKey(tenantId, slug, version);
  if (_schemaCache.has(key)) return _schemaCache.get(key);
  const schema    = typeof schemaJson === 'string' ? JSON.parse(schemaJson) : schemaJson;
  const validate  = ajv.compile(schema);
  _schemaCache.set(key, validate);
  return validate;
}

export function validateCredentialSubject(schemaRow, subject) {
  const validate = getValidator(
    schemaRow.tenant_id, schemaRow.slug, schemaRow.version,
    schemaRow.schema_json
  );
  const valid = validate(subject);
  return {
    valid,
    errors: valid ? [] : validate.errors.map(e => `${e.instancePath || '/'} ${e.message}`)
  };
}

// Validates a subject against a raw JSON schema (for verifier-side checks without DB lookup)
export function validateSubjectRaw(schemaJson, subject) {
  const schema   = typeof schemaJson === 'string' ? JSON.parse(schemaJson) : schemaJson;
  const validate = ajv.compile(schema);
  const valid    = validate(subject);
  return {
    valid,
    errors: valid ? [] : validate.errors.map(e => `${e.instancePath || '/'} ${e.message}`)
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export class SchemaVersionConflictError extends Error {}

// A published version is immutable: credentials already issued under it rely on
// its definition. Re-registering the identical definition is a no-op.
// Returns {schemaId, created}.
export async function saveSchema(tenantId, slug, version, schemaJson, baseUrl) {
  const pool     = getPool();
  const schemaId = `${baseUrl}/schemas/${slug}`;

  const [existing] = await pool.query(
    'SELECT schema_json FROM credential_schemas WHERE tenant_id = ? AND slug = ? AND version = ? LIMIT 1',
    [tenantId, slug, version]
  );
  if (existing.length) {
    const stored = typeof existing[0].schema_json === 'string' ? JSON.parse(existing[0].schema_json) : existing[0].schema_json;
    if (canonicalJson(stored) === canonicalJson(schemaJson)) return {schemaId, created: false};
    throw new SchemaVersionConflictError(
      `Schema "${slug}" version ${version} is already registered with a different definition. ` +
      'Register the change under a new version number.'
    );
  }

  await pool.query(
    'INSERT INTO credential_schemas (tenant_id, slug, schema_id, version, schema_json) VALUES (?, ?, ?, ?, ?)',
    [tenantId, slug, schemaId, version, JSON.stringify(schemaJson)]
  );
  return {schemaId, created: true};
}

// Drops blank values ('' / whitespace / null) so an unfilled form field counts as
// "not provided" and the schema's `required` list is actually enforced.
export function withoutBlankValues(subject) {
  return Object.fromEntries(Object.entries(subject ?? {}).filter(([, v]) =>
    v !== null && v !== undefined && !(typeof v === 'string' && v.trim() === '')));
}
