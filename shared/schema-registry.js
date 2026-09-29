// Schema lookups shared by issuer and verifier: which schema a URL points at,
// which credential type a schema defines, and which claims it contains.
//
// Accepted schema URL forms
//   <issuer>/schemas/<slug>                   (what credentials embed today; newest version)
//   <issuer>/schemas/<slug>?version=<version>
//   <issuer>/schemas/<slug>/<version>

import {getPool} from './db.js';

const SLUG_RE    = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const CLAIM_RE   = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/;

export function isValidClaimName(name) {
  return typeof name === 'string' && CLAIM_RE.test(name);
}

// Returns {base, slug, version|null} or null if the URL is not a schema URL.
export function parseSchemaUrl(url) {
  if (typeof url !== 'string' || !url) return null;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  const parts = u.pathname.split('/').filter(Boolean);
  const idx   = parts.lastIndexOf('schemas');
  if (idx === -1) return null;
  let rest;
  try { rest = parts.slice(idx + 1).map(decodeURIComponent); } catch { return null; }
  if (rest.length < 1 || rest.length > 2) return null;

  const slug    = rest[0];
  const version = rest[1] ?? u.searchParams.get('version') ?? null;
  if (!SLUG_RE.test(slug)) return null;
  if (version !== null && !VERSION_RE.test(version)) return null;

  const basePath = parts.slice(0, idx).join('/');
  return {base: `${u.origin}${basePath ? '/' + basePath : ''}`, slug, version};
}

// The credential type a schema defines. Same rule the demo UI uses to pre-fill
// "Credential Type": schema.title without a trailing "Subject", otherwise
// PascalCase(slug) + "Credential"  (student-graduation → StudentGraduationCredential).
export function credentialTypeFor(slug, schemaJson) {
  const schema = typeof schemaJson === 'string' ? JSON.parse(schemaJson) : schemaJson;
  const title  = typeof schema?.title === 'string' ? schema.title.trim() : '';
  if (title) {
    const t = title.replace(/Subject$/i, '');
    if (t) return t;
  }
  return slug.split(/[-_]/).filter(Boolean)
    .map(s => s.charAt(0).toUpperCase() + s.slice(1)).join('') + 'Credential';
}

function describeRow(row) {
  const schema = typeof row.schema_json === 'string' ? JSON.parse(row.schema_json) : row.schema_json;
  return {
    rowId:          row.id,
    tenantId:       row.tenant_id,
    slug:           row.slug,
    version:        row.version,
    schemaId:       row.schema_id,
    credentialType: credentialTypeFor(row.slug, schema),
    schema
  };
}

// Registered schema versions a URL refers to, newest first. A row only matches
// when the URL's host and path match where that row was published, so the right
// slug on the wrong host (or a typo in the host) does not resolve.
export async function resolveSchemaUrl(url) {
  const parsed = parseSchemaUrl(url);
  if (!parsed) return {parsed: null, candidates: []};

  const pool   = getPool();
  const params = parsed.version ? [parsed.slug, parsed.version] : [parsed.slug];
  const [rows] = await pool.query(
    `SELECT * FROM credential_schemas WHERE slug = ? ${parsed.version ? 'AND version = ?' : ''}
     ORDER BY id DESC`,
    params
  );
  const published = `${parsed.base}/schemas/${encodeURIComponent(parsed.slug)}`;
  const candidates = rows
    .filter(r => r.schema_id === published || r.schema_id === `${published}/${encodeURIComponent(r.version)}`)
    .map(describeRow);
  return {parsed, candidates};
}

// Newest version of every schema whose credential type equals `credentialType`.
export async function findSchemasByCredentialType(credentialType) {
  const pool   = getPool();
  const [rows] = await pool.query('SELECT * FROM credential_schemas ORDER BY id DESC');
  const latest = new Map();
  for (const row of rows) {
    const key = `${row.tenant_id}:${row.slug}`;
    if (!latest.has(key)) latest.set(key, describeRow(row));
  }
  return [...latest.values()].filter(d => d.credentialType === credentialType);
}

// Does the schema define `claim` ("name" or nested "address.city")?
export function schemaHasClaim(schema, claim) {
  let node = schema;
  for (const part of claim.split('.')) {
    if (!node || typeof node !== 'object' || !node.properties) return false;
    if (!Object.prototype.hasOwnProperty.call(node.properties, part)) return false;
    node = node.properties[part];
  }
  return true;
}

export function schemaClaimNames(schema) {
  return Object.keys(schema?.properties ?? {});
}
