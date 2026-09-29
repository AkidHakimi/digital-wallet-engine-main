// Checks run when a verifier CREATES a presentation request:
// the credential type, the schema URL and the required claims must agree,
// otherwise no request is created.

import {
  resolveSchemaUrl, findSchemasByCredentialType,
  schemaHasClaim, schemaClaimNames, isValidClaimName
} from '../shared/schema-registry.js';

export class RequestConstraintError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code   = code;
    this.extra  = extra;
  }

  toBody() {
    return {error: this.code, details: this.message, ...this.extra};
  }
}

function reject(status, code, message, extra) {
  throw new RequestConstraintError(status, code, message, extra);
}

function normaliseClaims(requiredClaims) {
  if (requiredClaims == null) return [];
  if (!Array.isArray(requiredClaims)) {
    reject(400, 'invalid_request', 'requiredClaims must be an array of claim names');
  }
  const claims = [...new Set(requiredClaims.map(c => String(c).trim()).filter(Boolean))];
  const bad    = claims.filter(c => !isValidClaimName(c));
  if (bad.length) reject(400, 'invalid_claim_name', `Invalid claim name(s): ${bad.join(', ')}`);
  return claims;
}

function text(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

// Validates {credentialType, schemaUrl, requiredClaims}.
// Returns the normalised values to build the request from:
//   {credentialType, schemaUrl, requiredClaims, schema}
// schemaUrl is replaced by the URL the schema is registered under, i.e. the
// value credentials actually carry in credentialSchema.id.
// Throws RequestConstraintError when they don't tally.
export async function validateRequestConstraints({credentialType, schemaUrl, requiredClaims}) {
  const claims = normaliseClaims(requiredClaims);
  credentialType = text(credentialType);
  schemaUrl      = text(schemaUrl);

  // ── Schema URL given: it must point at a registered schema ────────────
  if (schemaUrl) {
    const {parsed, candidates} = await resolveSchemaUrl(schemaUrl);
    if (!parsed) {
      reject(400, 'invalid_schema_url',
        `"${schemaUrl}" is not a schema URL. Expected <issuer>/schemas/<slug>`);
    }
    if (candidates.length === 0) {
      reject(400, 'invalid_schema_url',
        `No registered schema at "${schemaUrl}" (slug "${parsed.slug}"` +
        `${parsed.version ? `, version "${parsed.version}"` : ''}). Check the host, slug and version.`);
    }

    // Newest matching version (a title change between versions can change the type)
    const target = credentialType
      ? candidates.find(c => c.credentialType === credentialType)
      : candidates[0];
    if (!target) {
      reject(400, 'credential_type_schema_mismatch',
        `Schema "${parsed.slug}" defines credential type "${candidates[0].credentialType}", ` +
        `not "${credentialType}"`,
        {expectedCredentialType: candidates[0].credentialType});
    }

    const unknown = claims.filter(c => !schemaHasClaim(target.schema, c));
    if (unknown.length) {
      reject(400, 'claims_not_in_schema',
        `Claim(s) ${unknown.join(', ')} are not defined by ${target.credentialType} ` +
        `(schema ${target.slug}@${target.version})`,
        {unknownClaims: unknown, allowedClaims: schemaClaimNames(target.schema)});
    }

    return {
      credentialType: target.credentialType,
      schemaUrl:      target.schemaId,
      requiredClaims: claims,
      schema: {slug: target.slug, version: target.version, schemaId: target.schemaId,
               credentialType: target.credentialType}
    };
  }

  // ── Only a credential type: claims are checked against its schema ─────
  if (credentialType) {
    const matches = await findSchemasByCredentialType(credentialType);
    if (matches.length === 0) {
      if (claims.length) {
        reject(400, 'unknown_credential_type',
          `No registered schema defines credential type "${credentialType}", so the required claims ` +
          `cannot be checked. Use a registered credential type or give a schemaUrl.`);
      }
      return {credentialType, schemaUrl: null, requiredClaims: [], schema: null};
    }

    const target = matches.find(m => claims.every(c => schemaHasClaim(m.schema, c)));
    if (!target) {
      const unknown = claims.filter(c => !matches.some(m => schemaHasClaim(m.schema, c)));
      const listed  = unknown.length ? unknown : claims;
      reject(400, 'claims_not_in_schema',
        `Claim(s) ${listed.join(', ')} are not defined by ${credentialType} ` +
        `(schema ${matches[0].slug}@${matches[0].version})`,
        {unknownClaims: listed, allowedClaims: schemaClaimNames(matches[0].schema)});
    }
    return {
      credentialType,
      schemaUrl:      null,
      requiredClaims: claims,
      schema: {slug: target.slug, version: target.version, schemaId: target.schemaId,
               credentialType: target.credentialType}
    };
  }

  // ── Neither: required claims can't be checked against anything ────────
  if (claims.length) {
    reject(400, 'credential_type_required',
      'requiredClaims need a credentialType or schemaUrl so they can be checked against the credential schema');
  }
  return {credentialType: null, schemaUrl: null, requiredClaims: [], schema: null};
}

// Pulls type / schema / claims out of a caller-supplied presentation_definition
// so it goes through the same checks as the simple form.
export function constraintInputsFromDefinition(definition) {
  const descriptor = definition?.input_descriptors?.[0];
  const out = {credentialType: null, schemaUrl: null, requiredClaims: []};
  for (const field of descriptor?.constraints?.fields ?? []) {
    const paths = field.path ?? [];
    if (paths.includes('$.type')) {
      out.credentialType = field.filter?.contains?.const ?? out.credentialType;
    } else if (paths.includes('$.vct')) {
      out.credentialType = field.filter?.const ?? field.filter?.enum?.[0] ?? out.credentialType;
    } else if (paths.some(p => p.startsWith('$.credentialSchema'))) {
      out.schemaUrl = field.filter?.const ?? field.filter?.enum?.[0] ?? out.schemaUrl;
    } else {
      for (const p of paths) {
        const m = p.match(/^\$\.credentialSubject\.([A-Za-z0-9_.]+)$/);
        if (m) { out.requiredClaims.push(m[1]); break; }
      }
    }
  }
  return out;
}

// Same checks for a caller-supplied presentation_definition. The definition is
// not rewritten; the check only decides whether the request may be created.
export async function validateDefinition(definition) {
  return validateRequestConstraints(constraintInputsFromDefinition(definition));
}
