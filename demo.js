/**
 * W3C Digital Wallet POC — End-to-End Demo
 *
 * Requires all three services to be running:
 *   npm run issuer   (port 3001)
 *   npm run holder   (port 3002)
 *   npm run verifier (port 3003)
 *
 * Flow:
 *   1.  Each party exposes its DID document
 *   2.  Issuer signs an Employee Badge VC for the Holder
 *   3.  Holder stores the VC in its wallet
 *   4.  Verifier issues a one-time challenge nonce  (classic flow)
 *   5.  Holder wraps the VC in a signed VP          (classic flow)
 *   6.  Verifier verifies the VP + embedded VC      (classic flow)
 *   7.  Verifier creates an OID4VP request with a dynamic Presentation Definition
 *   8.  Holder auto-matches credential and responds
 *   9.  Verifier validates result against PD constraints
 */

import 'dotenv/config';

const ISSUER   = process.env.ISSUER_BASE_URL   || 'http://localhost:3001';
const HOLDER   = process.env.HOLDER_BASE_URL   || 'http://localhost:3002';
const VERIFIER = process.env.VERIFIER_BASE_URL || 'http://localhost:3003';

// Default tenant credentials seeded by db/migrate.js
const CLIENT_ID = process.env.DEFAULT_CLIENT_ID || 'default-client';
const API_KEY   = process.env.DEFAULT_API_KEY   || '';

const AUTH_HEADERS = {
  'Content-Type':  'application/json',
  'x-api-client':  CLIENT_ID,
  'x-api-key':     API_KEY
};

async function authGet(url) {
  const res = await fetch(url, {headers: AUTH_HEADERS});
  if (!res.ok) throw new Error(`GET ${url} → ${res.status}: ${await res.text()}`);
  return res.json();
}

async function post(url, body) {
  const res = await fetch(url, {
    method:  'POST',
    headers: AUTH_HEADERS,
    body:    JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`POST ${url} → ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

function separator(title) {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`  ${title}`);
  console.log('─'.repeat(60));
}

async function run() {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║       W3C Digital Wallet POC — Employee Badge Demo      ║');
  console.log('╚══════════════════════════════════════════════════════════╝');

  // ── Step 1: Resolve DIDs ──────────────────────────────────────
  separator('Step 1 │ Resolve DIDs for all parties');

  const {dids: issuerDids}   = await authGet(`${ISSUER}/dids`);
  const {dids: holderDids}   = await authGet(`${HOLDER}/dids`);
  const {dids: verifierDids} = await authGet(`${VERIFIER}/dids`);

  if (!issuerDids.length)   throw new Error('No issuer identity found — run POST /create on the issuer first.');
  if (!holderDids.length)   throw new Error('No holder identity found — run POST /create on the holder first.');
  if (!verifierDids.length) throw new Error('No verifier identity found — run POST /create on the verifier first.');

  const issuerDid   = issuerDids[0].did;
  const holderDid   = holderDids[0].did;
  const verifierDid = verifierDids[0].did;

  console.log(`  Issuer   DID : ${issuerDid}`);
  console.log(`  Holder   DID : ${holderDid}`);
  console.log(`  Verifier DID : ${verifierDid}`);

  // ── Step 2: Issue Verifiable Credential ──────────────────────
  separator('Step 2 │ Issuer signs Employee Badge VC for Holder');

  const {verifiableCredential} = await post(`${ISSUER}/issue`, {
    holderDid,
    employee: {
      id:          'EMP-2024-001',
      name:        'Alice Smith',
      department:  'Engineering',
      position:    'Senior Software Engineer',
      startDate:   '2024-01-15',
      accessLevel: 'Level-3'
    }
  });

  console.log(`  VC ID        : ${verifiableCredential.id}`);
  console.log(`  VC Types     : ${verifiableCredential.type.join(', ')}`);
  console.log(`  Issuer       : ${verifiableCredential.issuer}`);
  console.log(`  Subject      : ${verifiableCredential.credentialSubject.id}`);
  console.log(`  Proof type   : ${verifiableCredential.proof.type}`);
  console.log(`  Expires      : ${verifiableCredential.expirationDate}`);

  // ── Step 3: Holder stores VC in wallet ───────────────────────
  separator('Step 3 │ Holder stores the VC in its wallet');

  const stored = await post(`${HOLDER}/credentials`, {verifiableCredential});
  console.log(`  Stored       : ${stored.stored}`);
  console.log(`  Wallet ID    : ${stored.id}`);

  // ── Step 4: Verifier issues a challenge ──────────────────────
  separator('Step 4 │ Verifier issues a one-time challenge nonce');

  const {challenge, domain} = await post(`${VERIFIER}/challenge`, {});
  console.log(`  Challenge    : ${challenge}`);
  console.log(`  Domain       : ${domain}`);

  // ── Step 5: Holder creates a Verifiable Presentation ─────────
  separator('Step 5 │ Holder creates a signed Verifiable Presentation');

  const {verifiablePresentation} = await post(`${HOLDER}/present`, {
    credentialId: verifiableCredential.id,
    challenge,
    domain
  });

  console.log(`  VP Holder    : ${verifiablePresentation.holder}`);
  console.log(`  VP Proof     : ${verifiablePresentation.proof.type}`);
  console.log(`  VP Challenge : ${verifiablePresentation.proof.challenge}`);

  // ── Step 6: Verifier verifies the Presentation ───────────────
  separator('Step 6 │ Verifier cryptographically verifies the VP');

  const result = await post(`${VERIFIER}/verify`, {verifiablePresentation});

  if (result.verified) {
    const s = result.credential.credentialSubject;
    console.log('\n  ✓  VERIFICATION SUCCESSFUL\n');
    console.log(`     Name         : ${s.name}`);
    console.log(`     Employee ID  : ${s.employeeId}`);
    console.log(`     Department   : ${s.department}`);
    console.log(`     Position     : ${s.position}`);
    console.log(`     Access Level : ${s.accessLevel}`);
    console.log(`     Start Date   : ${s.startDate}`);
    console.log(`\n     Issuer       : ${result.credential.issuer}`);
    console.log(`     Issued On    : ${result.credential.issuanceDate}`);
    console.log(`     Expires On   : ${result.credential.expirationDate}`);
  } else {
    console.log('\n  ✗  VERIFICATION FAILED\n');
    console.log(`     Reason: ${result.error}`);
    process.exit(1);
  }

  // ── Step 7: OID4VP — Verifier creates dynamic request ────────
  separator('Step 7 │ Verifier creates OID4VP request (Presentation Definition)');

  // The verifier declares exactly what it needs:
  //   - credential type must be EmployeeBadgeCredential
  //   - must have been issued by this specific issuer DID
  //   - format: ldp_vc (VC-LD with Ed25519 proof)
  //   - required claims: name, department, position
  const oid4vpRequest = await post(`${VERIFIER}/oid4vp/request`, {
    credentialType:   'EmployeeBadgeCredential',
    issuerDid,
    credentialFormat: 'ldp_vc',
    requiredClaims:   ['name', 'department', 'position']
  });

  console.log(`  State        : ${oid4vpRequest.state}`);
  console.log(`  Request URI  : ${oid4vpRequest.requestUri}`);
  console.log(`  OID4VP URI   : ${oid4vpRequest.openid4vpUri.substring(0, 60)}...`);
  console.log('  (SVG QR code available in oid4vpRequest.qrcode)');

  // ── Step 8: Holder responds to OID4VP request ────────────────
  separator('Step 8 │ Holder responds to OID4VP request');

  // Holder receives the openid4vp:// URI (e.g. via QR scan), fetches the
  // signed request JWT, automatically matches the right credential in its
  // wallet against the Presentation Definition, and submits the VP.
  const holderResponse = await post(`${HOLDER}/oid4vp/initiate`, {
    requestUri: oid4vpRequest.openid4vpUri
  });

  console.log(`  Submitted    : ${holderResponse.submitted}`);
  console.log(`  Holder DID   : ${holderResponse.holder}`);
  console.log(`  State        : ${holderResponse.state}`);

  // ── Step 9: Verifier checks OID4VP result ────────────────────
  separator('Step 9 │ Verifier validates result against Presentation Definition');

  const oid4vpResult = await authGet(`${VERIFIER}/oid4vp/result/${oid4vpRequest.state}`);

  if (oid4vpResult.verified) {
    const s = oid4vpResult.credential?.credentialSubject ?? oid4vpResult.disclosedClaims ?? {};
    console.log('\n  ✓  OID4VP VERIFICATION SUCCESSFUL\n');
    console.log(`     Format       : ${oid4vpResult.format}`);
    console.log(`     Holder       : ${oid4vpResult.holder}`);
    console.log(`     Issuer       : ${oid4vpResult.credential?.issuer ?? oid4vpResult.issuer}`);
    console.log(`     Name         : ${s.name}`);
    console.log(`     Department   : ${s.department}`);
    console.log(`     Position     : ${s.position}`);
    console.log(`     Verified At  : ${oid4vpResult.verifiedAt}`);
  } else {
    console.log('\n  ✗  OID4VP VERIFICATION FAILED\n');
    console.log(`     Reason: ${oid4vpResult.error}`);
    process.exit(1);
  }

  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║            Demo Complete (Classic + OID4VP)             ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');
}

run().catch(err => {
  console.error('\n[Demo] Fatal error:', err.message);
  process.exit(1);
});
