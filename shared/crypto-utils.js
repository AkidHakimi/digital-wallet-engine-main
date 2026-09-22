import {hkdfSync, randomBytes, createCipheriv, createDecipheriv} from 'crypto';

// ── KMS abstraction boundary ──────────────────────────────────────────────
// To swap to AWS KMS: replace deriveMasterKey() with KMS.GenerateDataKey,
// and encryptPrivateKey/decryptPrivateKey with KMS.Encrypt/Decrypt envelope.
// The rest of the codebase only calls these two exports.
// ─────────────────────────────────────────────────────────────────────────

let _masterKey = null;

function getMasterKey() {
  if (_masterKey) return _masterKey;
  const raw = process.env.KMS_MASTER_KEY;
  if (!raw || raw.length !== 64) {
    throw new Error('KMS_MASTER_KEY must be set to exactly 64 hex chars (32 bytes)');
  }
  _masterKey = Buffer.from(raw, 'hex');
  return _masterKey;
}

// HKDF-SHA256 binds the derived key to this specific DID so that
// compromising one derived key cannot decrypt other keys.
function deriveKeyEncryptionKey(keyDid) {
  const master = getMasterKey();
  const salt   = Buffer.alloc(32);
  const info   = Buffer.from(keyDid, 'utf8');
  return Buffer.from(hkdfSync('sha256', master, salt, info, 32));
}

// Stored format: base64(iv):base64(authTag):base64(ciphertext)
export function encryptPrivateKey(jwkObj, keyDid) {
  const kek       = deriveKeyEncryptionKey(keyDid);
  const iv        = randomBytes(12);
  const cipher    = createCipheriv('aes-256-gcm', kek, iv);
  const plaintext = Buffer.from(JSON.stringify(jwkObj), 'utf8');
  const ct        = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag   = cipher.getAuthTag();
  return `${iv.toString('base64')}:${authTag.toString('base64')}:${ct.toString('base64')}`;
}

export function decryptPrivateKey(stored, keyDid) {
  const kek              = deriveKeyEncryptionKey(keyDid);
  const [ivB64, tagB64, ctB64] = stored.split(':');
  const iv        = Buffer.from(ivB64, 'base64');
  const authTag   = Buffer.from(tagB64, 'base64');
  const ct        = Buffer.from(ctB64, 'base64');
  const decipher  = createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(authTag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}
