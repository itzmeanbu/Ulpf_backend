const crypto = require('crypto');

// The master key never lives in code, the frontend, or the database as
// plain data. It is read from an environment secret only.
function getKey() {
  const hex = process.env.AES_MASTER_KEY_HEX;
  if (!hex || hex.length !== 64) {
    throw new Error(
      'AES_MASTER_KEY_HEX must be set in the environment as 64 hex characters (32 bytes).'
    );
  }
  return Buffer.from(hex, 'hex');
}

// Encrypts a JS object (turned into JSON text) with AES-256-GCM.
// Returns three separate pieces: the ciphertext, the IV used, and the
// authentication tag, all base64 so they store cleanly as text.
function encryptObject(obj) {
  const key = getKey();
  const iv = crypto.randomBytes(12); // 96-bit IV is standard for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    blob: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

// Reverses encryptObject - only ever called from the authorized unlock
// route, never automatically when a log is simply listed or viewed.
function decryptObject({ blob, iv, tag }) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(blob, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString('utf8'));
}

module.exports = { encryptObject, decryptObject };
