import crypto from 'crypto';

// The master key never lives in code, the frontend, or the database as
// plain data. It is read from an environment secret only.
function getKey(): Buffer {
  const hex = process.env.AES_MASTER_KEY_HEX;
  if (!hex || hex.length !== 64) {
    throw new Error(
      'AES_MASTER_KEY_HEX must be set in the environment as 64 hex characters (32 bytes).'
    );
  }
  return Buffer.from(hex, 'hex');
}

export interface EncryptedPayload {
  blob: string;
  iv: string;
  tag: string;
}

// Encrypts a JS object (turned into JSON text) with AES-256-GCM.
export function encryptObject(obj: unknown): EncryptedPayload {
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
export function decryptObject({ blob, iv, tag }: EncryptedPayload): any {
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
