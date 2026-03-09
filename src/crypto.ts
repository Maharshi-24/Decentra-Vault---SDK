/**
 * Client-side AES-256-GCM decryption.
 *
 * Uses the Web Crypto API (globalThis.crypto.subtle) which works in:
 *   - Modern browsers (Chrome, Firefox, Safari, Edge)
 *   - Node.js 18+
 *
 * The server NEVER decrypts — it returns encrypted bytes + key material.
 * All decryption happens here, inside the developer's app.
 */

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decrypt a file encrypted with AES-256-GCM.
 *
 * @param encryptedBase64 - Base64-encoded encrypted file bytes (from server)
 * @param keyHex          - Hex-encoded 256-bit AES key (unwrapped by server)
 * @param ivHex           - Hex-encoded 96-bit IV used during encryption
 * @param authTagHex      - Hex-encoded 128-bit GCM authentication tag
 * @returns               - Decrypted file as Uint8Array
 */
export async function decryptFile(
  encryptedBase64: string,
  keyHex: string,
  ivHex: string,
  authTagHex: string
): Promise<Uint8Array> {
  const keyBytes = hexToBytes(keyHex);
  const iv = hexToBytes(ivHex);
  const ciphertext = base64ToBytes(encryptedBase64);
  const authTag = hexToBytes(authTagHex);

  // Web Crypto AES-GCM expects: ciphertext || authTag (appended, not separate)
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);

  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    combined
  );

  return new Uint8Array(decrypted);
}
