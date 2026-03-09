// src/crypto.ts
function hexToBytes(hex) {
  const buf = new ArrayBuffer(hex.length / 2);
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
function base64ToBytes(b64) {
  const binary = atob(b64);
  const buf = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
async function decryptFile(encryptedBase64, keyHex, ivHex, authTagHex) {
  const keyBytes = hexToBytes(keyHex);
  const iv = hexToBytes(ivHex);
  const ciphertext = base64ToBytes(encryptedBase64);
  const authTag = hexToBytes(authTagHex);
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    combined
  );
  return new Uint8Array(decrypted);
}

// src/index.ts
var DEFAULT_BASE_URL = "https://decentra-vault.onrender.com/api";
var DecentraVault = class {
  constructor(apiKey, options = {}) {
    if (!apiKey || typeof apiKey !== "string") {
      throw new Error("DecentraVault: A valid API key is required.");
    }
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
  }
  // ── Internal helpers ────────────────────────────────────────────────────────
  get authHeaders() {
    return { "x-api-key": this.apiKey };
  }
  async request(path, options = {}) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        ...options.headers ?? {},
        ...this.authHeaders
      }
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data?.error ?? `DecentraVault API error ${res.status}: ${path}`);
    }
    return data;
  }
  // ── Public API ──────────────────────────────────────────────────────────────
  /**
   * Encrypt and upload a file.
   *
   * The file is AES-256-GCM encrypted server-side, stored on IPFS via Pinata,
   * and its hash is anchored on Polygon Amoy. Returns immediately with
   * `blockchainStatus: 'pending'` — use `waitForBlockchain()` or `verify()` to
   * confirm on-chain anchoring.
   *
   * @param file      File data as Blob, Buffer, or Uint8Array
   * @param filename  Original filename (stored encrypted — never sent to IPFS)
   * @param mimeType  MIME type e.g. 'application/pdf'
   */
  async upload(file, filename = "file", mimeType = "application/octet-stream") {
    let blob;
    if (file instanceof Blob) {
      blob = file;
    } else if (file instanceof ArrayBuffer) {
      blob = new Blob([file], { type: mimeType });
    } else {
      const plain = file.buffer instanceof ArrayBuffer ? file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength) : new Uint8Array(file).buffer;
      blob = new Blob([plain], { type: mimeType });
    }
    const form = new FormData();
    form.append("file", blob, filename);
    const res = await fetch(`${this.baseUrl}/files/upload`, {
      method: "POST",
      headers: this.authHeaders,
      body: form
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error ?? "Upload failed");
    return {
      fileId: data.fileId,
      hash: data.hash,
      cid: data.cid,
      ipfsUrl: data.ipfsUrl,
      blockchainStatus: data.blockchain_status
    };
  }
  /**
   * Download and decrypt a file.
   *
   * Fetches encrypted bytes from IPFS, verifies integrity against the stored
   * hash and the Polygon blockchain, then decrypts locally using the Web Crypto
   * API. The server never sees the plaintext.
   *
   * @param fileId  File ID returned from upload()
   */
  async retrieve(fileId) {
    const data = await this.request(`/files/${fileId}/download`);
    if (data.integrity !== "ok") {
      throw new Error(`DecentraVault: Integrity check failed for file ${fileId}`);
    }
    const decrypted = await decryptFile(
      data.encrypted.data,
      data.encrypted.key,
      data.encrypted.iv,
      data.encrypted.authTag
    );
    return {
      file: decrypted,
      name: data.file.name,
      mimeType: data.file.mimeType,
      integrity: data.integrity,
      blockchain: data.blockchain
    };
  }
  /**
   * Verify a file's integrity against the Polygon blockchain.
   *
   * Does NOT download the file. Fetches the on-chain transaction and compares
   * the hash in the `data` field against the stored hash.
   *
   * @param fileId  File ID returned from upload()
   */
  async verify(fileId) {
    const data = await this.request(`/files/${fileId}/verify`);
    return {
      verified: data.verified,
      reason: data.reason,
      fileId: data.file_id,
      hash: data.hash,
      onChainHash: data.on_chain_hash ?? null,
      blockchainTx: data.blockchain_tx ?? null
    };
  }
  /**
   * List all files uploaded with this API key.
   */
  async list() {
    const data = await this.request("/files");
    return (data.files ?? []).map((f) => ({
      fileId: f.file_id,
      originalName: f.original_name,
      mimeType: f.mime_type,
      sizeBytes: f.size_bytes,
      hash: f.hash,
      cid: f.cid,
      createdAt: f.created_at
    }));
  }
  /**
   * Permanently delete a file and its encryption key.
   *
   * @param fileId  File ID returned from upload()
   */
  async delete(fileId) {
    await this.request(`/files/${fileId}`, { method: "DELETE" });
  }
  /**
   * Poll until blockchain anchoring is confirmed or failed.
   *
   * Useful after upload() when you need the on-chain TX hash before proceeding.
   *
   * @param fileId      File ID returned from upload()
   * @param timeoutMs   Max wait time in milliseconds (default: 60000)
   *
   * @example
   * ```typescript
   * const { fileId } = await vault.upload(file, 'doc.pdf');
   * const status = await vault.waitForBlockchain(fileId);
   * console.log(status); // 'confirmed'
   * ```
   */
  async waitForBlockchain(fileId, timeoutMs = 6e4) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const data = await this.request(`/files/${fileId}`);
      const status = data.file?.blockchain_status;
      if (status === "confirmed" || status === "failed") {
        return status;
      }
      await new Promise((r) => setTimeout(r, 3e3));
    }
    throw new Error(`DecentraVault: Blockchain confirmation timed out for file ${fileId}`);
  }
};
export {
  DecentraVault
};
