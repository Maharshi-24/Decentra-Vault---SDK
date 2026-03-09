import { decryptFile } from './crypto.js';
import type {
  UploadResult,
  RetrieveResult,
  VerifyResult,
  FileInfo,
  DecentraVaultOptions,
} from './types.js';

export type { UploadResult, RetrieveResult, VerifyResult, FileInfo, DecentraVaultOptions };

const DEFAULT_BASE_URL = 'https://api.decentravault.com';

/**
 * DecentraVault SDK
 *
 * Encrypted decentralized file storage — one API key, zero complexity.
 *
 * @example
 * ```typescript
 * import { DecentraVault } from 'decentravault';
 *
 * const vault = new DecentraVault('dv_your_api_key', {
 *   baseUrl: 'http://localhost:3000/api'  // omit in production
 * });
 *
 * // Upload
 * const { fileId } = await vault.upload(file, 'report.pdf', 'application/pdf');
 *
 * // Retrieve (automatically decrypts)
 * const { file, name, integrity } = await vault.retrieve(fileId);
 *
 * // Verify integrity without downloading
 * const { verified } = await vault.verify(fileId);
 * ```
 */
export class DecentraVault {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(apiKey: string, options: DecentraVaultOptions = {}) {
    if (!apiKey || typeof apiKey !== 'string') {
      throw new Error('DecentraVault: A valid API key is required.');
    }
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  private get authHeaders(): Record<string, string> {
    return { 'x-api-key': this.apiKey };
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        ...(options.headers as Record<string, string> ?? {}),
        ...this.authHeaders,
      },
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data?.error ?? `DecentraVault API error ${res.status}: ${path}`);
    }
    return data as T;
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
  async upload(
    file: Blob | Uint8Array | ArrayBuffer,
    filename = 'file',
    mimeType = 'application/octet-stream'
  ): Promise<UploadResult> {
    let blob: Blob;
    if (file instanceof Blob) {
      blob = file;
    } else if (file instanceof ArrayBuffer) {
      blob = new Blob([file], { type: mimeType });
    } else {
      // Uint8Array — extract a plain ArrayBuffer slice to satisfy strict DOM types
      const plain: ArrayBuffer = file.buffer instanceof ArrayBuffer
        ? file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength)
        : new Uint8Array(file).buffer as ArrayBuffer;
      blob = new Blob([plain], { type: mimeType });
    }
    const form = new FormData();
    form.append('file', blob, filename);

    const res = await fetch(`${this.baseUrl}/files/upload`, {
      method: 'POST',
      headers: this.authHeaders,
      body: form,
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data?.error ?? 'Upload failed');

    return {
      fileId: data.fileId,
      hash: data.hash,
      cid: data.cid,
      ipfsUrl: data.ipfsUrl,
      blockchainStatus: data.blockchain_status,
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
  async retrieve(fileId: string): Promise<RetrieveResult> {
    const data = await this.request<any>(`/files/${fileId}/download`);

    if (data.integrity !== 'ok') {
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
      blockchain: data.blockchain,
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
  async verify(fileId: string): Promise<VerifyResult> {
    const data = await this.request<any>(`/files/${fileId}/verify`);
    return {
      verified: data.verified,
      reason: data.reason,
      fileId: data.file_id,
      hash: data.hash,
      onChainHash: data.on_chain_hash ?? null,
      blockchainTx: data.blockchain_tx ?? null,
    };
  }

  /**
   * List all files uploaded with this API key.
   */
  async list(): Promise<FileInfo[]> {
    const data = await this.request<any>('/files');
    return (data.files ?? []).map((f: any) => ({
      fileId: f.file_id,
      originalName: f.original_name,
      mimeType: f.mime_type,
      sizeBytes: f.size_bytes,
      hash: f.hash,
      cid: f.cid,
      createdAt: f.created_at,
    }));
  }

  /**
   * Permanently delete a file and its encryption key.
   *
   * @param fileId  File ID returned from upload()
   */
  async delete(fileId: string): Promise<void> {
    await this.request(`/files/${fileId}`, { method: 'DELETE' });
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
  async waitForBlockchain(
    fileId: string,
    timeoutMs = 60_000
  ): Promise<'confirmed' | 'failed'> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const data = await this.request<any>(`/files/${fileId}`);
      const status: string = data.file?.blockchain_status;

      if (status === 'confirmed' || status === 'failed') {
        return status as 'confirmed' | 'failed';
      }

      await new Promise((r) => setTimeout(r, 3000));
    }

    throw new Error(`DecentraVault: Blockchain confirmation timed out for file ${fileId}`);
  }
}
