// ── Upload ────────────────────────────────────────────────────────────────────

export interface UploadResult {
  /** Unique file ID — use this to retrieve or verify the file later */
  fileId: string;
  /** SHA-256 hash of the encrypted file bytes */
  hash: string;
  /** IPFS Content Identifier */
  cid: string;
  /** Public IPFS gateway URL (encrypted bytes only — unreadable without key) */
  ipfsUrl: string;
  /** Blockchain anchoring status at time of upload response */
  blockchainStatus: 'pending' | 'confirmed' | 'failed';
}

// ── Retrieve ─────────────────────────────────────────────────────────────────

export interface RetrieveResult {
  /** Decrypted file bytes — write directly to disk or use as Blob */
  file: Uint8Array;
  /** Original filename */
  name: string;
  /** MIME type e.g. "application/pdf" */
  mimeType: string;
  /** IPFS integrity check result */
  integrity: 'ok' | 'failed';
  /** Blockchain verification details */
  blockchain: {
    verified: boolean;
    status: 'pending' | 'confirmed' | 'failed';
    tx: string | null;
    reason: string;
  };
}

// ── Verify ────────────────────────────────────────────────────────────────────

export interface VerifyResult {
  /** true = file is untampered and hash matches on-chain record */
  verified: boolean;
  /** Human-readable explanation */
  reason: string;
  fileId: string;
  hash: string;
  onChainHash: string | null;
  blockchainTx: string | null;
}

// ── File list ─────────────────────────────────────────────────────────────────

export interface FileInfo {
  fileId: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  hash: string;
  cid: string;
  createdAt: string;
}

// ── Constructor options ───────────────────────────────────────────────────────

export interface DecentraVaultOptions {
  /**
   * Override the API base URL.
   * Defaults to 'https://api.decentravault.com'
   * Use 'http://localhost:3000/api' during local development.
   */
  baseUrl?: string;
}
