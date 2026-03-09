interface UploadResult {
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
interface RetrieveResult {
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
interface VerifyResult {
    /** true = file is untampered and hash matches on-chain record */
    verified: boolean;
    /** Human-readable explanation */
    reason: string;
    fileId: string;
    hash: string;
    onChainHash: string | null;
    blockchainTx: string | null;
}
interface FileInfo {
    fileId: string;
    originalName: string;
    mimeType: string;
    sizeBytes: number;
    hash: string;
    cid: string;
    createdAt: string;
}
interface DecentraVaultOptions {
    /**
     * Override the API base URL.
     * Defaults to 'https://decentra-vault.onrender.com/api'
     * Use 'http://localhost:3000/api' during local development.
     */
    baseUrl?: string;
}

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
declare class DecentraVault {
    private readonly apiKey;
    private readonly baseUrl;
    constructor(apiKey: string, options?: DecentraVaultOptions);
    private get authHeaders();
    private request;
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
    upload(file: Blob | Uint8Array | ArrayBuffer, filename?: string, mimeType?: string): Promise<UploadResult>;
    /**
     * Download and decrypt a file.
     *
     * Fetches encrypted bytes from IPFS, verifies integrity against the stored
     * hash and the Polygon blockchain, then decrypts locally using the Web Crypto
     * API. The server never sees the plaintext.
     *
     * @param fileId  File ID returned from upload()
     */
    retrieve(fileId: string): Promise<RetrieveResult>;
    /**
     * Verify a file's integrity against the Polygon blockchain.
     *
     * Does NOT download the file. Fetches the on-chain transaction and compares
     * the hash in the `data` field against the stored hash.
     *
     * @param fileId  File ID returned from upload()
     */
    verify(fileId: string): Promise<VerifyResult>;
    /**
     * List all files uploaded with this API key.
     */
    list(): Promise<FileInfo[]>;
    /**
     * Permanently delete a file and its encryption key.
     *
     * @param fileId  File ID returned from upload()
     */
    delete(fileId: string): Promise<void>;
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
    waitForBlockchain(fileId: string, timeoutMs?: number): Promise<'confirmed' | 'failed'>;
}

export { DecentraVault, type DecentraVaultOptions, type FileInfo, type RetrieveResult, type UploadResult, type VerifyResult };
