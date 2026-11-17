/**
 * VERICHAIN - Lightweight Proof-of-Work Blockchain Engine
 * Core Ledger Architecture with State Pruning & Inactivity Expiry Policies
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Class representing an individual Block in the ledger
 */
class Block {
  /**
   * @param {number} index - Position of block in the chain
   * @param {string} timestamp - ISO-8601 creation timestamp
   * @param {string} fileHash - SHA-256 hash of the registered file
   * @param {string} previousHash - SHA-256 hash of the preceding block
   * @param {number} nonce - Proof-of-work cryptographic counter
   * @param {object} metadata - File metadata (fileName, fileSize, mimeType, expiry policy)
   * @param {string} hash - Calculated block hash (if already mined/loaded)
   * @param {number} miningTimeMs - Time taken to mine the block in milliseconds
   */
  constructor(index, timestamp, fileHash, previousHash = '', nonce = 0, metadata = {}, hash = '', miningTimeMs = 0) {
    this.index = index;
    this.timestamp = timestamp;
    this.fileHash = fileHash;
    this.previousHash = previousHash;
    this.nonce = nonce;
    this.metadata = metadata || {};
    this.miningTimeMs = miningTimeMs || 0;

    // Inactivity Retention & Expiry Attributes
    this.inactivityMonths = metadata.inactivityMonths !== undefined ? metadata.inactivityMonths : null;
    this.lastAccessedAt = metadata.lastAccessedAt || timestamp;
    this.expiresAt = metadata.expiresAt || null;
    this.status = metadata.status || 'ACTIVE'; // 'ACTIVE' | 'EXPIRED_PRUNED'
    this.vaultFileName = metadata.vaultFileName || null;

    this.hash = hash || this.calculateHash();
  }

  /**
   * Recalculates the SHA-256 hash of the block contents
   * @returns {string} SHA-256 hexadecimal string
   */
  calculateHash() {
    const corePayload = `${this.index}|${this.previousHash}|${this.timestamp}|${this.fileHash}|${this.nonce}|${JSON.stringify({
      fileName: this.metadata.fileName || this.metadata.originalName,
      fileSize: this.metadata.size,
      mimeType: this.metadata.mimeType,
      inactivityMonths: this.inactivityMonths
    })}`;
    return crypto.createHash('sha256').update(corePayload).digest('hex');
  }

  /**
   * Mines the block using Proof of Work (PoW)
   * Finds a nonce such that the block hash begins with `difficulty` number of leading zeroes
   * @param {number} difficulty - Number of leading zeroes required
   */
  mineBlock(difficulty) {
    const targetPrefix = '0'.repeat(difficulty);
    const startTime = Date.now();

    while (this.hash.substring(0, difficulty) !== targetPrefix) {
      this.nonce++;
      this.hash = this.calculateHash();
    }

    this.miningTimeMs = Date.now() - startTime;
  }
}

/**
 * Class representing the complete Blockchain ledger
 */
class Blockchain {
  /**
   * @param {string} ledgerFilePath - Path to local persistent JSON file
   * @param {number} difficulty - PoW difficulty (leading zeroes)
   */
  constructor(ledgerFilePath = path.join(__dirname, 'ledger.json'), difficulty = 3) {
    this.ledgerFilePath = ledgerFilePath;
    this.difficulty = difficulty;
    this.chain = [];
    this.initializeLedger();
  }

  /**
   * Calculates expiration date based on inactivity months
   * @param {Date} fromDate
   * @param {number|null} months
   * @returns {string|null} ISO date string
   */
  static computeExpiryDate(fromDate, months) {
    if (months === null || months === undefined || months <= 0) return null;
    const expiry = new Date(fromDate);
    
    // Support fractional months for testing: if months is less than 1 (e.g. 0.0002 for 10 minutes)
    if (months < 1) {
      const minutes = Math.round(months * 30 * 24 * 60);
      expiry.setMinutes(expiry.getMinutes() + Math.max(1, minutes));
    } else {
      expiry.setMonth(expiry.getMonth() + Number(months));
    }
    return expiry.toISOString();
  }

  /**
   * Generates the immutable Genesis Block (Block #0)
   * @returns {Block}
   */
  createGenesisBlock() {
    const genesisTimestamp = '2026-01-01T00:00:00.000Z';
    const genesisFileHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const genesisMetadata = {
      fileName: 'GENESIS_ANCHOR.system',
      fileSize: 0,
      mimeType: 'application/x-genesis',
      author: 'VeriChain Engine',
      description: 'Cryptographic Root Anchor for File Integrity Ledger',
      inactivityMonths: null,
      status: 'ACTIVE'
    };

    const genesis = new Block(
      0,
      genesisTimestamp,
      genesisFileHash,
      '0000000000000000000000000000000000000000000000000000000000000000',
      0,
      genesisMetadata
    );

    genesis.mineBlock(this.difficulty);
    return genesis;
  }

  /**
   * Initializes or loads existing blockchain ledger from JSON storage
   */
  initializeLedger() {
    try {
      if (fs.existsSync(this.ledgerFilePath)) {
        const rawData = fs.readFileSync(this.ledgerFilePath, 'utf-8');
        const parsed = JSON.parse(rawData);

        if (Array.isArray(parsed) && parsed.length > 0) {
          this.chain = parsed.map(b => new Block(
            b.index,
            b.timestamp,
            b.fileHash,
            b.previousHash,
            b.nonce,
            b.metadata || {
              inactivityMonths: b.inactivityMonths,
              lastAccessedAt: b.lastAccessedAt,
              expiresAt: b.expiresAt,
              status: b.status,
              vaultFileName: b.vaultFileName,
              ...b.metadata
            },
            b.hash,
            b.miningTimeMs
          ));

          const validation = this.isChainValid();
          if (!validation.isValid) {
            console.warn(`[WARNING] Existing ledger integrity check failed: ${validation.reason}. Generating clean ledger.`);
            this.chain = [this.createGenesisBlock()];
            this.saveLedger();
          } else {
            console.log(`[LEDGER] Loaded ${this.chain.length} blocks successfully from ${path.basename(this.ledgerFilePath)}`);
          }
          return;
        }
      }
    } catch (err) {
      console.error(`[LEDGER ERROR] Failed to load ledger: ${err.message}. Initializing new ledger.`);
    }

    this.chain = [this.createGenesisBlock()];
    this.saveLedger();
    console.log(`[LEDGER] Genesis block anchored and ledger initialized.`);
  }

  /**
   * Persists the current chain to the local JSON file
   */
  saveLedger() {
    try {
      const data = JSON.stringify(this.chain, null, 2);
      fs.writeFileSync(this.ledgerFilePath, data, 'utf-8');
    } catch (err) {
      console.error(`[STORAGE ERROR] Failed to persist ledger: ${err.message}`);
      throw new Error(`Unable to save ledger: ${err.message}`);
    }
  }

  /**
   * Returns the latest block in the chain
   * @returns {Block}
   */
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  /**
   * Creates, mines, and records a new block containing the given file hash
   * @param {string} fileHash - 64-character SHA-256 hexadecimal string
   * @param {object} metadata - Metadata about the uploaded file (including inactivityMonths)
   * @returns {Block} The newly mined and appended block
   */
  addBlock(fileHash, metadata = {}) {
    if (!fileHash || typeof fileHash !== 'string' || fileHash.length !== 64) {
      throw new Error('Invalid file hash. Must be a 64-character hexadecimal SHA-256 string.');
    }

    const previousBlock = this.getLatestBlock();
    const newIndex = previousBlock.index + 1;
    const now = new Date();
    const timestamp = now.toISOString();

    // Calculate Inactivity Expiry Date
    const inactivityMonths = metadata.inactivityMonths !== undefined ? metadata.inactivityMonths : null;
    const expiresAt = Blockchain.computeExpiryDate(now, inactivityMonths);

    const enrichedMetadata = {
      ...metadata,
      inactivityMonths,
      lastAccessedAt: timestamp,
      expiresAt,
      status: 'ACTIVE'
    };

    const newBlock = new Block(
      newIndex,
      timestamp,
      fileHash.toLowerCase(),
      previousBlock.hash,
      0,
      enrichedMetadata
    );

    newBlock.mineBlock(this.difficulty);

    if (newBlock.hash !== newBlock.calculateHash()) {
      throw new Error('Cryptographic anomaly: Calculated block hash mismatch.');
    }

    this.chain.push(newBlock);
    this.saveLedger();
    return newBlock;
  }

  /**
   * Refreshes the lastAccessedAt timestamp and extends the inactivity expiration date
   * @param {string} fileHash
   * @returns {Block|null}
   */
  touchFileAccess(fileHash) {
    const targetHash = fileHash.toLowerCase();
    const block = this.chain.find(b => b.fileHash && b.fileHash.toLowerCase() === targetHash);
    if (!block) return null;

    const now = new Date();
    block.lastAccessedAt = now.toISOString();

    if (block.inactivityMonths !== null && block.inactivityMonths !== undefined) {
      block.expiresAt = Blockchain.computeExpiryDate(now, block.inactivityMonths);
      block.status = 'ACTIVE';
    }

    // Update metadata object as well for persistence
    if (block.metadata) {
      block.metadata.lastAccessedAt = block.lastAccessedAt;
      block.metadata.expiresAt = block.expiresAt;
      block.metadata.status = block.status;
    }

    this.saveLedger();
    return block;
  }

  /**
   * Scans the ledger to locate a matching file hash
   * @param {string} fileHash - SHA-256 string to query
   * @returns {{ found: boolean, block: Block | null, allMatches: Block[], isExpired: boolean }}
   */
  findFile(fileHash) {
    if (!fileHash || typeof fileHash !== 'string') {
      return { found: false, block: null, allMatches: [], isExpired: false };
    }

    const targetHash = fileHash.toLowerCase();
    const matches = this.chain.filter(b => b.fileHash && b.fileHash.toLowerCase() === targetHash);

    if (matches.length > 0) {
      const activeMatch = matches.find(b => b.status === 'ACTIVE') || matches[0];
      const isExpired = activeMatch.status === 'EXPIRED_PRUNED' || 
        (activeMatch.expiresAt && new Date(activeMatch.expiresAt).getTime() < Date.now());

      return {
        found: true,
        block: activeMatch,
        allMatches: matches,
        isExpired
      };
    }

    return { found: false, block: null, allMatches: [], isExpired: false };
  }

  /**
   * Prunes files that have exceeded their inactivity time limit without being opened
   * Deletes files from vault storage and marks their ledger block as EXPIRED_PRUNED
   * @param {string} vaultDir - Directory where vaulted files are stored
   * @returns {Array<object>} List of pruned block summaries
   */
  pruneExpiredFiles(vaultDir) {
    const now = Date.now();
    const pruned = [];

    for (const block of this.chain) {
      if (block.index === 0) continue; // Genesis block never expires

      if (block.status === 'ACTIVE' && block.expiresAt) {
        const expiryTime = new Date(block.expiresAt).getTime();
        if (now > expiryTime) {
          // File has expired due to inactivity
          block.status = 'EXPIRED_PRUNED';
          if (block.metadata) {
            block.metadata.status = 'EXPIRED_PRUNED';
          }

          // Delete physical file from disk vault if it exists to free memory
          if (vaultDir && block.vaultFileName) {
            const filePath = path.join(vaultDir, block.vaultFileName);
            if (fs.existsSync(filePath)) {
              try {
                fs.unlinkSync(filePath);
                console.log(`[PRUNING ENGINE] Auto-deleted expired file from vault: ${block.vaultFileName}`);
              } catch (e) {
                console.error(`[PRUNING ERROR] Failed to delete file: ${e.message}`);
              }
            }
          }

          pruned.push({
            blockIndex: block.index,
            fileHash: block.fileHash,
            fileName: block.metadata?.originalName || block.metadata?.fileName,
            expiredAt: block.expiresAt,
            inactivityMonths: block.inactivityMonths
          });
        }
      }
    }

    if (pruned.length > 0) {
      this.saveLedger();
      console.log(`[PRUNING ENGINE] Pruned ${pruned.length} expired file(s) from memory/vault.`);
    }

    return pruned;
  }

  /**
   * Mathematically validates every block and link across the entire chain
   * @returns {{ isValid: boolean, reason?: string, errorIndex?: number }}
   */
  isChainValid() {
    const targetPrefix = '0'.repeat(this.difficulty);

    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      // 1. Verify recalculation of current block's hash
      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return {
          isValid: false,
          errorIndex: i,
          reason: `Block #${currentBlock.index} hash has been tampered with. Stored: ${currentBlock.hash}, Calculated: ${currentBlock.calculateHash()}`
        };
      }

      // 2. Verify link to preceding block
      if (currentBlock.previousHash !== previousBlock.hash) {
        return {
          isValid: false,
          errorIndex: i,
          reason: `Chain broken at Block #${currentBlock.index}. PreviousHash (${currentBlock.previousHash}) does not match Block #${previousBlock.index} Hash (${previousBlock.hash})`
        };
      }

      // 3. Verify Proof-of-Work difficulty fulfillment
      if (currentBlock.hash.substring(0, this.difficulty) !== targetPrefix) {
        return {
          isValid: false,
          errorIndex: i,
          reason: `Block #${currentBlock.index} violates PoW difficulty (${this.difficulty} leading zeroes).`
        };
      }
    }

    return { isValid: true };
  }

  /**
   * Returns statistical metrics regarding the ledger
   */
  getStats() {
    const validation = this.isChainValid();
    const registeredFilesCount = this.chain.length > 1 ? this.chain.length - 1 : 0;
    const activeFilesCount = this.chain.filter(b => b.index > 0 && b.status === 'ACTIVE').length;
    const expiredFilesCount = this.chain.filter(b => b.index > 0 && b.status === 'EXPIRED_PRUNED').length;
    const latestBlock = this.getLatestBlock();

    return {
      totalBlocks: this.chain.length,
      registeredFiles: registeredFilesCount,
      activeFiles: activeFilesCount,
      expiredFiles: expiredFilesCount,
      difficulty: this.difficulty,
      isChainValid: validation.isValid,
      integrityDetails: validation,
      latestBlock: {
        index: latestBlock.index,
        timestamp: latestBlock.timestamp,
        hash: latestBlock.hash
      }
    };
  }
}

module.exports = {
  Block,
  Blockchain
};
