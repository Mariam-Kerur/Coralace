# Coraloce: Fortifying the World’s Critical Assets

An enterprise-grade, autonomous Cryptographic File Integrity Verification System and Real-Time Active Tamper Sentinel built with a lightweight **Proof-of-Work (PoW) Blockchain** architecture, **AES-256-GCM Vault Encryption**, and native SHA-256 cryptographic hashing.

> **Zero Cloud Lock-In**: Operates autonomously with zero third-party blockchain gas fees, external RPCs, or proprietary cloud dependencies.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |         Coraloce Web Client           |
                      |   HTML5 + Tailwind CSS + Vanilla JS   |
                      +---------------------------------------+
                                  |                |
                   POST /api/upload                POST /api/verify
                   (File Payload)                  (File Payload / Hash)
                                  v                v
                      +---------------------------------------+
                      |      Hardened Express.js Backend      |
                      |  - Helmet HTTP Security Headers (CSP) |
                      |  - Multi-Tier Rate Limiting (Anti-DoS)|
                      |  - File Upload Sanitizer & Sandbox    |
                      |  - AES-256-GCM Vault Encryption       |
                      +---------------------------------------+
                                  |                |
                                  v                v
     +----------------------------------+   +----------------------------------+
     |     Custom Blockchain Engine     |   |    Active FIM Sentinel Daemon    |
     |  - Genesis Anchor Block #0       |   |  - Real-time disk watcher (FIM)  |
     |  - Proof-of-Work (Target: 3)     |   |  - 30-Second Security Quarantine |
     |  - Cryptographic Chain Linking   |   |  - Automated Snapshot Rollback   |
     |  - Persistent ledger.json        |   |  - Real-time SSE / Email Alerts  |
     +----------------------------------+   +----------------------------------+
```

---

## Directory Structure

```
d:\New folder\
├── blockchain.js        # Core Blockchain Engine (Block & Blockchain classes, PoW mining, ledger persistence)
├── server.js            # Express REST API (/api/upload, /api/verify, /api/chain, /api/stats)
├── ledger.json          # Persistent local blockchain ledger (JSON file)
├── package.json         # Node.js project manifest and run scripts
├── test-blockchain.js   # Automated unit tests for PoW and tamper detection
├── test-api.js          # Integration tests for multipart API endpoints
├── public/
│   └── index.html       # Standalone high-tech Dashboard UI
└── index.html           # Root mirror of dashboard UI
```

---

## Cryptographic & Blockchain Specifications

- **Hashing Algorithm**: SHA-256 (`crypto.createHash('sha256')`) applied directly on file byte buffers.
- **Proof-of-Work Consensus**:
  - Each block must find a 32-bit `nonce` such that the block hash begins with a target number of leading zeroes (default `difficulty = 3`, prefix `000...`).
  - Recalculates `SHA256(Index + PreviousHash + Timestamp + FileHash + Nonce + Metadata)`.
- **Chain Immutability & Linkage**:
  - Every block embeds the exact hexadecimal hash of the previous block (`previousHash`).
  - Modifying even a single bit of any registered file or block invalidates all subsequent block hashes and triggers immediate tamper warnings.
- **Persistence**:
  - Automatically loads from and serializes to `ledger.json`. Re-instantiates `Block` prototypes on boot and performs cryptographic integrity verification.

---

## Quick Start Guide

### 1. Prerequisites
- **Node.js** (v18.x or later recommended; tested on v24.x)
- **npm** (included with Node.js)

### 2. Install Dependencies
Open your terminal or PowerShell in the project directory and run:
```bash
npm install
```
*(Dependencies: `express`, `multer`, `cors`)*

### 3. Run Automated Cryptographic Tests
Verify mining, difficulty, and tamper detection:
```bash
npm test
```
Or execute:
```bash
node test-blockchain.js
```

### 4. Start the Server
Launch the production Express server:
```bash
npm start
```
The server will boot on port `3000`:
```
=======================================================
 VERICHAIN FILE INTEGRITY LEDGER RUNNING
 Server URL : http://localhost:3000
 API Endpoints:
   - POST /api/upload    : Register file & mine block
   - POST /api/verify    : Check file integrity against ledger
   - GET  /api/chain     : Fetch full blockchain
   - GET  /api/stats     : Blockchain health & stats
=======================================================
```

### 5. Access Dashboard
Open your browser and navigate to:
```
http://localhost:3000
```

---

## REST API Reference

### 1. Register File
- **Endpoint**: `POST /api/upload`
- **Content-Type**: `multipart/form-data`
- **Field Name**: `file`
- **Description**: Computes the file's SHA-256 digest, mines a new Proof-of-Work block, and appends it to the immutable ledger.
- **cURL Example**:
  ```bash
  curl -X POST http://localhost:3000/api/upload \
    -F "file=@/path/to/your/document.pdf"
  ```
- **Response** (HTTP 201 Created):
  ```json
  {
    "success": true,
    "message": "File registered successfully and block mined to ledger.",
    "isDuplicate": false,
    "fileHash": "8c1dfb89f1fe60babb0802089ec9470ebc38b5c8e7389336f67b3696d8ade9ce",
    "block": {
      "index": 1,
      "timestamp": "2026-10-29T17:41:52.857Z",
      "fileHash": "8c1dfb89f1fe60babb0802089ec9470ebc38b5c8e7389336f67b3696d8ade9ce",
      "previousHash": "00093fa156037109f7c28c6b75aa321badfaef3fbf9e800032e9eef21bf1f520",
      "nonce": 1856,
      "hash": "000b1139cd8de3bb3dda6a2d9a675de0c8855a18582c50a1551ea95117f79392",
      "miningTimeMs": 6,
      "metadata": {
        "originalName": "document.pdf",
        "size": 49,
        "mimeType": "application/pdf"
      }
    }
  }
  ```

---

### 2. Verify File Integrity
- **Endpoint**: `POST /api/verify`
- **Content-Type**: `multipart/form-data` OR `application/json`
- **Description**: Verifies if the uploaded file (or hash string) exists in the ledger without alteration.
- **Option A (File Upload)**:
  ```bash
  curl -X POST http://localhost:3000/api/verify \
    -F "file=@/path/to/your/document.pdf"
  ```
- **Option B (Direct Hash JSON)**:
  ```bash
  curl -X POST http://localhost:3000/api/verify \
    -H "Content-Type: application/json" \
    -d "{\"hash\": \"8c1dfb89f1fe60babb0802089ec9470ebc38b5c8e7389336f67b3696d8ade9ce\"}"
  ```
- **Response (Authentic File - Status 200)**:
  ```json
  {
    "status": "VERIFIED",
    "isVerified": true,
    "message": "File is authentic and untampered. Cryptographic signature matches ledger record.",
    "fileHash": "8c1dfb89f1fe60babb0802089ec9470ebc38b5c8e7389336f67b3696d8ade9ce",
    "fileName": "document.pdf",
    "blockIndex": 1,
    "timestamp": "2026-10-29T17:41:52.857Z",
    "nonce": 1856,
    "blockHash": "000b1139cd8de3bb3dda6a2d9a675de0c8855a18582c50a1551ea95117f79392",
    "previousHash": "00093fa156037109f7c28c6b75aa321badfaef3fbf9e800032e9eef21bf1f520"
  }
  ```
- **Response (Tampered / Unknown File - Status 200)**:
  ```json
  {
    "status": "TAMPERED_OR_UNKNOWN",
    "isVerified": false,
    "message": "File is altered, corrupted, or was never registered on this blockchain.",
    "fileHash": "9751a25121ca648c3ae71985fcc936925371ddd6c77624a970e1185209a349ca",
    "blockIndex": null,
    "timestamp": null
  }
  ```

---

### 3. Fetch Full Blockchain
- **Endpoint**: `GET /api/chain`
- **Description**: Returns all blocks in chronological order and whole-chain validation status.
- **cURL Example**:
  ```bash
  curl http://localhost:3000/api/chain
  ```

---

### 4. Cryptographic Ledger Audit
- **Endpoint**: `POST /api/audit`
- **Description**: Recalculates all cryptographic hashes from Genesis to the tip to ensure zero bit flips or ledger tampering.
- **cURL Example**:
  ```bash
  curl -X POST http://localhost:3000/api/audit
  ```

---

## User Interface Highlights

1. **Register File Zone**:
   - Drag-and-drop or file picker with instant client-side WebCrypto SHA-256 digest preview.
   - Live PoW mining animation.
   - Success alert displaying the assigned block index, PoW nonce, file hash, and mining duration with one-click copy.
2. **Verify File Zone**:
   - Drag-and-drop file verification against the entire blockchain.
   - **Green Badge (`VALID / UNTAMPERED`)**: Appears when the computed hash matches an existing block, displaying anchor block index, timestamp, and mining proof.
   - **Red Badge (`WARNING: INVALID OR ALTERED FILE`)**: Appears when even a single byte differs, highlighting the mismatch.
3. **Immutable Blockchain Ledger Viewer**:
   - Visual chain representation displaying connected block nodes.
   - Shows Block #, Genesis identifier, Block Hash, Previous Hash link, File Payload Hash, Nonce, and Timestamp.
   - Real-time search/filter by block index, file name, or hash substring.
   - "Audit Integrity" button that validates the entire chain on-demand.
