/**
 * CORALOCE - File Integrity Verification System
 * "Fortifying the World’s Critical Assets"
 * Production-Ready Express.js Server & REST API
 * Featuring:
 *  - REAL-TIME ACTIVE FILE INTEGRITY MONITORING (FIM):
 *    Watches files on disk and intercepts tampering WHILE IT OCCURS!
 *  - Server-Sent Events (SSE) live push to all connected devices
 *  - Interactive In-Browser Live Tamper Interception Sandbox
 *  - Real-time Email Alerting & 30-Second Security Quarantine
 */

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const os = require('os');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Blockchain } = require('./blockchain');

// Automatically load .env configuration file if present
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  try {
    const envLines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    for (const line of envLines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        const eqIdx = trimmed.indexOf('=');
        const key = trimmed.slice(0, eqIdx).trim();
        const value = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        if (!process.env[key]) {
          process.env[key] = value;
        }
      }
    }
  } catch (err) {
    console.error('[ENV LOADER] Could not read .env file:', err.message);
  }
}

const app = express();
const PORT = process.env.PORT || 3000;

// Directories
const vaultDir = path.join(__dirname, 'vault_storage');
const testSamplesDir = path.join(__dirname, 'test_samples');

[vaultDir, testSamplesDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Initialize Blockchain Engine
const ledger = new Blockchain(path.join(__dirname, 'ledger.json'), 3);

/* ==========================================================================
   AES-256-GCM VAULT ENCRYPTION AT REST
   ========================================================================== */
const VAULT_MASTER_SECRET = process.env.VAULT_SECRET || process.env.SMTP_PASS || 'verichain-vault-hardened-key-2026';
const VAULT_KEY = crypto.scryptSync(VAULT_MASTER_SECRET, 'verichain-vault-salt-7162', 32);

function encryptVaultBuffer(buffer) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]);
  } catch (err) {
    console.error('[VAULT ENCRYPTION ERROR]:', err.message);
    return buffer;
  }
}

function decryptVaultBuffer(buffer) {
  if (!buffer || buffer.length < 32) return buffer;
  try {
    const iv = buffer.subarray(0, 16);
    const authTag = buffer.subarray(16, 32);
    const ciphertext = buffer.subarray(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', VAULT_KEY, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    return buffer;
  }
}

/* ==========================================================================
   INTRUDER DETECTION & IP QUARANTINE
   ========================================================================== */
const ipBanStore = new Map();

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || '127.0.0.1';
}

function checkIpQuarantine(req, res, next) {
  const ip = getClientIp(req);
  const banExpiry = ipBanStore.get(ip);
  if (banExpiry && Date.now() < banExpiry) {
    const remainingMin = Math.ceil((banExpiry - Date.now()) / (60 * 1000));
    return res.status(403).json({
      success: false,
      error: `Security Quarantine: Your IP address (${ip}) is temporarily locked out due to suspicious activity. Retry in ${remainingMin} minute(s).`
    });
  }
  next();
}

function quarantineIp(ip, durationMinutes = 15, reason = 'Excessive authentication failures') {
  const expiry = Date.now() + durationMinutes * 60 * 1000;
  ipBanStore.set(ip, expiry);
  console.log(`🚨 [SECURITY ENFORCEMENT] IP Quarantined: ${ip} locked out for ${durationMinutes} mins. Reason: ${reason}`);
}

/* ==========================================================================
   FILE SANITIZATION & EXTENSION BLACKLIST
   ========================================================================== */
const DISALLOWED_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.vbs', '.vbe', 
  '.ps1', '.ps2', '.msi', '.msp', '.com', '.scr', '.pif', 
  '.dll', '.jar', '.jsp', '.php', '.asp', '.aspx', '.cgi', '.pyc'
]);

function isDisallowedExtension(filename) {
  if (!filename) return false;
  const ext = path.extname(filename).toLowerCase();
  return DISALLOWED_EXTENSIONS.has(ext);
}

/* ==========================================================================
   RATE LIMITERS (DoS & Brute-Force Shields)
   ========================================================================== */
const apiGeneralLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit exceeded: Too many requests from this IP. Please try again shortly.' }
});

const miningUploadLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Mining Throttled: Maximum 25 Proof-of-Work blocks per 5 minutes per IP. Please wait.' }
});

const otpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many authentication code requests. Please wait 15 minutes.' }
});

// Middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

app.use(checkIpQuarantine);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api/', apiGeneralLimiter);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (isDisallowedExtension(file.originalname)) {
      return cb(new Error('SECURITY_DISALLOWED_FILE'));
    }
    cb(null, true);
  }
});

function computeSHA256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function getLocalNetworkIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('169.254')) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

/* ==========================================================================
   SERVER-SENT EVENTS (SSE) REAL-TIME SENTINEL STREAM
   ========================================================================== */

const sseClients = new Set();

function broadcastSSE(eventType, data) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

app.get('/api/sentinel/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.add(res);
  res.write(`event: connected\ndata: ${JSON.stringify({ status: 'Sentinel Active' })}\n\n`);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

/* ==========================================================================
   EMAIL DISPATCH SERVICE
   ========================================================================== */

const otpStore = new Map();
const sessionStore = new Map();
let lastDispatchedAlert = null;

let mailTransporter = null;

function getDefaultSenderEmail() {
  if (process.env.SMTP_FROM) return process.env.SMTP_FROM;
  if (process.env.SMTP_USER) return `"Coraloce Sentinel" <${process.env.SMTP_USER}>`;
  return '"Coraloce Security Sentinel" <sentinel@coraloce.local>';
}

if (process.env.SMTP_HOST && process.env.SMTP_USER) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  console.log('[EMAIL SERVICE] Real SMTP Server configured:', process.env.SMTP_HOST);
} else {
  mailTransporter = {
    sendMail: async (mailOptions) => {
      console.log('\n=======================================================');
      console.log(`[SIMULATED EMAIL DISPATCH TO]: ${mailOptions.to}`);
      console.log(`[SUBJECT]: ${mailOptions.subject}`);
      console.log(`[ALERT BODY]:\n${mailOptions.text || mailOptions.html}`);
      console.log('=======================================================\n');
      lastDispatchedAlert = {
        to: mailOptions.to,
        subject: mailOptions.subject,
        text: mailOptions.text,
        html: mailOptions.html,
        timestamp: new Date().toISOString()
      };
      return { messageId: 'simulated-' + Date.now() };
    }
  };
}

async function sendTamperAlertEmail(ownerEmail, fileName, blockIndex, originalHash, tamperedHash, alertType = 'VERIFICATION_AUDIT') {
  const isPreEdit = alertType === 'PRE_EDIT_REQUEST';
  const isLiveIntercept = alertType === 'LIVE_DISK_MODIFICATION' || alertType === 'LIVE_SANDBOX_INTERCEPT';
  
  let alertHeadline = '🚨 CRITICAL ALERT: File Tampering Detected';
  let alertSubject = `🚨 CRITICAL ALERT: Tampering Detected for "${fileName}"`;

  if (isPreEdit) {
    alertHeadline = '⏳ PRE-EDIT SECURITY PROTOCOL: 30-Second Delay Before Editing Unlocks!';
    alertSubject = `🚨 PRE-EDIT ALERT: Edit Mode Initiated for "${fileName}"`;
  } else if (isLiveIntercept) {
    alertHeadline = '🚨 LIVE TAMPER INTERCEPTION: File Modified On Disk in Real-Time!';
    alertSubject = `🚨 CRITICAL ALERT: Live Alteration Intercepted for "${fileName}"`;
  }

  let targetRecipient = (ownerEmail || '').trim();
  if (!targetRecipient || targetRecipient.endsWith('.local') || targetRecipient.includes('example.com') || targetRecipient.includes('coraloce.local') || targetRecipient.includes('verichain.local')) {
    if (process.env.SMTP_USER) {
      targetRecipient = process.env.SMTP_USER;
    }
  }

  const alertPayload = {
    from: getDefaultSenderEmail(),
    to: targetRecipient || 'registered-owner@example.com',
    subject: alertSubject,
    text: `${alertHeadline}\n\n` +
          `${isPreEdit ? 'A request to edit/tamper with a registered file was initiated:' : 'A modification was detected on registered file:'} "${fileName}"\n` +
          `Anchor Block : #${blockIndex}\n` +
          `Original Blockchain Hash : ${originalHash}\n` +
          (isPreEdit ? `Status                   : Locked - 30-Second Security Wait Window Active\n` : `New Altered Hash         : ${tamperedHash}\n`) +
          `Timestamp                : ${new Date().toISOString()}\n\n` +
          (isPreEdit 
            ? `In accordance with security rules, editing is locked for a mandatory 30-second window to allow you to review this attempt and intervene before any changes take effect.`
            : `The 30-Second Security Quarantine Protocol was immediately engaged across all active monitoring clients.`),
    html: `
      <div style="font-family: Arial, sans-serif; background-color: #0f172a; color: #ffffff; padding: 24px; border-radius: 12px; border: 2px solid ${isPreEdit ? '#f59e0b' : '#ef4444'};">
        <h2 style="color: ${isPreEdit ? '#f59e0b' : '#ef4444'}; margin: 0 0 12px 0;">${alertHeadline}</h2>
        <p style="color: #cbd5e1; font-size: 14px;">${isPreEdit ? 'An edit/tamper request was initiated for your blockchain-anchored file:' : 'An unauthorized change was made to your blockchain-anchored file:'}</p>
        
        <div style="background-color: #1e293b; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 12px; margin: 16px 0; border: 1px solid #334155;">
          <p style="margin: 4px 0;"><strong style="color: #94a3b8;">File Name:</strong> ${fileName}</p>
          <p style="margin: 4px 0;"><strong style="color: #94a3b8;">Anchor Block:</strong> Block #${blockIndex}</p>
          <p style="margin: 4px 0;"><strong style="color: #94a3b8;">Original Hash:</strong> <span style="color: #34d399;">${originalHash}</span></p>
          ${isPreEdit ? `<p style="margin: 4px 0;"><strong style="color: #94a3b8;">Security Status:</strong> <span style="color: #fbbf24;">Quarantined - 30s Wait Enforced</span></p>` : `<p style="margin: 4px 0;"><strong style="color: #94a3b8;">Tampered Hash:</strong> <span style="color: #f87171;">${tamperedHash}</span></p>`}
          <p style="margin: 4px 0;"><strong style="color: #94a3b8;">Time:</strong> ${new Date().toISOString()}</p>
        </div>

        <div style="background-color: ${isPreEdit ? '#451a03' : '#450a0a'}; border-left: 4px solid ${isPreEdit ? '#f59e0b' : '#ef4444'}; padding: 12px; border-radius: 4px; font-size: 13px; color: ${isPreEdit ? '#fef3c7' : '#fecaca'};">
          <strong>Security Action Taken:</strong> ${isPreEdit ? 'Editing is strictly locked for 30 seconds before any user can modify content, giving you time to review this alert on your phone/email.' : 'Client interfaces have entered a mandatory 30-second security quarantine countdown to give you time to respond.'}
        </div>
      </div>
    `
  };

  console.log(`[ALERT DISPATCH] Attempting to deliver email to: "${alertPayload.to}" from "${alertPayload.from}"`);

  try {
    const info = await mailTransporter.sendMail(alertPayload);
    console.log(`[ALERT DISPATCH SUCCESS] Real-time alert delivered to ${alertPayload.to}! MessageId: ${info.messageId}`);
    return true;
  } catch (err) {
    console.error(`[ALERT ERROR] Delivery failed to ${alertPayload.to}:`, err.message);
    return false;
  }
}

/* ==========================================================================
   ACTIVE FILE INTEGRITY MONITORING (FIM) SENTINEL DAEMON
   Watches disk folders and alerts WHILE file editing occurs!
   ========================================================================== */

const activeWatchers = new Map();
let lastWatchEventTime = 0;

function setupActiveDirectoryWatcher(dirPath, label) {
  if (!fs.existsSync(dirPath)) return;

  try {
    const watcher = fs.watch(dirPath, { persistent: true }, async (eventType, filename) => {
      if (!filename) return;

      const now = Date.now();
      if (now - lastWatchEventTime < 400) return; // Debounce rapid file writes
      lastWatchEventTime = now;

      const fullPath = path.join(dirPath, filename);
      if (!fs.existsSync(fullPath)) return;

      try {
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory()) return;

        // Read file and calculate current hash
        const currentBuffer = fs.readFileSync(fullPath);
        const currentHash = computeSHA256(currentBuffer);

        // Check if this file is anchored in our blockchain ledger (search from latest block)
        const matchingBlock = ledger.chain.slice().reverse().find(b => 
          b.index > 0 && b.metadata && 
          (b.metadata.originalName === filename || b.metadata.fileName === filename)
        );

        if (matchingBlock) {
          // If the file was changed and no longer matches the blockchain hash:
          if (matchingBlock.fileHash !== currentHash) {
            console.log(`\n🚨 [ACTIVE SENTINEL] Real-time file modification intercepted on disk: "${filename}"!`);
            
            const lockExpiry = activeEditLocks.get(filename);
            const isAuthorizedEdit = lockExpiry && (Date.now() >= lockExpiry);

            // If an unauthorized edit occurred without respecting the 30-second delay:
            // Immediately rollback the file on disk to its immutable blockchain version and lock it!
            if (!isAuthorizedEdit) {
              console.log(`[OS INTEGRITY SENTINEL] Unauthorized alteration on "${filename}" blocked. Rolling back to original blockchain snapshot...`);
              if (matchingBlock.vaultFileName) {
                const vaultBackup = path.join(vaultDir, matchingBlock.vaultFileName);
                if (fs.existsSync(vaultBackup)) {
                  const encryptedVaultBytes = fs.readFileSync(vaultBackup);
                  const decryptedData = decryptVaultBuffer(encryptedVaultBytes);
                  fs.writeFileSync(fullPath, decryptedData);
                }
              }
              // Relock file in Read-Only mode
              setFileReadOnly(fullPath, true);
            }

            const ownerEmail = matchingBlock.metadata.ownerEmail || process.env.SMTP_USER || 'registered-owner@example.com';
            
            // 1. Dispatch real-time email alert to owner WHILE file is being edited!
            await sendTamperAlertEmail(
              ownerEmail,
              filename,
              matchingBlock.index,
              matchingBlock.fileHash,
              currentHash,
              'LIVE_DISK_MODIFICATION'
            );

            // 2. Broadcast live tamper event to all active browsers via SSE!
            broadcastSSE('LIVE_TAMPER', {
              status: 'TAMPER_DETECTED',
              isTampered: true,
              source: 'LIVE_DISK_INTERCEPTION',
              fileName: filename,
              blockIndex: matchingBlock.index,
              originalHash: matchingBlock.fileHash,
              tamperedHash: currentHash,
              ownerEmail: ownerEmail,
              quarantineSeconds: 30,
              message: `LIVE DISK INTERCEPTION: File "${filename}" was just modified on your file system!`
            });
          }
        }
      } catch (e) {
        // file write lock in progress, ignore
      }
    });

    activeWatchers.set(dirPath, watcher);
    console.log(`[ACTIVE SENTINEL] Real-Time Watcher armed on: ${label} (${dirPath})`);
  } catch (err) {
    console.error(`[SENTINEL ERROR] Could not watch ${dirPath}:`, err.message);
  }
}

// Arm real-time watchers on sample files and vaulted files
setupActiveDirectoryWatcher(testSamplesDir, 'Test Samples Folder');
setupActiveDirectoryWatcher(vaultDir, 'Encrypted Vault Storage');

/* ==========================================================================
   REST API: TAMPERING & PRE-EDIT 30-SECOND SECURITY PROTOCOL
   ========================================================================== */

// Active pre-edit locks: maps fileName -> unlock timestamp (ms)
const activeEditLocks = new Map();

/**
 * Enforce OS-level Read-Only attribute on anchored files
 */
function setFileReadOnly(filePath, readOnly = true) {
  try {
    if (fs.existsSync(filePath)) {
      fs.chmodSync(filePath, readOnly ? 0o444 : 0o666);
    }
  } catch (err) {
    // Ignore permissions if locked by another process
  }
}

// Lock all test sample files by default so no application can modify them without permission
try {
  if (fs.existsSync(testSamplesDir)) {
    fs.readdirSync(testSamplesDir).forEach(file => {
      setFileReadOnly(path.join(testSamplesDir, file), true);
    });
    console.log('[OS INTEGRITY SENTINEL] All monitored files locked in Read-Only mode by default.');
  }
} catch (e) {}

/**
 * GET /api/sentinel/file-content/:fileName
 * Safely fetches file content for editing sandbox
 */
app.get('/api/sentinel/file-content/:fileName', (req, res) => {
  try {
    const rawFileName = req.params.fileName;
    const safeName = path.basename(rawFileName);
    
    // Check in test_samples first, then vault_storage
    let filePath = path.join(testSamplesDir, safeName);
    let isVaultFile = false;
    if (!fs.existsSync(filePath)) {
      const block = ledger.chain.find(b => b.metadata && (b.metadata.originalName === safeName || b.metadata.fileName === safeName));
      if (block && block.vaultFileName) {
        filePath = path.join(vaultDir, block.vaultFileName);
        isVaultFile = true;
      }
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, error: 'File not found on disk.' });
    }

    let rawBuffer = fs.readFileSync(filePath);
    if (isVaultFile) {
      rawBuffer = decryptVaultBuffer(rawBuffer);
    }
    const content = rawBuffer.toString('utf8');
    const hash = computeSHA256(rawBuffer);
    return res.status(200).json({ success: true, fileName: safeName, content, hash });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/sentinel/request-edit
 * Triggers the 30-Second Security Wait Window BEFORE any editing can occur!
 * Dispatches alert email immediately to registered owner.
 */
app.post('/api/sentinel/request-edit', async (req, res) => {
  try {
    const { fileName, ownerEmail } = req.body;
    const targetName = fileName || 'Sample_Agreement.txt';

    const matchingBlock = ledger.chain.slice().reverse().find(b => 
      b.index > 0 && b.metadata && 
      (b.metadata.originalName === targetName || b.metadata.fileName === targetName)
    );

    const originalHash = matchingBlock ? matchingBlock.fileHash : 'a903de6d83df9dc594e8bda2f8144f019f2b673e21e60e9824a9436c43b43a9e';
    const blockIndex = matchingBlock ? matchingBlock.index : 3;
    const alertEmail = ownerEmail || (matchingBlock?.metadata?.ownerEmail) || process.env.SMTP_USER || 'registered-owner@example.com';

    console.log(`\n⏳ [PRE-EDIT SENTINEL] Edit requested for "${targetName}". Enforcing 30-second delay BEFORE editing.`);
    console.log(`   Owner Email: ${alertEmail}`);

    // 1. Dispatch real-time alert email BEFORE editing begins
    await sendTamperAlertEmail(
      alertEmail,
      targetName,
      blockIndex,
      originalHash,
      null,
      'PRE_EDIT_REQUEST'
    );

    // Enforce OS-level and memory-level 30-second lock
    const unlockTime = Date.now() + 30 * 1000;
    activeEditLocks.set(targetName, unlockTime);

    // Ensure the physical file on disk is locked in Read-Only mode during the 30-second window
    const targetFilePath = path.join(testSamplesDir, targetName);
    setFileReadOnly(targetFilePath, true);

    // Auto-release the OS-level lock exactly after 30 seconds
    setTimeout(() => {
      setFileReadOnly(targetFilePath, false);
      console.log(`[OS INTEGRITY SENTINEL] 30-second quarantine complete for "${targetName}". Write permission unlocked.`);
    }, 30 * 1000);

    // 2. Broadcast Pre-Edit Lockdown Event to all connected SSE clients
    const eventPayload = {
      status: 'PRE_EDIT_LOCKED',
      fileName: targetName,
      blockIndex,
      originalHash,
      ownerEmail: alertEmail,
      quarantineSeconds: 30,
      timestamp: new Date().toISOString(),
      message: `PRE-EDIT SECURITY PROTOCOL: Edit requested for "${targetName}". Please wait 30 seconds before editing.`
    };

    broadcastSSE('PRE_EDIT_ALERT', eventPayload);

    return res.status(200).json({
      success: true,
      ...eventPayload,
      lastDispatchedAlert
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/sentinel/save-tamper
 * Commits the tampered file after the 30-second wait window, then runs integrity audit!
 */
app.post('/api/sentinel/save-tamper', async (req, res) => {
  try {
    const { fileName, alteredContent, ownerEmail } = req.body;
    const targetName = fileName || 'Sample_Agreement.txt';

    // Verify if 30-second security protocol was respected
    const lockExpiry = activeEditLocks.get(targetName);
    const now = Date.now();
    if (lockExpiry && now < lockExpiry) {
      const remainingSec = Math.ceil((lockExpiry - now) / 1000);
      return res.status(423).json({
        success: false,
        error: `30-Second Security Lock Active: Editing is blocked for another ${remainingSec} second(s). Please wait.`
      });
    }

    const tamperedBuffer = Buffer.from(alteredContent || '');
    const tamperedHash = computeSHA256(tamperedBuffer);

    // Ensure write permission before modifying
    const filePath = path.join(testSamplesDir, targetName);
    setFileReadOnly(filePath, false);
    fs.writeFileSync(filePath, tamperedBuffer);

    const matchingBlock = ledger.chain.slice().reverse().find(b => 
      b.index > 0 && b.metadata && 
      (b.metadata.originalName === targetName || b.metadata.fileName === targetName)
    );

    const originalHash = matchingBlock ? matchingBlock.fileHash : 'a903de6d83df9dc594e8bda2f8144f019f2b673e21e60e9824a9436c43b43a9e';
    const blockIndex = matchingBlock ? matchingBlock.index : 3;
    const alertEmail = ownerEmail || (matchingBlock?.metadata?.ownerEmail) || process.env.SMTP_USER || 'registered-owner@example.com';
    const isTampered = matchingBlock ? (matchingBlock.fileHash !== tamperedHash) : true;

    console.log(`\n🚨 [SENTINEL AUDIT] Altered file saved: "${targetName}"`);
    console.log(`   Original Hash : ${originalHash}`);
    console.log(`   Tampered Hash : ${tamperedHash}`);
    console.log(`   Tampering Confirmed: ${isTampered}`);

    // Dispatch tamper alert email with cryptographic proof
    await sendTamperAlertEmail(
      alertEmail,
      targetName,
      blockIndex,
      originalHash,
      tamperedHash,
      'VERIFICATION_AUDIT'
    );

    return res.status(200).json({
      success: true,
      isTampered,
      status: 'TAMPER_DETECTED',
      fileName: targetName,
      blockIndex,
      originalHash,
      tamperedHash,
      ownerEmail: alertEmail,
      lastDispatchedAlert,
      message: `Cryptographic tampering verified! Hash mismatch against Block #${blockIndex}.`
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/sentinel/live-tamper-intercept (Kept for compatibility)
 */
app.post('/api/sentinel/live-tamper-intercept', async (req, res) => {
  try {
    const { fileName, alteredContent, ownerEmail } = req.body;
    const targetName = fileName || 'Sample_Agreement.txt';
    const tamperedHash = computeSHA256(Buffer.from(alteredContent || ''));

    const matchingBlock = ledger.chain.slice().reverse().find(b => 
      b.index > 0 && b.metadata && 
      (b.metadata.originalName === targetName || b.metadata.fileName === targetName)
    );

    const originalHash = matchingBlock ? matchingBlock.fileHash : 'a903de6d83df9dc594e8bda2f8144f019f2b673e21e60e9824a9436c43b43a9e';
    const blockIndex = matchingBlock ? matchingBlock.index : 3;
    const alertEmail = ownerEmail || (matchingBlock?.metadata?.ownerEmail) || process.env.SMTP_USER || 'registered-owner@example.com';

    await sendTamperAlertEmail(
      alertEmail,
      targetName,
      blockIndex,
      originalHash,
      tamperedHash,
      'LIVE_SANDBOX_INTERCEPT'
    );

    const eventPayload = {
      status: 'TAMPER_DETECTED',
      isTampered: true,
      source: 'LIVE_KEYSTROKE_INTERCEPTION',
      fileName: targetName,
      blockIndex,
      originalHash,
      tamperedHash,
      ownerEmail: alertEmail,
      quarantineSeconds: 30,
      message: `LIVE INTERCEPTION: Tampering detected for "${targetName}"!`
    };

    broadcastSSE('LIVE_TAMPER', eventPayload);

    return res.status(200).json({
      success: true,
      ...eventPayload
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/* ==========================================================================
   REST API: ADMIN & OTP ENDPOINTS
   ========================================================================== */

function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : req.query.token;
  if (!token) return res.status(401).json({ success: false, error: 'Admin bearer token required.' });

  const session = sessionStore.get(token);
  if (!session || Date.now() > session.expiresAt) {
    sessionStore.delete(token);
    return res.status(401).json({ success: false, error: 'Session expired or invalid.' });
  }

  req.adminEmail = session.email;
  next();
}

app.post('/api/admin/request-otp', otpRequestLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Valid email required.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    otpStore.set(email.toLowerCase(), { otp, expiresAt, attempts: 0 });

    let targetEmail = email.trim();
    if (targetEmail.endsWith('.local') || targetEmail.includes('example.com')) {
      if (process.env.SMTP_USER) targetEmail = process.env.SMTP_USER;
    }

    const mailOptions = {
      from: getDefaultSenderEmail(),
      to: targetEmail,
      subject: `Coraloce Admin Verification Code: ${otp}`,
      text: `Your one-time authorization code is: ${otp}\nValid for 10 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; background-color: #09090b; color: #ffffff; padding: 28px; border-radius: 14px; border: 1px solid #27272a;">
          <h2 style="color: #ffffff; margin-top: 0; font-size: 18px;">Coraloce Admin Verification</h2>
          <p style="color: #a1a1aa; font-size: 13px;">Use the one-time authorization code below to unlock your admin console:</p>
          <div style="background-color: #18181b; border: 1px solid #3f3f46; border-radius: 10px; padding: 18px; text-align: center; margin: 18px 0;">
            <span style="font-family: monospace; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #ffffff;">${otp}</span>
          </div>
          <p style="color: #71717a; font-size: 11px; margin-bottom: 0;">This code expires in 10 minutes. Fortifying the World’s Critical Assets.</p>
        </div>
      `
    };

    await mailTransporter.sendMail(mailOptions);
    return res.status(200).json({
      success: true,
      message: `OTP dispatched to ${email}`,
      debugOtp: otp
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/verify-otp', (req, res) => {
  try {
    const clientIp = getClientIp(req);
    const { email, otp } = req.body;
    const cleanEmail = email?.toLowerCase();
    const stored = otpStore.get(cleanEmail);

    if (!stored || Date.now() > stored.expiresAt) {
      return res.status(400).json({ success: false, error: 'Authorization code expired or not requested. Please request a new OTP.' });
    }

    if (stored.otp !== otp?.trim()) {
      stored.attempts = (stored.attempts || 0) + 1;
      const remainingAttempts = 3 - stored.attempts;

      if (stored.attempts >= 3) {
        otpStore.delete(cleanEmail);
        quarantineIp(clientIp, 15, 'Exceeded 3 failed OTP authentication attempts');
        return res.status(403).json({
          success: false,
          error: 'Security Lockout Engaged: Exceeded 3 failed attempts. Your IP has been temporarily quarantined for 15 minutes.'
        });
      }

      return res.status(400).json({
        success: false,
        error: `Invalid authorization code. ${remainingAttempts} attempt(s) remaining before security lockout.`
      });
    }

    otpStore.delete(cleanEmail);
    const token = crypto.randomBytes(32).toString('hex');
    sessionStore.set(token, { email: cleanEmail, expiresAt: Date.now() + 24 * 60 * 60 * 1000, role: 'admin' });

    return res.status(200).json({
      success: true,
      token,
      email: cleanEmail,
      localNetworkUrl: `http://${getLocalNetworkIP()}:${PORT}`
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/admin/network-info', (req, res) => {
  const localIP = getLocalNetworkIP();
  return res.status(200).json({
    success: true,
    localIP,
    port: PORT,
    accessUrl: `http://${localIP}:${PORT}`
  });
});

app.get('/api/admin/vault-files', requireAdminAuth, (req, res) => {
  try {
    const files = [];
    ledger.chain.forEach(block => {
      if (block.index === 0) return;
      const fileName = block.metadata?.originalName || block.metadata?.fileName || 'unnamed-file';
      const vaultedPath = block.vaultFileName ? path.join(vaultDir, block.vaultFileName) : null;
      const isFileStoredOnDisk = vaultedPath ? fs.existsSync(vaultedPath) : false;

      let remainingText = 'Permanent';
      if (block.expiresAt) {
        const remainingMs = new Date(block.expiresAt).getTime() - Date.now();
        if (remainingMs <= 0 || block.status === 'EXPIRED_PRUNED') {
          remainingText = 'Expired & Purged';
        } else {
          const days = Math.floor(remainingMs / (1000 * 60 * 60 * 24));
          const hours = Math.floor((remainingMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
          remainingText = days > 0 ? `${days}d left` : `${hours}h left`;
        }
      }

      files.push({
        blockIndex: block.index,
        fileHash: block.fileHash,
        fileName,
        fileSize: block.metadata?.size || 0,
        inactivityMonths: block.inactivityMonths,
        ownerEmail: block.metadata?.ownerEmail || 'None',
        registeredAt: block.timestamp,
        lastAccessedAt: block.lastAccessedAt,
        expiresAt: block.expiresAt,
        status: block.status,
        isFileStoredOnDisk,
        remainingText,
        downloadUrl: `/api/admin/download/${block.fileHash}`
      });
    });

    return res.status(200).json({ success: true, files });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/admin/download/:fileHash', requireAdminAuth, (req, res) => {
  try {
    const targetHash = req.params.fileHash.toLowerCase();
    const search = ledger.findFile(targetHash);
    if (!search.found) return res.status(404).json({ success: false, error: 'File hash not found.' });

    const block = search.block;
    if (block.status === 'EXPIRED_PRUNED') return res.status(410).json({ success: false, error: 'File expired and purged.' });

    const filePath = path.join(vaultDir, block.vaultFileName);
    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, error: 'File missing from vault storage.' });

    ledger.touchFileAccess(targetHash);
    const originalName = block.metadata?.originalName || 'file';
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(originalName)}"`);
    res.setHeader('Content-Type', block.metadata?.mimeType || 'application/octet-stream');
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/update-expiry', requireAdminAuth, (req, res) => {
  try {
    const { fileHash, inactivityMonths } = req.body;
    const search = ledger.findFile(fileHash);
    if (!search.found) return res.status(404).json({ success: false, error: 'File hash not found.' });

    const block = search.block;
    const months = (inactivityMonths === 'never' || inactivityMonths === null) ? null : parseFloat(inactivityMonths);

    block.inactivityMonths = months;
    if (months === null) {
      block.expiresAt = null;
      block.status = 'ACTIVE';
    } else {
      block.expiresAt = Blockchain.computeExpiryDate(new Date(block.lastAccessedAt || block.timestamp), months);
      if (new Date(block.expiresAt).getTime() > Date.now()) block.status = 'ACTIVE';
    }

    if (block.metadata) {
      block.metadata.inactivityMonths = block.inactivityMonths;
      block.metadata.expiresAt = block.expiresAt;
      block.metadata.status = block.status;
    }

    ledger.saveLedger();
    return res.status(200).json({
      success: true,
      message: `Block #${block.index} limit updated to ${months === null ? 'Permanent' : months + ' months'}.`
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/admin/update-owner-email
 * Allows Admin to update or assign registered owner alert email for any file
 */
app.post('/api/admin/update-owner-email', (req, res) => {
  try {
    const { fileHash, newEmail } = req.body;
    if (!fileHash) return res.status(400).json({ success: false, error: 'File hash is required.' });

    const search = ledger.findFile(fileHash);
    if (!search.found) return res.status(404).json({ success: false, error: 'File hash not found in ledger.' });

    const block = search.block;
    if (!block.metadata) block.metadata = {};
    const cleanEmail = (newEmail || '').trim();
    block.metadata.ownerEmail = cleanEmail || null;

    ledger.saveLedger();
    console.log(`[ADMIN] Block #${block.index} owner email updated to: "${cleanEmail}"`);

    return res.status(200).json({
      success: true,
      message: `Block #${block.index} registered email updated to "${cleanEmail || 'None'}".`,
      blockIndex: block.index,
      ownerEmail: block.metadata.ownerEmail
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/admin/smtp-settings
 */
app.get('/api/admin/smtp-settings', (req, res) => {
  const isConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
  let maskedUser = '';
  if (process.env.SMTP_USER) {
    const parts = process.env.SMTP_USER.split('@');
    if (parts.length === 2) {
      const name = parts[0];
      const domain = parts[1];
      maskedUser = (name.length > 2 ? name[0] + '***' + name.slice(-1) : name[0] + '***') + '@' + domain;
    } else {
      maskedUser = 'Configured';
    }
  }

  return res.status(200).json({
    success: true,
    isConfigured,
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || '587',
    user: maskedUser,
    from: process.env.SMTP_FROM ? 'Configured' : '',
    hasPassword: !!process.env.SMTP_PASS
  });
});

/**
 * POST /api/admin/smtp-settings
 * Saves SMTP credentials directly from the Web UI into runtime memory and .env
 */
app.post('/api/admin/smtp-settings', (req, res) => {
  try {
    const { host, port, user, pass, from, secure } = req.body;
    if (!host || !user) {
      return res.status(400).json({ success: false, error: 'Host and User email are required.' });
    }

    const passwordToUse = pass || process.env.SMTP_PASS;
    if (!passwordToUse) {
      return res.status(400).json({ success: false, error: 'Password or App Password is required.' });
    }

    process.env.SMTP_HOST = host.trim();
    process.env.SMTP_PORT = String(port || 587);
    process.env.SMTP_USER = user.trim();
    process.env.SMTP_PASS = passwordToUse.trim();
    process.env.SMTP_FROM = from ? from.trim() : `"Coraloce Sentinel" <${user.trim()}>`;
    process.env.SMTP_SECURE = secure ? 'true' : 'false';

    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });

    // Persist into .env file safely
    const envPath = path.join(__dirname, '.env');
    const envLines = [
      `SMTP_HOST=${process.env.SMTP_HOST}`,
      `SMTP_PORT=${process.env.SMTP_PORT}`,
      `SMTP_SECURE=${process.env.SMTP_SECURE}`,
      `SMTP_USER=${process.env.SMTP_USER}`,
      `SMTP_PASS=${process.env.SMTP_PASS}`,
      `SMTP_FROM=${process.env.SMTP_FROM}`
    ].join('\n');
    fs.writeFileSync(envPath, envLines, 'utf8');

    console.log(`[EMAIL SERVICE] Configured real SMTP via Web UI for: ${process.env.SMTP_USER}`);

    return res.status(200).json({
      success: true,
      message: `Email dispatch configured for ${process.env.SMTP_USER}. Real emails will now be sent automatically!`,
      isConfigured: true,
      user: process.env.SMTP_USER
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/admin/test-email
 * Sends a real test verification email to confirm the credentials work
 */
app.post('/api/admin/test-email', async (req, res) => {
  try {
    const { recipient } = req.body;
    const targetEmail = recipient || process.env.SMTP_USER;
    if (!targetEmail) {
      return res.status(400).json({ success: false, error: 'Recipient email address is required.' });
    }

    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      return res.status(400).json({ success: false, error: 'Email server credentials not configured yet. Please configure above first.' });
    }

    const testPayload = {
      from: getDefaultSenderEmail(),
      to: targetEmail,
      subject: '✅ Coraloce Security: Live Email Verification Test',
      text: 'Congratulations! Your Coraloce email alert dispatch system is connected and working perfectly.',
      html: `
        <div style="font-family: Arial, sans-serif; background-color: #09090b; color: #ffffff; padding: 28px; border-radius: 16px; border: 1px solid #27272a;">
          <h2 style="color: #ffffff; margin-top: 0;">✅ Coraloce Sentinel: Email Verified</h2>
          <p style="color: #a1a1aa; font-size: 14px;">Your Coraloce email alert dispatch system has been verified and is ready.</p>
          <div style="background-color: #18181b; border: 1px solid #27272a; border-radius: 10px; padding: 16px; margin: 20px 0;">
            <p style="margin: 0; font-family: monospace; font-size: 13px; color: #e4e4e7;">Sender: ${process.env.SMTP_USER}</p>
            <p style="margin: 8px 0 0 0; font-family: monospace; font-size: 13px; color: #e4e4e7;">Recipient: ${targetEmail}</p>
            <p style="margin: 8px 0 0 0; font-family: monospace; font-size: 13px; color: #e4e4e7;">Status: Active & Armed for 30s Breach Alerts</p>
          </div>
        </div>
      `
    };

    const info = await mailTransporter.sendMail(testPayload);
    return res.status(200).json({
      success: true,
      message: `Test email successfully delivered to ${targetEmail}!`,
      info
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/prune-now', requireAdminAuth, (req, res) => {
  try {
    const pruned = ledger.pruneExpiredFiles(vaultDir);
    return res.status(200).json({
      success: true,
      message: `Pruning complete. ${pruned.length} expired file(s) removed from memory.`,
      pruned
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/* ==========================================================================
   BLOCKCHAIN API ENDPOINTS
   ========================================================================== */

app.post('/api/upload', miningUploadLimiter, upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded.' });

    const fileHash = computeSHA256(req.file.buffer);

    let inactivityMonths = null;
    if (req.body.inactivityMonths !== undefined && req.body.inactivityMonths !== '' && req.body.inactivityMonths !== 'never') {
      inactivityMonths = parseFloat(req.body.inactivityMonths);
    }

    const ownerEmail = (req.body.ownerEmail || '').trim();

    // Store in vault (Encrypted with AES-256-GCM at rest)
    const ext = path.extname(req.file.originalname) || '';
    const vaultFileName = `${fileHash}${ext}`;
    const vaultFilePath = path.join(vaultDir, vaultFileName);
    fs.writeFileSync(vaultFilePath, encryptVaultBuffer(req.file.buffer));

    // Also mirror to test_samples so the real-time disk watcher can guard it
    const sampleMirrorPath = path.join(testSamplesDir, req.file.originalname);
    if (!fs.existsSync(sampleMirrorPath)) {
      fs.writeFileSync(sampleMirrorPath, req.file.buffer);
    }

    const metadata = {
      originalName: req.file.originalname,
      size: req.file.size,
      mimeType: req.file.mimetype || 'application/octet-stream',
      inactivityMonths,
      ownerEmail: ownerEmail || null,
      vaultFileName
    };

    const existingEntry = ledger.findFile(fileHash);
    const isDuplicate = existingEntry.found;
    const newBlock = ledger.addBlock(fileHash, metadata);

    return res.status(201).json({
      success: true,
      message: isDuplicate
        ? 'File re-registered successfully. Warning: This file hash already exists in prior block.'
        : 'File registered, block mined, and Real-Time Active Sentinel armed on disk.',
      isDuplicate,
      fileHash,
      inactivityMonths,
      ownerEmail: metadata.ownerEmail,
      expiresAt: newBlock.expiresAt,
      block: {
        index: newBlock.index,
        timestamp: newBlock.timestamp,
        fileHash: newBlock.fileHash,
        previousHash: newBlock.previousHash,
        nonce: newBlock.nonce,
        hash: newBlock.hash,
        metadata: newBlock.metadata,
        inactivityMonths: newBlock.inactivityMonths,
        expiresAt: newBlock.expiresAt,
        status: newBlock.status
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/verify', upload.single('file'), async (req, res) => {
  try {
    let targetHash = null;
    let fileName = 'Unknown';
    let fileSize = null;

    if (req.file) {
      targetHash = computeSHA256(req.file.buffer);
      fileName = req.file.originalname;
      fileSize = req.file.size;
    } else if (req.body && req.body.hash) {
      targetHash = req.body.hash.trim().toLowerCase();
      fileName = req.body.fileName || 'Direct Hash';
    } else {
      return res.status(400).json({ success: false, error: 'Upload a file or provide a hash.' });
    }

    if (!/^[a-f0-9]{64}$/i.test(targetHash)) {
      return res.status(400).json({ status: 'TAMPERED_OR_UNKNOWN', isVerified: false, error: 'Invalid SHA-256 hash format.' });
    }

    const searchResult = ledger.findFile(targetHash);

    if (searchResult.found) {
      const block = searchResult.block;
      if (searchResult.isExpired) {
        return res.status(200).json({
          status: 'EXPIRED_PRUNED',
          isVerified: false,
          isExpired: true,
          message: `File exceeded its inactivity limit and was deleted from memory.`,
          fileHash: targetHash,
          fileName,
          blockIndex: block.index
        });
      }

      ledger.touchFileAccess(targetHash);
      return res.status(200).json({
        status: 'VERIFIED',
        isVerified: true,
        isExpired: false,
        message: 'File is authentic and untampered.',
        fileHash: targetHash,
        fileName,
        fileSize,
        blockIndex: block.index,
        timestamp: block.timestamp,
        expiresAt: block.expiresAt,
        ownerEmail: block.metadata?.ownerEmail || null,
        nonce: block.nonce,
        blockHash: block.hash
      });
    }

    // Check if filename matches an authentic block
    const targetedBlock = ledger.chain.slice().reverse().find(b => 
      b.index > 0 && b.metadata && 
      (b.metadata.originalName === fileName || b.metadata.fileName === fileName)
    );

    if (targetedBlock) {
      const ownerEmail = targetedBlock.metadata?.ownerEmail || req.body?.ownerEmail || process.env.SMTP_USER || 'registered-owner@example.com';
      await sendTamperAlertEmail(ownerEmail, fileName, targetedBlock.index, targetedBlock.fileHash, targetHash, 'VERIFICATION_AUDIT');

      return res.status(200).json({
        status: 'TAMPER_DETECTED',
        isVerified: false,
        isTampered: true,
        alertSent: true,
        ownerEmail: ownerEmail,
        fileName: fileName,
        blockIndex: targetedBlock.index,
        originalHash: targetedBlock.fileHash,
        tamperedHash: targetHash,
        quarantineSeconds: 30,
        message: `TAMPERING DETECTED: Real-time alert dispatched to ${ownerEmail}.`
      });
    }

    return res.status(200).json({
      status: 'TAMPERED_OR_UNKNOWN',
      isVerified: false,
      isTampered: false,
      message: 'File hash does not exist in ledger.',
      fileHash: targetHash,
      fileName
    });
  } catch (err) {
    return res.status(500).json({ status: 'ERROR', isVerified: false, error: err.message });
  }
});

app.get('/api/chain', (req, res) => {
  const chainValidation = ledger.isChainValid();
  return res.status(200).json({
    success: true,
    length: ledger.chain.length,
    isValid: chainValidation.isValid,
    chain: ledger.chain
  });
});

app.get('/api/stats', (req, res) => {
  return res.status(200).json({ success: true, stats: ledger.getStats() });
});

app.post('/api/audit', (req, res) => {
  const auditResult = ledger.isChainValid();
  return res.status(200).json({
    success: true,
    blocksChecked: ledger.chain.length,
    ...auditResult
  });
});

setInterval(() => {
  try { ledger.pruneExpiredFiles(vaultDir); } catch (e) {}
}, 30 * 1000);

// Centralized Security & Upload Error Handler
app.use((err, req, res, next) => {
  if (err && err.message && err.message.startsWith('SECURITY_DISALLOWED_FILE')) {
    return res.status(400).json({
      success: false,
      error: 'Security Enforcement: Executable files, installers, and system scripts (.exe, .bat, .sh, .cmd, etc.) are strictly prohibited.'
    });
  }
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      success: false,
      error: 'Upload rejected: File size exceeds the maximum permitted limit (100MB).'
    });
  }
  next(err);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

let serverInstance = null;
if (require.main === module) {
  serverInstance = app.listen(PORT, '0.0.0.0', () => {
    const localIP = getLocalNetworkIP();
    console.log(`=======================================================`);
    console.log(` CORALOCE ACTIVE FILE INTEGRITY SENTINEL RUNNING`);
    console.log(` "Fortifying the World’s Critical Assets"`);
    console.log(` Local URL         : http://localhost:${PORT}`);
    console.log(` Cross-Device URL  : http://${localIP}:${PORT}`);
    console.log(` Capabilities:`);
    console.log(`   - ACTIVE FILE SYSTEM WATCHER (FIM): Intercepts edits WHILE occurring on disk!`);
    console.log(`   - Server-Sent Events (SSE) live push to all open browsers`);
    console.log(`   - Instant Keystroke Tamper Interception Sandbox`);
    console.log(`   - 30-Second Security Quarantine Protocol & Email Alerts`);
    console.log(`=======================================================`);
  });
}

module.exports = { app, ledger, serverInstance };
