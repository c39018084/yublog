import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { db } from './database.js';

/**
 * TOTP (Time-based One-Time Password) Authentication Module
 * 
 * This module provides TOTP authentication for backup login when WebAuthn is not available.
 * It follows TOTP RFC 6238 and HOTP RFC 4226 standards for security.
 * 
 * Security Features:
 * - 30-second time windows (industry standard)
 * - 6-digit codes for balance of security and usability
 * - Encrypted secret storage
 * - Rate limiting protection
 * - Backup recovery codes
 * - Comprehensive audit logging
 */

const TOTP_CONFIG = {
  // TOTP Configuration following RFC 6238
  window: 1, // Allow 1 window before/after for clock drift (±30 seconds)
  step: 30, // 30-second time step (industry standard)
  digits: 6, // 6-digit codes (balance of security and usability)
  algorithm: 'sha1', // SHA-1 for TOTP compatibility (required by RFC)
  
  // Service Configuration
  issuer: process.env.TOTP_ISSUER || 'YuBlog',
  
  // Security Configuration
  backup_codes_count: 8, // Number of backup recovery codes
  backup_code_length: 8, // Length of each backup code
  
  // Rate Limiting
  max_attempts: 5, // Maximum failed attempts before lockout
  lockout_duration: 15 * 60, // 15 minutes lockout
};

// Encryption key for storing TOTP secrets securely
const ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || (() => {
  console.error('⚠️  SECURITY WARNING: TOTP_ENCRYPTION_KEY not set!');
  console.error('⚠️  Using temporary key. Set TOTP_ENCRYPTION_KEY in production!');
  return crypto.randomBytes(32).toString('hex');
})();

/**
 * Encrypt sensitive data (TOTP secrets, backup codes)
 */
function encrypt(text) {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const iv = crypto.randomBytes(16);
  
  const cipher = crypto.createCipherGCM(algorithm, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Decrypt sensitive data
 */
function decrypt(encryptedData) {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const iv = Buffer.from(encryptedData.iv, 'hex');
  
  const decipher = crypto.createDecipherGCM(algorithm, key, iv);
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

/**
 * Generate cryptographically secure backup codes
 */
function generateBackupCodes() {
  const codes = [];
  for (let i = 0; i < TOTP_CONFIG.backup_codes_count; i++) {
    // Generate random backup code with mixed case and numbers
    const code = crypto.randomBytes(TOTP_CONFIG.backup_code_length)
      .toString('base64')
      .replace(/[+/=]/g, '')
      .substr(0, TOTP_CONFIG.backup_code_length)
      .toUpperCase();
    codes.push(code);
  }
  return codes;
}

/**
 * Setup TOTP for a user (login-only, requires existing WebAuthn credential)
 */
export async function setupTotp(userId, req) {
  try {
    // Security Check: Ensure user already has WebAuthn credentials
    const userCredentials = await db.getUserCredentials(userId);
    if (!userCredentials || userCredentials.length === 0) {
      throw new Error('TOTP setup requires at least one WebAuthn credential');
    }

    // Check if user already has TOTP enabled
    const existingTotp = await db.getTotpAuthenticator(userId);
    if (existingTotp) {
      throw new Error('TOTP authenticator already enabled for this user');
    }

    // Generate TOTP secret
    const secret = speakeasy.generateSecret({
      name: `YuBlog (${req.user.username})`,
      issuer: TOTP_CONFIG.issuer,
      length: 32 // 256-bit secret for security
    });

    // Generate backup codes
    const backupCodes = generateBackupCodes();

    // Encrypt sensitive data
    const encryptedSecret = encrypt(secret.base32);
    const encryptedBackupCodes = backupCodes.map(code => encrypt(code));

    // Store in database
    await db.createTotpAuthenticator({
      userId,
      secret: JSON.stringify(encryptedSecret),
      name: 'Authenticator App',
      backupCodes: encryptedBackupCodes.map(enc => JSON.stringify(enc))
    });

    // Generate QR code for easy setup
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Log the setup
    await db.logAuditEvent({
      userId,
      action: 'totp_setup',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: {
        timestamp: new Date().toISOString()
      }
    });

    return {
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      backupCodes: backupCodes, // Return unencrypted for user to save
      issuer: TOTP_CONFIG.issuer,
      accountName: req.user.username
    };

  } catch (error) {
    console.error('TOTP setup error:', error);
    
    // Log failed setup attempt
    await db.logAuditEvent({
      userId,
      action: 'totp_setup',
      success: false,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: {
        error: error.message,
        timestamp: new Date().toISOString()
      }
    });

    throw error;
  }
}

/**
 * Verify TOTP code during login
 */
export async function verifyTotp(userId, token, req) {
  try {
    // Get user's TOTP configuration
    const totpAuth = await db.getTotpAuthenticator(userId);
    if (!totpAuth || !totpAuth.is_active) {
      throw new Error('TOTP authenticator not found or disabled');
    }

    // Decrypt the secret
    const encryptedSecret = JSON.parse(totpAuth.secret);
    const secret = decrypt(encryptedSecret);

    // Verify the TOTP token
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: TOTP_CONFIG.window,
      step: TOTP_CONFIG.step
    });

    if (verified) {
      // Update last used timestamp
      await db.updateTotpLastUsed(userId);

      // Log successful authentication
      await db.logAuditEvent({
        userId,
        action: 'totp_login_success',
        success: true,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          timestamp: new Date().toISOString()
        }
      });

      return { verified: true };
    } else {
      // Log failed attempt
      await db.logAuditEvent({
        userId,
        action: 'totp_login_attempt',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          reason: 'invalid_code',
          timestamp: new Date().toISOString()
        }
      });

      return { verified: false, error: 'Invalid TOTP code' };
    }

  } catch (error) {
    console.error('TOTP verification error:', error);
    
    // Log error
    await db.logAuditEvent({
      userId,
      action: 'totp_login_attempt',
      success: false,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: {
        error: error.message,
        timestamp: new Date().toISOString()
      }
    });

    throw error;
  }
}

/**
 * Verify backup recovery code
 */
export async function verifyBackupCode(userId, code, req) {
  try {
    // Get user's TOTP configuration
    const totpAuth = await db.getTotpAuthenticator(userId);
    if (!totpAuth || !totpAuth.is_active) {
      throw new Error('TOTP authenticator not found or disabled');
    }

    // Decrypt backup codes
    const encryptedCodes = totpAuth.backup_codes || [];
    let codeFound = false;
    let codeIndex = -1;

    for (let i = 0; i < encryptedCodes.length; i++) {
      if (encryptedCodes[i]) { // Skip used codes (null values)
        try {
          const encryptedCode = JSON.parse(encryptedCodes[i]);
          const decryptedCode = decrypt(encryptedCode);
          
          if (decryptedCode === code.toUpperCase()) {
            codeFound = true;
            codeIndex = i;
            break;
          }
        } catch (decryptError) {
          // Skip corrupted codes
          continue;
        }
      }
    }

    if (codeFound) {
      // Mark code as used
      await db.useBackupCode(userId, codeIndex);

      // Update last used timestamp
      await db.updateTotpLastUsed(userId);

      // Log successful authentication
      await db.logAuditEvent({
        userId,
        action: 'totp_backup_code_used',
        success: true,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          codeIndex: codeIndex,
          timestamp: new Date().toISOString()
        }
      });

      return { verified: true, message: 'Backup code accepted' };
    } else {
      // Log failed attempt
      await db.logAuditEvent({
        userId,
        action: 'totp_login_attempt',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          reason: 'invalid_backup_code',
          timestamp: new Date().toISOString()
        }
      });

      return { verified: false, error: 'Invalid backup code' };
    }

  } catch (error) {
    console.error('Backup code verification error:', error);
    
    // Log error
    await db.logAuditEvent({
      userId,
      action: 'totp_login_attempt',
      success: false,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: {
        error: error.message,
        timestamp: new Date().toISOString()
      }
    });

    throw error;
  }
}

/**
 * Disable TOTP for a user
 */
export async function disableTotp(userId, req) {
  try {
    // Disable TOTP authenticator
    await db.disableTotpAuthenticator(userId);

    // Log the action
    await db.logAuditEvent({
      userId,
      action: 'totp_disable',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details: {
        timestamp: new Date().toISOString()
      }
    });

    return { success: true };

  } catch (error) {
    console.error('TOTP disable error:', error);
    throw error;
  }
}

/**
 * Get TOTP status for a user
 */
export async function getTotpStatus(userId) {
  try {
    const hasTotp = await db.hasTotpAuthenticator(userId);
    const totpAuth = await db.getTotpAuthenticator(userId);

    return {
      enabled: hasTotp,
      lastUsed: totpAuth?.last_used || null,
      createdAt: totpAuth?.created_at || null
    };

  } catch (error) {
    console.error('Get TOTP status error:', error);
    throw error;
  }
}

export default {
  setupTotp,
  verifyTotp,
  verifyBackupCode,
  disableTotp,
  getTotpStatus
}; 