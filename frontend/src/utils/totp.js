import axios from 'axios';

// TOTP-specific error class
class TotpError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'TotpError';
    this.details = details;
  }
}

/**
 * Login with TOTP authenticator code
 */
export async function loginWithTotp({ username, code, isBackupCode = false }) {
  try {
    console.log('Starting TOTP login for:', username);
    
    const { data } = await axios.post('/auth/totp/login', {
      username,
      code,
      isBackupCode
    });

    console.log('TOTP login successful:', data);
    return data;
  } catch (error) {
    console.error('TOTP login error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'TOTP login failed');
    }
  }
}

/**
 * Check if TOTP is available for a username
 */
export async function checkTotpAvailable(username) {
  try {
    // We'll make a simple request to check if the user has TOTP enabled
    // This is a safe operation that doesn't reveal sensitive information
    const { data } = await axios.post('/auth/totp/check', { username });
    return data.available || false;
  } catch (error) {
    // If the endpoint doesn't exist or fails, assume TOTP is not available
    console.log('TOTP check failed:', error.message);
    return false;
  }
}

/**
 * Get TOTP status for the authenticated user
 */
export async function getTotpStatus() {
  try {
    const token = localStorage.getItem('yublog_token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await axios.get('/auth/totp/status', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return data;
  } catch (error) {
    console.error('TOTP status error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'Failed to get TOTP status');
    }
  }
}

/**
 * Disable TOTP for the authenticated user
 */
export async function disableTotp() {
  try {
    const token = localStorage.getItem('yublog_token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await axios.post('/auth/totp/disable', {}, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return data;
  } catch (error) {
    console.error('TOTP disable error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'Failed to disable TOTP');
    }
  }
}

/**
 * Generate TOTP secret and QR code (without saving to database yet)
 */
export async function generateTotpSecret() {
  try {
    const token = localStorage.getItem('yublog_token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await axios.post('/auth/totp/generate', {}, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return data;
  } catch (error) {
    console.error('TOTP secret generation error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'Failed to generate TOTP secret');
    }
  }
}

/**
 * Verify TOTP code and complete setup (saves to database)
 */
export async function verifyTotpSetup(secret, verificationCode) {
  try {
    const token = localStorage.getItem('yublog_token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await axios.post('/auth/totp/verify-setup', {
      secret,
      verificationCode
    }, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return data;
  } catch (error) {
    console.error('TOTP verification error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'Failed to verify TOTP code');
    }
  }
}

/**
 * Reset TOTP setup (cleanup incomplete setups)
 */
export async function resetTotpSetup() {
  try {
    const token = localStorage.getItem('yublog_token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await axios.post('/auth/totp/reset', {}, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return data;
  } catch (error) {
    console.error('TOTP reset error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'Failed to reset TOTP setup');
    }
  }
}

export default {
  loginWithTotp,
  checkTotpAvailable,
  getTotpStatus,
  disableTotp,
  generateTotpSecret,
  verifyTotpSetup,
  resetTotpSetup
}; 