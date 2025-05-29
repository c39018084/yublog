import axios from 'axios';

// Configure axios base URL
const API_BASE_URL = process.env.REACT_APP_API_URL || '';
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Custom error class for TOTP operations
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
    
    const { data } = await api.post('/api/auth/totp/login', {
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
    const { data } = await api.post('/api/auth/totp/check', { username });
    return data.available || false;
  } catch (error) {
    // If the endpoint doesn't exist or fails, assume TOTP is not available
    console.log('TOTP check failed:', error.message);
    return false;
  }
}

/**
 * Setup TOTP for the authenticated user
 */
export async function setupTotp() {
  try {
    const token = localStorage.getItem('token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await api.post('/api/auth/totp/setup', {}, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    return data;
  } catch (error) {
    console.error('TOTP setup error:', error);
    
    if (error.response?.data?.error) {
      throw new TotpError(error.response.data.error);
    } else {
      throw new TotpError(error.message || 'TOTP setup failed');
    }
  }
}

/**
 * Get TOTP status for the authenticated user
 */
export async function getTotpStatus() {
  try {
    const token = localStorage.getItem('token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await api.get('/api/auth/totp/status', {
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
    const token = localStorage.getItem('token');
    if (!token) {
      throw new TotpError('Authentication required');
    }

    const { data } = await api.post('/api/auth/totp/disable', {}, {
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

export default {
  loginWithTotp,
  checkTotpAvailable,
  setupTotp,
  getTotpStatus,
  disableTotp
}; 