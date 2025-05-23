import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import axios from 'axios';

// Configure axios base URL
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Register a new WebAuthn credential (YubiKey)
 */
export const registerWebAuthn = async (userData) => {
  try {
    // Step 1: Begin registration
    const { data: options } = await api.post('/api/auth/webauthn/register/begin', userData);
    
    // Step 2: Get credential from authenticator
    const credential = await startRegistration({
      optionsJSON: options
    });
    
    // Step 3: Complete registration
    const { data: result } = await api.post('/api/auth/webauthn/register/complete', credential);
    
    return result;
  } catch (error) {
    if (error.name === 'InvalidStateError') {
      throw new Error('Authenticator is already registered. Please try logging in instead.');
    } else if (error.name === 'NotAllowedError') {
      throw new Error('Registration was cancelled or timed out.');
    } else if (error.name === 'SecurityError') {
      throw new Error('Security error. Please make sure you\'re using HTTPS.');
    } else if (error.name === 'NotSupportedError') {
      throw new Error('WebAuthn is not supported on this device/browser.');
    } else if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    
    console.error('WebAuthn registration error:', error);
    throw new Error('Registration failed. Please try again.');
  }
};

/**
 * Authenticate with WebAuthn (YubiKey login)
 */
export const authenticateWebAuthn = async (username) => {
  try {
    // Step 1: Begin authentication
    const { data: options } = await api.post('/api/auth/webauthn/login/begin', { username });
    
    // Step 2: Get assertion from authenticator
    const credential = await startAuthentication({
      optionsJSON: options
    });
    
    // Step 3: Complete authentication
    const { data: result } = await api.post('/api/auth/webauthn/login/complete', credential);
    
    return result;
  } catch (error) {
    if (error.name === 'InvalidStateError') {
      throw new Error('No credentials found for this account.');
    } else if (error.name === 'NotAllowedError') {
      throw new Error('Authentication was cancelled or timed out.');
    } else if (error.name === 'SecurityError') {
      throw new Error('Security error. Please make sure you\'re using HTTPS.');
    } else if (error.name === 'NotSupportedError') {
      throw new Error('WebAuthn is not supported on this device/browser.');
    } else if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    
    console.error('WebAuthn authentication error:', error);
    throw new Error('Authentication failed. Please try again.');
  }
};

/**
 * Check if WebAuthn is supported by the browser
 */
export const isWebAuthnSupported = () => {
  return typeof window !== 'undefined' && 
         window.PublicKeyCredential && 
         typeof window.PublicKeyCredential === 'function' &&
         typeof navigator.credentials === 'object' &&
         typeof navigator.credentials.create === 'function' &&
         typeof navigator.credentials.get === 'function';
};

/**
 * Check if platform authenticator (like Touch ID, Face ID, Windows Hello) is available
 */
export const isPlatformAuthenticatorAvailable = async () => {
  if (!isWebAuthnSupported()) return false;
  
  try {
    return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
};

/**
 * Get a user-friendly device type name
 */
export const getDeviceType = () => {
  if (typeof window === 'undefined' || typeof navigator === 'undefined') {
    return 'Unknown Device';
  }
  
  const userAgent = navigator.userAgent;
  
  if (/Android/i.test(userAgent)) return 'Android Device';
  if (/iPhone|iPad|iPod/i.test(userAgent)) return 'iOS Device';
  if (/Windows/i.test(userAgent)) return 'Windows Device';
  if (/Macintosh|Mac OS X/i.test(userAgent)) return 'Mac Device';
  if (/Linux/i.test(userAgent)) return 'Linux Device';
  
  return 'Unknown Device';
}; 