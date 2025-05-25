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

// Helper functions for WebAuthn
function base64URLToArrayBuffer(base64URL) {
  // Add padding if needed
  const padding = 4 - (base64URL.length % 4);
  if (padding !== 4) {
    base64URL += '='.repeat(padding);
  }
  // Replace URL-safe characters
  const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64URL(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function convertPublicKeyCredentialCreationOptions(options) {
  return {
    ...options,
    challenge: base64URLToArrayBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64URLToArrayBuffer(options.user.id),
    },
    excludeCredentials: options.excludeCredentials?.map(cred => ({
      ...cred,
      id: base64URLToArrayBuffer(cred.id),
    })) || [],
  };
}

function convertPublicKeyCredentialRequestOptions(options) {
  return {
    ...options,
    challenge: base64URLToArrayBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map(cred => ({
      ...cred,
      id: base64URLToArrayBuffer(cred.id),
    })) || [],
  };
}

function convertCredentialForTransport(credential) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64URL(credential.rawId),
    response: {
      clientDataJSON: arrayBufferToBase64URL(credential.response.clientDataJSON),
      attestationObject: arrayBufferToBase64URL(credential.response.attestationObject),
    },
    type: credential.type,
  };
}

function convertAssertionForTransport(assertion) {
  return {
    id: assertion.id,
    rawId: arrayBufferToBase64URL(assertion.rawId),
    response: {
      authenticatorData: arrayBufferToBase64URL(assertion.response.authenticatorData),
      clientDataJSON: arrayBufferToBase64URL(assertion.response.clientDataJSON),
      signature: arrayBufferToBase64URL(assertion.response.signature),
      userHandle: assertion.response.userHandle ? arrayBufferToBase64URL(assertion.response.userHandle) : null,
    },
    type: assertion.type,
  };
}

/**
 * Register a new WebAuthn credential (YubiKey)
 */
export const registerWebAuthn = async (userData) => {
  try {
    // Step 1: Begin registration
    console.log('Starting WebAuthn registration for:', userData);
    const { data: options } = await api.post('/api/auth/webauthn/register/begin', userData);
    
    console.log('WebAuthn options received from server:', JSON.stringify(options, null, 2));
    
    // Step 2: Convert options for browser API
    const publicKeyCredentialCreationOptions = convertPublicKeyCredentialCreationOptions(options);
    
    console.log('Converted options for browser:', publicKeyCredentialCreationOptions);
    
    // Step 3: Get credential from authenticator using native API
    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions
    });
    
    if (!credential) {
      throw new Error('Failed to create credential');
    }
    
    console.log('Received credential from authenticator:', credential);
    
    // Step 4: Convert credential for transport
    const credentialForTransport = convertCredentialForTransport(credential);
    
    console.log('Credential converted for transport:', credentialForTransport);
    
    // Step 5: Complete registration
    const { data: result } = await api.post('/api/auth/webauthn/register/complete', credentialForTransport);
    
    console.log('Registration completed successfully:', result);
    return result;
  } catch (error) {
    console.error('WebAuthn registration error:', error);
    
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
    
    throw new Error('Registration failed. Please try again.');
  }
};

/**
 * Authenticate with WebAuthn (YubiKey login)
 */
export const authenticateWebAuthn = async (username) => {
  try {
    // Step 1: Begin authentication
    console.log('Starting WebAuthn authentication for:', username);
    const { data: options } = await api.post('/api/auth/webauthn/login/begin', { username });
    
    console.log('WebAuthn auth options received from server:', JSON.stringify(options, null, 2));
    
    // Step 2: Convert options for browser API
    const publicKeyCredentialRequestOptions = convertPublicKeyCredentialRequestOptions(options);
    
    console.log('Converted auth options for browser:', publicKeyCredentialRequestOptions);
    
    // Step 3: Get assertion from authenticator using native API
    const assertion = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    });
    
    if (!assertion) {
      throw new Error('Failed to get assertion from authenticator');
    }
    
    console.log('Received assertion from authenticator:', assertion);
    
    // Step 4: Convert assertion for transport
    const assertionForTransport = convertAssertionForTransport(assertion);
    
    console.log('Assertion converted for transport:', assertionForTransport);
    
    // Step 5: Complete authentication
    const { data: result } = await api.post('/api/auth/webauthn/login/complete', assertionForTransport);
    
    console.log('Authentication completed successfully:', result);
    console.log('Result has token:', !!result.token);
    console.log('Result token value:', result.token);
    console.log('Complete result object:', JSON.stringify(result, null, 2));
    return result;
  } catch (error) {
    console.error('WebAuthn authentication error:', error);
    
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