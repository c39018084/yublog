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

// Custom error class for WebAuthn operations
class WebAuthnError extends Error {
  constructor(type, message, details = {}) {
    super(message);
    this.name = 'WebAuthnError';
    this.type = type;
    this.blocked_until = details.blocked_until;
    this.days_remaining = details.days_remaining;
    this.reason = details.reason;
  }
}

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
 * Register a new WebAuthn credential (Security Key)
 */
export async function registerWebAuthn(userData) {
  try {
    console.log('WebAuthn registration starting for:', userData);

    if (!isWebAuthnSupported()) {
      throw new WebAuthnError('not_supported', 'WebAuthn is not supported on this device/browser');
    }

    // Step 1: Begin registration
    console.log('Starting WebAuthn registration for:', userData);
    const { data: options } = await api.post('/auth/webauthn/register/begin', userData);

    console.log('Registration options received:', options);

    // Step 2: Convert challenge and user ID from base64url
    const challenge = base64URLToArrayBuffer(options.challenge);
    const userId = base64URLToArrayBuffer(options.user.id);

    // Step 3: Prepare credential creation options
    const publicKeyCredentialCreationOptions = {
      ...options,
      challenge,
      user: {
        ...options.user,
        id: userId,
      },
    };

    console.log('Creating credential with options:', publicKeyCredentialCreationOptions);

    // Step 4: Create credential using WebAuthn API
    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    });

    console.log('Credential created:', credential);

    if (!credential) {
      throw new WebAuthnError('not_allowed', 'User cancelled the registration process');
    }

    // Step 5: Prepare credential for transport
    const credentialForTransport = {
      id: credential.id,
      rawId: credential.id,
      response: {
        clientDataJSON: arrayBufferToBase64URL(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64URL(credential.response.attestationObject),
      },
      type: credential.type,
    };

    console.log('Credential prepared for transport:', credentialForTransport);

    // Step 5: Complete registration
    const { data: result } = await api.post('/auth/webauthn/register/complete', credentialForTransport);

    console.log('Registration completed:', result);
    return result;
  } catch (error) {
    console.error('WebAuthn registration error:', error);
    
    if (error.name === 'NotSupportedError') {
      throw new WebAuthnError('not_supported', 'WebAuthn is not supported on this device');
    } else if (error.name === 'SecurityError') {
      throw new WebAuthnError('security_error', 'Security error occurred during registration');
    } else if (error.name === 'NotAllowedError') {
      throw new WebAuthnError('not_allowed', 'Registration was cancelled or not allowed');
    } else if (error.name === 'InvalidStateError') {
      throw new WebAuthnError('invalid_state', 'This security key is already registered');
    } else if (error.response?.status === 429) {
      // Handle device blocking
      const errorData = error.response.data;
      throw new WebAuthnError('device_blocked', errorData.message, {
        blocked_until: errorData.blocked_until,
        days_remaining: errorData.days_remaining,
        reason: errorData.reason
      });
    } else if (error.response?.data?.error) {
      throw new WebAuthnError('registration_failed', error.response.data.error);
    } else {
      throw new WebAuthnError('registration_failed', error.message || 'Registration failed');
    }
  }
}

/**
 * Authenticate with WebAuthn (Security Key login)
 */
export const authenticateWebAuthn = async (username) => {
  try {
    // Step 1: Begin authentication
    console.log('Starting WebAuthn authentication for:', username);
    const { data: options } = await api.post('/auth/webauthn/login/begin', { username });
    
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
    const { data: result } = await api.post('/auth/webauthn/login/complete', assertionForTransport);
    
    console.log('Authentication completed successfully:', result);
    console.log('Result has token:', !!result.token);
    console.log('Result token value:', result.token);
    console.log('Complete result object:', JSON.stringify(result, null, 2));
    return result;
  } catch (error) {
    console.error('WebAuthn authentication error:', error);
    
    if (error.name === 'InvalidStateError') {
      const invalidStateError = new Error('No credentials found for this account. Please make sure you\'re using the correct username and that your security key is registered.');
      invalidStateError.type = 'invalid_state';
      throw invalidStateError;
    } else if (error.name === 'NotAllowedError') {
      const notAllowedError = new Error('Authentication was cancelled or timed out. Please try again and make sure to touch your security key when prompted.');
      notAllowedError.type = 'not_allowed';
      throw notAllowedError;
    } else if (error.name === 'SecurityError') {
      const securityError = new Error('Security error occurred. Please make sure you\'re using HTTPS and try again.');
      securityError.type = 'security_error';
      throw securityError;
    } else if (error.name === 'NotSupportedError') {
      const notSupportedError = new Error('WebAuthn is not supported on this device/browser. Please use a modern browser like Chrome, Firefox, Safari, or Edge.');
      notSupportedError.type = 'not_supported';
      throw notSupportedError;
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

/**
 * Register an additional WebAuthn device for an existing authenticated user
 */
export async function registerAdditionalDevice(deviceName) {
  try {
    console.log('Additional WebAuthn device registration starting for:', deviceName);

    if (!isWebAuthnSupported()) {
      throw new WebAuthnError('not_supported', 'WebAuthn is not supported on this device/browser');
    }

    // Get authentication token from localStorage
    const token = localStorage.getItem('yublog_token');
    if (!token) {
      throw new WebAuthnError('authentication_required', 'You must be logged in to add additional devices');
    }

    // Step 1: Begin additional device registration
    console.log('Starting additional WebAuthn device registration');
    const { data: options } = await api.post('/user/devices/webauthn/begin', { deviceName }, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    console.log('Additional device registration options received:', options);

    // Step 2: Convert challenge and user ID from base64url
    const challenge = base64URLToArrayBuffer(options.challenge);
    const userId = base64URLToArrayBuffer(options.user.id);

    // Step 3: Prepare credential creation options
    const publicKeyCredentialCreationOptions = {
      ...options,
      challenge,
      user: {
        ...options.user,
        id: userId,
      },
      excludeCredentials: options.excludeCredentials?.map(cred => ({
        ...cred,
        id: base64URLToArrayBuffer(cred.id),
      })) || [],
    };

    console.log('Creating additional device credential with options:', publicKeyCredentialCreationOptions);

    // Step 4: Create credential using WebAuthn API
    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    });

    console.log('Additional device credential created:', credential);

    if (!credential) {
      throw new WebAuthnError('not_allowed', 'User cancelled the device registration process');
    }

    // Step 5: Prepare credential for transport
    const credentialForTransport = {
      id: credential.id,
      rawId: credential.id,
      response: {
        clientDataJSON: arrayBufferToBase64URL(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64URL(credential.response.attestationObject),
      },
      type: credential.type,
    };

    console.log('Additional device credential prepared for transport:', credentialForTransport);

    // Step 6: Complete additional device registration
    const { data: result } = await api.post('/user/devices/webauthn/complete', credentialForTransport, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    console.log('Additional device registration completed:', result);
    return result;
  } catch (error) {
    console.error('Additional WebAuthn device registration error:', error);
    
    if (error.name === 'NotSupportedError') {
      throw new WebAuthnError('not_supported', 'WebAuthn is not supported on this device');
    } else if (error.name === 'SecurityError') {
      throw new WebAuthnError('security_error', 'Security error occurred during device registration');
    } else if (error.name === 'NotAllowedError') {
      throw new WebAuthnError('not_allowed', 'Device registration was cancelled or not allowed');
    } else if (error.name === 'InvalidStateError') {
      throw new WebAuthnError('invalid_state', 'This security key is already registered');
    } else if (error.response?.status === 429) {
      // Handle device blocking
      const errorData = error.response.data;
      throw new WebAuthnError('device_blocked', errorData.message, {
        blocked_until: errorData.blocked_until,
        days_remaining: errorData.days_remaining,
        reason: errorData.reason
      });
    } else if (error.response?.data?.error) {
      throw new WebAuthnError('registration_failed', error.response.data.error);
    } else {
      throw new WebAuthnError('registration_failed', error.message || 'Device registration failed');
    }
  }
} 