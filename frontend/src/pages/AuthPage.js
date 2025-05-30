import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { registerWebAuthn, authenticateWebAuthn, isWebAuthnSupported } from '../utils/webauthn';
import { loginWithTotp, checkTotpAvailable } from '../utils/totp';
import LoadingSpinner from '../components/LoadingSpinner';
import AuthMessage from '../components/AuthMessage';
import { Shield, Key, Smartphone, AlertTriangle, CheckCircle } from 'lucide-react';

const AuthPage = () => {
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [loginTab, setLoginTab] = useState('webauthn'); // 'webauthn' or 'totp' when in login mode
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    totpCode: ''
  });
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const [isBackupCode, setIsBackupCode] = useState(false);
  const [totpUsernameEntered, setTotpUsernameEntered] = useState(false); // Track if username entered for TOTP
  const [message, setMessage] = useState(null);
  const { login } = useAuth();

  const totpCodeInputRef = useRef(null);
  const totpUsernameInputRef = useRef(null);

  useEffect(() => {
    setWebAuthnSupported(isWebAuthnSupported());
  }, []);

  // Auto-focus appropriate input when switching to TOTP tab
  useEffect(() => {
    if (mode === 'login' && loginTab === 'totp') {
      if (!totpUsernameEntered && totpUsernameInputRef.current) {
        // Focus username field if not entered yet
        setTimeout(() => {
          totpUsernameInputRef.current?.focus();
        }, 100);
      } else if (totpUsernameEntered && totpCodeInputRef.current) {
        // Focus code field if username already entered
        setTimeout(() => {
          totpCodeInputRef.current?.focus();
        }, 100);
      }
    }
  }, [mode, loginTab, totpUsernameEntered]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });

    // When username is entered in TOTP tab, show code fields and focus
    if (name === 'username' && loginTab === 'totp' && value.trim().length > 0 && !totpUsernameEntered) {
      setTotpUsernameEntered(true);
      // Small delay to ensure code field is rendered before focusing
      setTimeout(() => {
        if (totpCodeInputRef.current) {
          totpCodeInputRef.current.focus();
        }
      }, 100);
    } else if (name === 'username' && loginTab === 'totp' && value.trim().length === 0) {
      setTotpUsernameEntered(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage(null);

    try {
      const result = await registerWebAuthn({
        username: formData.username,
        displayName: formData.username
      });

      console.log('Registration result:', result);

      if (result && result.verified) {
        // Enhanced success message with sophisticated styling
        setMessage({
          type: 'success',
          title: 'Registration Successful!',
          message: `Welcome to YuBlog, ${formData.username}! Your account has been created successfully with passwordless authentication.`,
          details: {
            icon: '🎉',
            features: [
              'Your security key has been securely registered',
              'No passwords needed - maximum security',
              'Account is ready for secure blogging',
              result.user?.isAdmin ? 'Administrator privileges granted (first user)' : null
            ].filter(Boolean),
            nextSteps: [
              'You can now sign in anytime with your security key',
              'Start creating your first blog post',
              'Explore your secure dashboard'
            ],
            additionalInfo: 'Your device is now registered with our secure system. Keep your security key safe - it\'s your key to your account!',
            actions: [{
              label: 'Continue to Sign In',
              action: () => {
                setMode('login');
                setFormData({ username: formData.username }); // Keep username for convenience
                setMessage(null);
              }
            }],
            showSkipButton: true, // Add skip button functionality
            skipDelay: 5000 // Show skip button after 5 seconds
          },
          autoHide: false, // Don't auto-hide success messages
        });

        // Auto-switch to login after showing success for 60 seconds (1 minute)
        setTimeout(() => {
          setMode('login');
          setFormData({ username: formData.username }); // Keep username for convenience
          setMessage(null);
        }, 60000); // Changed from 10000 to 60000 (1 minute)
      } else {
        throw new Error('Registration failed - no verification result received');
      }
    } catch (error) {
      console.error('Registration error:', error);
      
      if (error.type === 'device_blocked') {
        setMessage({
          type: 'device_blocked',
          title: 'Device Registration Blocked',
          message: error.message,
          details: {
            blockedUntil: error.blocked_until,
            daysRemaining: error.days_remaining,
            reason: 'account_spam_prevention',
            additionalInfo: 'This security measure prevents abuse and ensures platform integrity. Each device can only create one account every 34 days.'
          }
        });
      } else if (error.type === 'invalid_state') {
        setMessage({
          type: 'error',
          title: 'Security Key Error',
          message: error.message,
          details: {
            additionalInfo: 'This usually happens when the connection is not secure. Make sure you\'re accessing the site via HTTPS.'
          }
        });
      } else if (error.type === 'not_allowed') {
        setMessage({
          type: 'error',
          title: 'Authentication Cancelled',
          message: error.message,
          details: {
            additionalInfo: 'Registration was cancelled. Please try again and follow the prompts on your security device.'
          }
        });
      } else if (error.type === 'security_error') {
        setMessage({
          type: 'error',
          title: 'Security Error',
          message: error.message,
          details: {
            additionalInfo: 'This usually happens when the connection is not secure. Make sure you\'re accessing the site via HTTPS.'
          }
        });
      } else if (error.type === 'not_supported') {
        setMessage({
          type: 'error',
          title: 'WebAuthn Not Supported',
          message: error.message,
          details: {
            additionalInfo: 'WebAuthn requires a modern browser and operating system. Please update your browser or try a different device.'
          }
        });
      } else {
        setMessage({
          type: 'error',
          title: 'Registration Failed',
          message: error.message,
          details: {
            additionalInfo: 'Please check your security key and username, then try again. Make sure your device supports WebAuthn.'
          }
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!webAuthnSupported) {
      setMessage({
        type: 'error',
        title: 'WebAuthn Not Supported',
        message: 'WebAuthn is not supported on this device/browser. Please use a modern browser like Chrome, Firefox, Safari, or Edge.',
        details: {
          additionalInfo: 'WebAuthn requires a compatible browser and operating system to function properly.'
        }
      });
      return;
    }

    setMessage(null); // Clear any existing messages
    setIsLoading(true);
    
    try {
      const result = await authenticateWebAuthn(formData.username);
      
      if (result.token) {
        console.log('About to call login with:', { token: result.token, user: result.user });
        login(result.token, result.user);
        console.log('Login called successfully');
        
        setMessage({
          type: 'success',
          title: 'Welcome Back!',
          message: `Successfully authenticated as ${result.user.displayName || result.user.username}`,
          autoHide: true,
          duration: 2000
        });
        
        // Add a short delay to ensure state updates
        setTimeout(() => {
          console.log('Current auth state after login:', {
            isAuthenticated: Boolean(result.token && result.user),
            hasToken: !!result.token,
            hasUser: !!result.user
          });
        }, 100);
      }
    } catch (error) {
      console.error('Login error:', error);
      
      if (error.type === 'invalid_state') {
        setMessage({
          type: 'warning',
          title: 'No Credentials Found',
          message: error.message,
          details: {
            additionalInfo: 'Make sure you\'re using the correct username and that you\'ve registered this security key with this account.'
          }
        });
      } else if (error.type === 'not_allowed') {
        setMessage({
          type: 'warning',
          title: 'Authentication Cancelled',
          message: error.message,
          details: {
            additionalInfo: 'Make sure to touch your security key when prompted. Authentication requires physical interaction with your device.'
          }
        });
      } else if (error.type === 'security_error') {
        setMessage({
          type: 'error',
          title: 'Security Error',
          message: error.message,
          details: {
            additionalInfo: 'This usually happens when the connection is not secure. Make sure you\'re accessing the site via HTTPS.'
          }
        });
      } else if (error.type === 'not_supported') {
        setMessage({
          type: 'error',
          title: 'WebAuthn Not Supported',
          message: error.message,
          details: {
            additionalInfo: 'WebAuthn requires a modern browser and operating system. Please update your browser or try a different device.'
          }
        });
      } else {
        setMessage({
          type: 'error',
          title: 'Authentication Failed',
          message: error.message,
          details: {
            additionalInfo: 'Please check your security key and username, then try again. Make sure your device is registered for this account.'
          }
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleTotpLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage(null);

    try {
      const result = await loginWithTotp({
        username: formData.username,
        code: formData.totpCode,
        isBackupCode: isBackupCode
      });

      if (result.token) {
        login(result.token, result.user);
        
        setMessage({
          type: 'success',
          title: 'Welcome Back!',
          message: `Successfully authenticated with ${isBackupCode ? 'backup code' : 'authenticator app'}`,
          autoHide: true,
          duration: 2000
        });
      }
    } catch (error) {
      console.error('TOTP login error:', error);
      
      setMessage({
        type: 'error',
        title: 'Authentication Failed',
        message: error.message || 'Invalid code or username',
        details: {
          additionalInfo: isBackupCode 
            ? 'Please check your backup code and try again. Each backup code can only be used once.'
            : 'Please check your authenticator app and enter the current 6-digit code.'
        }
      });
    } finally {
      setIsLoading(false);
    }
  };

  const switchMode = () => {
    if (mode === 'login') {
      setMode('register');
      setLoginTab('webauthn'); // Reset to webauthn tab when switching to register
    } else {
      setMode('login');
      setLoginTab('webauthn'); // Reset to webauthn tab when switching to login
    }
    setFormData({ username: '', totpCode: '' });
    setTotpUsernameEntered(false); // Reset TOTP username state
    setMessage(null);
    setIsBackupCode(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 bg-gradient-to-br from-primary-50 via-white to-secondary-50">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-md w-full space-y-8"
      >
        {/* Header */}
        <div className="text-center">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
            className="mx-auto h-16 w-16 flex items-center justify-center rounded-full bg-primary-100"
          >
            <Shield className="h-10 w-10 text-primary-600" />
          </motion.div>
          <h2 className="mt-6 text-3xl font-bold gradient-text">
            {mode === 'login' ? 'Welcome back' : 'Create your account'}
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            {mode === 'login' 
              ? `Sign in securely with your ${loginTab === 'webauthn' ? 'security key' : 'authenticator app'}` 
              : 'Register with passwordless authentication'
            }
          </p>
        </div>

        {/* Message Display */}
        {message && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <AuthMessage
              type={message.type}
              title={message.title}
              message={message.message}
              details={message.details}
              autoHide={message.autoHide}
              duration={message.duration}
              onDismiss={() => setMessage(null)}
            />
          </motion.div>
        )}

        {/* WebAuthn Support Warning */}
        {!webAuthnSupported && !message && (
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="bg-amber-50 border border-amber-200 rounded-lg p-4"
          >
            <div className="flex items-start">
              <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5 mr-3 flex-shrink-0" />
              <div>
                <h3 className="text-sm font-medium text-amber-800">
                  WebAuthn Not Supported
                </h3>
                <p className="mt-1 text-sm text-amber-700">
                  Your browser doesn't support WebAuthn. Please use a modern browser like Chrome, Firefox, Safari, or Edge.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {/* Main Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="card"
        >
          {/* Login Tabs (only show in login mode) */}
          {mode === 'login' && (
            <div className="mb-6">
              <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
                <button
                  type="button"
                  onClick={() => {
                    setLoginTab('webauthn');
                    setTotpUsernameEntered(false); // Reset when switching away from TOTP
                  }}
                  className={`flex-1 py-2 px-3 text-sm font-medium rounded-md transition-colors ${
                    loginTab === 'webauthn'
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <Key className="h-4 w-4 inline mr-2" />
                  Security Key
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setLoginTab('totp');
                    setTotpUsernameEntered(false); // Reset when switching to TOTP
                  }}
                  className={`flex-1 py-2 px-3 text-sm font-medium rounded-md transition-colors ${
                    loginTab === 'totp'
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <Smartphone className="h-4 w-4 inline mr-2" />
                  Authenticator App
                </button>
              </div>
            </div>
          )}

          <form onSubmit={
            mode === 'login' ? (
              loginTab === 'webauthn' ? handleLogin : 
              loginTab === 'totp' ? (
                totpUsernameEntered ? handleTotpLogin : 
                (e) => {
                  e.preventDefault();
                  if (formData.username.trim()) {
                    setTotpUsernameEntered(true);
                    setTimeout(() => {
                      if (totpCodeInputRef.current) {
                        totpCodeInputRef.current.focus();
                      }
                    }, 100);
                  }
                }
              ) : handleLogin
            ) : handleRegister
          } className="space-y-6">
            {/* Username Field */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-secondary-700 mb-2">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                value={formData.username}
                onChange={handleInputChange}
                className="input-field"
                placeholder="Enter your username"
                disabled={isLoading}
                ref={loginTab === 'totp' ? totpUsernameInputRef : null}
              />
              {/* TOTP Instructions */}
              {mode === 'login' && loginTab === 'totp' && !totpUsernameEntered && (
                <p className="mt-2 text-sm text-gray-600">
                  Enter your username to sign in with your authenticator app
                </p>
              )}
            </div>

            {/* TOTP Code Field (only in TOTP tab and after username entered) */}
            {mode === 'login' && loginTab === 'totp' && totpUsernameEntered && (
              <div>
                <label htmlFor="totpCode" className="block text-sm font-medium text-secondary-700 mb-2">
                  {isBackupCode ? 'Backup Code' : 'Authenticator Code'}
                </label>
                <input
                  id="totpCode"
                  name="totpCode"
                  type="text"
                  required
                  value={formData.totpCode}
                  onChange={handleInputChange}
                  className="input-field"
                  placeholder={isBackupCode ? "Enter backup code" : "Enter 6-digit code"}
                  disabled={isLoading}
                  maxLength={isBackupCode ? 8 : 6}
                  ref={totpCodeInputRef}
                />
                <div className="mt-2 flex items-center justify-between">
                  <button
                    type="button"
                    onClick={() => setIsBackupCode(!isBackupCode)}
                    className="text-sm text-primary-600 hover:text-primary-700 font-medium"
                    disabled={isLoading}
                  >
                    {isBackupCode ? 'Use authenticator code' : 'Use backup code instead'}
                  </button>
                </div>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || (mode === 'login' && loginTab === 'webauthn' && !webAuthnSupported)}
              className={`w-full flex items-center justify-center py-3 text-base font-medium transition-all duration-200 ${
                mode === 'login' && loginTab === 'webauthn'
                  ? 'btn-primary' // Blue for WebAuthn login
                  : mode === 'login' && loginTab === 'totp'
                  ? 'bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 text-white shadow-lg hover:shadow-xl disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed rounded-lg font-medium transition-all duration-200' // Purple for TOTP
                  : 'bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 text-white shadow-lg hover:shadow-xl disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed rounded-lg font-medium transition-all duration-200' // Green for registration
              }`}
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <LoadingSpinner size="small" className="mr-2" />
                  {mode === 'login' && loginTab === 'webauthn' ? 'Authenticating...' : mode === 'login' && loginTab === 'totp' ? 'Verifying...' : 'Creating Account...'}
                </div>
              ) : (
                <div className="flex items-center justify-center">
                  {mode === 'login' && loginTab === 'webauthn' ? (
                    <Key className="h-5 w-5 mr-2" />
                  ) : mode === 'login' && loginTab === 'totp' ? (
                    <Smartphone className="h-5 w-5 mr-2" />
                  ) : (
                    <CheckCircle className="h-5 w-5 mr-2" />
                  )}
                  {mode === 'login' && loginTab === 'webauthn'
                    ? 'Sign In with Security Key' 
                    : mode === 'login' && loginTab === 'totp'
                    ? totpUsernameEntered 
                      ? `Verify ${isBackupCode ? 'Backup Code' : 'Authenticator Code'}`
                      : 'Continue with Username'
                    : 'Create Account with Security Key'
                  }
                </div>
              )}
            </button>
          </form>

          {/* Mode Switch */}
          <div className="mt-6 text-center">
            <button
              onClick={switchMode}
              disabled={isLoading}
              className="text-sm text-primary-600 hover:text-primary-700 font-medium transition-colors"
            >
              {mode === 'login' 
                ? "Don't have an account? Register here" 
                : 'Already have an account? Sign in'
              }
            </button>
          </div>
        </motion.div>

        {/* Security Features */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-white/60 backdrop-blur-sm rounded-lg p-4 border border-white/40"
        >
          <h3 className="text-sm font-medium text-secondary-800 mb-3 flex items-center">
            <Shield className="h-4 w-4 mr-2 text-primary-600" />
            Security Features
          </h3>
          <div className="space-y-2">
            <div className="flex items-center text-xs text-secondary-600">
              <CheckCircle className="h-3 w-3 mr-2 text-green-500" />
              Passwordless authentication
            </div>
            <div className="flex items-center text-xs text-secondary-600">
              <CheckCircle className="h-3 w-3 mr-2 text-green-500" />
              Hardware security key support
            </div>
            <div className="flex items-center text-xs text-secondary-600">
              <CheckCircle className="h-3 w-3 mr-2 text-green-500" />
              End-to-end encryption
            </div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default AuthPage; 