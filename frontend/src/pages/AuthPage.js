import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { registerWebAuthn, authenticateWebAuthn, isWebAuthnSupported } from '../utils/webauthn';
import LoadingSpinner from '../components/LoadingSpinner';
import toast from 'react-hot-toast';
import { Shield, Key, Smartphone, AlertTriangle, CheckCircle } from 'lucide-react';

const AuthPage = () => {
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: ''
  });
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const { login } = useAuth();

  useEffect(() => {
    setWebAuthnSupported(isWebAuthnSupported());
  }, []);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!webAuthnSupported) {
      toast.error('WebAuthn is not supported on this device/browser');
      return;
    }

    setIsLoading(true);
    try {
      const result = await registerWebAuthn({
        username: formData.username
      });
      
      toast.success('Registration successful! You can now sign in.');
      setMode('login');
      setFormData({ username: '' });
    } catch (error) {
      console.error('Registration error:', error);
      toast.error(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!webAuthnSupported) {
      toast.error('WebAuthn is not supported on this device/browser');
      return;
    }

    setIsLoading(true);
    try {
      const result = await authenticateWebAuthn(formData.username);
      
      if (result.token) {
        console.log('About to call login with:', { token: result.token, user: result.user });
        login(result.token, result.user);
        console.log('Login called successfully');
        toast.success('Welcome back!');
        
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
      toast.error(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const switchMode = () => {
    setMode(mode === 'login' ? 'register' : 'login');
    setFormData({ username: '' });
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
              ? 'Sign in securely with your YubiKey' 
              : 'Register with passwordless authentication'
            }
          </p>
        </div>

        {/* WebAuthn Support Warning */}
        {!webAuthnSupported && (
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
          <form onSubmit={mode === 'login' ? handleLogin : handleRegister} className="space-y-6">
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
              />
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || !webAuthnSupported}
              className="btn-primary w-full justify-center py-3 text-base font-medium"
            >
              {isLoading ? (
                <div className="flex items-center">
                  <LoadingSpinner size="small" className="mr-2" />
                  {mode === 'login' ? 'Authenticating...' : 'Registering...'}
                </div>
              ) : (
                <div className="flex items-center">
                  {mode === 'login' ? (
                    <Key className="h-5 w-5 mr-2" />
                  ) : (
                    <CheckCircle className="h-5 w-5 mr-2" />
                  )}
                  {mode === 'login' ? 'Sign In with YubiKey' : 'Register with YubiKey'}
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