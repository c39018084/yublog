import React, { useState } from 'react';
import { motion } from 'framer-motion';
import AuthMessage from './AuthMessage';

const MessageDemo = () => {
  const [currentMessage, setCurrentMessage] = useState(null);

  const demoMessages = {
    device_blocked: {
      type: 'device_blocked',
      title: 'Device Registration Temporarily Blocked',
      message: 'This security key was recently used to create an account. To prevent spam and maintain security, each device has a 34-day cooldown period between account registrations.',
      details: {
        blocked_until: new Date(Date.now() + (2 * 24 * 60 * 60 * 1000 + 5 * 60 * 60 * 1000 + 30 * 60 * 1000)).toISOString(), // 2 days, 5 hours, 30 minutes from now
        days_remaining: 2,
        reason: 'account_spam_prevention'
      }
    },
    success: {
      type: 'success',
      title: 'Registration Successful!',
      message: 'Your account has been created successfully. You can now sign in with your security key.',
      autoHide: false
    },
    error: {
      type: 'error',
      title: 'Registration Failed',
      message: 'Unable to complete registration. Please check your security key and try again.',
      details: {
        additionalInfo: 'Make sure you\'re using a compatible device and browser with HTTPS enabled.'
      }
    },
    warning: {
      type: 'warning',
      title: 'Security Key Already Registered',
      message: 'This security key is already registered with an account. Please try logging in instead, or use a different security key.',
      details: {
        additionalInfo: 'If this is your security key, try logging in instead. If you need to register a new account, please use a different security key.'
      }
    },
    info: {
      type: 'info',
      title: 'WebAuthn Information',
      message: 'WebAuthn provides passwordless authentication using hardware security keys, biometrics, or platform authenticators.',
      details: {
        additionalInfo: 'This technology ensures the highest level of security for your account without the need for traditional passwords.'
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50 py-12 px-4">
      <div className="max-w-2xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8"
        >
          <h1 className="text-3xl font-bold text-gray-900 mb-4">
            Authentication Message Demo
          </h1>
          <p className="text-gray-600">
            Preview different message types used in the authentication system
          </p>
        </motion.div>

        {/* Message Controls */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card mb-8"
        >
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Message Types
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {Object.entries(demoMessages).map(([key, message]) => (
              <button
                key={key}
                onClick={() => setCurrentMessage(message)}
                className="btn-secondary text-sm py-2 px-3"
              >
                {message.title}
              </button>
            ))}
            <button
              onClick={() => setCurrentMessage(null)}
              className="btn-outline text-sm py-2 px-3"
            >
              Clear Message
            </button>
          </div>
        </motion.div>

        {/* Message Display */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="space-y-6"
        >
          {currentMessage && (
            <AuthMessage
              type={currentMessage.type}
              title={currentMessage.title}
              message={currentMessage.message}
              details={currentMessage.details}
              autoHide={currentMessage.autoHide}
              duration={currentMessage.duration}
              onDismiss={() => setCurrentMessage(null)}
            />
          )}

          {!currentMessage && (
            <div className="card text-center py-16">
              <div className="text-gray-400 mb-4">
                <svg className="h-16 w-16 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                </svg>
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                No Message Selected
              </h3>
              <p className="text-gray-600">
                Click a button above to preview different message types
              </p>
            </div>
          )}
        </motion.div>

        {/* Feature Highlights */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="mt-12 card"
        >
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Message System Features
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="font-medium text-gray-900 mb-2">Device Blocking</h3>
              <ul className="text-sm text-gray-600 space-y-1">
                <li>• Real-time countdown timer</li>
                <li>• Detailed blocking information</li>
                <li>• Security explanation</li>
                <li>• Exact availability date/time</li>
              </ul>
            </div>
            <div>
              <h3 className="font-medium text-gray-900 mb-2">User Experience</h3>
              <ul className="text-sm text-gray-600 space-y-1">
                <li>• Integrated design (no popups)</li>
                <li>• Contextual help information</li>
                <li>• Smooth animations</li>
                <li>• Auto-hide for success messages</li>
              </ul>
            </div>
            <div>
              <h3 className="font-medium text-gray-900 mb-2">Error Handling</h3>
              <ul className="text-sm text-gray-600 space-y-1">
                <li>• Categorized error types</li>
                <li>• Helpful troubleshooting tips</li>
                <li>• Clear action guidance</li>
                <li>• Professional styling</li>
              </ul>
            </div>
            <div>
              <h3 className="font-medium text-gray-900 mb-2">Accessibility</h3>
              <ul className="text-sm text-gray-600 space-y-1">
                <li>• Screen reader friendly</li>
                <li>• Keyboard navigation</li>
                <li>• High contrast colors</li>
                <li>• Clear visual hierarchy</li>
              </ul>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default MessageDemo; 