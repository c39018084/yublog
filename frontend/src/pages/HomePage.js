import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Key, Monitor, Lock, CheckCircle, ArrowRight, Github, Globe } from 'lucide-react';

const HomePage = () => {
  const features = [
    {
      icon: Shield,
      title: 'Passwordless Security',
      description: 'No passwords to remember or steal. Your YubiKey is your secure digital identity.',
    },
    {
      icon: Key,
      title: 'YubiKey Integration',
      description: 'Full WebAuthn/FIDO2 support with hardware security keys for ultimate protection.',
    },
    {
      icon: Monitor,
      title: 'Modern Web Platform',
      description: 'Built with React and modern web technologies for a smooth, responsive experience.',
    },
    {
      icon: Lock,
      title: 'Self-Hosted',
      description: 'Complete control over your data. No cloud dependencies, fully self-hostable.',
    },
  ];

  const securityFeatures = [
    'Zero password storage',
    'Public key cryptography',
    'Hardware security keys',
    'TLS 1.3 encryption',
    'CSP security headers',
    'Rate limiting protection',
    'Audit logging',
    'Session management',
  ];

  return (
    <div className="bg-white">
      {/* Hero Section */}
      <div className="relative bg-gradient-to-br from-primary-50 via-white to-secondary-50 overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 lg:py-32">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
              className="mx-auto h-20 w-20 bg-primary-100 rounded-full flex items-center justify-center mb-8"
            >
              <Shield className="h-12 w-12 text-primary-600" />
            </motion.div>
            
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-gray-900 mb-6">
              <span className="gradient-text">Secure Blogging</span>
              <br />
              Without Passwords
            </h1>
            
            <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto leading-relaxed">
              YuBlog is a modern, self-hosted blogging platform that uses YubiKey and WebAuthn 
              for passwordless authentication. Write, publish, and share your thoughts with 
              military-grade security.
            </p>
            
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="flex flex-col sm:flex-row gap-4 justify-center items-center"
            >
              <Link
                to="/auth"
                className="btn-primary px-8 py-4 text-lg font-medium"
              >
                Get Started
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
              <Link
                to="/blog"
                className="btn-secondary px-8 py-4 text-lg font-medium"
              >
                <Globe className="mr-2 h-5 w-5" />
                View Blog
              </Link>
            </motion.div>
          </motion.div>
        </div>
      </div>

      {/* Features Section */}
      <div className="py-24 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
            className="text-center mb-16"
          >
            <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 mb-4">
              Why Choose YuBlog?
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Built with security-first principles and modern technologies for the ultimate blogging experience.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="card text-center hover:shadow-md transition-shadow"
              >
                <div className="mx-auto h-12 w-12 bg-primary-100 rounded-lg flex items-center justify-center mb-4">
                  <feature.icon className="h-6 w-6 text-primary-600" />
                </div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  {feature.title}
                </h3>
                <p className="text-gray-600 text-sm leading-relaxed">
                  {feature.description}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </div>

      {/* Security Section */}
      <div className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.8 }}
            >
              <h2 className="text-3xl sm:text-4xl font-bold text-gray-900 mb-6">
                Enterprise-Grade Security
              </h2>
              <p className="text-lg text-gray-600 mb-8 leading-relaxed">
                YuBlog implements the latest security standards and best practices to protect 
                your content and data. No passwords means no password breaches.
              </p>
              
              <div className="space-y-3">
                {securityFeatures.map((feature, index) => (
                  <motion.div
                    key={feature}
                    initial={{ opacity: 0, x: -10 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    className="flex items-center"
                  >
                    <CheckCircle className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                    <span className="text-gray-700">{feature}</span>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.8 }}
              className="relative"
            >
              <div className="card p-8 bg-gradient-to-br from-primary-50 to-secondary-50">
                <div className="text-center">
                  <div className="mx-auto h-16 w-16 bg-primary-100 rounded-full flex items-center justify-center mb-6">
                    <Key className="h-8 w-8 text-primary-600" />
                  </div>
                  <h3 className="text-xl font-semibold text-gray-900 mb-4">
                    Your YubiKey is Your Password
                  </h3>
                  <p className="text-gray-600 mb-6">
                    Simply touch your YubiKey to authenticate. No typing, no remembering, 
                    no phishing attacks.
                  </p>
                  <div className="bg-white rounded-lg p-4 border border-primary-200">
                    <div className="flex items-center justify-center space-x-2 text-sm text-gray-500">
                      <div className="h-2 w-2 bg-green-400 rounded-full animate-pulse"></div>
                      <span>WebAuthn Ready</span>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="py-24 bg-primary-600">
        <div className="max-w-4xl mx-auto text-center px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
              Ready to Start Blogging Securely?
            </h2>
            <p className="text-xl text-primary-100 mb-8 leading-relaxed">
              Join the passwordless revolution. Set up your YuBlog instance in minutes 
              and experience the future of secure authentication.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Link
                to="/auth"
                className="inline-flex items-center px-8 py-4 border border-transparent text-lg font-medium rounded-lg text-primary-600 bg-white hover:bg-gray-50 transition-colors"
              >
                Get Started Now
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
              <a
                href="https://github.com/yourusername/yublog"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center px-8 py-4 border border-primary-400 text-lg font-medium rounded-lg text-white hover:bg-primary-500 transition-colors"
              >
                <Github className="mr-2 h-5 w-5" />
                View on GitHub
              </a>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default HomePage; 