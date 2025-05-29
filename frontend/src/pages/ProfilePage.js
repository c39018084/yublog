import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Shield, Trash2, Calendar, Smartphone, AlertCircle, BookOpen, Edit3, Eye, Plus } from 'lucide-react';
import axios from 'axios';
import { registerAdditionalDevice } from '../utils/webauthn';
import { setupTotp, getTotpStatus, disableTotp } from '../utils/totp';
import AuthMessage from '../components/AuthMessage';
import ConfirmationModal from '../components/ConfirmationModal';

const ProfilePage = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') || 'profile');
  const [devices, setDevices] = useState([]);
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [deletingDevice, setDeletingDevice] = useState(null);
  const [deletingPost, setDeletingPost] = useState(null);
  const [addingDevice, setAddingDevice] = useState(false);
  const [showAddDeviceModal, setShowAddDeviceModal] = useState(false);
  const [newDeviceName, setNewDeviceName] = useState('');
  
  // TOTP state
  const [totpStatus, setTotpStatus] = useState({ enabled: false, lastUsed: null });
  const [settingUpTotp, setSettingUpTotp] = useState(false);
  const [showTotpSetup, setShowTotpSetup] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState(null);
  const [disablingTotp, setDisablingTotp] = useState(false);
  
  // Message and confirmation state
  const [message, setMessage] = useState(null);
  const [confirmationModal, setConfirmationModal] = useState({
    isOpen: false,
    type: 'danger',
    title: '',
    message: '',
    itemName: '',
    itemType: '',
    confirmText: '',
    onConfirm: null
  });

  useEffect(() => {
    if (activeTab === 'devices') {
      fetchDevices();
      fetchTotpStatus();
    } else if (activeTab === 'posts') {
      fetchUserPosts();
    }
  }, [activeTab]);

  useEffect(() => {
    const tab = searchParams.get('tab');
    if (tab && ['profile', 'devices', 'posts'].includes(tab)) {
      setActiveTab(tab);
    }
  }, [searchParams]);

  const showMessage = (type, title, messageText, details = {}) => {
    setMessage({
      type,
      title,
      message: messageText,
      details,
      autoHide: type === 'success',
      duration: type === 'success' ? 4000 : 0
    });
  };

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/user/devices');
      setDevices(response.data);
    } catch (error) {
      console.error('Failed to fetch devices:', error);
      showMessage('error', 'Failed to Load Devices', 'Unable to retrieve your security devices. Please refresh the page and try again.', {
        additionalInfo: 'This could be due to a network issue or server problem. Check your connection and try again.'
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchUserPosts = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/user/posts');
      setPosts(response.data);
    } catch (error) {
      console.error('Failed to fetch posts:', error);
      showMessage('error', 'Failed to Load Posts', 'Unable to retrieve your blog posts. Please refresh the page and try again.', {
        additionalInfo: 'This could be due to a network issue or server problem. Check your connection and try again.'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteDevice = async (deviceId, deviceName) => {
    setConfirmationModal({
      isOpen: true,
      type: 'danger',
      title: 'Remove Security Device',
      message: 'This will permanently remove the security device from your account. You will no longer be able to use it to sign in.',
      itemName: deviceName,
      itemType: 'Security Device',
      confirmText: 'Remove Device',
      onConfirm: () => confirmDeleteDevice(deviceId, deviceName)
    });
  };

  const confirmDeleteDevice = async (deviceId, deviceName) => {
    setConfirmationModal(prev => ({ ...prev, isOpen: false }));
    
    try {
      setDeletingDevice(deviceId);
      
      // Get the token from localStorage to ensure it's included
      const token = localStorage.getItem('yublog_token');
      if (!token) {
        showMessage('error', 'Authentication Required', 'Please log in again to continue.', {
          additionalInfo: 'Your session may have expired. Try refreshing the page and signing in again.'
        });
        return;
      }
      
      await axios.delete(`/user/devices/${deviceId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      setDevices(devices.filter(device => device.id !== deviceId));
      showMessage('success', 'Device Removed Successfully', `"${deviceName}" has been removed from your account.`, {
        icon: '✅',
        features: [
          'Device access revoked immediately',
          'Security audit log updated', 
          'Account remains secure with remaining devices'
        ],
        additionalInfo: 'Make sure you have at least one security device registered to maintain access to your account.'
      });
    } catch (error) {
      console.error('Failed to delete device:', error);
      
      if (error.response?.status === 401 || error.response?.status === 403) {
        showMessage('error', 'Authentication Failed', 'Your session has expired. Please log in again.', {
          additionalInfo: 'Try refreshing the page and signing in again to continue managing your devices.'
        });
      } else if (error.response?.status === 404) {
        showMessage('warning', 'Device Not Found', 'This device may have already been removed from your account.', {
          additionalInfo: 'The device list will be refreshed to show the current state.'
        });
        // Refresh the devices list
        fetchDevices();
      } else {
        showMessage('error', 'Failed to Remove Device', 'An error occurred while removing the security device. Please try again.', {
          additionalInfo: 'If the problem persists, try refreshing the page or contact support.'
        });
      }
    } finally {
      setDeletingDevice(null);
    }
  };

  const handleDeletePost = async (postId, postTitle) => {
    setConfirmationModal({
      isOpen: true,
      type: 'danger',
      title: 'Delete Blog Post',
      message: 'This will permanently delete your blog post and remove it from public view. All comments and analytics data will also be lost.',
      itemName: postTitle,
      itemType: 'Blog Post',
      confirmText: 'Delete Post',
      onConfirm: () => confirmDeletePost(postId, postTitle)
    });
  };

  const confirmDeletePost = async (postId, postTitle) => {
    console.log('*** CLOSING MODAL from confirmDeletePost ***');
    setConfirmationModal(prev => ({ ...prev, isOpen: false }));
    
    try {
      setDeletingPost(postId);
      await axios.delete(`/posts/${postId}`);
      setPosts(posts.filter(post => post.id !== postId));
      showMessage('success', 'Post Deleted Successfully', `"${postTitle}" has been permanently deleted.`, {
        icon: '🗑️',
        features: [
          'Post removed from public view',
          'All associated data cleared',
          'Blog index updated automatically'
        ],
        additionalInfo: 'This action cannot be undone. The post and all its content have been permanently removed.'
      });
    } catch (error) {
      console.error('Failed to delete post:', error);
      showMessage('error', 'Failed to Delete Post', 'An error occurred while deleting your blog post. Please try again.', {
        additionalInfo: 'If the problem persists, try refreshing the page or contact support.'
      });
    } finally {
      setDeletingPost(null);
    }
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSearchParams({ tab });
    // Clear any existing messages when switching tabs
    setMessage(null);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const truncateContent = (content, maxLength = 150) => {
    if (content.length <= maxLength) return content;
    return content.substring(0, maxLength) + '...';
  };

  const handleAddDevice = async () => {
    if (!newDeviceName.trim()) {
      showMessage('error', 'Device Name Required', 'Please enter a name for your security device.', {
        additionalInfo: 'This helps you identify the device in your security settings.'
      });
      return;
    }

    try {
      setAddingDevice(true);
      const result = await registerAdditionalDevice(newDeviceName.trim());
      
      if (result.verified) {
        showMessage('success', 'Device Added Successfully!', `"${newDeviceName}" has been registered with your account.`, {
          icon: '🔐',
          features: [
            'New security device registered',
            'WebAuthn authentication enabled',
            'Device ready for secure sign-in'
          ],
          nextSteps: [
            'You can now use this device to sign in',
            'Keep your security device safe',
            'Consider adding a backup device'
          ],
          additionalInfo: 'Your new security device has been added to your account and is ready to use for passwordless authentication.'
        });
        setNewDeviceName('');
        setShowAddDeviceModal(false);
        // Refresh devices list
        await fetchDevices();
      }
    } catch (error) {
      console.error('Add device error:', error);
      
      if (error.type === 'device_blocked') {
        showMessage('device_blocked', 'Device Registration Blocked', error.message, {
          blocked_until: error.blocked_until,
          days_remaining: error.days_remaining,
          reason: error.reason,
          additionalInfo: 'This security measure prevents spam and maintains platform integrity. Each device has a 34-day cooldown period between account registrations.'
        });
      } else if (error.type === 'not_supported') {
        showMessage('error', 'WebAuthn Not Supported', 'Your device or browser does not support WebAuthn authentication.', {
          additionalInfo: 'Please use a modern browser like Chrome, Firefox, Safari, or Edge with WebAuthn support.'
        });
      } else if (error.type === 'not_allowed') {
        showMessage('warning', 'Device Registration Cancelled', 'The security device registration was cancelled or not permitted.', {
          additionalInfo: 'Make sure to follow the prompts on your security device and try again.'
        });
      } else if (error.type === 'invalid_state') {
        showMessage('warning', 'Device Already Registered', 'This security device is already registered with an account.', {
          additionalInfo: 'If this is your device, try signing in instead. Each security device can only be registered once.'
        });
      } else {
        showMessage('error', 'Failed to Add Device', error.message || 'An error occurred while registering your security device.', {
          additionalInfo: 'Please check your device and connection, then try again.'
        });
      }
    } finally {
      setAddingDevice(false);
    }
  };

  // TOTP Management Functions
  const fetchTotpStatus = async () => {
    try {
      const status = await getTotpStatus();
      setTotpStatus(status);
    } catch (error) {
      console.error('Failed to fetch TOTP status:', error);
      // Don't show error message as this is not critical
    }
  };

  const handleSetupTotp = async () => {
    try {
      setSettingUpTotp(true);
      const setupData = await setupTotp();
      setTotpSetupData(setupData);
      setShowTotpSetup(true);
      
      // Refresh TOTP status
      await fetchTotpStatus();
      
      showMessage('success', 'TOTP Setup Complete', 'Your authenticator app has been set up successfully!', {
        icon: '📱',
        features: [
          'Backup login method enabled',
          'Compatible with Google Authenticator, Authy, and more',
          'Secure backup codes generated'
        ],
        additionalInfo: 'Save your backup codes in a secure location. You can now login with your authenticator app when WebAuthn is not available.'
      });
    } catch (error) {
      console.error('Failed to setup TOTP:', error);
      showMessage('error', 'TOTP Setup Failed', error.message || 'Failed to set up authenticator app', {
        additionalInfo: 'Make sure you have at least one WebAuthn device registered before setting up TOTP.'
      });
    } finally {
      setSettingUpTotp(false);
    }
  };

  const handleDisableTotp = async () => {
    setConfirmationModal({
      isOpen: true,
      type: 'danger',
      title: 'Disable Authenticator App',
      message: 'This will disable your authenticator app as a backup login method. You will only be able to login with your security keys.',
      itemName: 'Authenticator App Access',
      itemType: 'TOTP Authentication',
      confirmText: 'Disable TOTP',
      onConfirm: confirmDisableTotp
    });
  };

  const confirmDisableTotp = async () => {
    setConfirmationModal(prev => ({ ...prev, isOpen: false }));
    
    try {
      setDisablingTotp(true);
      await disableTotp();
      
      // Refresh TOTP status
      await fetchTotpStatus();
      setTotpSetupData(null);
      setShowTotpSetup(false);
      
      showMessage('success', 'TOTP Disabled', 'Your authenticator app has been disabled successfully.', {
        icon: '🔒',
        additionalInfo: 'You can only login with your WebAuthn security keys now. You can re-enable TOTP at any time.'
      });
    } catch (error) {
      console.error('Failed to disable TOTP:', error);
      showMessage('error', 'Failed to Disable TOTP', error.message || 'Failed to disable authenticator app', {
        additionalInfo: 'Please try again or contact support if the problem persists.'
      });
    } finally {
      setDisablingTotp(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <h1 className="text-3xl font-bold text-gray-900 mb-8">Account Settings</h1>

          {/* Tabs */}
          <div className="mb-8">
            <nav className="flex space-x-8" aria-label="Tabs">
              <button
                onClick={() => handleTabChange('profile')}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'profile'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                Profile
              </button>
              <button
                onClick={() => handleTabChange('devices')}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'devices'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                Security Devices
              </button>
              <button
                onClick={() => handleTabChange('posts')}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === 'posts'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                My Posts
              </button>
            </nav>
          </div>

          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
              className="card"
            >
              <h2 className="text-xl font-semibold text-gray-900 mb-6">
                Profile Information
              </h2>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Username
                  </label>
                  <div className="text-gray-900 font-medium">{user?.username}</div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Email
                  </label>
                  <div className="text-gray-900">{user?.email || 'Not provided'}</div>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Display Name
                  </label>
                  <div className="text-gray-900">{user?.displayName || user?.username}</div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Account Created
                  </label>
                  <div className="text-gray-900">
                    {user?.createdAt ? formatDate(user.createdAt) : 'Unknown'}
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* Devices Tab */}
          {activeTab === 'devices' && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
              className="space-y-6"
            >
              <div className="card">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold text-gray-900">
                    Security Devices
                  </h2>
                  <div className="flex items-center space-x-4">
                    <button
                      onClick={() => setShowAddDeviceModal(true)}
                      disabled={addingDevice}
                      className="btn-primary flex items-center space-x-2"
                    >
                      <Plus className="h-4 w-4" />
                      <span>Add Device</span>
                    </button>
                    <div className="flex items-center text-sm text-gray-500">
                      <Shield className="h-4 w-4 mr-1" />
                      WebAuthn Devices
                    </div>
                  </div>
                </div>

                {loading ? (
                  <div className="space-y-4">
                    {[...Array(2)].map((_, i) => (
                      <div key={i} className="animate-pulse">
                        <div className="h-16 bg-gray-200 rounded-lg"></div>
                      </div>
                    ))}
                  </div>
                ) : devices.length === 0 ? (
                  <div className="text-center py-12">
                    <Smartphone className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      No devices registered
                    </h3>
                    <p className="text-gray-600 mb-4">
                      Add a security device to enhance your account security.
                    </p>
                    <button
                      onClick={() => setShowAddDeviceModal(true)}
                      className="btn-primary flex items-center space-x-2 mx-auto"
                    >
                      <Plus className="h-4 w-4" />
                      <span>Add Your First Device</span>
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {devices.map((device) => (
                      <div
                        key={device.id}
                        className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition-colors"
                      >
                        <div className="flex items-start space-x-4">
                          <div className="p-2 bg-green-100 rounded-lg">
                            <Shield className="h-5 w-5 text-green-600" />
                          </div>
                          <div>
                            <h3 className="font-medium text-gray-900">
                              {device.name}
                            </h3>
                            <div className="text-sm text-gray-500 space-y-1">
                              <div className="flex items-center">
                                <Calendar className="h-3 w-3 mr-1" />
                                Added {formatDate(device.createdAt)}
                              </div>
                              {device.lastUsed && (
                                <div className="flex items-center">
                                  <Calendar className="h-3 w-3 mr-1" />
                                  Last used {formatDate(device.lastUsed)}
                                </div>
                              )}
                              <div className="text-xs text-gray-400">
                                Counter: {device.counter}
                              </div>
                            </div>
                          </div>
                        </div>

                        <button
                          onClick={() => handleDeleteDevice(device.id, device.name)}
                          disabled={deletingDevice === device.id}
                          className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50"
                          title="Remove device"
                        >
                          {deletingDevice === device.id ? (
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-600"></div>
                          ) : (
                            <Trash2 className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {devices.length > 0 && (
                  <div className="mt-6 p-4 bg-amber-50 border border-amber-200 rounded-lg">
                    <div className="flex items-start">
                      <AlertCircle className="h-5 w-5 text-amber-600 mt-0.5 mr-3 flex-shrink-0" />
                      <div className="text-sm text-amber-800">
                        <p className="font-medium mb-1">Important Security Information</p>
                        <p>
                          Removing a device will prevent you from using it to sign in. Make sure you have at least one device registered to maintain access to your account.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* TOTP Authenticator Section */}
              <div className="card mt-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold text-gray-900">
                    Authenticator App
                  </h3>
                  <div className="flex items-center text-sm text-gray-500">
                    <Smartphone className="h-4 w-4 mr-1" />
                    Backup Login Method
                  </div>
                </div>

                {totpStatus.enabled ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                      <div className="flex items-start space-x-4">
                        <div className="p-2 bg-purple-100 rounded-lg">
                          <Smartphone className="h-5 w-5 text-purple-600" />
                        </div>
                        <div>
                          <h4 className="font-medium text-gray-900">
                            Authenticator App Enabled
                          </h4>
                          <div className="text-sm text-gray-500 space-y-1">
                            <div className="flex items-center">
                              <Calendar className="h-3 w-3 mr-1" />
                              Set up {totpStatus.createdAt ? formatDate(totpStatus.createdAt) : 'recently'}
                            </div>
                            {totpStatus.lastUsed && (
                              <div className="flex items-center">
                                <Calendar className="h-3 w-3 mr-1" />
                                Last used {formatDate(totpStatus.lastUsed)}
                              </div>
                            )}
                            <div className="text-xs text-gray-400">
                              Compatible with Google Authenticator, Authy, and more
                            </div>
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={handleDisableTotp}
                        disabled={disablingTotp}
                        className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50"
                        title="Disable TOTP"
                      >
                        {disablingTotp ? (
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-600"></div>
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </button>
                    </div>

                    {showTotpSetup && totpSetupData && (
                      <div className="p-4 bg-purple-50 border border-purple-200 rounded-lg">
                        <h4 className="font-medium text-purple-900 mb-3">Setup Complete!</h4>
                        <div className="space-y-3">
                          <div>
                            <p className="text-sm text-purple-800 mb-2">
                              Your backup codes (save these securely):
                            </p>
                            <div className="bg-white p-3 rounded border text-xs font-mono space-y-1">
                              {totpSetupData.backupCodes?.map((code, index) => (
                                <div key={index} className="text-gray-800">{code}</div>
                              ))}
                            </div>
                          </div>
                          <div className="text-xs text-purple-700">
                            You can now login with codes from your authenticator app or these backup codes when WebAuthn is not available.
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Smartphone className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h4 className="text-lg font-medium text-gray-900 mb-2">
                      Authenticator App Not Set Up
                    </h4>
                    <p className="text-gray-600 mb-4">
                      Add a backup login method using Google Authenticator, Authy, or similar apps.
                    </p>
                    {devices.length > 0 ? (
                      <button
                        onClick={handleSetupTotp}
                        disabled={settingUpTotp}
                        className="bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 text-white py-2 px-4 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2 mx-auto"
                      >
                        {settingUpTotp ? (
                          <>
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                            <span>Setting up...</span>
                          </>
                        ) : (
                          <>
                            <Smartphone className="h-4 w-4" />
                            <span>Set Up Authenticator App</span>
                          </>
                        )}
                      </button>
                    ) : (
                      <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg">
                        <div className="flex items-start">
                          <AlertCircle className="h-5 w-5 text-amber-600 mt-0.5 mr-3 flex-shrink-0" />
                          <div className="text-sm text-amber-800">
                            <p className="font-medium mb-1">WebAuthn Device Required</p>
                            <p>
                              You need at least one WebAuthn security device before you can set up an authenticator app backup method.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                  <div className="flex items-start">
                    <Smartphone className="h-5 w-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
                    <div className="text-sm text-blue-800">
                      <p className="font-medium mb-1">Backup Authentication</p>
                      <p>
                        Authenticator apps provide a backup way to login when your WebAuthn devices are not available. 
                        This is especially useful when switching between devices or traveling.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* Posts Tab */}
          {activeTab === 'posts' && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
              className="space-y-6"
            >
              <div className="card">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold text-gray-900">
                    My Posts
                  </h2>
                </div>

                {loading ? (
                  <div className="space-y-4">
                    {[...Array(2)].map((_, i) => (
                      <div key={i} className="animate-pulse">
                        <div className="h-16 bg-gray-200 rounded-lg"></div>
                      </div>
                    ))}
                  </div>
                ) : posts.length === 0 ? (
                  <div className="text-center py-12">
                    <BookOpen className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      No posts found
                    </h3>
                    <p className="text-gray-600">
                      You haven't created any posts yet.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {posts.map((post) => (
                      <div
                        key={post.id}
                        className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition-colors"
                      >
                        <div className="flex items-start space-x-4">
                          <div className="p-2 bg-green-100 rounded-lg">
                            <BookOpen className="h-5 w-5 text-green-600" />
                          </div>
                          <div>
                            <h3 className="font-medium text-gray-900">
                              {truncateContent(post.title)}
                            </h3>
                            <div className="text-sm text-gray-500 space-y-1">
                              <div className="flex items-center">
                                <Calendar className="h-3 w-3 mr-1" />
                                Created {formatDate(post.created_at)}
                              </div>
                              <div className="text-xs text-gray-400">
                                Status: {post.published ? 'Published' : 'Draft'}
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleDeletePost(post.id, post.title)}
                            disabled={deletingPost === post.id}
                            className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50"
                            title="Delete post"
                          >
                            {deletingPost === post.id ? (
                              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-600"></div>
                            ) : (
                              <Trash2 className="h-4 w-4" />
                            )}
                          </button>
                          {post.published && (
                            <button
                              onClick={() => navigate(`/blog/${post.id}`)}
                              className="p-2 text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded-lg transition-colors"
                              title="View post"
                            >
                              <Eye className="h-4 w-4" />
                            </button>
                          )}
                          <button
                            onClick={() => navigate(`/edit/${post.id}`)}
                            className="p-2 text-gray-600 hover:text-gray-700 hover:bg-gray-50 rounded-lg transition-colors"
                            title="Edit post"
                          >
                            <Edit3 className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </motion.div>

        {/* Add Device Modal */}
        {showAddDeviceModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-lg p-6 max-w-md w-full mx-4"
            >
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Add Security Device
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Device Name
                  </label>
                  <input
                    type="text"
                    value={newDeviceName}
                    onChange={(e) => setNewDeviceName(e.target.value)}
                    placeholder="e.g., YubiKey 5 Series, Touch ID, etc."
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    disabled={addingDevice}
                  />
                </div>
                
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                  <div className="flex items-start">
                    <Shield className="h-5 w-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
                    <div className="text-sm text-blue-800">
                      <p className="font-medium mb-1">Security Information</p>
                      <p>
                        You'll be prompted to touch your security key or use your device's biometric authentication. 
                        The same 34-day restriction applies to prevent account spamming.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex space-x-3 mt-6">
                <button
                  onClick={handleAddDevice}
                  disabled={addingDevice || !newDeviceName.trim()}
                  className="flex-1 btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {addingDevice ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Adding Device...
                    </>
                  ) : (
                    'Add Device'
                  )}
                </button>
                <button
                  onClick={() => {
                    setShowAddDeviceModal(false);
                    setNewDeviceName('');
                  }}
                  disabled={addingDevice}
                  className="flex-1 btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Cancel
                </button>
              </div>
            </motion.div>
          </div>
        )}

        {/* TOTP Setup Modal */}
        {showTotpSetup && totpSetupData && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-white rounded-lg p-6 max-w-lg w-full mx-4"
            >
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Set Up Authenticator App
              </h3>
              
              <div className="space-y-6">
                <div className="text-center">
                  <p className="text-sm text-gray-600 mb-4">
                    Scan this QR code with your authenticator app:
                  </p>
                  <div className="bg-white p-4 rounded-lg border-2 border-gray-200 inline-block">
                    <img src={totpSetupData.qrCode} alt="TOTP QR Code" className="w-48 h-48" />
                  </div>
                </div>

                <div>
                  <p className="text-sm font-medium text-gray-700 mb-2">
                    Or enter this code manually:
                  </p>
                  <div className="bg-gray-50 p-3 rounded border text-sm font-mono text-center">
                    {totpSetupData.manualEntryKey}
                  </div>
                </div>

                <div>
                  <p className="text-sm font-medium text-gray-700 mb-2">
                    Backup codes (save these securely):
                  </p>
                  <div className="bg-gray-50 p-3 rounded border text-xs font-mono space-y-1">
                    {totpSetupData.backupCodes?.map((code, index) => (
                      <div key={index} className="text-gray-800">{code}</div>
                    ))}
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    These backup codes can be used if you lose access to your authenticator app. Each code can only be used once.
                  </p>
                </div>

                <div className="p-4 bg-purple-50 border border-purple-200 rounded-lg">
                  <div className="flex items-start">
                    <Smartphone className="h-5 w-5 text-purple-600 mt-0.5 mr-3 flex-shrink-0" />
                    <div className="text-sm text-purple-800">
                      <p className="font-medium mb-1">Compatible Apps</p>
                      <p>
                        Works with Google Authenticator, Authy, Microsoft Authenticator, 1Password, and other TOTP apps.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-end mt-6">
                <button
                  onClick={() => {
                    setShowTotpSetup(false);
                    setTotpSetupData(null);
                  }}
                  className="btn-primary"
                >
                  Done
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </div>

      {/* AuthMessage and ConfirmationModal */}
      {message && (
        <div className="fixed top-4 left-1/2 transform -translate-x-1/2 z-50 max-w-md w-full mx-4">
          <AuthMessage
            type={message.type}
            title={message.title}
            message={message.message}
            details={message.details}
            autoHide={message.autoHide}
            duration={message.duration}
            onDismiss={() => setMessage(null)}
          />
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmationModal
        isOpen={confirmationModal.isOpen}
        onClose={() => setConfirmationModal(prev => ({ ...prev, isOpen: false }))}
        onConfirm={confirmationModal.onConfirm}
        type={confirmationModal.type}
        title={confirmationModal.title}
        message={confirmationModal.message}
        itemName={confirmationModal.itemName}
        itemType={confirmationModal.itemType}
        confirmText={confirmationModal.confirmText}
      />
    </div>
  );
};

export default ProfilePage; 