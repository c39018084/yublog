import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Shield, Trash2, Calendar, Smartphone, AlertCircle, BookOpen, Edit3, Eye, MoreHorizontal } from 'lucide-react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

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

  useEffect(() => {
    if (activeTab === 'devices') {
      fetchDevices();
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

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/user/devices');
      setDevices(response.data);
    } catch (error) {
      console.error('Failed to fetch devices:', error);
      toast.error('Failed to load devices');
    } finally {
      setLoading(false);
    }
  };

  const fetchUserPosts = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/user/posts');
      setPosts(response.data);
    } catch (error) {
      console.error('Failed to fetch posts:', error);
      toast.error('Failed to load posts');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteDevice = async (deviceId, deviceName) => {
    if (!window.confirm(`Are you sure you want to remove "${deviceName}"? This action cannot be undone.`)) {
      return;
    }

    try {
      setDeletingDevice(deviceId);
      await axios.delete(`/api/user/devices/${deviceId}`);
      setDevices(devices.filter(device => device.id !== deviceId));
      toast.success('Device removed successfully');
    } catch (error) {
      console.error('Failed to delete device:', error);
      toast.error('Failed to remove device');
    } finally {
      setDeletingDevice(null);
    }
  };

  const handleDeletePost = async (postId, postTitle) => {
    if (!window.confirm(`Are you sure you want to delete "${postTitle}"? This action cannot be undone.`)) {
      return;
    }

    try {
      setDeletingPost(postId);
      await axios.delete(`/api/posts/${postId}`);
      setPosts(posts.filter(post => post.id !== postId));
      toast.success('Post deleted successfully');
    } catch (error) {
      console.error('Failed to delete post:', error);
      toast.error('Failed to delete post');
    } finally {
      setDeletingPost(null);
    }
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSearchParams({ tab });
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
                  <div className="flex items-center text-sm text-gray-500">
                    <Shield className="h-4 w-4 mr-1" />
                    WebAuthn Devices
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
                    <p className="text-gray-600">
                      Your security devices will appear here after registration.
                    </p>
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
      </div>
    </div>
  );
};

export default ProfilePage; 