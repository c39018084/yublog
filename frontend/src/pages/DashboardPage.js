import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { BarChart3, Users, BookOpen, Shield } from 'lucide-react';
import axios from 'axios';
import AuthMessage from '../components/AuthMessage';

const DashboardPage = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState({
    totalPosts: 0,
    publishedPosts: 0,
    draftPosts: 0,
    deviceCount: 0
  });
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState(null);

  const showMessage = (type, title, messageText, details = {}) => {
    setMessage({
      type,
      title,
      message: messageText,
      details,
      autoHide: type === 'success' || type === 'info',
      duration: type === 'success' || type === 'info' ? 4000 : 0
    });
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      // Fetch user's devices and posts stats in parallel
      const [devicesResponse, statsResponse] = await Promise.all([
        axios.get('/api/user/devices'),
        axios.get('/api/user/posts/stats')
      ]);
      
      const devices = devicesResponse.data;
      const postStats = statsResponse.data;
      
      setStats({
        totalPosts: postStats.totalPosts,
        publishedPosts: postStats.publishedPosts,
        draftPosts: postStats.draftPosts,
        deviceCount: devices.length
      });
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      showMessage('error', 'Failed to Load Dashboard Data', 'Unable to retrieve your dashboard information. Please refresh the page and try again.', {
        additionalInfo: 'This could be due to a network issue or server problem. Check your connection and try again.'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePost = () => {
    navigate('/create');
  };

  const handleManageDevices = () => {
    navigate('/profile?tab=devices');
  };

  const handleViewAnalytics = () => {
    showMessage('info', 'Analytics Coming Soon!', 'Advanced analytics and insights for your blog are currently under development.', {
      icon: '📊',
      features: [
        'Post performance metrics',
        'Reader engagement statistics',
        'Traffic and growth insights'
      ],
      nextSteps: [
        'Keep creating great content',
        'Check back for updates',
        'Follow our development progress'
      ],
      additionalInfo: 'We\'re working hard to bring you comprehensive analytics to help you understand your audience and grow your blog.'
    });
  };

  const handleMyPosts = () => {
    navigate('/profile?tab=posts');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded w-1/3 mb-4"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2 mb-8"></div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-24 bg-gray-200 rounded-lg"></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900">
              Welcome back, {user?.displayName || user?.username}!
            </h1>
            <p className="text-gray-600 mt-2">
              Here's an overview of your YuBlog activity.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="card">
              <div className="flex items-center">
                <div className="p-3 bg-primary-100 rounded-lg mr-4">
                  <BookOpen className="h-6 w-6 text-primary-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Posts</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.totalPosts}</p>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="flex items-center">
                <div className="p-3 bg-green-100 rounded-lg mr-4">
                  <Users className="h-6 w-6 text-green-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Published</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.publishedPosts}</p>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="flex items-center">
                <div className="p-3 bg-amber-100 rounded-lg mr-4">
                  <BarChart3 className="h-6 w-6 text-amber-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Drafts</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.draftPosts}</p>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="flex items-center">
                <div className="p-3 bg-red-100 rounded-lg mr-4">
                  <Shield className="h-6 w-6 text-red-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Devices</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.deviceCount}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">
              Quick Actions
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              <button 
                onClick={handleCreatePost}
                className="btn-primary justify-center"
              >
                Create New Post
              </button>
              <button 
                onClick={handleManageDevices}
                className="btn-secondary justify-center"
              >
                Manage Devices
              </button>
              <button 
                onClick={handleViewAnalytics}
                className="btn-ghost justify-center"
              >
                View Analytics
              </button>
              <button 
                onClick={handleMyPosts}
                className="btn-ghost justify-center"
              >
                My Posts
              </button>
            </div>
          </div>
        </motion.div>
        
        {/* AuthMessage */}
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
      </div>
    </div>
  );
};

export default DashboardPage; 