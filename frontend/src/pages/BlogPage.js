import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { BookOpen, Calendar, User, Tag } from 'lucide-react';
import axios from 'axios';
import AuthMessage from '../components/AuthMessage';

const BlogPage = () => {
  const navigate = useNavigate();
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);

  const showMessage = (type, title, messageText, details = {}) => {
    setMessage({
      type,
      title,
      message: messageText,
      details,
      autoHide: false,
      duration: 0
    });
  };

  useEffect(() => {
    fetchPosts();
  }, []);

  const fetchPosts = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/posts');
      setPosts(response.data);
      setError(null);
    } catch (error) {
      console.error('Failed to fetch posts:', error);
      setError('Failed to load blog posts');
      showMessage('error', 'Failed to Load Blog Posts', 'Unable to retrieve the latest blog posts. Please refresh the page and try again.', {
        additionalInfo: 'This could be due to a network issue or server problem. Check your connection and try again.'
      });
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const truncateContent = (content, maxLength = 200) => {
    if (content.length <= maxLength) return content;
    return content.substring(0, maxLength) + '...';
  };

  const handlePostClick = (postId) => {
    navigate(`/blog/${postId}`);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="animate-pulse">
            <div className="text-center mb-12">
              <div className="h-10 bg-gray-200 rounded w-1/3 mx-auto mb-4"></div>
              <div className="h-6 bg-gray-200 rounded w-1/2 mx-auto"></div>
            </div>
            <div className="space-y-6">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-48 bg-gray-200 rounded-lg"></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center mb-12"
        >
          <h1 className="text-4xl font-bold gradient-text mb-4">
            Blog Posts
          </h1>
          <p className="text-xl text-gray-600">
            Discover secure, passwordless thoughts and insights
          </p>
        </motion.div>

        {error ? (
          <div className="card text-center py-16">
            <BookOpen className="h-16 w-16 text-red-400 mx-auto mb-4" />
            <h2 className="text-2xl font-semibold text-gray-900 mb-2">
              Error Loading Posts
            </h2>
            <p className="text-gray-600 mb-8">
              {error}
            </p>
            <button 
              onClick={fetchPosts}
              className="btn-primary"
            >
              Try Again
            </button>
          </div>
        ) : posts.length === 0 ? (
          <div className="card text-center py-16">
            <BookOpen className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h2 className="text-2xl font-semibold text-gray-900 mb-2">
              No Posts Yet
            </h2>
            <p className="text-gray-600 mb-8">
              This blog is just getting started. Check back soon for amazing content!
            </p>
            <div className="text-sm text-gray-500">
              Posts will appear here once authors start publishing content.
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            {posts.map((post, index) => (
              <motion.article
                key={post.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="card hover:shadow-lg transition-shadow cursor-pointer"
                onClick={() => handlePostClick(post.id)}
              >
                <div className="space-y-4">
                  {/* Post Header */}
                  <div className="flex items-start justify-between">
                    <h2 className="text-2xl font-bold text-gray-900 hover:text-blue-600 transition-colors">
                      {post.title}
                    </h2>
                  </div>

                  {/* Post Meta */}
                  <div className="flex items-center space-x-6 text-sm text-gray-500">
                    <div className="flex items-center">
                      <User className="h-4 w-4 mr-1" />
                      {post.author_display_name || post.author_username}
                    </div>
                    <div className="flex items-center">
                      <Calendar className="h-4 w-4 mr-1" />
                      {formatDate(post.created_at)}
                    </div>
                  </div>

                  {/* Post Content Preview */}
                  <p className="text-gray-700 leading-relaxed">
                    {truncateContent(post.content)}
                  </p>

                  {/* Tags */}
                  {post.tags && post.tags.length > 0 && (
                    <div className="flex items-center flex-wrap gap-2">
                      <Tag className="h-4 w-4 text-gray-400" />
                      {post.tags.map((tag) => (
                        <span
                          key={tag.id}
                          className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                        >
                          {tag.name}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Read More */}
                  <div className="pt-4 border-t border-gray-200">
                    <span className="text-blue-600 font-medium hover:text-blue-700 transition-colors">
                      Read full post →
                    </span>
                  </div>
                </div>
              </motion.article>
            ))}
          </div>
        )}
        
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

export default BlogPage; 