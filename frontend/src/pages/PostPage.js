import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Calendar, User, Tag, BookOpen } from 'lucide-react';
import axios from 'axios';
import AuthMessage from '../components/AuthMessage';

const PostPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [post, setPost] = useState(null);
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
    if (id) {
      fetchPost();
    }
  }, [id]);

  const fetchPost = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await axios.get(`/posts/${id}`);
      setPost(response.data);
    } catch (error) {
      console.error('Failed to fetch post:', error);
      if (error.response?.status === 404) {
        setError('Post not found');
      } else {
        setError('Failed to load post');
        showMessage('error', 'Failed to Load Post', 'Unable to retrieve the requested blog post. Please check the URL and try again.', {
          additionalInfo: 'This could be due to a network issue, server problem, or the post may have been removed.'
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatContent = (content) => {
    // Simple line break formatting (replace \n with <br>)
    return content.split('\n').map((line, index) => (
      <React.Fragment key={index}>
        {line}
        {index < content.split('\n').length - 1 && <br />}
      </React.Fragment>
    ));
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="animate-pulse">
            <div className="h-8 bg-gray-200 rounded w-1/4 mb-8"></div>
            <div className="card">
              <div className="h-10 bg-gray-200 rounded w-3/4 mb-4"></div>
              <div className="h-4 bg-gray-200 rounded w-1/2 mb-6"></div>
              <div className="space-y-3">
                <div className="h-4 bg-gray-200 rounded"></div>
                <div className="h-4 bg-gray-200 rounded"></div>
                <div className="h-4 bg-gray-200 rounded w-5/6"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 py-8">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <button
              onClick={() => navigate('/blog')}
              className="flex items-center text-gray-600 hover:text-gray-900 mb-8 transition-colors"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Blog
            </button>

            <div className="card text-center py-16">
              <BookOpen className="h-16 w-16 text-red-400 mx-auto mb-4" />
              <h1 className="text-2xl font-semibold text-gray-900 mb-4">
                {error}
              </h1>
              <p className="text-gray-600 mb-8">
                The post you're looking for doesn't exist or has been removed.
              </p>
              <button 
                onClick={() => navigate('/blog')}
                className="btn-primary"
              >
                View All Posts
              </button>
            </div>
          </motion.div>
        </div>
      </div>
    );
  }

  if (!post) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <button
            onClick={() => navigate('/blog')}
            className="flex items-center text-gray-600 hover:text-gray-900 mb-8 transition-colors"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Blog
          </button>

          <article className="card">
            <header className="mb-8">
              <h1 className="text-4xl font-bold text-gray-900 mb-6 leading-tight">
                {post.title}
              </h1>

              <div className="flex items-center space-x-6 text-gray-600 mb-6">
                <div className="flex items-center">
                  <User className="h-4 w-4 mr-2" />
                  <span className="font-medium">
                    {post.author_display_name || post.author_username}
                  </span>
                </div>
                <div className="flex items-center">
                  <Calendar className="h-4 w-4 mr-2" />
                  <span>{formatDate(post.created_at)}</span>
                </div>
              </div>

              {post.tags && post.tags.length > 0 && (
                <div className="flex items-center flex-wrap gap-2 mb-6">
                  <Tag className="h-4 w-4 text-gray-400" />
                  {post.tags.map((tag) => (
                    <span
                      key={tag.id}
                      className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800"
                    >
                      {tag.name}
                    </span>
                  ))}
                </div>
              )}

              <hr className="border-gray-200" />
            </header>

            <div className="prose prose-lg max-w-none">
              <div className="text-gray-800 leading-relaxed whitespace-pre-wrap">
                {formatContent(post.content)}
              </div>
            </div>

            <footer className="mt-12 pt-8 border-t border-gray-200">
              <div className="flex items-center justify-between">
                <div className="text-sm text-gray-500">
                  {post.updated_at !== post.created_at && (
                    <span>Last updated: {formatDate(post.updated_at)}</span>
                  )}
                </div>
                <button
                  onClick={() => navigate('/blog')}
                  className="btn-secondary"
                >
                  View More Posts
                </button>
              </div>
            </footer>
          </article>
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

export default PostPage; 