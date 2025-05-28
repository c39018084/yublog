import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Save, ArrowLeft, Tag } from 'lucide-react';
import axios from 'axios';
import AuthMessage from '../components/AuthMessage';

const CreatePostPage = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    tags: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState(null);

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

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.content.trim()) {
      showMessage('error', 'Missing Required Fields', 'Please provide both a title and content for your post.', {
        additionalInfo: 'Both title and content are required to create a meaningful blog post.'
      });
      return;
    }

    setIsSubmitting(true);
    
    try {
      const postData = {
        title: formData.title.trim(),
        content: formData.content.trim(),
        tags: formData.tags ? formData.tags.split(',').map(tag => tag.trim()).filter(tag => tag) : []
      };

      const response = await axios.post('/posts', postData);
      
      showMessage('success', 'Post Published Successfully!', `"${formData.title}" has been published and is now live on your blog.`, {
        icon: '🚀',
        features: [
          'Post is now publicly visible',
          'Added to your blog index',
          'Ready for readers to discover'
        ],
        nextSteps: [
          'Share your post with others',
          'Monitor engagement and feedback',
          'Start working on your next post'
        ],
        additionalInfo: 'Your post has been successfully published and added to the public blog. You can view it or make edits from your dashboard.',
        actions: [{
          label: 'View Post',
          action: () => navigate(`/blog/${response.data.id}`)
        }]
      });
      
      // Navigate to dashboard after showing success message briefly
      setTimeout(() => {
        navigate('/dashboard');
      }, 2000);
    } catch (error) {
      console.error('Failed to create post:', error);
      if (error.response?.data?.error) {
        showMessage('error', 'Failed to Publish Post', error.response.data.error, {
          additionalInfo: 'Please check your input and try again. If the problem persists, contact support.'
        });
      } else {
        showMessage('error', 'Publication Error', 'An error occurred while publishing your post. Please try again.', {
          additionalInfo: 'This could be due to a network issue or server problem. Check your connection and try again.'
        });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSaveDraft = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.content.trim()) {
      showMessage('error', 'Missing Required Fields', 'Please provide both a title and content before saving as draft.', {
        additionalInfo: 'Even drafts need a title and content to be saved properly.'
      });
      return;
    }

    setIsSubmitting(true);
    
    try {
      const postData = {
        title: formData.title.trim(),
        content: formData.content.trim(),
        tags: formData.tags ? formData.tags.split(',').map(tag => tag.trim()).filter(tag => tag) : [],
        isDraft: true
      };

      const response = await axios.post('/posts', postData);
      
      showMessage('success', 'Draft Saved Successfully!', `"${formData.title}" has been saved as a draft for later editing.`, {
        icon: '💾',
        features: [
          'Draft securely saved',
          'Available in your dashboard',
          'Can be edited and published anytime'
        ],
        nextSteps: [
          'Continue editing when ready',
          'Publish when you\'re satisfied',
          'Review and refine your content'
        ],
        additionalInfo: 'Your draft has been saved and can be accessed from your dashboard. You can continue editing and publish it when ready.',
        actions: [{
          label: 'Continue Editing',
          action: () => navigate(`/edit/${response.data.id}`)
        }]
      });
      
      // Navigate to dashboard after showing success message briefly
      setTimeout(() => {
        navigate('/dashboard');
      }, 2000);
    } catch (error) {
      console.error('Failed to save draft:', error);
      if (error.response?.data?.error) {
        showMessage('error', 'Failed to Save Draft', error.response.data.error, {
          additionalInfo: 'Please check your input and try again. If the problem persists, contact support.'
        });
      } else {
        showMessage('error', 'Save Error', 'An error occurred while saving your draft. Please try again.', {
          additionalInfo: 'This could be due to a network issue or server problem. Check your connection and try again.'
        });
      }
    } finally {
      setIsSubmitting(false);
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
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center">
              <button
                onClick={() => navigate('/dashboard')}
                className="mr-4 p-2 text-gray-600 hover:text-gray-900 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <ArrowLeft className="h-5 w-5" />
              </button>
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Create New Post</h1>
                <p className="text-gray-600 mt-1">Share your thoughts with the world</p>
              </div>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="card">
              <div className="space-y-6">
                {/* Title */}
                <div>
                  <label htmlFor="title" className="block text-sm font-medium text-gray-700 mb-2">
                    Post Title
                  </label>
                  <input
                    type="text"
                    id="title"
                    name="title"
                    value={formData.title}
                    onChange={handleChange}
                    placeholder="Enter a compelling title for your post..."
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-lg"
                    maxLength={200}
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    {formData.title.length}/200 characters
                  </p>
                </div>

                {/* Tags */}
                <div>
                  <label htmlFor="tags" className="block text-sm font-medium text-gray-700 mb-2">
                    Tags
                  </label>
                  <div className="relative">
                    <Tag className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                    <input
                      type="text"
                      id="tags"
                      name="tags"
                      value={formData.tags}
                      onChange={handleChange}
                      placeholder="technology, webauthn, security (comma-separated)"
                      className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <p className="text-sm text-gray-500 mt-1">
                    Separate tags with commas. This helps readers discover your content.
                  </p>
                </div>

                {/* Content */}
                <div>
                  <label htmlFor="content" className="block text-sm font-medium text-gray-700 mb-2">
                    Content
                  </label>
                  <textarea
                    id="content"
                    name="content"
                    value={formData.content}
                    onChange={handleChange}
                    placeholder="Write your post content here... You can use markdown formatting."
                    rows={20}
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-vertical"
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    {formData.content.length} characters. Markdown formatting is supported.
                  </p>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex justify-end space-x-4">
              <button
                type="button"
                onClick={() => navigate('/dashboard')}
                className="btn-ghost"
                disabled={isSubmitting}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSaveDraft}
                className="btn-secondary"
                disabled={isSubmitting || !formData.title.trim() || !formData.content.trim()}
              >
                {isSubmitting ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-gray-600 mr-2"></div>
                    Saving...
                  </div>
                ) : (
                  'Save as Draft'
                )}
              </button>
              <button
                type="submit"
                className="btn-primary"
                disabled={isSubmitting || !formData.title.trim() || !formData.content.trim()}
              >
                {isSubmitting ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Publishing...
                  </div>
                ) : (
                  <div className="flex items-center">
                    <Save className="h-4 w-4 mr-2" />
                    Publish Post
                  </div>
                )}
              </button>
            </div>
          </form>
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

export default CreatePostPage; 