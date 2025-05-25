import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Save, ArrowLeft, Tag } from 'lucide-react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const CreatePostPage = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    tags: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.content.trim()) {
      toast.error('Title and content are required');
      return;
    }

    setIsSubmitting(true);
    
    try {
      const postData = {
        title: formData.title.trim(),
        content: formData.content.trim(),
        tags: formData.tags ? formData.tags.split(',').map(tag => tag.trim()).filter(tag => tag) : []
      };

      const response = await axios.post('/api/posts', postData);
      
      toast.success('Post created successfully!');
      navigate('/dashboard');
    } catch (error) {
      console.error('Failed to create post:', error);
      if (error.response?.data?.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error('Failed to create post. Please try again.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSaveDraft = async (e) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.content.trim()) {
      toast.error('Title and content are required');
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

      const response = await axios.post('/api/posts', postData);
      
      toast.success('Draft saved successfully!');
      navigate('/dashboard');
    } catch (error) {
      console.error('Failed to save draft:', error);
      if (error.response?.data?.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error('Failed to save draft. Please try again.');
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
      </div>
    </div>
  );
};

export default CreatePostPage; 