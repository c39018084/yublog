import React from 'react';
import { motion } from 'framer-motion';

const CreatePostPage = () => {
  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="card text-center py-16"
        >
          <h1 className="text-2xl font-semibold text-gray-900 mb-4">
            Create New Post
          </h1>
          <p className="text-gray-600">
            Post creation interface will be available here.
          </p>
        </motion.div>
      </div>
    </div>
  );
};

export default CreatePostPage; 