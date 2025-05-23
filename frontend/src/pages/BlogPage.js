import React from 'react';
import { motion } from 'framer-motion';
import { BookOpen, Calendar, User } from 'lucide-react';

const BlogPage = () => {
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
      </div>
    </div>
  );
};

export default BlogPage; 