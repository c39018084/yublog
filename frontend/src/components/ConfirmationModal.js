import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, Shield, Trash2, XCircle } from 'lucide-react';

const ConfirmationModal = ({ 
  isOpen, 
  onConfirm, 
  onCancel, 
  title, 
  message, 
  confirmText = 'Confirm', 
  cancelText = 'Cancel',
  type = 'danger', // 'danger', 'warning', 'info'
  itemName = '',
  itemType = 'item',
  isLoading = false
}) => {
  if (!isOpen) return null;

  const getConfig = () => {
    switch (type) {
      case 'danger':
        return {
          icon: Trash2,
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
          iconColor: 'text-red-600',
          titleColor: 'text-red-800',
          textColor: 'text-red-700',
          accentColor: 'bg-red-100',
          buttonColor: 'bg-red-600 hover:bg-red-700 focus:ring-red-500',
          buttonTextColor: 'text-white'
        };
      case 'warning':
        return {
          icon: AlertTriangle,
          bgColor: 'bg-amber-50',
          borderColor: 'border-amber-200',
          iconColor: 'text-amber-600',
          titleColor: 'text-amber-800',
          textColor: 'text-amber-700',
          accentColor: 'bg-amber-100',
          buttonColor: 'bg-amber-600 hover:bg-amber-700 focus:ring-amber-500',
          buttonTextColor: 'text-white'
        };
      default:
        return {
          icon: Shield,
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200',
          iconColor: 'text-blue-600',
          titleColor: 'text-blue-800',
          textColor: 'text-blue-700',
          accentColor: 'bg-blue-100',
          buttonColor: 'bg-blue-600 hover:bg-blue-700 focus:ring-blue-500',
          buttonTextColor: 'text-white'
        };
    }
  };

  const config = getConfig();
  const IconComponent = config.icon;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
        className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
        onClick={(e) => e.target === e.currentTarget && onCancel()}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 20 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          className="bg-white rounded-xl shadow-2xl max-w-md w-full mx-4 overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header with Icon */}
          <div className={`${config.bgColor} ${config.borderColor} border-b px-6 py-4`}>
            <div className="flex items-center space-x-4">
              <div className={`flex-shrink-0 rounded-full p-2 ${config.accentColor}`}>
                <IconComponent className={`h-6 w-6 ${config.iconColor}`} />
              </div>
              <div className="flex-1">
                <h3 className={`text-lg font-semibold ${config.titleColor}`}>
                  {title}
                </h3>
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="px-6 py-6 space-y-4">
            <p className={`text-sm ${config.textColor} leading-relaxed`}>
              {message}
            </p>

            {/* Highlighted item name */}
            {itemName && (
              <div className={`rounded-lg p-4 ${config.accentColor} border ${config.borderColor}`}>
                <div className="flex items-center space-x-2">
                  <span className={`text-xs font-medium ${config.titleColor} uppercase tracking-wide`}>
                    {itemType}
                  </span>
                </div>
                <p className={`text-sm font-medium ${config.titleColor} mt-1`}>
                  "{itemName}"
                </p>
              </div>
            )}

            {/* Warning message */}
            <div className={`rounded-lg p-4 border ${config.borderColor} bg-white/50`}>
              <div className="flex items-start space-x-2">
                <AlertTriangle className={`h-4 w-4 ${config.iconColor} mt-0.5 flex-shrink-0`} />
                <div>
                  <p className={`text-xs ${config.textColor} leading-relaxed`}>
                    <span className="font-medium">This action cannot be undone.</span> Please make sure this is what you want to do.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="px-6 py-4 bg-gray-50 border-t border-gray-200 flex items-center justify-end space-x-3">
            <button
              onClick={onCancel}
              disabled={isLoading}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {cancelText}
            </button>
            <button
              onClick={onConfirm}
              disabled={isLoading}
              className={`px-4 py-2 text-sm font-medium ${config.buttonTextColor} ${config.buttonColor} rounded-lg focus:ring-2 focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2`}
            >
              {isLoading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <span>Processing...</span>
                </>
              ) : (
                <span>{confirmText}</span>
              )}
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default ConfirmationModal; 