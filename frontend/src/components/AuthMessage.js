import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Info, 
  Clock, 
  Shield,
  Calendar,
  Timer,
  ArrowRight
} from 'lucide-react';

const AuthMessage = ({ 
  type = 'info', 
  title, 
  message, 
  details = {},
  onDismiss,
  autoHide = false,
  duration = 5000 
}) => {
  const [isVisible, setIsVisible] = useState(true);
  const [timeRemaining, setTimeRemaining] = useState(null);
  const [showSkipButton, setShowSkipButton] = useState(false);

  // Handle auto-hide
  useEffect(() => {
    if (autoHide && duration > 0) {
      const timer = setTimeout(() => {
        handleDismiss();
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [autoHide, duration]);

  // Handle skip button visibility for success messages
  useEffect(() => {
    if (type === 'success' && details.showSkipButton && details.skipDelay) {
      const timer = setTimeout(() => {
        setShowSkipButton(true);
      }, details.skipDelay);
      return () => clearTimeout(timer);
    }
  }, [type, details.showSkipButton, details.skipDelay]);

  // Handle countdown for device blocking
  useEffect(() => {
    if (details.blocked_until) {
      const updateCountdown = () => {
        const now = new Date();
        const blockedUntil = new Date(details.blocked_until);
        const diff = blockedUntil - now;
        
        if (diff <= 0) {
          setTimeRemaining(null);
          return;
        }
        
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        
        setTimeRemaining({ days, hours, minutes });
      };
      
      updateCountdown();
      const interval = setInterval(updateCountdown, 60000); // Update every minute
      
      return () => clearInterval(interval);
    }
  }, [details.blocked_until]);

  const handleDismiss = () => {
    setIsVisible(false);
    setTimeout(() => {
      onDismiss?.();
    }, 300);
  };

  const getMessageConfig = () => {
    switch (type) {
      case 'success':
        return {
          icon: CheckCircle,
          bgColor: 'bg-green-50',
          borderColor: 'border-green-200',
          iconColor: 'text-green-600',
          titleColor: 'text-green-800',
          textColor: 'text-green-700',
          accentColor: 'bg-green-100'
        };
      case 'error':
        return {
          icon: XCircle,
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
          iconColor: 'text-red-600',
          titleColor: 'text-red-800',
          textColor: 'text-red-700',
          accentColor: 'bg-red-100'
        };
      case 'warning':
        return {
          icon: AlertTriangle,
          bgColor: 'bg-amber-50',
          borderColor: 'border-amber-200',
          iconColor: 'text-amber-600',
          titleColor: 'text-amber-800',
          textColor: 'text-amber-700',
          accentColor: 'bg-amber-100'
        };
      case 'device_blocked':
        return {
          icon: Shield,
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200',
          iconColor: 'text-blue-600',
          titleColor: 'text-blue-800',
          textColor: 'text-blue-700',
          accentColor: 'bg-blue-100'
        };
      default:
        return {
          icon: Info,
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200',
          iconColor: 'text-blue-600',
          titleColor: 'text-blue-800',
          textColor: 'text-blue-700',
          accentColor: 'bg-blue-100'
        };
    }
  };

  const config = getMessageConfig();
  const IconComponent = config.icon;

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, y: -20, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -20, scale: 0.95 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          className={`relative overflow-hidden rounded-xl border ${config.bgColor} ${config.borderColor} p-6 shadow-lg backdrop-blur-sm`}
        >
          {/* Accent bar */}
          <div className={`absolute left-0 top-0 h-full w-1 ${config.accentColor}`} />
          
          <div className="flex items-start space-x-4">
            {/* Icon */}
            <div className={`flex-shrink-0 rounded-full p-2 ${config.accentColor}`}>
              <IconComponent className={`h-6 w-6 ${config.iconColor}`} />
            </div>
            
            {/* Content */}
            <div className="flex-1 min-w-0">
              {title && (
                <h3 className={`text-lg font-semibold ${config.titleColor} mb-2`}>
                  {title}
                </h3>
              )}
              
              <p className={`text-sm ${config.textColor} leading-relaxed mb-4`}>
                {message}
              </p>
              
              {/* Success message specific content */}
              {type === 'success' && details.features && (
                <div className="space-y-4">
                  {/* Icon and emoji */}
                  {details.icon && (
                    <div className="text-center">
                      <span className="text-4xl">{details.icon}</span>
                    </div>
                  )}
                  
                  {/* Features list */}
                  {details.features && details.features.length > 0 && (
                    <div className={`rounded-lg p-4 ${config.accentColor} border ${config.borderColor}`}>
                      <div className="flex items-center space-x-2 mb-3">
                        <CheckCircle className={`h-4 w-4 ${config.iconColor}`} />
                        <span className={`text-sm font-medium ${config.titleColor}`}>
                          What's Been Set Up
                        </span>
                      </div>
                      <ul className="space-y-2">
                        {details.features.map((feature, index) => (
                          <li key={index} className="flex items-start space-x-2">
                            <CheckCircle className={`h-3 w-3 ${config.iconColor} mt-0.5 flex-shrink-0`} />
                            <span className={`text-xs ${config.textColor}`}>{feature}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  
                  {/* Next steps */}
                  {details.nextSteps && details.nextSteps.length > 0 && (
                    <div className={`rounded-lg p-4 border ${config.borderColor} bg-white/50`}>
                      <div className="flex items-center space-x-2 mb-3">
                        <ArrowRight className={`h-4 w-4 ${config.iconColor}`} />
                        <span className={`text-sm font-medium ${config.titleColor}`}>
                          What's Next
                        </span>
                      </div>
                      <ul className="space-y-2">
                        {details.nextSteps.map((step, index) => (
                          <li key={index} className="flex items-start space-x-2">
                            <div className={`rounded-full w-4 h-4 flex items-center justify-center text-xs font-medium ${config.accentColor} ${config.iconColor} mt-0.5 flex-shrink-0`}>
                              {index + 1}
                            </div>
                            <span className={`text-xs ${config.textColor}`}>{step}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  
                  {/* Additional info */}
                  {details.additionalInfo && (
                    <div className={`rounded-lg p-4 border ${config.borderColor} bg-white/30`}>
                      <div className="flex items-center space-x-2 mb-2">
                        <Info className={`h-4 w-4 ${config.iconColor}`} />
                        <span className={`text-sm font-medium ${config.titleColor}`}>
                          Important
                        </span>
                      </div>
                      <p className={`text-xs ${config.textColor} leading-relaxed`}>
                        {details.additionalInfo}
                      </p>
                    </div>
                  )}
                </div>
              )}
              
              {/* Action buttons for success messages */}
              {type === 'success' && details.actions && details.actions.length > 0 && (
                <div className="mt-4 flex space-x-3">
                  {details.actions.map((action, index) => (
                    <button
                      key={index}
                      onClick={action.action}
                      className={`px-4 py-2 text-xs font-medium rounded-lg transition-all duration-200 ${config.accentColor} ${config.iconColor} hover:shadow-md`}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              )}
              

              
              {/* Device blocking specific content */}
              {type === 'device_blocked' && (
                <div className="space-y-4">
                  {/* Countdown timer */}
                  {timeRemaining && (
                    <div className={`rounded-lg p-4 ${config.accentColor} border ${config.borderColor}`}>
                      <div className="flex items-center space-x-2 mb-2">
                        <Timer className={`h-4 w-4 ${config.iconColor}`} />
                        <span className={`text-sm font-medium ${config.titleColor}`}>
                          Time Remaining
                        </span>
                      </div>
                      <div className="flex items-center space-x-4 text-sm">
                        {timeRemaining.days > 0 && (
                          <div className="flex items-center space-x-1">
                            <span className={`font-bold text-lg ${config.titleColor}`}>
                              {timeRemaining.days}
                            </span>
                            <span className={config.textColor}>
                              {timeRemaining.days === 1 ? 'day' : 'days'}
                            </span>
                          </div>
                        )}
                        <div className="flex items-center space-x-1">
                          <span className={`font-bold text-lg ${config.titleColor}`}>
                            {timeRemaining.hours}
                          </span>
                          <span className={config.textColor}>
                            {timeRemaining.hours === 1 ? 'hour' : 'hours'}
                          </span>
                        </div>
                        <div className="flex items-center space-x-1">
                          <span className={`font-bold text-lg ${config.titleColor}`}>
                            {timeRemaining.minutes}
                          </span>
                          <span className={config.textColor}>
                            {timeRemaining.minutes === 1 ? 'minute' : 'minutes'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {/* Available date */}
                  {details.blocked_until && (
                    <div className={`rounded-lg p-4 border ${config.borderColor} bg-white/50`}>
                      <div className="flex items-center space-x-2 mb-2">
                        <Calendar className={`h-4 w-4 ${config.iconColor}`} />
                        <span className={`text-sm font-medium ${config.titleColor}`}>
                          Available Again
                        </span>
                      </div>
                      <p className={`text-sm ${config.textColor}`}>
                        {formatDate(details.blocked_until)}
                      </p>
                    </div>
                  )}
                  
                  {/* Security explanation */}
                  <div className={`rounded-lg p-4 border ${config.borderColor} bg-white/30`}>
                    <div className="flex items-center space-x-2 mb-2">
                      <Shield className={`h-4 w-4 ${config.iconColor}`} />
                      <span className={`text-sm font-medium ${config.titleColor}`}>
                        Why is this happening?
                      </span>
                    </div>
                    <p className={`text-xs ${config.textColor} leading-relaxed`}>
                      This security measure prevents automated account creation and spam. 
                      Each hardware security key can only create one account every 34 days 
                      to maintain platform integrity and security.
                    </p>
                  </div>
                </div>
              )}
              
              {/* Additional details for other message types */}
              {details.additionalInfo && type !== 'device_blocked' && (
                <div className={`mt-3 p-3 rounded-lg ${config.accentColor} border ${config.borderColor}`}>
                  <p className={`text-xs ${config.textColor}`}>
                    {details.additionalInfo}
                  </p>
                </div>
              )}
            </div>
            
            {/* Dismiss button */}
            {onDismiss && (
              <button
                onClick={handleDismiss}
                className={`flex-shrink-0 rounded-full p-1 ${config.textColor} hover:${config.accentColor} transition-colors`}
                aria-label="Dismiss message"
              >
                <XCircle className="h-5 w-5" />
              </button>
            )}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default AuthMessage; 