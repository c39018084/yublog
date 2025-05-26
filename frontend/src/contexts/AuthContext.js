import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('yublog_token'));
  const [skipProfileFetch, setSkipProfileFetch] = useState(false);

  // Configure axios defaults
  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      // Only verify token and get user data if we don't already have user data
      if (!user && !skipProfileFetch) {
        fetchUserProfile();
      } else {
        setIsLoading(false);
      }
    } else {
      setIsLoading(false);
    }
  }, [token, skipProfileFetch]);

  // Debug authentication state changes
  useEffect(() => {
    console.log('Auth state changed:', {
      hasUser: !!user,
      hasToken: !!token,
      isAuthenticated: Boolean(user && token),
      isLoading,
      skipProfileFetch
    });
  }, [user, token, isLoading, skipProfileFetch]);

  const fetchUserProfile = async () => {
    try {
      console.log('Fetching user profile...');
      const response = await axios.get('/api/user/profile');
      console.log('Profile fetch successful:', response.data);
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      if (error.response) {
        console.error('Error response:', error.response.status, error.response.data);
      }
      // Token might be invalid, clear it
      logout();
    } finally {
      setIsLoading(false);
    }
  };

  const login = (authToken, userData) => {
    console.log('AuthContext login called with:', { authToken: !!authToken, userData });
    
    setSkipProfileFetch(true); // Don't fetch profile since we already have user data
    setToken(authToken);
    setUser(userData);
    localStorage.setItem('yublog_token', authToken);
    axios.defaults.headers.common['Authorization'] = `Bearer ${authToken}`;
    setIsLoading(false); // Set loading to false since we have all the data we need
    
    console.log('AuthContext state updated. Token set:', !!authToken, 'User set:', !!userData);
    
    // Reset skip flag after a short delay
    setTimeout(() => {
      setSkipProfileFetch(false);
    }, 1000);
  };

  const logout = async () => {
    try {
      // Call logout endpoint if token exists
      if (token) {
        await axios.post('/api/auth/logout');
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setToken(null);
      setUser(null);
      localStorage.removeItem('yublog_token');
      delete axios.defaults.headers.common['Authorization'];
    }
  };

  const isAuthenticated = Boolean(user && token);

  const value = {
    user,
    token,
    isLoading,
    isAuthenticated,
    login,
    logout,
    fetchUserProfile,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}; 