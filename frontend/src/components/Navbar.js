import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { 
  Menu, 
  X, 
  PenTool, 
  User, 
  LogOut, 
  Shield,
  Home,
  BookOpen,
  Plus,
  BarChart3
} from 'lucide-react';

const Navbar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const { user, isAuthenticated, logout } = useAuth();
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  const handleLogout = () => {
    logout();
    setIsMenuOpen(false);
  };

  const toggleMenu = () => setIsMenuOpen(!isMenuOpen);

  const NavLink = ({ to, children, onClick, icon: Icon }) => (
    <Link
      to={to}
      onClick={onClick}
      className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
        isActive(to)
          ? 'bg-primary-100 text-primary-700 shadow-sm'
          : 'text-secondary-600 hover:text-secondary-900 hover:bg-secondary-50'
      }`}
    >
      {Icon && <Icon size={18} />}
      <span>{children}</span>
    </Link>
  );

  const MobileNavLink = ({ to, children, onClick, icon: Icon }) => (
    <Link
      to={to}
      onClick={onClick}
      className={`flex items-center space-x-3 px-4 py-3 text-base font-medium transition-colors ${
        isActive(to)
          ? 'bg-primary-50 text-primary-700 border-r-2 border-primary-500'
          : 'text-secondary-700 hover:text-secondary-900 hover:bg-secondary-50'
      }`}
    >
      {Icon && <Icon size={20} />}
      <span>{children}</span>
    </Link>
  );

  return (
    <nav className="bg-white border-b border-secondary-200 sticky top-0 z-40 backdrop-blur-sm bg-white/95">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2 group">
            <div className="relative">
              <Shield className="h-8 w-8 text-primary-600 group-hover:text-primary-700 transition-colors" />
              <div className="absolute -top-1 -right-1 h-3 w-3 bg-accent-500 rounded-full opacity-75 group-hover:opacity-100 transition-opacity" />
            </div>
            <span className="text-xl font-bold gradient-text">YuBlog</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-1">
            <NavLink to="/" icon={Home}>Home</NavLink>
            <NavLink to="/blog" icon={BookOpen}>Blog</NavLink>
            
            {isAuthenticated ? (
              <>
                <NavLink to="/dashboard" icon={BarChart3}>Dashboard</NavLink>
                <NavLink to="/create" icon={Plus}>Create</NavLink>
              </>
            ) : null}
          </div>

          {/* Desktop User Menu */}
          <div className="hidden md:flex items-center space-x-4">
            {isAuthenticated ? (
              <div className="flex items-center space-x-2">
                <div className="relative group">
                  <button className="flex items-center space-x-2 p-2 rounded-lg hover:bg-secondary-50 transition-colors">
                    <div className="h-8 w-8 rounded-full bg-primary-100 flex items-center justify-center">
                      <User size={16} className="text-primary-600" />
                    </div>
                    <span className="text-sm font-medium text-secondary-700">
                      {user?.displayName || user?.username}
                    </span>
                  </button>
                  
                  {/* Dropdown Menu */}
                  <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-secondary-200 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
                    <div className="py-1">
                      <Link
                        to="/profile"
                        className="flex items-center space-x-2 px-4 py-2 text-sm text-secondary-700 hover:bg-secondary-50"
                      >
                        <User size={16} />
                        <span>Profile</span>
                      </Link>
                      <button
                        onClick={handleLogout}
                        className="flex items-center space-x-2 w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                      >
                        <LogOut size={16} />
                        <span>Logout</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <Link
                to="/auth"
                className="btn-primary"
              >
                Sign In
              </Link>
            )}
          </div>

          {/* Mobile menu button */}
          <button
            onClick={toggleMenu}
            className="md:hidden p-2 rounded-lg text-secondary-600 hover:text-secondary-900 hover:bg-secondary-50 transition-colors"
          >
            {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="md:hidden bg-white border-t border-secondary-200"
          >
            <div className="px-2 pt-2 pb-3 space-y-1">
              <MobileNavLink to="/" onClick={() => setIsMenuOpen(false)} icon={Home}>
                Home
              </MobileNavLink>
              <MobileNavLink to="/blog" onClick={() => setIsMenuOpen(false)} icon={BookOpen}>
                Blog
              </MobileNavLink>
              
              {isAuthenticated ? (
                <>
                  <MobileNavLink to="/dashboard" onClick={() => setIsMenuOpen(false)} icon={BarChart3}>
                    Dashboard
                  </MobileNavLink>
                  <MobileNavLink to="/create" onClick={() => setIsMenuOpen(false)} icon={Plus}>
                    Create Post
                  </MobileNavLink>
                  <MobileNavLink to="/profile" onClick={() => setIsMenuOpen(false)} icon={User}>
                    Profile
                  </MobileNavLink>
                  <button
                    onClick={handleLogout}
                    className="flex items-center space-x-3 w-full px-4 py-3 text-base font-medium text-red-600 hover:bg-red-50"
                  >
                    <LogOut size={20} />
                    <span>Logout</span>
                  </button>
                </>
              ) : (
                <div className="px-4 py-3">
                  <Link
                    to="/auth"
                    onClick={() => setIsMenuOpen(false)}
                    className="btn-primary w-full justify-center"
                  >
                    Sign In
                  </Link>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </nav>
  );
};

export default Navbar; 