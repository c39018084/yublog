import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import { db, redis } from './database.js';
import { Pool } from 'pg';
import {
  beginRegistration,
  completeRegistration,
  beginAuthentication,
  completeAuthentication
} from './webauthn.js';

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Trust first proxy (nginx)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'", "wss:"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // limit each IP to 50 requests per windowMs for auth endpoints (increased for testing)
  message: 'Too many authentication attempts, please try again later.'
});

app.use(limiter);

// CORS Configuration
app.use(cors({
  origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET_KEY || 'your-super-secret-jwt-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Utility functions
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function logAuditEvent(userId, action, success, req, details = {}) {
  try {
    await db.logAuditEvent({
      id: uuidv4(),
      userId,
      action,
      success,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      details,
      resourceType: details.resourceType,
      resourceId: details.resourceId
    });
  } catch (error) {
    console.error('Failed to log audit event:', error);
  }
}

// Validation schemas
const userRegistrationValidation = [
  body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[A-Za-z0-9_-]+$/)
    .withMessage('Username must be 3-50 characters and contain only letters, numbers, hyphens, and underscores'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Must be a valid email address'),
  body('display_name')
    .optional()
    .isLength({ min: 1, max: 255 })
    .withMessage('Display name must be 1-255 characters')
];

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    const dbHealthy = await db.testConnection();
    
    // Test Redis connection
    const redisHealthy = await redis.ping() === 'PONG';
    
    res.json({
      status: dbHealthy && redisHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      services: {
        database: dbHealthy ? 'connected' : 'disconnected',
        redis: redisHealthy ? 'connected' : 'disconnected'
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// WebAuthn Registration Routes
app.post('/api/auth/webauthn/register/begin', strictLimiter, async (req, res) => {
  req.app.locals.db = db;
  req.app.locals.redis = redis;
  await beginRegistration(req, res);
});

app.post('/api/auth/webauthn/register/complete', strictLimiter, async (req, res) => {
  req.app.locals.db = db;
  req.app.locals.redis = redis;
  await completeRegistration(req, res);
});

// WebAuthn Authentication Routes
app.post('/api/auth/webauthn/login/begin', strictLimiter, async (req, res) => {
  req.app.locals.db = db;
  req.app.locals.redis = redis;
  await beginAuthentication(req, res);
});

app.post('/api/auth/webauthn/login/complete', strictLimiter, async (req, res) => {
  req.app.locals.db = db;
  req.app.locals.redis = redis;
  await completeAuthentication(req, res);
});

// JWT Authentication middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const session = await db.getActiveSession(hashToken(token));
    
    if (!session) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
    
    req.user = session;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

// Protected route example
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.getUserById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      displayName: user.display_name,
      createdAt: user.created_at
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const tokenHash = hashToken(req.headers['authorization'].split(' ')[1]);
    
    // Invalidate session in database
    await db.invalidateSession(tokenHash);
    
    await logAuditEvent(req.user.id, 'logout', true, req);
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Blog endpoints
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await db.getAllPosts();
    res.json(posts);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await db.getPostById(req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    res.json(post);
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

// User-specific posts endpoints
app.get('/api/user/posts', authenticateToken, async (req, res) => {
  try {
    const posts = await db.getUserPosts(req.user.id);
    res.json(posts);
  } catch (error) {
    console.error('Get user posts error:', error);
    res.status(500).json({ error: 'Failed to fetch user posts' });
  }
});

app.get('/api/user/posts/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await db.getUserPostStats(req.user.id);
    res.json(stats);
  } catch (error) {
    console.error('Get user post stats error:', error);
    res.status(500).json({ error: 'Failed to fetch post statistics' });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, tags, isDraft = false } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    
    const postData = {
      id: uuidv4(),
      authorId: req.user.id,
      title: title.trim(),
      content: content.trim(),
      tags: tags || [],
      slug: title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
      isPublished: !isDraft
    };
    
    const post = await db.createPost(postData);
    
    await logAuditEvent(req.user.id, 'create_post', true, req, { postId: post.id });
    
    res.status(201).json(post);
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    const { title, content, tags, isDraft } = req.body;
    
    // Check if user owns the post
    const existingPost = await db.getPostById(postId);
    if (!existingPost || existingPost.author_id !== req.user.id) {
      return res.status(404).json({ error: 'Post not found or access denied' });
    }
    
    const updateData = {
      title: title?.trim(),
      content: content?.trim(),
      tags: tags || [],
      isPublished: isDraft !== undefined ? !isDraft : existingPost.published
    };
    
    const updatedPost = await db.updatePost(postId, updateData);
    
    await logAuditEvent(req.user.id, 'update_post', true, req, { postId });
    
    res.json(updatedPost);
  } catch (error) {
    console.error('Update post error:', error);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check if user owns the post
    const post = await db.getPostById(postId);
    if (!post || post.author_id !== req.user.id) {
      return res.status(404).json({ error: 'Post not found or access denied' });
    }
    
    await db.deletePost(postId);
    
    await logAuditEvent(req.user.id, 'delete_post', true, req, { postId });
    
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Device management endpoints
app.get('/api/user/devices', authenticateToken, async (req, res) => {
  try {
    const devices = await db.getUserCredentials(req.user.id);
    
    const deviceList = devices.map(device => ({
      id: device.id,
      name: device.device_name || 'Unknown Device',
      createdAt: device.created_at,
      lastUsed: device.last_used,
      counter: device.counter
    }));
    
    res.json(deviceList);
  } catch (error) {
    console.error('Get devices error:', error);
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
});

app.delete('/api/user/devices/:id', authenticateToken, async (req, res) => {
  try {
    const deviceId = req.params.id;
    const device = await db.getCredentialById(deviceId);
    
    if (!device || device.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Device not found' });
    }
    
    await db.deleteCredential(deviceId);
    
    await logAuditEvent(req.user.id, 'delete_device', true, req, { deviceId });
    
    res.json({ message: 'Device removed successfully' });
  } catch (error) {
    console.error('Delete device error:', error);
    res.status(500).json({ error: 'Failed to remove device' });
  }
});

// Debug endpoint to check credentials (temporary for debugging)
app.get('/api/debug/credentials', async (req, res) => {
  try {
    const credentials = await db.debugGetCredentials();
    res.json({
      credentials,
      count: credentials.length
    });
  } catch (error) {
    console.error('Debug credentials error:', error);
    res.status(500).json({ error: 'Failed to fetch credentials' });
  }
});

// Debug endpoint to check users (temporary for debugging)
app.get('/api/debug/users', async (req, res) => {
  try {
    const users = await db.debugGetUsers();
    res.json({
      users,
      count: users.length
    });
  } catch (error) {
    console.error('Debug users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
async function startServer() {
  try {
    // Test database connection
    const dbConnected = await db.testConnection();
    if (!dbConnected) {
      console.error('Failed to connect to database');
      process.exit(1);
    }

    // Test Redis connection
    try {
      await redis.ping();
      console.log('Redis connection successful');
    } catch (error) {
      console.error('Failed to connect to Redis:', error);
      process.exit(1);
    }

    app.listen(port, '0.0.0.0', () => {
      console.log(`YuBlog Express Backend listening on port ${port}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`WebAuthn Origin: ${process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

startServer(); 