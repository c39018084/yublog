import pg from 'pg';
import { createClient } from 'redis';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;

// PostgreSQL connection pool
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'yublog',
  user: process.env.DB_USER || 'yublog',
  password: process.env.DB_PASSWORD || 'password',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Redis client for challenges
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.on('connect', () => console.log('Redis Client Connected'));

// Initialize Redis connection
await redisClient.connect();

// Database operations
export const db = {
  // Test database connection
  async testConnection() {
    try {
      const client = await pool.connect();
      const result = await client.query('SELECT NOW()');
      client.release();
      console.log('Database connected successfully:', result.rows[0]);
      return true;
    } catch (err) {
      console.error('Database connection failed:', err);
      return false;
    }
  },

  // User operations
  async createUser(userData) {
    const { username, email, displayName } = userData;
    const id = uuidv4();
    const query = `
      INSERT INTO users (id, username, email, display_name, created_at, updated_at, is_active)
      VALUES ($1, $2, $3, $4, NOW(), NOW(), true)
      RETURNING *
    `;
    const values = [id, username, email, displayName];
    const result = await pool.query(query, values);
    return result.rows[0];
  },

  async findUserByUsername(username) {
    const query = `
      SELECT * FROM users 
      WHERE (username = $1 OR email = $1) AND is_active = true
    `;
    const result = await pool.query(query, [username]);
    return result.rows[0];
  },

  async getUserByUsername(username) {
    return this.findUserByUsername(username);
  },

  async getUserById(id) {
    const query = 'SELECT * FROM users WHERE id = $1 AND is_active = true';
    const result = await pool.query(query, [id]);
    return result.rows[0];
  },

  async findUserById(id) {
    return this.getUserById(id);
  },

  // Credential operations
  async createCredential(credentialData) {
    const { 
      userId, 
      credentialId, 
      publicKey, 
      counter, 
      deviceName, 
      aaguid, 
      attestationCertHash, 
      deviceRegistrationId 
    } = credentialData;
    const id = uuidv4();
    const query = `
      INSERT INTO credentials (
        id, user_id, credential_id, public_key, counter, created_at, 
        device_name, aaguid, attestation_cert_hash, device_registration_id
      )
      VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8, $9)
      RETURNING *
    `;
    const values = [
      id, userId, credentialId, publicKey, counter || 0, 
      deviceName, aaguid, attestationCertHash, deviceRegistrationId
    ];
    const result = await pool.query(query, values);
    return result.rows[0];
  },

  async saveCredential(credentialData) {
    return this.createCredential(credentialData);
  },

  async findCredentialById(credentialId) {
    const query = `
      SELECT * FROM credentials
      WHERE credential_id = $1
    `;
    const result = await pool.query(query, [credentialId]);
    return result.rows[0];
  },

  async getCredentialById(credentialId) {
    const query = `
      SELECT c.*, u.* FROM credentials c
      JOIN users u ON c.user_id = u.id
      WHERE c.credential_id = $1
    `;
    const result = await pool.query(query, [credentialId]);
    return result.rows[0];
  },

  async getCredentialByDatabaseId(id) {
    const query = `
      SELECT c.*, u.* FROM credentials c
      JOIN users u ON c.user_id = u.id
      WHERE c.id = $1
    `;
    const result = await pool.query(query, [id]);
    return result.rows[0];
  },

  async findCredentialsByUserId(userId) {
    const query = 'SELECT * FROM credentials WHERE user_id = $1';
    const result = await pool.query(query, [userId]);
    return result.rows;
  },

  async getUserCredentials(userId) {
    return this.findCredentialsByUserId(userId);
  },

  async updateCredentialCounter(credentialId, counter) {
    const query = `
      UPDATE credentials 
      SET counter = $1, last_used = NOW() 
      WHERE credential_id = $2
    `;
    await pool.query(query, [counter, credentialId]);
  },

  // Device registration tracking for spam prevention
  async checkDeviceRegistrationEligibility(aaguid, attestationCertHash = null) {
    const query = `
      SELECT can_register, blocked_until, days_remaining
      FROM can_device_register($1, $2)
    `;
    const result = await pool.query(query, [aaguid, attestationCertHash]);
    return result.rows[0];
  },

  async checkDeviceAddToAccountEligibility(aaguid, attestationCertHash = null, userId = null) {
    const query = `
      SELECT can_register, blocked_until, days_remaining
      FROM can_device_add_to_account($1, $2, $3)
    `;
    const result = await pool.query(query, [aaguid, attestationCertHash, userId]);
    return result.rows[0];
  },

  async recordDeviceRegistration(aaguid, attestationCertHash = null, deviceFingerprint = null, success = true, userId = null) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Set user context if userId is provided
      if (userId && success) {
        await client.query('SELECT set_config($1, $2, true)', ['app.current_user_id', userId]);
      }
      
      const query = `
        SELECT record_device_registration($1, $2, $3, $4) as device_registration_id
      `;
      const result = await client.query(query, [aaguid, attestationCertHash, deviceFingerprint, success]);
      
      await client.query('COMMIT');
      return result.rows[0].device_registration_id;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  },

  async getDeviceRegistrationStats(aaguid) {
    const query = `
      SELECT * FROM device_registrations 
      WHERE aaguid = $1
    `;
    const result = await pool.query(query, [aaguid]);
    return result.rows[0];
  },

  // Session operations
  async createSession(sessionData) {
    const { id, userId, tokenHash, expiresAt, ipAddress, userAgent } = sessionData;
    const query = `
      INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, last_activity, ip_address, user_agent, is_active)
      VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6, true)
      RETURNING *
    `;
    const values = [id, userId, tokenHash, expiresAt, ipAddress, userAgent];
    const result = await pool.query(query, values);
    return result.rows[0];
  },

  async getActiveSession(tokenHash) {
    const query = `
      SELECT s.*, u.* FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = $1 AND s.is_active = true AND s.expires_at > NOW()
    `;
    const result = await pool.query(query, [tokenHash]);
    return result.rows[0];
  },

  async invalidateSession(tokenHash) {
    const query = `
      UPDATE sessions 
      SET is_active = false, last_activity = NOW()
      WHERE token_hash = $1
    `;
    await pool.query(query, [tokenHash]);
  },

  // Post operations
  async createPost(postData) {
    const { id, authorId, title, content, tags, slug, isPublished } = postData;
    const query = `
      INSERT INTO posts (id, author_id, title, content, slug, published, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
      RETURNING *
    `;
    const values = [id, authorId, title, content, slug, isPublished];
    const result = await pool.query(query, values);
    
    // Handle tags if provided
    if (tags && tags.length > 0) {
      for (const tagName of tags) {
        // Insert or get tag
        const tagQuery = `
          INSERT INTO tags (name) VALUES ($1) 
          ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
          RETURNING id
        `;
        const tagResult = await pool.query(tagQuery, [tagName.trim()]);
        const tagId = tagResult.rows[0].id;
        
        // Link post to tag
        const linkQuery = `
          INSERT INTO post_tags (post_id, tag_id) VALUES ($1, $2)
          ON CONFLICT (post_id, tag_id) DO NOTHING
        `;
        await pool.query(linkQuery, [id, tagId]);
      }
    }
    
    return result.rows[0];
  },

  async getAllPosts() {
    const query = `
      SELECT p.*, u.username as author_username, u.display_name as author_display_name,
             COALESCE(
               json_agg(
                 json_build_object('id', t.id, 'name', t.name)
               ) FILTER (WHERE t.id IS NOT NULL), 
               '[]'::json
             ) as tags
      FROM posts p
      JOIN users u ON p.author_id = u.id
      LEFT JOIN post_tags pt ON p.id = pt.post_id
      LEFT JOIN tags t ON pt.tag_id = t.id
      WHERE p.published = true
      GROUP BY p.id, u.username, u.display_name
      ORDER BY p.created_at DESC
      LIMIT 50
    `;
    const result = await pool.query(query);
    return result.rows;
  },

  async getPostById(id) {
    const query = `
      SELECT p.*, u.username as author_username, u.display_name as author_display_name,
             COALESCE(
               json_agg(
                 json_build_object('id', t.id, 'name', t.name)
               ) FILTER (WHERE t.id IS NOT NULL), 
               '[]'::json
             ) as tags
      FROM posts p
      JOIN users u ON p.author_id = u.id
      LEFT JOIN post_tags pt ON p.id = pt.post_id
      LEFT JOIN tags t ON pt.tag_id = t.id
      WHERE p.id = $1 AND p.published = true
      GROUP BY p.id, u.username, u.display_name
    `;
    const result = await pool.query(query, [id]);
    return result.rows[0] || null;
  },

  async getUserPosts(userId) {
    const query = `
      SELECT p.*, u.username as author_username, u.display_name as author_display_name,
             COALESCE(
               json_agg(
                 json_build_object('id', t.id, 'name', t.name)
               ) FILTER (WHERE t.id IS NOT NULL), 
               '[]'::json
             ) as tags
      FROM posts p
      JOIN users u ON p.author_id = u.id
      LEFT JOIN post_tags pt ON p.id = pt.post_id
      LEFT JOIN tags t ON pt.tag_id = t.id
      WHERE p.author_id = $1
      GROUP BY p.id, u.username, u.display_name
      ORDER BY p.created_at DESC
    `;
    const result = await pool.query(query, [userId]);
    return result.rows;
  },

  async getUserPostStats(userId) {
    const query = `
      SELECT 
        COUNT(*) as total_posts,
        COUNT(*) FILTER (WHERE published = true) as published_posts,
        COUNT(*) FILTER (WHERE published = false) as draft_posts
      FROM posts
      WHERE author_id = $1
    `;
    const result = await pool.query(query, [userId]);
    const stats = result.rows[0];
    return {
      totalPosts: parseInt(stats.total_posts) || 0,
      publishedPosts: parseInt(stats.published_posts) || 0,
      draftPosts: parseInt(stats.draft_posts) || 0
    };
  },

  async updatePost(postId, updateData) {
    const { title, content, tags, isPublished } = updateData;
    
    // Update the post
    const query = `
      UPDATE posts 
      SET title = COALESCE($1, title),
          content = COALESCE($2, content),
          published = COALESCE($3, published),
          updated_at = NOW()
      WHERE id = $4
      RETURNING *
    `;
    const values = [title, content, isPublished, postId];
    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      throw new Error('Post not found');
    }
    
    // Handle tags update if provided
    if (tags && Array.isArray(tags)) {
      // Remove existing tags
      await pool.query('DELETE FROM post_tags WHERE post_id = $1', [postId]);
      
      // Add new tags
      for (const tagName of tags) {
        if (tagName.trim()) {
          // Insert or get tag
          const tagQuery = `
            INSERT INTO tags (name) VALUES ($1) 
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
          `;
          const tagResult = await pool.query(tagQuery, [tagName.trim()]);
          const tagId = tagResult.rows[0].id;
          
          // Link post to tag
          const linkQuery = `
            INSERT INTO post_tags (post_id, tag_id) VALUES ($1, $2)
            ON CONFLICT (post_id, tag_id) DO NOTHING
          `;
          await pool.query(linkQuery, [postId, tagId]);
        }
      }
    }
    
    return result.rows[0];
  },

  async deletePost(postId) {
    // Delete post tags first (foreign key constraint)
    await pool.query('DELETE FROM post_tags WHERE post_id = $1', [postId]);
    
    // Delete the post
    const query = 'DELETE FROM posts WHERE id = $1';
    const result = await pool.query(query, [postId]);
    
    if (result.rowCount === 0) {
      throw new Error('Post not found');
    }
  },

  async deleteCredential(credentialId) {
    const query = 'DELETE FROM credentials WHERE id = $1';
    await pool.query(query, [credentialId]);
  },

  // Audit logging
  async logAuditEvent(auditData) {
    const { userId, action, resourceType, resourceId, details, ipAddress, userAgent, success } = auditData;
    const query = `
      INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent, success, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    `;
    const values = [userId, action, resourceType, resourceId, JSON.stringify(details), ipAddress, userAgent, success];
    await pool.query(query, values);
  },

  // Debug methods (temporary)
  async debugGetCredentials() {
    const query = 'SELECT id, user_id, credential_id, device_name, created_at FROM credentials ORDER BY created_at DESC LIMIT 10';
    const result = await pool.query(query);
    return result.rows;
  },

  async debugGetUsers() {
    const query = 'SELECT id, username, email, display_name, created_at FROM users ORDER BY created_at DESC LIMIT 10';
    const result = await pool.query(query);
    return result.rows;
  },

  // Enhanced session management methods
  async updateSessionActivity(sessionId, ipAddress, userAgent) {
    const query = `
      UPDATE sessions 
      SET last_activity = NOW(), ip_address = $2, user_agent = $3
      WHERE id = $1
    `;
    await pool.query(query, [sessionId, ipAddress, userAgent]);
  },

  async updateSessionToken(sessionId, newTokenHash) {
    const query = `
      UPDATE sessions 
      SET token_hash = $2, last_activity = NOW()
      WHERE id = $1
    `;
    await pool.query(query, [sessionId, newTokenHash]);
  },

  async setUserContext(userId) {
    await pool.query('SELECT set_config($1, $2, true)', ['app.current_user_id', userId]);
  }
};

// Redis operations with direct access methods
export const redis = {
  // Direct Redis client methods for webauthn.js
  async setex(key, seconds, value) {
    await redisClient.setEx(key, seconds, value);
  },

  async get(key) {
    return await redisClient.get(key);
  },

  async del(key) {
    await redisClient.del(key);
  },

  async keys(pattern) {
    return await redisClient.keys(pattern);
  },

  // Existing challenge methods
  async setChallenge(key, challenge, expirationSeconds = 300) {
    await redisClient.setEx(key, expirationSeconds, JSON.stringify(challenge));
  },

  async getChallenge(key) {
    const data = await redisClient.get(key);
    return data ? JSON.parse(data) : null;
  },

  async getAll(pattern) {
    const keys = await redisClient.keys(pattern);
    return keys;
  },

  async deleteChallenge(key) {
    await redisClient.del(key);
  },

  async ping() {
    return await redisClient.ping();
  }
};

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await pool.end();
  await redisClient.quit();
  process.exit(0);
});

export default { db, redis }; 