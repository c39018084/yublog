-- YuBlog Database Schema
-- Security-first design with no password storage

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table - core user information
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Security constraints
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_username CHECK (username ~* '^[A-Za-z0-9_-]{3,50}$')
);

-- WebAuthn credentials for YubiKey authentication
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    device_name VARCHAR(255),
    aaguid TEXT, -- Authenticator AAGUID for device identification
    
    -- Indexes for performance
    CONSTRAINT fk_credential_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Registered devices for QR code authentication
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(255) NOT NULL,
    device_type VARCHAR(50) NOT NULL CHECK (device_type IN ('mobile', 'tablet', 'desktop')),
    public_key TEXT NOT NULL,
    push_token TEXT, -- For push notifications (if implemented)
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    device_fingerprint TEXT, -- Additional device identification
    
    -- Constraints
    CONSTRAINT fk_device_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Blog posts
CREATE TABLE posts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    slug VARCHAR(500) UNIQUE NOT NULL,
    content TEXT NOT NULL,
    excerpt TEXT,
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    published BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- SEO and content constraints
    CONSTRAINT valid_slug CHECK (slug ~* '^[a-z0-9-]+$'),
    CONSTRAINT fk_post_author FOREIGN KEY (author_id) REFERENCES users(id)
);

-- Tags for organizing posts
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Tag name constraints
    CONSTRAINT valid_tag_name CHECK (name ~* '^[A-Za-z0-9\s-]+$')
);

-- Post-Tag many-to-many relationship
CREATE TABLE post_tags (
    post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (post_id, tag_id)
);

-- Secure session management
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Session security constraints
    CONSTRAINT session_not_expired CHECK (expires_at > created_at),
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(id)
);

-- QR authentication sessions (temporary for login flow)
CREATE TABLE qr_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    
    -- Cleanup constraint
    CONSTRAINT qr_session_not_expired CHECK (expires_at > created_at)
);

-- Comprehensive audit logs for security monitoring
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Audit constraints
    CONSTRAINT valid_action CHECK (action IN (
        'login_attempt', 'login_success', 'logout', 'register_credential',
        'remove_credential', 'register_device', 'remove_device',
        'create_post', 'update_post', 'delete_post', 'publish_post',
        'access_denied', 'rate_limit_exceeded'
    ))
);

-- Performance indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);

CREATE INDEX idx_credentials_user ON credentials(user_id);
CREATE INDEX idx_credentials_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(user_id) WHERE last_used IS NOT NULL;

CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_active ON devices(user_id, is_active);

CREATE INDEX idx_posts_published ON posts(published, created_at DESC);
CREATE INDEX idx_posts_author ON posts(author_id, created_at DESC);
CREATE INDEX idx_posts_slug ON posts(slug);
CREATE INDEX idx_posts_search ON posts USING gin(to_tsvector('english', title || ' ' || content));

CREATE INDEX idx_tags_name ON tags(name);

CREATE INDEX idx_sessions_user ON sessions(user_id, expires_at);
CREATE INDEX idx_sessions_token ON sessions(token_hash);
CREATE INDEX idx_sessions_cleanup ON sessions(expires_at) WHERE is_active = TRUE;

CREATE INDEX idx_qr_sessions_cleanup ON qr_sessions(expires_at);
CREATE INDEX idx_qr_sessions_id ON qr_sessions(session_id);

CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, created_at DESC);
CREATE INDEX idx_audit_timeline ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);

-- Automatic updated_at triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_posts_updated_at 
    BEFORE UPDATE ON posts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Automatic session cleanup function
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    DELETE FROM qr_sessions WHERE expires_at < NOW();
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Security function to hash tokens
CREATE OR REPLACE FUNCTION hash_token(token TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(digest(token, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Row Level Security (RLS) policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY user_access_policy ON users
    FOR ALL TO authenticated_users
    USING (id = current_setting('app.current_user_id')::UUID);

-- Users can only see published posts or their own posts
CREATE POLICY post_access_policy ON posts
    FOR SELECT TO authenticated_users
    USING (published = TRUE OR author_id = current_setting('app.current_user_id')::UUID);

-- Users can only modify their own posts
CREATE POLICY post_modify_policy ON posts
    FOR ALL TO authenticated_users
    USING (author_id = current_setting('app.current_user_id')::UUID);

-- Users can only see their own sessions
CREATE POLICY session_access_policy ON sessions
    FOR ALL TO authenticated_users
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Create database roles for principle of least privilege
CREATE ROLE yublog_app;
CREATE ROLE yublog_readonly;
CREATE ROLE authenticated_users;

-- Grant appropriate permissions to application role
GRANT CONNECT ON DATABASE yublog TO yublog_app;
GRANT USAGE ON SCHEMA public TO yublog_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO yublog_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO yublog_app;

-- Grant read-only permissions
GRANT CONNECT ON DATABASE yublog TO yublog_readonly;
GRANT USAGE ON SCHEMA public TO yublog_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO yublog_readonly;

-- Grant permissions to authenticated users role
GRANT CONNECT ON DATABASE yublog TO authenticated_users;
GRANT USAGE ON SCHEMA public TO authenticated_users;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated_users;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated_users;

-- Sample data for testing (remove in production)
INSERT INTO users (username, email, display_name) VALUES 
('admin', 'admin@yublog.local', 'Administrator'),
('demo', 'demo@yublog.local', 'Demo User');

-- Initial blog post
INSERT INTO posts (title, slug, content, excerpt, author_id, published)
SELECT 
    'Welcome to YuBlog',
    'welcome-to-yublog',
    '<h1>Welcome to YuBlog</h1><p>This is a secure, passwordless blogging platform that uses YubiKey and QR code authentication.</p><p>Key features:</p><ul><li>No passwords stored anywhere</li><li>YubiKey (FIDO2/WebAuthn) authentication</li><li>QR code mobile authentication</li><li>Self-hosted and secure</li></ul>',
    'Welcome to YuBlog - a secure, passwordless blogging platform.',
    users.id,
    TRUE
FROM users WHERE username = 'admin';

-- Create initial tag
INSERT INTO tags (name) VALUES ('Security'), ('Technology'), ('Privacy');

-- Link post with tags
INSERT INTO post_tags (post_id, tag_id)
SELECT p.id, t.id
FROM posts p, tags t
WHERE p.slug = 'welcome-to-yublog' AND t.name IN ('Security', 'Technology');

COMMIT; 