-- Migration: Remove email field and constraints from users table
-- This migration removes all email-related functionality from YuBlog

-- Remove email-related constraints and indexes
DROP INDEX IF EXISTS idx_users_email;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS valid_email;

-- Drop the email column
ALTER TABLE users DROP COLUMN IF EXISTS email;

-- Update any remaining audit logs or system references that might reference email
-- (This is a data cleanup step)
UPDATE audit_logs 
SET details = jsonb_set(
    details, 
    '{updated_fields}', 
    (details->'updated_fields') - 'email'
) 
WHERE details ? 'updated_fields' 
AND details->'updated_fields' ? 'email';

-- Note: This migration makes YuBlog completely email-free
-- Users are identified solely by their username and WebAuthn credentials
-- No personal information (email, phone numbers) is required or stored 