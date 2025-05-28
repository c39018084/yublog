-- Migration: Improve device tracking to distinguish between new account creation and adding devices to existing accounts
-- Date: 2024-01-XX
-- Description: Updates device_registrations table to track which user last registered each device

BEGIN;

-- Add new column to track which user last registered this device
ALTER TABLE device_registrations 
ADD COLUMN last_registered_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Rename blocked_until to be more specific about what it blocks
ALTER TABLE device_registrations 
RENAME COLUMN blocked_until TO account_creation_blocked_until;

-- Update the index to use the new column name
DROP INDEX IF EXISTS idx_device_registrations_blocked;
CREATE INDEX idx_device_registrations_blocked ON device_registrations(account_creation_blocked_until) WHERE account_creation_blocked_until IS NOT NULL;

-- Create the new function to check device eligibility for adding to existing accounts
CREATE OR REPLACE FUNCTION can_device_add_to_account(
    p_aaguid TEXT,
    p_attestation_cert_hash TEXT DEFAULT NULL,
    p_user_id UUID DEFAULT NULL
)
RETURNS TABLE (
    can_register BOOLEAN,
    blocked_until TIMESTAMP WITH TIME ZONE,
    days_remaining INTEGER
) AS $$
DECLARE
    device_record RECORD;
    cooldown_period INTERVAL := '34 days';
    current_user_id UUID;
BEGIN
    -- Get current user ID from session or parameter
    current_user_id := COALESCE(p_user_id, current_setting('app.current_user_id', true)::UUID);
    
    -- Look for existing device registration
    SELECT * INTO device_record
    FROM device_registrations dr
    WHERE dr.aaguid = p_aaguid 
    AND (p_attestation_cert_hash IS NULL OR dr.attestation_cert_hash = p_attestation_cert_hash);
    
    -- If no previous registration, allow (first time use)
    IF NOT FOUND THEN
        RETURN QUERY SELECT TRUE, NULL::TIMESTAMP WITH TIME ZONE, 0;
        RETURN;
    END IF;
    
    -- If device was last registered by the same user, allow re-adding (no restriction)
    IF device_record.last_registered_user_id = current_user_id THEN
        RETURN QUERY SELECT TRUE, NULL::TIMESTAMP WITH TIME ZONE, 0;
        RETURN;
    END IF;
    
    -- If device was used by a different user, apply 34-day restriction
    IF device_record.account_creation_blocked_until IS NOT NULL AND device_record.account_creation_blocked_until > NOW() THEN
        RETURN QUERY SELECT 
            FALSE,
            device_record.account_creation_blocked_until,
            EXTRACT(DAYS FROM (device_record.account_creation_blocked_until - NOW()))::INTEGER;
        RETURN;
    END IF;
    
    -- Check if enough time has passed since last registration by different user
    IF device_record.last_registration_at + cooldown_period > NOW() AND device_record.last_registered_user_id IS NOT NULL AND device_record.last_registered_user_id != current_user_id THEN
        RETURN QUERY SELECT 
            FALSE,
            device_record.last_registration_at + cooldown_period,
            EXTRACT(DAYS FROM ((device_record.last_registration_at + cooldown_period) - NOW()))::INTEGER;
        RETURN;
    END IF;
    
    -- Device can be added to account
    RETURN QUERY SELECT TRUE, NULL::TIMESTAMP WITH TIME ZONE, 0;
END;
$$ LANGUAGE plpgsql;

-- Update the existing can_device_register function to use the new column name
CREATE OR REPLACE FUNCTION can_device_register(
    p_aaguid TEXT,
    p_attestation_cert_hash TEXT DEFAULT NULL
)
RETURNS TABLE (
    can_register BOOLEAN,
    blocked_until TIMESTAMP WITH TIME ZONE,
    days_remaining INTEGER
) AS $$
DECLARE
    device_record RECORD;
    cooldown_period INTERVAL := '34 days';
BEGIN
    -- Look for existing device registration
    SELECT * INTO device_record
    FROM device_registrations dr
    WHERE dr.aaguid = p_aaguid 
    AND (p_attestation_cert_hash IS NULL OR dr.attestation_cert_hash = p_attestation_cert_hash);
    
    -- If no previous registration, allow
    IF NOT FOUND THEN
        RETURN QUERY SELECT TRUE, NULL::TIMESTAMP WITH TIME ZONE, 0;
        RETURN;
    END IF;
    
    -- Check if device is currently blocked for account creation
    IF device_record.account_creation_blocked_until IS NOT NULL AND device_record.account_creation_blocked_until > NOW() THEN
        RETURN QUERY SELECT 
            FALSE,
            device_record.account_creation_blocked_until,
            EXTRACT(DAYS FROM (device_record.account_creation_blocked_until - NOW()))::INTEGER;
        RETURN;
    END IF;
    
    -- Check if enough time has passed since last registration
    IF device_record.last_registration_at + cooldown_period > NOW() THEN
        RETURN QUERY SELECT 
            FALSE,
            device_record.last_registration_at + cooldown_period,
            EXTRACT(DAYS FROM ((device_record.last_registration_at + cooldown_period) - NOW()))::INTEGER;
        RETURN;
    END IF;
    
    -- Device can register
    RETURN QUERY SELECT TRUE, NULL::TIMESTAMP WITH TIME ZONE, 0;
END;
$$ LANGUAGE plpgsql;

-- Update the record_device_registration function to track user ID
CREATE OR REPLACE FUNCTION record_device_registration(
    p_aaguid TEXT,
    p_attestation_cert_hash TEXT DEFAULT NULL,
    p_device_fingerprint TEXT DEFAULT NULL,
    p_success BOOLEAN DEFAULT TRUE
)
RETURNS UUID AS $$
DECLARE
    device_reg_id UUID;
    cooldown_period INTERVAL := '34 days';
BEGIN
    -- Insert or update device registration record
    INSERT INTO device_registrations (
        aaguid, 
        attestation_cert_hash, 
        device_fingerprint,
        first_registration_at,
        last_registration_at,
        last_registered_user_id,
        registration_count,
        account_creation_blocked_until
    )
    VALUES (
        p_aaguid,
        p_attestation_cert_hash,
        p_device_fingerprint,
        NOW(),
        NOW(),
        CASE WHEN p_success THEN current_setting('app.current_user_id', true)::UUID ELSE NULL END,
        1,
        CASE WHEN p_success THEN NOW() + cooldown_period ELSE NULL END
    )
    ON CONFLICT (aaguid, attestation_cert_hash)
    DO UPDATE SET
        last_registration_at = NOW(),
        registration_count = device_registrations.registration_count + 1,
        account_creation_blocked_until = CASE WHEN p_success THEN NOW() + cooldown_period ELSE device_registrations.account_creation_blocked_until END,
        device_fingerprint = COALESCE(p_device_fingerprint, device_registrations.device_fingerprint),
        last_registered_user_id = CASE WHEN p_success THEN current_setting('app.current_user_id', true)::UUID ELSE device_registrations.last_registered_user_id END
    RETURNING id INTO device_reg_id;
    
    RETURN device_reg_id;
END;
$$ LANGUAGE plpgsql;

COMMIT; 