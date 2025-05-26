# YuBlog Security Features Documentation

## Overview

YuBlog implements advanced security features to prevent account spam and ensure secure user management. This document outlines the security mechanisms implemented in the system.

## 🔐 Device Registration Spam Prevention

### FIDO2/WebAuthn Device Identification

YuBlog uses the FIDO2/WebAuthn standard to uniquely identify security devices and prevent account spam:

#### AAGUID (Authenticator Attestation GUID)
- **Purpose**: Uniquely identifies the make and model of authenticators
- **Implementation**: Extracted from WebAuthn registration responses
- **Usage**: Primary identifier for device registration tracking

#### Attestation Certificate Hashing
- **Purpose**: Additional device verification beyond AAGUID
- **Implementation**: SHA-256 hash of the attestation certificate
- **Usage**: Secondary identifier for enhanced device tracking

### 34-Day Cooldown Period

#### Registration Limits
- **Cooldown Duration**: 34 days between account registrations per device
- **Enforcement**: Database-level functions prevent rapid account creation
- **User Experience**: Clear error messages with countdown timers

#### Database Implementation
```sql
-- Function to check device registration eligibility
CREATE OR REPLACE FUNCTION can_device_register(
    p_aaguid TEXT,
    p_attestation_cert_hash TEXT DEFAULT NULL
)
RETURNS TABLE (
    can_register BOOLEAN,
    blocked_until TIMESTAMP WITH TIME ZONE,
    days_remaining INTEGER
)
```

### Device Registration Tracking

#### Database Schema
```sql
CREATE TABLE device_registrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    aaguid TEXT NOT NULL,
    attestation_cert_hash TEXT,
    device_fingerprint TEXT,
    first_registration_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_registration_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    registration_count INTEGER DEFAULT 1,
    blocked_until TIMESTAMP WITH TIME ZONE,
    UNIQUE(aaguid, attestation_cert_hash)
);
```

#### Registration Process
1. **Device Detection**: Extract AAGUID and attestation certificate from WebAuthn response
2. **Eligibility Check**: Query database for existing registrations
3. **Cooldown Enforcement**: Block registration if within 34-day period
4. **Registration Recording**: Log successful registration with blocking period

## 👑 Administrator Privileges

### First User Admin Grant

#### Automatic Assignment
- **Trigger**: First user to register receives admin privileges automatically
- **Implementation**: PostgreSQL trigger function on user insertion
- **Audit**: All admin privilege grants are logged

#### Database Implementation
```sql
-- Trigger function to grant admin to first user
CREATE OR REPLACE FUNCTION grant_admin_to_first_user()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM users WHERE id != NEW.id) = 0 THEN
        NEW.is_admin := TRUE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

### Admin Privilege Logging
- **Audit Trail**: All admin grants logged to `audit_logs` table
- **Details**: Includes reason, username, and timestamp
- **Monitoring**: Enables detection of unauthorized privilege escalation

## 📊 Enhanced Audit Logging

### Security Event Tracking

#### Logged Events
- `account_creation_attempt`: User registration attempts
- `device_registration_blocked`: Blocked device registrations
- `admin_privilege_granted`: Admin privilege assignments
- `login_attempt`: Authentication attempts
- `access_denied`: Unauthorized access attempts

#### Audit Log Schema
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Device Registration Monitoring

#### Blocked Registration Logging
```javascript
await db.logAuditEvent({
    userId: null,
    action: 'device_registration_blocked',
    resourceType: 'device',
    details: {
        aaguid: deviceInfo.aaguid,
        blocked_until: eligibility.blocked_until,
        days_remaining: eligibility.days_remaining,
        reason: 'cooldown_period'
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    success: false
});
```

## 🛡️ Frontend Security Integration

### Error Handling

#### Device Blocking Messages
- **User-Friendly**: Clear explanations of blocking reasons
- **Countdown Display**: Shows exact date when registration will be allowed
- **Security Context**: Explains spam prevention purpose

#### Implementation
```javascript
if (error.response?.data?.error?.includes('device_blocked')) {
    const match = error.response.data.error.match(/until (.+?)\./);
    if (match) {
        const blockedUntil = new Date(match[1]);
        throw new Error(
            `This device was recently used to create an account and is temporarily blocked ` +
            `to prevent spam. You can create a new account with this device on ` +
            `${blockedUntil.toLocaleDateString()}. This security measure helps protect ` +
            `the platform from automated account creation.`
        );
    }
}
```

## 🔧 Database Security Functions

### Device Registration Functions

#### `can_device_register()`
- **Purpose**: Check if device can register new account
- **Parameters**: AAGUID, optional attestation certificate hash
- **Returns**: Registration eligibility, blocked until date, days remaining

#### `record_device_registration()`
- **Purpose**: Record device registration attempt
- **Parameters**: Device identifiers, success status
- **Returns**: Registration record ID
- **Side Effects**: Sets 34-day blocking period

### Security Triggers

#### Admin Privilege Assignment
- **Trigger**: `grant_admin_to_first_user_trigger`
- **Timing**: BEFORE INSERT on users table
- **Function**: Automatically grants admin to first user

#### Audit Logging
- **Trigger**: `log_admin_privilege_grant_trigger`
- **Timing**: AFTER INSERT OR UPDATE on users table
- **Function**: Logs admin privilege changes

## 🚀 Deployment Considerations

### Production Security

#### Environment Variables
```bash
# Required for production
JWT_SECRET_KEY=<cryptographically-secure-secret>
SECRET_KEY=<cryptographically-secure-secret>
DB_PASSWORD=<strong-database-password>
REDIS_PASSWORD=<strong-redis-password>
```

#### SSL Requirements
- **WebAuthn Requirement**: HTTPS mandatory for production
- **Certificate Management**: Use proper CA certificates
- **Development**: Self-signed certificates acceptable

### Monitoring and Alerting

#### Key Metrics
- Device registration block rate
- Failed authentication attempts
- Admin privilege grants
- Unusual device registration patterns

#### Recommended Alerts
- Multiple blocked registrations from same IP
- Rapid admin privilege grants
- High failure rates in authentication

## 🔍 Testing the Security Features

### Manual Testing Steps

1. **First User Admin Test**
   ```bash
   # Reset database
   ./scripts/reset-database-docker.sh
   
   # Register first user - should get admin privileges
   # Check audit logs for admin grant
   ```

2. **Device Blocking Test**
   ```bash
   # Register user with device
   # Attempt immediate second registration
   # Should be blocked with 34-day message
   ```

3. **Audit Logging Test**
   ```bash
   # Check audit_logs table after each action
   # Verify all security events are logged
   ```

### Database Queries for Verification

#### Check Device Registrations
```sql
SELECT * FROM device_registrations ORDER BY last_registration_at DESC;
```

#### Check Admin Users
```sql
SELECT username, is_admin, created_at FROM users WHERE is_admin = TRUE;
```

#### Check Audit Logs
```sql
SELECT action, details, created_at 
FROM audit_logs 
WHERE action IN ('admin_privilege_granted', 'device_registration_blocked')
ORDER BY created_at DESC;
```

## 📋 Security Checklist

### Pre-Production
- [ ] Change all default passwords
- [ ] Generate new JWT secrets
- [ ] Configure proper SSL certificates
- [ ] Set up monitoring and alerting
- [ ] Test device registration blocking
- [ ] Verify admin privilege assignment
- [ ] Review audit log configuration

### Post-Deployment
- [ ] Monitor device registration patterns
- [ ] Review audit logs regularly
- [ ] Test security features periodically
- [ ] Update security documentation
- [ ] Train administrators on security features

## 🔗 Related Documentation

- [Technical Design](TECHNICAL_DESIGN.md)
- [WebAuthn Implementation](../backend-js/src/webauthn.js)
- [Database Schema](../database/init.sql)
- [Frontend Security](../frontend/src/utils/webauthn.js)

---

**Last Updated**: May 26, 2025  
**Version**: 1.0.0  
**Branch**: feature/account-security-controls 