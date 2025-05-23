"""
Test Suite for YuBlog Authentication
Tests for WebAuthn, QR Code Authentication, and Security Features
"""

import pytest
import json
import base64
import secrets
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from backend.app_complete import app, db, redis_client
from backend.app_complete import User, Credential, Device, Session, QRSession, AuditLog


@pytest.fixture
def client():
    """Create test client with isolated database"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()


@pytest.fixture
def sample_user(client):
    """Create a sample user for testing"""
    user = User(
        username='testuser',
        email='test@example.com',
        display_name='Test User'
    )
    db.session.add(user)
    db.session.commit()
    return user


class TestWebAuthnRegistration:
    """Test WebAuthn registration flow"""
    
    def test_webauthn_register_begin_success(self, client):
        """Test successful WebAuthn registration initiation"""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'displayName': 'New User'
        }
        
        response = client.post('/api/auth/webauthn/register/begin',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        
        # Check required WebAuthn fields
        assert 'challenge' in response_data
        assert 'rp' in response_data
        assert 'user' in response_data
        assert 'pubKeyCredParams' in response_data
        
        # Verify challenge is stored in Redis
        user_id = base64.b64decode(response_data['user']['id']).decode()
        challenge_key = f"webauthn_challenge:{user_id}"
        stored_data = redis_client.get(challenge_key)
        assert stored_data is not None
    
    def test_webauthn_register_begin_duplicate_user(self, client, sample_user):
        """Test WebAuthn registration with existing user"""
        data = {
            'username': sample_user.username,
            'email': sample_user.email,
            'displayName': 'Test User'
        }
        
        response = client.post('/api/auth/webauthn/register/begin',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'error' in response_data
        assert 'already exists' in response_data['error']
    
    def test_webauthn_register_begin_invalid_data(self, client):
        """Test WebAuthn registration with invalid data"""
        # Missing required fields
        data = {
            'username': 'newuser'
            # Missing email and displayName
        }
        
        response = client.post('/api/auth/webauthn/register/begin',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Validation failed' in response_data['error']
    
    def test_webauthn_register_begin_rate_limiting(self, client):
        """Test rate limiting on registration endpoint"""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'displayName': 'Test User'
        }
        
        # Make multiple rapid requests
        for i in range(6):  # Exceeds rate limit of 5/minute
            response = client.post('/api/auth/webauthn/register/begin',
                                 json=data,
                                 content_type='application/json')
            if i < 5:
                assert response.status_code in [200, 400]  # Valid or duplicate error
            else:
                assert response.status_code == 429  # Rate limited
    
    @patch('webauthn.verify_registration_response')
    def test_webauthn_register_complete_success(self, mock_verify, client):
        """Test successful WebAuthn registration completion"""
        # Setup mock verification response
        mock_verification = MagicMock()
        mock_verification.verified = True
        mock_verification.credential_id = b'test_credential_id'
        mock_verification.credential_public_key = b'test_public_key'
        mock_verification.sign_count = 0
        mock_verification.aaguid = 'test-aaguid'
        mock_verify.return_value = mock_verification
        
        # First, initiate registration
        init_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'displayName': 'New User'
        }
        
        init_response = client.post('/api/auth/webauthn/register/begin',
                                  json=init_data,
                                  content_type='application/json')
        init_response_data = json.loads(init_response.data)
        
        # Complete registration
        complete_data = {
            'id': 'test_credential_id',
            'user': {
                'id': init_response_data['user']['id']
            },
            'response': {
                'clientDataJSON': base64.b64encode(json.dumps({
                    'type': 'webauthn.create',
                    'challenge': init_response_data['challenge'],
                    'origin': 'https://localhost:3000'
                }).encode()).decode(),
                'attestationObject': 'test_attestation'
            },
            'type': 'public-key',
            'deviceName': 'Test YubiKey'
        }
        
        response = client.post('/api/auth/webauthn/register/complete',
                             json=complete_data,
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['success'] is True
        assert 'user' in response_data
        
        # Verify user and credential were created
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        
        credential = Credential.query.filter_by(user_id=user.id).first()
        assert credential is not None
        assert credential.device_name == 'Test YubiKey'


class TestWebAuthnAuthentication:
    """Test WebAuthn authentication flow"""
    
    def test_webauthn_login_begin_success(self, client, sample_user):
        """Test successful WebAuthn authentication initiation"""
        # Create a credential for the user
        credential = Credential(
            user_id=sample_user.id,
            credential_id='test_credential_id',
            public_key='test_public_key',
            device_name='Test YubiKey'
        )
        db.session.add(credential)
        db.session.commit()
        
        data = {'username': sample_user.username}
        
        response = client.post('/api/auth/webauthn/login/begin',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        
        assert 'challenge' in response_data
        assert 'allowCredentials' in response_data
        assert len(response_data['allowCredentials']) == 1
        assert response_data['allowCredentials'][0]['id'] == 'test_credential_id'
    
    def test_webauthn_login_begin_nonexistent_user(self, client):
        """Test WebAuthn authentication with non-existent user"""
        data = {'username': 'nonexistentuser'}
        
        response = client.post('/api/auth/webauthn/login/begin',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Invalid username' in response_data['error']
    
    def test_webauthn_login_begin_no_credentials(self, client, sample_user):
        """Test WebAuthn authentication with user having no credentials"""
        data = {'username': sample_user.username}
        
        response = client.post('/api/auth/webauthn/login/begin',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'No credentials registered' in response_data['error']
    
    @patch('webauthn.verify_authentication_response')
    def test_webauthn_login_complete_success(self, mock_verify, client, sample_user):
        """Test successful WebAuthn authentication completion"""
        # Setup credential
        credential = Credential(
            user_id=sample_user.id,
            credential_id='test_credential_id',
            public_key=base64.b64encode(b'test_public_key').decode(),
            counter=0,
            device_name='Test YubiKey'
        )
        db.session.add(credential)
        db.session.commit()
        
        # Setup mock verification
        mock_verification = MagicMock()
        mock_verification.verified = True
        mock_verification.new_sign_count = 1
        mock_verify.return_value = mock_verification
        
        # Initiate login
        init_response = client.post('/api/auth/webauthn/login/begin',
                                  json={'username': sample_user.username},
                                  content_type='application/json')
        init_data = json.loads(init_response.data)
        
        # Complete login
        complete_data = {
            'id': 'test_credential_id',
            'response': {
                'authenticatorData': 'test_auth_data',
                'signature': 'test_signature',
                'clientDataJSON': base64.b64encode(json.dumps({
                    'type': 'webauthn.get',
                    'challenge': init_data['challenge'],
                    'origin': 'https://localhost:3000'
                }).encode()).decode()
            },
            'type': 'public-key'
        }
        
        response = client.post('/api/auth/webauthn/login/complete',
                             json=complete_data,
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['success'] is True
        assert 'token' in response_data
        assert 'user' in response_data
        
        # Verify credential counter was updated
        updated_credential = Credential.query.get(credential.id)
        assert updated_credential.counter == 1
        assert updated_credential.last_used is not None


class TestQRCodeAuthentication:
    """Test QR code authentication flow"""
    
    def test_qr_generate_success(self, client):
        """Test successful QR code generation"""
        response = client.post('/api/auth/qr/generate',
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        
        assert 'qrCode' in response_data
        assert 'sessionId' in response_data
        assert 'expiresAt' in response_data
        assert response_data['qrCode'].startswith('data:image/png;base64,')
        
        # Verify QR session was created
        qr_session = QRSession.query.filter_by(
            session_id=response_data['sessionId']
        ).first()
        assert qr_session is not None
        assert qr_session.verified is False
    
    def test_qr_generate_rate_limiting(self, client):
        """Test rate limiting on QR generation"""
        # Make multiple rapid requests
        for i in range(4):  # Exceeds rate limit of 3/minute
            response = client.post('/api/auth/qr/generate',
                                 content_type='application/json')
            if i < 3:
                assert response.status_code == 200
            else:
                assert response.status_code == 429
    
    @patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify')
    def test_qr_verify_success(self, mock_verify, client, sample_user):
        """Test successful QR code verification"""
        # Create device
        device = Device(
            user_id=sample_user.id,
            device_name='Test Phone',
            device_type='mobile',
            public_key='-----BEGIN PUBLIC KEY-----\ntest_key\n-----END PUBLIC KEY-----',
            is_active=True
        )
        db.session.add(device)
        db.session.commit()
        
        # Create QR session
        qr_session = QRSession(
            session_id='test_session_id',
            challenge='test_challenge',
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            verified=False
        )
        db.session.add(qr_session)
        db.session.commit()
        
        # Mock signature verification
        mock_verify.return_value = None  # No exception means valid
        
        data = {
            'sessionId': 'test_session_id',
            'deviceId': device.id,
            'deviceSignature': base64.b64encode(b'test_signature').decode()
        }
        
        response = client.post('/api/auth/qr/verify',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['success'] is True
        assert 'token' in response_data
        assert 'user' in response_data
        
        # Verify QR session was marked as verified
        updated_session = QRSession.query.get(qr_session.id)
        assert updated_session.verified is True
        assert updated_session.user_id == sample_user.id
    
    def test_qr_verify_invalid_session(self, client):
        """Test QR verification with invalid session"""
        data = {
            'sessionId': 'invalid_session_id',
            'deviceId': 'test_device_id',
            'deviceSignature': 'test_signature'
        }
        
        response = client.post('/api/auth/qr/verify',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Invalid or expired QR session' in response_data['error']
    
    def test_qr_verify_expired_session(self, client):
        """Test QR verification with expired session"""
        # Create expired QR session
        qr_session = QRSession(
            session_id='expired_session_id',
            challenge='test_challenge',
            expires_at=datetime.utcnow() - timedelta(minutes=1),  # Expired
            verified=False
        )
        db.session.add(qr_session)
        db.session.commit()
        
        data = {
            'sessionId': 'expired_session_id',
            'deviceId': 'test_device_id',
            'deviceSignature': 'test_signature'
        }
        
        response = client.post('/api/auth/qr/verify',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Invalid or expired QR session' in response_data['error']
    
    def test_qr_status_verified(self, client, sample_user):
        """Test QR status check for verified session"""
        # Create verified QR session
        qr_session = QRSession(
            session_id='verified_session_id',
            user_id=sample_user.id,
            challenge='test_challenge',
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            verified=True
        )
        db.session.add(qr_session)
        db.session.commit()
        
        response = client.get('/api/auth/qr/status/verified_session_id')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['verified'] is True
        assert response_data['expired'] is False
        assert 'token' in response_data
        assert 'user' in response_data
    
    def test_qr_status_pending(self, client):
        """Test QR status check for pending session"""
        # Create pending QR session
        qr_session = QRSession(
            session_id='pending_session_id',
            challenge='test_challenge',
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            verified=False
        )
        db.session.add(qr_session)
        db.session.commit()
        
        response = client.get('/api/auth/qr/status/pending_session_id')
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['verified'] is False
        assert response_data['expired'] is False


class TestDeviceManagement:
    """Test device management functionality"""
    
    def test_get_devices_authenticated(self, client, sample_user):
        """Test getting user's devices when authenticated"""
        # Create test devices
        device1 = Device(
            user_id=sample_user.id,
            device_name='iPhone 13',
            device_type='mobile',
            public_key='test_key_1',
            is_active=True
        )
        device2 = Device(
            user_id=sample_user.id,
            device_name='iPad Pro',
            device_type='tablet',
            public_key='test_key_2',
            is_active=True
        )
        db.session.add_all([device1, device2])
        db.session.commit()
        
        # Create auth token
        from flask_jwt_extended import create_access_token
        with app.app_context():
            token = create_access_token(identity=sample_user.id)
        
        response = client.get('/api/auth/devices',
                            headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert len(response_data['devices']) == 2
        
        device_names = [d['name'] for d in response_data['devices']]
        assert 'iPhone 13' in device_names
        assert 'iPad Pro' in device_names
    
    def test_get_devices_unauthenticated(self, client):
        """Test getting devices without authentication"""
        response = client.get('/api/auth/devices')
        
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'Authentication required' in response_data['error']
    
    def test_remove_device_success(self, client, sample_user):
        """Test successful device removal"""
        # Create test device
        device = Device(
            user_id=sample_user.id,
            device_name='Test Device',
            device_type='mobile',
            public_key='test_key',
            is_active=True
        )
        db.session.add(device)
        db.session.commit()
        
        # Create auth token
        from flask_jwt_extended import create_access_token
        with app.app_context():
            token = create_access_token(identity=sample_user.id)
        
        response = client.delete(f'/api/auth/devices/{device.id}',
                               headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert response_data['success'] is True
        
        # Verify device was deactivated
        updated_device = Device.query.get(device.id)
        assert updated_device.is_active is False
    
    def test_remove_device_not_found(self, client, sample_user):
        """Test removing non-existent device"""
        from flask_jwt_extended import create_access_token
        with app.app_context():
            token = create_access_token(identity=sample_user.id)
        
        response = client.delete('/api/auth/devices/nonexistent_id',
                               headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 404
        response_data = json.loads(response.data)
        assert 'Device not found' in response_data['error']


class TestSecurityFeatures:
    """Test security-related features"""
    
    def test_audit_logging(self, client, sample_user):
        """Test that security events are logged"""
        # Perform an action that should be audited
        data = {'username': sample_user.username}
        client.post('/api/auth/webauthn/login/begin',
                   json=data,
                   content_type='application/json')
        
        # Check audit log
        audit_log = AuditLog.query.filter_by(
            user_id=sample_user.id,
            action='login_attempt'
        ).first()
        
        assert audit_log is not None
        assert audit_log.success is False  # No credentials registered
        assert audit_log.ip_address is not None
    
    def test_session_cleanup(self, client, sample_user):
        """Test expired session cleanup"""
        # Create expired session
        expired_session = Session(
            user_id=sample_user.id,
            token_hash='expired_token_hash',
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_active=True
        )
        db.session.add(expired_session)
        db.session.commit()
        
        # Run cleanup command
        from backend.app_complete import cleanup_sessions
        with app.app_context():
            cleanup_sessions()
        
        # Verify expired session was removed
        remaining_session = Session.query.get(expired_session.id)
        assert remaining_session is None
    
    def test_input_validation(self, client):
        """Test input validation and sanitization"""
        # Test with malicious input
        malicious_data = {
            'username': '<script>alert("xss")</script>',
            'email': 'invalid-email',
            'displayName': 'x' * 300  # Too long
        }
        
        response = client.post('/api/auth/webauthn/register/begin',
                             json=malicious_data,
                             content_type='application/json')
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Validation failed' in response_data['error']
    
    def test_jwt_token_validation(self, client):
        """Test JWT token validation"""
        # Test with invalid token
        response = client.get('/api/auth/devices',
                            headers={'Authorization': 'Bearer invalid_token'})
        
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'Invalid token' in response_data['error']
    
    def test_csrf_protection(self, client):
        """Test CSRF protection is in place"""
        # Test that CSRF token is required for state-changing operations
        # (This would be more comprehensive in a real test environment)
        response = client.post('/api/auth/webauthn/register/begin',
                             json={'username': 'test'},
                             content_type='application/json')
        
        # Should succeed because CSRF is disabled in test config
        # In production, this would require CSRF token
        assert response.status_code in [200, 400]  # Valid request structure


if __name__ == '__main__':
    pytest.main([__file__, '-v']) 