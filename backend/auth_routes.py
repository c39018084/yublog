"""
Additional Authentication Routes for YuBlog
WebAuthn Login, QR Code Authentication, and Device Management
"""

import base64
import json
import secrets
from datetime import datetime, timedelta
from io import BytesIO

from flask import request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import AuthenticationCredential, PublicKeyCredentialDescriptor
import qrcode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from app import app, db, redis_client, limiter, log_audit_event
from app import User, Credential, Device, Session, QRSession, hash_token

# WebAuthn Authentication Routes
@app.route('/api/auth/webauthn/login/begin', methods=['POST'])
@limiter.limit("10 per minute")
def webauthn_login_begin():
    """Begin WebAuthn authentication process"""
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({'error': 'Username required'}), 400
        
        # Find user and their credentials
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not user.is_active:
            log_audit_event(None, 'login_attempt', False, 
                          details={'username': username, 'error': 'User not found'})
            return jsonify({'error': 'Invalid username'}), 400
        
        # Get user's credentials
        credentials = Credential.query.filter_by(user_id=user.id).all()
        
        if not credentials:
            log_audit_event(user.id, 'login_attempt', False, 
                          details={'error': 'No credentials registered'})
            return jsonify({'error': 'No credentials registered for this user'}), 400
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64.b64decode(cred.credential_id)
                )
                for cred in credentials
            ],
        )
        
        # Store challenge in Redis
        challenge_key = f"webauthn_auth_challenge:{user.id}"
        redis_client.setex(
            challenge_key,
            300,  # 5 minutes
            base64.b64encode(options.challenge).decode()
        )
        
        return jsonify({
            'challenge': base64.b64encode(options.challenge).decode(),
            'rpId': app.config['WEBAUTHN_RP_ID'],
            'allowCredentials': [
                {
                    'type': 'public-key',
                    'id': cred.credential_id
                }
                for cred in credentials
            ],
            'timeout': options.timeout,
            'userVerification': options.user_verification.value
        })
        
    except Exception as e:
        log_audit_event(None, 'login_attempt', False, 
                      details={'error': str(e)})
        return jsonify({'error': 'Login initialization failed'}), 500

@app.route('/api/auth/webauthn/login/complete', methods=['POST'])
@limiter.limit("10 per minute")
def webauthn_login_complete():
    """Complete WebAuthn authentication process"""
    try:
        data = request.get_json()
        
        # Find credential
        credential_id = data.get('id')
        credential_record = Credential.query.filter_by(credential_id=credential_id).first()
        
        if not credential_record:
            log_audit_event(None, 'login_attempt', False, 
                          details={'error': 'Credential not found'})
            return jsonify({'error': 'Invalid credential'}), 400
        
        user = credential_record.user
        
        # Get stored challenge
        challenge_key = f"webauthn_auth_challenge:{user.id}"
        stored_challenge = redis_client.get(challenge_key)
        
        if not stored_challenge:
            log_audit_event(user.id, 'login_attempt', False, 
                          details={'error': 'Invalid or expired challenge'})
            return jsonify({'error': 'Invalid or expired challenge'}), 400
        
        challenge = base64.b64decode(stored_challenge)
        
        # Verify authentication response
        credential = AuthenticationCredential.parse_raw(json.dumps(data))
        
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=app.config['WEBAUTHN_ORIGIN'],
            expected_rp_id=app.config['WEBAUTHN_RP_ID'],
            credential_public_key=base64.b64decode(credential_record.public_key),
            credential_current_sign_count=credential_record.counter,
        )
        
        if not verification.verified:
            log_audit_event(user.id, 'login_attempt', False, 
                          details={'error': 'WebAuthn verification failed'})
            return jsonify({'error': 'Authentication verification failed'}), 400
        
        # Update credential counter and last used
        credential_record.counter = verification.new_sign_count
        credential_record.last_used = datetime.utcnow()
        
        # Create JWT token
        access_token = create_access_token(
            identity=user.id,
            expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
        )
        
        # Create session record
        session_record = Session(
            user_id=user.id,
            token_hash=hash_token(access_token),
            expires_at=datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(session_record)
        db.session.commit()
        
        # Clean up challenge
        redis_client.delete(challenge_key)
        
        log_audit_event(user.id, 'login_success', True,
                      resource_type='session', resource_id=session_record.id)
        
        return jsonify({
            'success': True,
            'token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'displayName': user.display_name,
                'email': user.email
            }
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(None, 'login_attempt', False, 
                      details={'error': str(e)})
        return jsonify({'error': 'Authentication failed'}), 500

# QR Code Authentication Routes
@app.route('/api/auth/qr/generate', methods=['POST'])
@limiter.limit("3 per minute")
def qr_generate():
    """Generate QR code for mobile device authentication"""
    try:
        # Generate unique session ID and challenge
        session_id = secrets.token_urlsafe(32)
        challenge = secrets.token_urlsafe(64)
        
        # Store QR session
        qr_session = QRSession(
            session_id=session_id,
            challenge=challenge,
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            ip_address=request.remote_addr
        )
        db.session.add(qr_session)
        db.session.commit()
        
        # Create QR code data
        qr_data = {
            'sessionId': session_id,
            'challenge': challenge,
            'origin': app.config['WEBAUTHN_ORIGIN'],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(json.dumps(qr_data))
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        # Convert to base64
        img_base64 = base64.b64encode(img_buffer.read()).decode()
        
        return jsonify({
            'qrCode': f'data:image/png;base64,{img_base64}',
            'sessionId': session_id,
            'expiresAt': qr_session.expires_at.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(None, 'qr_generate', False, details={'error': str(e)})
        return jsonify({'error': 'QR code generation failed'}), 500

@app.route('/api/auth/qr/verify', methods=['POST'])
@limiter.limit("10 per minute")
def qr_verify():
    """Verify QR code authentication from mobile device"""
    try:
        data = request.get_json()
        session_id = data.get('sessionId')
        device_signature = data.get('deviceSignature')
        device_id = data.get('deviceId')
        
        if not all([session_id, device_signature, device_id]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Find QR session
        qr_session = QRSession.query.filter_by(
            session_id=session_id,
            verified=False
        ).first()
        
        if not qr_session or qr_session.expires_at < datetime.utcnow():
            log_audit_event(None, 'qr_verify', False, 
                          details={'error': 'Invalid or expired QR session'})
            return jsonify({'error': 'Invalid or expired QR session'}), 400
        
        # Find registered device
        device = Device.query.filter_by(id=device_id, is_active=True).first()
        
        if not device:
            log_audit_event(None, 'qr_verify', False, 
                          details={'error': 'Device not found'})
            return jsonify({'error': 'Device not registered'}), 400
        
        # Verify device signature
        try:
            public_key = serialization.load_pem_public_key(
                device.public_key.encode(),
                backend=default_backend()
            )
            
            # Verify signature (challenge + sessionId)
            message = f"{qr_session.challenge}:{session_id}".encode()
            signature = base64.b64decode(device_signature)
            
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
        except Exception as e:
            log_audit_event(device.user_id, 'qr_verify', False, 
                          details={'error': 'Signature verification failed'})
            return jsonify({'error': 'Invalid device signature'}), 400
        
        # Mark QR session as verified
        qr_session.verified = True
        qr_session.user_id = device.user_id
        
        # Update device last used
        device.last_used = datetime.utcnow()
        
        # Create JWT token
        access_token = create_access_token(
            identity=device.user_id,
            expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
        )
        
        # Create session record
        session_record = Session(
            user_id=device.user_id,
            token_hash=hash_token(access_token),
            device_id=device.id,
            expires_at=datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(session_record)
        db.session.commit()
        
        log_audit_event(device.user_id, 'login_success', True,
                      resource_type='qr_session', resource_id=qr_session.id)
        
        return jsonify({
            'success': True,
            'token': access_token,
            'user': {
                'id': device.user.id,
                'username': device.user.username,
                'displayName': device.user.display_name,
                'email': device.user.email
            }
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(None, 'qr_verify', False, details={'error': str(e)})
        return jsonify({'error': 'QR verification failed'}), 500

@app.route('/api/auth/qr/status/<session_id>', methods=['GET'])
@limiter.limit("30 per minute")
def qr_status(session_id):
    """Check QR authentication status"""
    try:
        qr_session = QRSession.query.filter_by(session_id=session_id).first()
        
        if not qr_session:
            return jsonify({'verified': False, 'expired': True})
        
        if qr_session.expires_at < datetime.utcnow():
            return jsonify({'verified': False, 'expired': True})
        
        if qr_session.verified and qr_session.user_id:
            # Generate token for verified session
            access_token = create_access_token(
                identity=qr_session.user_id,
                expires_delta=app.config['JWT_ACCESS_TOKEN_EXPIRES']
            )
            
            user = User.query.get(qr_session.user_id)
            
            return jsonify({
                'verified': True,
                'expired': False,
                'token': access_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'displayName': user.display_name,
                    'email': user.email
                }
            })
        
        return jsonify({'verified': False, 'expired': False})
        
    except Exception as e:
        return jsonify({'verified': False, 'expired': True, 'error': str(e)})

# Device Management Routes
@app.route('/api/auth/devices', methods=['GET'])
@jwt_required()
def get_devices():
    """Get user's registered devices"""
    try:
        user_id = get_jwt_identity()
        devices = Device.query.filter_by(user_id=user_id, is_active=True).all()
        
        return jsonify({
            'devices': [
                {
                    'id': device.id,
                    'name': device.device_name,
                    'type': device.device_type,
                    'lastUsed': device.last_used.isoformat() if device.last_used else None,
                    'registered': device.created_at.isoformat()
                }
                for device in devices
            ]
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch devices'}), 500

@app.route('/api/auth/devices/<device_id>', methods=['DELETE'])
@jwt_required()
@limiter.limit("10 per minute")
def remove_device(device_id):
    """Remove a registered device"""
    try:
        user_id = get_jwt_identity()
        device = Device.query.filter_by(id=device_id, user_id=user_id).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        device.is_active = False
        db.session.commit()
        
        log_audit_event(user_id, 'remove_device', True,
                      resource_type='device', resource_id=device_id)
        
        return jsonify({
            'success': True,
            'message': 'Device removed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'remove_device', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Failed to remove device'}), 500

@app.route('/api/auth/devices/register', methods=['POST'])
@jwt_required()
@limiter.limit("5 per minute")
def register_device():
    """Register a new device for QR authentication"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        device_name = data.get('deviceName')
        device_type = data.get('deviceType')
        public_key_pem = data.get('publicKey')
        device_fingerprint = data.get('deviceFingerprint')
        
        if not all([device_name, device_type, public_key_pem]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate device type
        if device_type not in ['mobile', 'tablet', 'desktop']:
            return jsonify({'error': 'Invalid device type'}), 400
        
        # Validate public key format
        try:
            serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
        except Exception:
            return jsonify({'error': 'Invalid public key format'}), 400
        
        # Create device record
        device = Device(
            user_id=user_id,
            device_name=device_name,
            device_type=device_type,
            public_key=public_key_pem,
            device_fingerprint=device_fingerprint
        )
        db.session.add(device)
        db.session.commit()
        
        log_audit_event(user_id, 'register_device', True,
                      resource_type='device', resource_id=device.id)
        
        return jsonify({
            'success': True,
            'device': {
                'id': device.id,
                'name': device.device_name,
                'type': device.device_type,
                'registered': device.created_at.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'register_device', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Device registration failed'}), 500

# Logout Route
@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user and invalidate session"""
    try:
        user_id = get_jwt_identity()
        
        # Get current token from header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            token_hash = hash_token(token)
            
            # Deactivate session
            session = Session.query.filter_by(
                user_id=user_id,
                token_hash=token_hash,
                is_active=True
            ).first()
            
            if session:
                session.is_active = False
                db.session.commit()
        
        log_audit_event(user_id, 'logout', True)
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        log_audit_event(get_jwt_identity(), 'logout', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Logout failed'}), 500 