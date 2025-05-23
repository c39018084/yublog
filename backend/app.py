"""
YuBlog - Secure Passwordless Blogging Platform
Main Flask Application with WebAuthn and QR Code Authentication
"""

import os
import json
import base64
import hashlib
import secrets
import hmac
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from io import BytesIO

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import redis
import qrcode
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import bleach
from marshmallow import Schema, fields, validate, ValidationError
from sqlalchemy import text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app with security configurations
app = Flask(__name__)

# Enable debug mode for better error messages
app.config['DEBUG'] = True

# Security Configuration
app.config.update(
    # Database
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'postgresql://yublog:password@localhost/yublog'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {'sslmode': 'prefer'}
    },
    
    # JWT Configuration
    JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY', secrets.token_urlsafe(32)),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
    JWT_ALGORITHM='HS256',
    
    # Session Security
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_urlsafe(32)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    
    # Security Headers
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=None,
    
    # WebAuthn Configuration
    WEBAUTHN_RP_ID=os.environ.get('WEBAUTHN_RP_ID', 'localhost'),
    WEBAUTHN_RP_NAME=os.environ.get('WEBAUTHN_RP_NAME', 'YuBlog'),
    WEBAUTHN_ORIGIN=os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:3000'),
    
    # Redis Configuration
    REDIS_URL=os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
redis_client = redis.from_url(app.config['REDIS_URL'])

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],
    storage_uri=app.config['REDIS_URL']
)

# CORS Configuration
CORS(app, 
     origins=[app.config['WEBAUTHN_ORIGIN']],
     supports_credentials=True)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')
    devices = db.relationship('Device', backref='user', lazy=True, cascade='all, delete-orphan')
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    sessions = db.relationship('Session', backref='user', lazy=True, cascade='all, delete-orphan')

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.Text, unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    counter = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    device_name = db.Column(db.String(255))
    aaguid = db.Column(db.Text)

class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    device_name = db.Column(db.String(255), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    push_token = db.Column(db.Text)
    last_used = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    device_fingerprint = db.Column(db.Text)

class Post(db.Model):
    __tablename__ = 'posts'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(500), nullable=False)
    slug = db.Column(db.String(500), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.Text)
    author_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    published = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    token_hash = db.Column(db.String(255), unique=True, nullable=False)
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'))
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)

class QRSession(db.Model):
    __tablename__ = 'qr_sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    challenge = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(36))
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    success = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Input Validation Schemas
class UserRegistrationSchema(Schema):
    username = fields.Str(required=True, validate=validate.Regexp(r'^[A-Za-z0-9_-]{3,50}$'))
    email = fields.Email(required=False, missing=None)
    display_name = fields.Str(required=False, missing=None, validate=validate.Length(min=1, max=255))

class PostSchema(Schema):
    title = fields.Str(required=True, validate=validate.Length(max=500))
    content = fields.Str(required=True, validate=validate.Length(max=50000))
    published = fields.Bool(missing=False)
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])
    
    def load(self, json_data, *args, **kwargs):
        data = super().load(json_data, *args, **kwargs)
        # Sanitize HTML content
        allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre']
        allowed_attributes = {'a': ['href'], 'img': ['src', 'alt']}
        data['content'] = bleach.clean(data['content'], tags=allowed_tags, attributes=allowed_attributes)
        return data

# Utility Functions
def log_audit_event(user_id: Optional[str], action: str, success: bool, **kwargs):
    """Log security audit events"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        success=success,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        **kwargs
    )
    db.session.add(audit_log)
    db.session.commit()

def generate_slug(title: str) -> str:
    """Generate URL-safe slug from title"""
    import re
    slug = re.sub(r'[^\w\s-]', '', title.lower())
    slug = re.sub(r'[-\s]+', '-', slug)
    return slug.strip('-')

def hash_token(token: str) -> str:
    """Hash token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()

# Security Headers Middleware
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self' wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response

# WebAuthn Registration Routes
@app.route('/api/auth/webauthn/register/begin', methods=['POST'])
@limiter.limit("5 per minute")
def webauthn_register_begin():
    """Begin WebAuthn registration process"""
    try:
        data = request.get_json()
        schema = UserRegistrationSchema()
        validated_data = schema.load(data)
        
        # Provide defaults for optional fields
        if not validated_data.get('email'):
            validated_data['email'] = f"{validated_data['username']}@yublog.local"
        if not validated_data.get('display_name'):
            validated_data['display_name'] = validated_data['username']
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == validated_data['username']) | 
            (User.email == validated_data['email'])
        ).first()
        
        if existing_user:
            log_audit_event(None, 'register_credential', False, 
                          details={'error': 'User already exists'})
            return jsonify({'error': 'User already exists'}), 400
        
        # Generate WebAuthn registration options
        user_id = str(uuid.uuid4())
        
        options = generate_registration_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            rp_name=app.config['WEBAUTHN_RP_NAME'],
            user_id=user_id,
            user_name=validated_data['username'],
            user_display_name=validated_data['display_name'],
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
        )
        
        # Store challenge in Redis with 5-minute expiration
        challenge_key = f"webauthn_challenge:{user_id}"
        redis_client.setex(
            challenge_key, 
            300,  # 5 minutes
            json.dumps({
                'challenge': base64.b64encode(options.challenge).decode(),
                'user_data': validated_data
            })
        )
        
        return jsonify({
            'challenge': base64.b64encode(options.challenge).decode(),
            'rp': {'name': options.rp.name, 'id': options.rp.id},
            'user': {
                'id': base64.b64encode(options.user.id).decode(),
                'name': options.user.name,
                'displayName': options.user.display_name
            },
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': alg.alg}
                for alg in options.pub_key_cred_params
            ],
            'timeout': options.timeout,
            'attestation': options.attestation.value,
            'authenticatorSelection': {
                'userVerification': options.authenticator_selection.user_verification.value
            },
            'excludeCredentials': []
        })
        
    except ValidationError as e:
        log_audit_event(None, 'register_credential', False, 
                      details={'validation_errors': e.messages})
        return jsonify({'error': 'Validation failed', 'details': e.messages}), 400
    except Exception as e:
        import traceback
        error_details = str(e)
        if app.config.get('DEBUG'):
            error_details = traceback.format_exc()
        
        log_audit_event(None, 'register_credential', False, 
                      details={'error': str(e), 'traceback': error_details})
        return jsonify({'error': 'Registration failed', 'details': error_details if app.config.get('DEBUG') else str(e)}), 500

@app.route('/api/auth/webauthn/register/complete', methods=['POST'])
@limiter.limit("5 per minute")
def webauthn_register_complete():
    """Complete WebAuthn registration process"""
    try:
        data = request.get_json()
        
        # Get the user ID from the credential response
        user_id_b64 = data.get('response', {}).get('userHandle') or data.get('user', {}).get('id')
        if not user_id_b64:
            return jsonify({'error': 'Missing user ID in response'}), 400
        
        # Get challenge from Redis using the user ID from the request
        challenge_key = f"webauthn_challenge:{base64.b64decode(user_id_b64).decode('utf-8')}"
        stored_data = redis_client.get(challenge_key)
        
        if not stored_data:
            log_audit_event(None, 'register_credential', False, 
                          details={'error': 'Invalid or expired challenge'})
            return jsonify({'error': 'Invalid or expired challenge'}), 400
        
        challenge_data = json.loads(stored_data)
        challenge = base64.b64decode(challenge_data['challenge'])
        user_data = challenge_data['user_data']
        
        # Verify registration response
        credential = RegistrationCredential.parse_raw(json.dumps(data))
        
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=app.config['WEBAUTHN_ORIGIN'],
            expected_rp_id=app.config['WEBAUTHN_RP_ID'],
        )
        
        if not verification.verified:
            log_audit_event(None, 'register_credential', False, 
                          details={'error': 'WebAuthn verification failed'})
            return jsonify({'error': 'Registration verification failed'}), 400
        
        # Create user and store credential
        user = User(
            username=user_data['username'],
            email=user_data['email'],
            display_name=user_data['display_name']
        )
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        credential_record = Credential(
            user_id=user.id,
            credential_id=base64.b64encode(verification.credential_id).decode(),
            public_key=base64.b64encode(verification.credential_public_key).decode(),
            counter=verification.sign_count,
            device_name=data.get('deviceName', 'Unknown Device'),
            aaguid=str(verification.aaguid) if verification.aaguid else None
        )
        db.session.add(credential_record)
        db.session.commit()
        
        # Clean up challenge
        redis_client.delete(challenge_key)
        
        log_audit_event(user.id, 'register_credential', True,
                      resource_type='credential', resource_id=credential_record.id)
        
        return jsonify({
            'success': True,
            'message': 'YubiKey registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'displayName': user.display_name
            }
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(None, 'register_credential', False, 
                      details={'error': str(e)})
        return jsonify({'error': 'Registration failed'}), 500

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
            'rp_id': options.rp_id,
            'allowCredentials': [
                {
                    'type': 'public-key',
                    'id': base64.b64encode(base64.b64decode(cred.credential_id)).decode()
                }
                for cred in credentials
            ],
            'userVerification': 'required',
            'timeout': options.timeout
        })
        
    except Exception as e:
        log_audit_event(None, 'login_attempt', False, 
                      details={'error': str(e)})
        return jsonify({'error': 'Authentication initialization failed'}), 500

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

# Health Check Endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for Docker containers"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        
        # Test Redis connection
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {
                'database': 'connected',
                'redis': 'connected'
            }
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

# Continue with authentication routes...
# [This is part 1 of the Flask app - I'll continue with more routes in the next section]

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_ENV') == 'development', host='0.0.0.0', port=5000) 