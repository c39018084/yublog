"""
YuBlog - Complete Flask Application
Passwordless Secure Blogging Platform with WebAuthn and QR Authentication
"""

import os
import json
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import redis
from marshmallow import Schema, fields, validate, ValidationError
import bleach
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app with security configurations
app = Flask(__name__)

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
    
    # WebAuthn Configuration
    WEBAUTHN_RP_ID=os.environ.get('WEBAUTHN_RP_ID', 'localhost'),
    WEBAUTHN_RP_NAME=os.environ.get('WEBAUTHN_RP_NAME', 'YuBlog'),
    WEBAUTHN_ORIGIN=os.environ.get('WEBAUTHN_ORIGIN', 'https://localhost:3000'),
    
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

# Import required WebAuthn modules
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
    email = fields.Email(required=True)
    display_name = fields.Str(required=True, validate=validate.Length(min=1, max=255))

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

# Health Check and System Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check endpoint"""
    try:
        # Check database connection
        db.session.execute(db.text('SELECT 1'))
        
        # Check Redis connection
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'services': {
                'database': 'ok',
                'redis': 'ok'
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

@app.route('/api/info', methods=['GET'])
@limiter.limit("10 per minute")
def system_info():
    """Get public system information"""
    return jsonify({
        'name': 'YuBlog',
        'description': 'Passwordless Secure Blogging Platform',
        'version': '1.0.0',
        'authentication': ['webauthn', 'qr_code'],
        'features': [
            'passwordless_auth',
            'yubikey_support',
            'qr_authentication',
            'secure_blogging',
            'self_hosted'
        ]
    })

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get current user's profile information"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'displayName': user.display_name,
                'createdAt': user.created_at.isoformat(),
                'isActive': user.is_active
            }
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch profile'}), 500

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
@limiter.limit("5 per hour")
def update_user_profile():
    """Update current user's profile information"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Validate display name
        if 'displayName' in data:
            if not data['displayName'] or len(data['displayName']) > 255:
                return jsonify({'error': 'Invalid display name'}), 400
            user.display_name = data['displayName']
        
        # Email updates require additional verification in a real system
        if 'email' in data:
            if not validate.Email()(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            
            # Check if email is already taken
            existing_user = User.query.filter(
                User.email == data['email'],
                User.id != user.id
            ).first()
            
            if existing_user:
                return jsonify({'error': 'Email already in use'}), 400
            
            user.email = data['email']
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_audit_event(user_id, 'update_profile', True)
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'displayName': user.display_name,
                'updatedAt': user.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(get_jwt_identity(), 'update_profile', False,
                      details={'error': str(e)})
        return jsonify({'error': 'Failed to update profile'}), 500

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    log_audit_event(None, 'rate_limit_exceeded', False,
                  details={'limit': str(error.description)})
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authentication required'}), 401

# WebAuthn Registration Routes
@app.route('/api/auth/webauthn/register/begin', methods=['POST'])
@limiter.limit("5 per minute")
def webauthn_register_begin():
    """Begin WebAuthn registration process"""
    try:
        data = request.get_json()
        schema = UserRegistrationSchema()
        
        try:
            validated_data = schema.load(data)
        except ValidationError as e:
            app.logger.error(f"Validation error in registration: {e.messages}")
            return jsonify({'error': 'Invalid input data', 'details': e.messages}), 400
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == validated_data['username']) | 
            (User.email == validated_data['email'])
        ).first()
        
        if existing_user:
            app.logger.warning(f"User already exists: {validated_data['username']} or {validated_data['email']}")
            return jsonify({'error': 'User already exists'}), 409
        
        # Generate WebAuthn registration options
        user_id = secrets.token_urlsafe(32)
        
        app.logger.info(f"Generating WebAuthn options for user: {validated_data['username']}")
        
        options = generate_registration_options(
            rp_id=app.config['WEBAUTHN_RP_ID'],
            rp_name=app.config['WEBAUTHN_RP_NAME'],
            user_id=user_id,  # Remove .encode() - user_id is already a string
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
        
        # Store registration data in Redis temporarily
        registration_data = {
            'user_id': user_id,
            'username': validated_data['username'],
            'email': validated_data['email'],
            'display_name': validated_data['display_name'],
            'challenge': base64.b64encode(options.challenge).decode()
        }
        
        challenge_key = f"webauthn_reg_challenge:{user_id}"
        redis_client.setex(challenge_key, 300, json.dumps(registration_data))  # 5 minutes
        
        app.logger.info(f"Registration challenge stored for user: {validated_data['username']}")
        
        return jsonify({
            'challenge': base64.b64encode(options.challenge).decode(),
            'rp': {
                'name': app.config['WEBAUTHN_RP_NAME'],
                'id': app.config['WEBAUTHN_RP_ID']
            },
            'user': {
                'id': user_id,
                'name': validated_data['username'],
                'displayName': validated_data['display_name']
            },
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},  # ES256
                {'type': 'public-key', 'alg': -257}  # RS256
            ],
            'timeout': options.timeout,
            'attestation': options.attestation.value,
            'authenticatorSelection': {
                'authenticatorAttachment': 'platform',
                'userVerification': 'required'
            }
        })
        
    except Exception as e:
        app.logger.error(f"Detailed error in webauthn_register_begin: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

@app.route('/api/auth/webauthn/register/complete', methods=['POST'])
@limiter.limit("5 per minute")
def webauthn_register_complete():
    """Complete WebAuthn registration process"""
    try:
        data = request.get_json()
        
        # Extract user ID from credential response
        user_id_from_response = data.get('response', {}).get('clientDataJSON', '')
        if user_id_from_response:
            client_data = json.loads(base64.b64decode(user_id_from_response))
            # Get the user ID from the challenge data stored in Redis
            # We'll need to find it by checking all stored challenges
            
        # For now, let's try to find the challenge by searching Redis keys
        # This is a simplified approach - in production you'd want better key management
        stored_data = None
        challenge_data = None
        
        # Try to find the matching challenge in Redis
        for key in redis_client.scan_iter(match="webauthn_challenge:*"):
            try:
                stored_data = redis_client.get(key)
                if stored_data:
                    challenge_data = json.loads(stored_data)
                    break
            except:
                continue
        
        if not stored_data or not challenge_data:
            log_audit_event(None, 'register_credential', False, 
                          details={'error': 'Invalid or expired challenge'})
            return jsonify({'error': 'Invalid or expired challenge'}), 400
        
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
        redis_client.delete(key)
        
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

# Import route modules after app initialization
try:
    from auth_routes import *  # Authentication routes
    from blog_routes import *  # Blog CRUD routes
    print("✓ All route modules loaded successfully")
except ImportError as e:
    print(f"Warning: Could not import route modules: {e}")

# Session cleanup task
@app.cli.command()
def cleanup_sessions():
    """CLI command to clean up expired sessions"""
    try:
        expired_sessions = Session.query.filter(
            Session.expires_at < datetime.utcnow()
        ).delete()
        
        expired_qr_sessions = QRSession.query.filter(
            QRSession.expires_at < datetime.utcnow()
        ).delete()
        
        db.session.commit()
        
        print(f"Cleaned up {expired_sessions} expired sessions and {expired_qr_sessions} QR sessions")
        
    except Exception as e:
        print(f"Error cleaning up sessions: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✓ Database tables created/verified")
        print("✓ YuBlog backend server starting...")
        print(f"✓ WebAuthn RP ID: {app.config['WEBAUTHN_RP_ID']}")
        print(f"✓ WebAuthn Origin: {app.config['WEBAUTHN_ORIGIN']}")
    
    app.run(
        debug=os.environ.get('FLASK_ENV') == 'development',
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000))
    ) 