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
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        )
        
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        
    except ValidationError as e:
        log_audit_event(None, 'register_credential', False, 
                      details={'validation_errors': e.messages})
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        if not user_id_b64:
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(None, 'register_credential', False, 
                      details={'error': str(e)})
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        
        # Find user and their credentials
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not user.is_active:
            log_audit_event(None, 'login_attempt', False, 
                          details={'username': username, 'error': 'User not found'})
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        
    except Exception as e:
        log_audit_event(None, 'login_attempt', False, 
                      details={'error': str(e)})
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
        
    except Exception as e:
        db.session.rollback()
        log_audit_event(None, 'login_attempt', False, 
                      details={'error': str(e)})
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })
    except Exception as e:
        return jsonify({
            "challenge": base64.b64encode(options.challenge).decode(),
            "rp": {"name": options.rp.name, "id": options.rp.id},
            "user": {
                "id": base64.b64encode(options.user.id).decode(),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": alg.alg}
                for alg in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation.value,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification.value
            },
            "excludeCredentials": []
        })

# Continue with authentication routes...
# [This is part 1 of the Flask app - I'll continue with more routes in the next section]

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('FLASK_ENV') == 'development', host='0.0.0.0', port=5000) 