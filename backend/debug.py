#!/usr/bin/env python3
"""Debug script to test WebAuthn registration step by step"""

import sys
import traceback
import json

def test_components():
    """Test each component individually"""
    try:
        print("Testing app imports...")
        from app import app, db, redis_client
        print("✅ App imports successful")
        
        print("Testing database connection...")
        with app.app_context():
            from sqlalchemy import text
            db.session.execute(text('SELECT 1'))
            print("✅ Database connection works")
        
        print("Testing Redis connection...")
        redis_client.ping()
        print("✅ Redis connection works")
        
        print("Testing WebAuthn imports...")
        from webauthn import generate_registration_options
        from webauthn.helpers.cose import COSEAlgorithmIdentifier
        from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement
        print("✅ WebAuthn imports work")
        
        print("Testing registration logic...")
        with app.app_context():
            # Test user validation
            from app import UserRegistrationSchema
            schema = UserRegistrationSchema()
            validated_data = schema.load({"username": "testuser"})
            print(f"✅ User validation works: {validated_data}")
            
            # Test WebAuthn option generation
            import uuid
            user_id = str(uuid.uuid4())
            print(f"✅ UUID generation works: {user_id}")
            
            options = generate_registration_options(
                rp_id=app.config['WEBAUTHN_RP_ID'],
                rp_name=app.config['WEBAUTHN_RP_NAME'],
                user_id=user_id,
                user_name=validated_data['username'],
                user_display_name=validated_data.get('display_name', validated_data['username']),
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier.ECDSA_SHA_256,
                    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                ],
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.REQUIRED
                ),
            )
            print("✅ WebAuthn options generation works")
            
            # Test Redis storage
            import base64
            challenge_key = f"webauthn_challenge:{user_id}"
            redis_client.setex(
                challenge_key, 
                300,
                json.dumps({
                    'challenge': base64.b64encode(options.challenge).decode(),
                    'user_data': validated_data
                })
            )
            print("✅ Redis storage works")
            
            print("🎉 All components work individually!")
            
    except Exception as e:
        print(f"❌ Error in {sys.exc_info()[2].tb_frame.f_code.co_name}: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_components() 