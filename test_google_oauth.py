#!/usr/bin/env python3
"""
Test script to verify Google OAuth configuration
"""
import os
import sys

# Add the flask directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from config import Config

def test_google_oauth_config():
    """Test if Google OAuth configuration is properly loaded"""
    print("🔍 Testing Google OAuth Configuration...")
    
    # Check if the config class can be instantiated
    config = Config()
    
    # Check Google Client ID
    client_id = config.GOOGLE_CLIENT_ID
    print(f"✅ Google Client ID: {client_id[:20]}..." if client_id and client_id != 'your-google-client-id' else "❌ Google Client ID not set")
    
    # Check Google Client Secret
    client_secret = config.GOOGLE_CLIENT_SECRET
    print(f"✅ Google Client Secret exists: {bool(client_secret and client_secret != 'your-google-client-secret')}")
    
    # Check Secret Key
    secret_key = config.SECRET_KEY
    print(f"✅ Flask Secret Key exists: {bool(secret_key)}")
    
    return bool(client_id and client_id != 'your-google-client-id' and 
                client_secret and client_secret != 'your-google-client-secret' and
                secret_key)

def test_redirect_uris():
    """Test if the redirect URIs are properly configured"""
    print("\n🔍 Testing Redirect URIs...")
    
    # These are the redirect URIs that should be configured in Google Cloud Console
    expected_uris = [
        "http://127.0.0.1:8000/auth/google/callback",
        "http://localhost:8000/auth/google/callback"
    ]
    
    print("Make sure these URIs are added to your Google Cloud Console OAuth 2.0 Client:")
    for uri in expected_uris:
        print(f"  - {uri}")
    
    return True

if __name__ == "__main__":
    success = test_google_oauth_config()
    test_redirect_uris()
    
    if success:
        print("\n✅ Google OAuth configuration test PASSED")
        print("💡 Next steps:")
        print("   1. Make sure the redirect URIs above are added to your Google Cloud Console")
        print("   2. Start your Flask app: python app.py")
        print("   3. Navigate to http://127.0.0.1:8000/login")
        print("   4. Click 'Sign in with Google'")
        sys.exit(0)
    else:
        print("\n❌ Google OAuth configuration test FAILED")
        sys.exit(1)