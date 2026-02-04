#!/usr/bin/env python3
"""
Simplified Flask application with Google OAuth login only
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from dotenv import load_dotenv

# Google OAuth2 imports
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests

# Flask-Login imports
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

# Load environment variables
load_dotenv()

class User(UserMixin):
    def __init__(self, id, email, name, picture):
        self.id = id
        self.email = email
        self.name = name
        self.picture = picture
        
    def get_id(self):
        return self.id

# Simple in-memory user storage
users = {}

def get_user(user_id):
    return users.get(user_id)

def create_user(user_info):
    user = User(
        id=user_info['id'],
        email=user_info['email'],
        name=user_info['name'],
        picture=user_info.get('picture', '')
    )
    users[user_info['id']] = user
    return user

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'banana-disease-detection-super-secret-key-2025-change-in-production'

# Google OAuth2 Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID') or 'your-google-client-id'
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET') or 'your-google-client-secret'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

@app.route('/')
def home():
    """Home page route"""
    return '<h1>Simple OAuth Test</h1><p><a href="/login">Login with Google</a></p>'

@app.route('/login')
def login():
    """Login page route"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return '<h1>Login</h1><p><a href="/auth/google">Sign in with Google</a></p>'

@app.route('/auth/google')
def google_auth():
    """Initiate Google OAuth2 authentication"""
    try:
        # Use a fixed redirect URI that matches the app's actual port
        redirect_uri = "http://127.0.0.1:8000/auth/google/callback"
        
        # Create a fresh flow for each request
        fresh_flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri]
                }
            },
            scopes=["https://www.googleapis.com/auth/userinfo.profile", 
                   "https://www.googleapis.com/auth/userinfo.email", 
                   "openid"]
        )
        fresh_flow.redirect_uri = redirect_uri
        
        authorization_url, state = fresh_flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        # Make session permanent for OAuth flow
        session.permanent = True
        session['state'] = state
        
        return redirect(authorization_url)
        
    except Exception as e:
        print(f"Error initiating Google auth: {e}")
        flash('Authentication setup failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/auth/google/callback')
def google_auth_callback():
    """Handle Google OAuth2 callback"""
    try:
        # Check state parameter
        if 'state' not in session:
            flash('Authentication failed. Please try again.', 'error')
            return redirect(url_for('login'))
        
        request_state = request.args.get('state')
        session_state = session.get('state')
        
        if session_state != request_state:
            flash('Authentication failed. Please try again.', 'error')
            return redirect(url_for('login'))
        
        # Recreate flow from stored config
        redirect_uri = "http://127.0.0.1:8000/auth/google/callback"
        
        callback_flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri]
                }
            },
            scopes=["https://www.googleapis.com/auth/userinfo.profile", 
                   "https://www.googleapis.com/auth/userinfo.email", 
                   "openid"]
        )
        callback_flow.redirect_uri = redirect_uri
        
        # Fetch token
        callback_flow.fetch_token(authorization_response=request.url)
        
        credentials = callback_flow.credentials
        request_session = google_requests.Request()
        
        # Access the ID token correctly
        id_token_value = getattr(credentials, 'id_token', None)
        if not id_token_value:
            raise ValueError("Could not retrieve ID token from credentials")
        
        # Verify the token
        id_info = id_token.verify_oauth2_token(
            id_token=id_token_value,
            request=request_session,
            audience=GOOGLE_CLIENT_ID
        )
        
        # Extract user information
        user_info = {
            'id': id_info.get('sub'),
            'email': id_info.get('email'),
            'name': id_info.get('name'),
            'picture': id_info.get('picture')
        }
        
        # Get or create user
        user = get_user(user_info['id'])
        if not user:
            user = create_user(user_info)
        
        # Login the user
        login_user(user)
        
        # Clean up session
        session.pop('state', None)
        
        flash(f'Welcome {user.name}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Google auth callback error: {e}")
        session.pop('state', None)
        flash('Authentication failed. Please check your Google credentials and try again.', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard after login"""
    return f'<h1>Dashboard</h1><p>Welcome {current_user.name}!</p><p><a href="/logout">Logout</a></p>'

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("Starting Simple OAuth Test App...")
    print(f"Google Client ID: {GOOGLE_CLIENT_ID[:20]}...")
    app.run(debug=True, host='127.0.0.1', port=8000)