#!/usr/bin/env python3
"""
Flask application for banana disease detection with Google OAuth login
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
import base64
from io import BytesIO
from PIL import Image
import numpy as np
import json
import time

# TensorFlow imports with error handling for linter
try:
    from tensorflow.keras.models import load_model
    from tensorflow.keras.preprocessing import image as keras_image
except ImportError:
    # This should not happen since we verified TensorFlow is installed
    print("Error: TensorFlow imports failed despite TensorFlow being installed")
    load_model = None
    keras_image = None

# Google OAuth2 imports
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests

# Flask-Login imports
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

# Local imports
from config import Config
from user_model import User, get_user, create_user, db, get_user_by_email, create_analysis_result, AnalysisResult

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Ensure session configuration for OAuth
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on filesystem for persistence
app.permanent_session_lifetime = 1800  # 30 minutes

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Please log in to access this page.'

# Suppress the type error for login_view assignment
# This is a known issue with the type hints in Flask-Login
# https://github.com/maxcountryman/flask-login/issues/507

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

# Configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Google OAuth2 Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
GOOGLE_CLIENT_ID = app.config['GOOGLE_CLIENT_ID']
print(f"✅ Google Client ID loaded: {GOOGLE_CLIENT_ID[:20]}...")
print(f"✅ Google Client Secret loaded: {'Yes' if app.config['GOOGLE_CLIENT_SECRET'] else 'No'}")
client_secrets_file = os.path.join(os.path.dirname(__file__), 'client_secret.json')

# Note: We create OAuth2 flows dynamically in each route for better reliability

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# OAuth state management for development (to handle Flask restarts)
STATE_FILE = 'oauth_states.json'

def save_oauth_state(state, config):
    """Save OAuth state to file for persistence during development"""
    try:
        states = {}
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                states = json.load(f)
        
        # Clean old states (older than 10 minutes)
        current_time = time.time()
        states = {k: v for k, v in states.items() if current_time - v.get('timestamp', 0) < 600}
        
        states[state] = {
            'config': config,
            'timestamp': current_time
        }
        
        with open(STATE_FILE, 'w') as f:
            json.dump(states, f)
        print(f"🔄 Saved OAuth state: {state}")
    except Exception as e:
        print(f"⚠️ Could not save OAuth state: {e}")

def get_oauth_state(state):
    """Retrieve OAuth state from file"""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                states = json.load(f)
            
            if state in states:
                print(f"🔄 Retrieved OAuth state: {state}")
                return states[state]['config']
    except Exception as e:
        print(f"⚠️ Could not retrieve OAuth state: {e}")
    return None

# Model and dataset paths
MODEL_PATH = "D:/banana_disease_app/banana_disease_app/flask_api/model/best_hybrid_cnn_model.keras"
DATASET_PATH = r"D:/banana_disease_app/banana_disease_app/banana_disease_dataset_split/train"

# Load model and class names
try:
    # Check if load_model is not None before calling it
    if load_model is not None:
        model = load_model(MODEL_PATH)
        class_names = sorted(os.listdir(DATASET_PATH))
        print(f"✅ Model loaded successfully with {len(class_names)} classes")
    else:
        model = None
        class_names = []
        print("⚠️ Model loading skipped due to import issues")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None
    class_names = []

# Disease information dictionary
disease_info = {
    "potassium_deficiency": {
        "cause": "Lack of potassium in soil.",
        "effects": "Yellowing of leaf edges, weak stems, reduced fruit quality.",
        "remedies": ["Apply potassium-rich fertilizers.", "Mulch to retain soil moisture.", "Irrigate properly to improve nutrient uptake."],
        "medicines": [
            {"name": "Muriate of Potash", "use": "Fertilizer", "price": "₹500/kg", "buy_link": "https://www.amazon.in/muriate-of-potash/s?k=muriate+of+potash"},
            {"name": "Potassium Sulphate", "use": "Fertilizer", "price": "₹450/kg", "buy_link": "https://www.amazon.in/potassium-sulphate/s?k=potassium+sulphate"}
        ]
    },
    "_bacterial_softrot": {
        "cause": "Bacteria Erwinia spp. infects plant tissues.",
        "effects": "Softening and rotting of fruit and pseudostem.",
        "remedies": ["Remove and destroy infected plants.", "Avoid injuries during harvesting.", "Use copper-based bactericides."],
        "medicines": [{"name": "Copper Oxychloride", "use": "Bactericide", "price": "₹600/kg", "buy_link": "https://easy2agri.in/products/copper-oxychloride-50-wp"}]
    },
    "_banana_aphids": {
        "cause": "Infestation by Pentalonia nigronervosa aphids.",
        "effects": "Honeydew secretion, sooty mold, virus transmission.",
        "remedies": ["Spray neem oil or insecticidal soap.", "Remove heavily infested leaves.", "Encourage natural predators like ladybugs."],
        "medicines": [{"name": "Neem Oil", "use": "Insecticide", "price": "₹250/litre", "buy_link": "https://www.amazon.in/Ugaoo-Neem-Oil-Plants-Garden/dp/B09D3KLRJJ?th=1"}]
    },
    "_banana_fruit__scarring_beetle": {
        "cause": "Beetle infestation causing scars on fruits.",
        "effects": "Reduced fruit quality and market value.",
        "remedies": ["Remove and destroy infested fruits.", "Spray appropriate insecticides.", "Use pheromone traps."],
        "medicines": [{"name": "Imidacloprid", "use": "Insecticide", "price": "₹400/litre", "buy_link": "https://agribegri.com/products/buy-bayer-admire-imidacloprid-70-online--buy-admire-insecticide.php"}]
    },
    "_bhimkol": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_black_sigatoka": {
        "cause": "Fungal infection caused by Mycosphaerella fijiensis.",
        "effects": "Black streaks on leaves, reduced photosynthesis.",
        "remedies": ["Remove infected leaves.", "Spray fungicides regularly.", "Maintain proper spacing."],
        "medicines": [{"name": "Propiconazole", "use": "Fungicide", "price": "₹450/litre", "buy_link": "https://www.amazon.in/Adama-Bumper-Propiconazole-25-1Ltr/dp/B09RQPN3YH"}]
    },
    "_jahaji_fruit": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_jahaji_leaf": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_jahaji_stem": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_kachkol_fruit": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_malbhog_fruit": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_malbhog_leaf": {
        "cause": "",
        "effects": "",
        "remedies": [],
        "medicines": [],
        "is_type": True
    },
    "_panama_disease": {
        "cause": "Fungal infection caused by Fusarium oxysporum.",
        "effects": "Wilting of plants, yellowing leaves, root rot.",
        "remedies": ["Use resistant varieties.", "Remove infected plants.", "Soil treatment before planting."],
        "medicines": [{"name": "Soil Fungicide", "use": "Fungicide", "price": "₹300/kg", "buy_link": "https://www.flipkart.com/origin-proceed-bio-fungicide-soil/p/itm5abfaa26733f8"}]
    },
    "_pseudostem_weevil": {
        "cause": "Infestation by weevil on pseudostem.",
        "effects": "Stem damage, plant weakening, fruit loss.",
        "remedies": ["Remove infected pseudostems.", "Spray insecticides.", "Trap adult weevils."],
        "medicines": [{"name": "Fipronil", "use": "Insecticide", "price": "₹450/litre", "buy_link": "https://www.amazon.in/Bayer-Jump-Fipronil-80-Insecticide/dp/B08S59ZZMT"}]
    },
    "_yellow_sigatoka": {
        "cause": "Fungal infection caused by Mycosphaerella musicola.",
        "effects": "Yellow streaks on leaves, reduced photosynthesis.",
        "remedies": ["Remove affected leaves.", "Spray fungicides regularly.", "Ensure proper spacing and ventilation."],
        "medicines": [{"name": "Azoxystrobin", "use": "Fungicide", "price": "₹500/litre", "buy_link": "https://www.amazon.in/Adama-Custodia-Azoxystrobin-Tebuconazole-18-3/dp/B09RQK5921"}]
    }
}

# Define banana types
banana_types = ["_bhimkol", "_jahaji_fruit", "_jahaji_leaf", "_jahaji_stem", "_kachkol_fruit", "_malbhog_fruit", "_malbhog_leaf"]

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def process_image(image_path):
    """Process image for model prediction"""
    try:
        # Check if keras_image is not None before using it
        if keras_image is not None:
            img = keras_image.load_img(image_path, target_size=(224, 224))
            img_array = keras_image.img_to_array(img)
            img_array = np.expand_dims(img_array, axis=0)
            img_array = img_array / 255.0
            return img_array
        else:
            print("⚠️ Image processing skipped due to import issues")
            return None
    except Exception as e:
        print(f"Error processing image: {e}")
        return None

def predict_disease(image_path):
    """Make prediction on image"""
    if model is None:
        return None, "Model not loaded"
    
    img_array = process_image(image_path)
    if img_array is None:
        return None, "Image processing failed"
    
    try:
        predictions = model.predict(img_array)[0]
        results = list(zip(class_names, predictions * 100))
        results.sort(key=lambda x: x[1], reverse=True)
        return results, None
    except Exception as e:
        return None, f"Prediction failed: {str(e)}"

@app.route('/debug/config')
def debug_config():
    """Debug configuration - remove this route in production"""
    return {
        'client_id': app.config['GOOGLE_CLIENT_ID'][:20] + '...',
        'client_secret_exists': bool(app.config['GOOGLE_CLIENT_SECRET']),
        'redirect_uri': 'http://127.0.0.1:5000/auth/google/callback',
        'scopes': ['profile', 'email', 'openid'],
        'secret_key_set': bool(app.config['SECRET_KEY']),
        'secret_key_length': len(app.config['SECRET_KEY']) if app.config['SECRET_KEY'] else 0
    }

@app.route('/debug/test-oauth')
def test_oauth():
    """Test OAuth configuration without actual redirect"""
    try:
        # Test creating a flow without redirecting
        test_flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": app.config['GOOGLE_CLIENT_ID'],
                    "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://127.0.0.1:5000/auth/google/callback"]
                }
            },
            scopes=["https://www.googleapis.com/auth/userinfo.profile", 
                   "https://www.googleapis.com/auth/userinfo.email", 
                   "openid"]
        )
        test_flow.redirect_uri = "http://127.0.0.1:5000/auth/google/callback"
        
        # Try to generate auth URL
        auth_url, state = test_flow.authorization_url()
        
        return {
            "status": "success",
            "message": "OAuth configuration is valid",
            "auth_url_generated": bool(auth_url),
            "state_generated": bool(state),
            "client_id_valid": bool(app.config['GOOGLE_CLIENT_ID']),
            "client_secret_valid": bool(app.config['GOOGLE_CLIENT_SECRET'])
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "error_type": str(type(e))
        }

@app.route('/debug/simple-auth')
def simple_auth():
    """Simple OAuth test without session state"""
    try:
        # Create flow without session dependency
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": app.config['GOOGLE_CLIENT_ID'],
                    "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://127.0.0.1:5000/auth/google/callback"]
                }
            },
            scopes=["https://www.googleapis.com/auth/userinfo.profile", 
                   "https://www.googleapis.com/auth/userinfo.email", 
                   "openid"]
        )
        flow.redirect_uri = "http://127.0.0.1:5000/auth/google/callback"
        
        # Generate auth URL
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        return f'''
        <h2>OAuth Test</h2>
        <p><strong>Status:</strong> Configuration is working!</p>
        <p><strong>Generated State:</strong> {state}</p>
        <p><strong>Auth URL (first 100 chars):</strong> {auth_url[:100]}...</p>
        <p><a href="{auth_url}" target="_blank">Click here to test OAuth (opens in new tab)</a></p>
        <p><strong>Note:</strong> This will fail at callback since we're not storing state in session, but it tests if Google accepts our config.</p>
        '''
        
    except Exception as e:
        return f'''
        <h2>OAuth Test Failed</h2>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><strong>Error Type:</strong> {str(type(e))}</p>
        '''

@app.route('/')
def home():
    """Home page route"""
    return render_template('index.html')

@app.route('/login')
def login():
    """Login page route"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/auth/google')
def google_auth():
    """Initiate Google OAuth2 authentication"""
    try:
        print(f"🔍 Starting Google auth with Client ID: {app.config['GOOGLE_CLIENT_ID'][:20]}...")
        print(f"🔍 Client Secret exists: {bool(app.config['GOOGLE_CLIENT_SECRET'])}")
        
        # Use a fixed redirect URI that matches the app's actual port
        # The app runs on port 8000, so we should use that instead of 5000
        redirect_uri = "http://127.0.0.1:8000/auth/google/callback"
        
        print(f"🔍 Using redirect URI: {redirect_uri}")
        
        # Create a fresh flow for each request
        fresh_flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": app.config['GOOGLE_CLIENT_ID'],
                    "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
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
        
        print(f"🔍 Flow created successfully")
        
        authorization_url, state = fresh_flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        print(f"🔍 Authorization URL generated: {authorization_url[:100]}...")
        
        # Make session permanent for OAuth flow
        session.permanent = True
        session['state'] = state
        
        # Store OAuth config in session AND persistent file
        oauth_config = {
            "client_id": app.config['GOOGLE_CLIENT_ID'],
            "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
            "redirect_uri": redirect_uri
        }
        session['oauth_config'] = oauth_config
        
        # Also save to persistent storage for development
        save_oauth_state(state, oauth_config)
        
        print(f"✅ Generated auth URL with state: {state}")
        print(f"🔍 Session after storing state: {dict(session)}")
        
        return redirect(authorization_url)
        
    except Exception as e:
        print(f"❌ Error initiating Google auth: {e}")
        print(f"❌ Error type: {type(e)}")
        import traceback
        print(f"❌ Full traceback: {traceback.format_exc()}")
        flash('Authentication setup failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/auth/google/callback')
def google_auth_callback():
    """Handle Google OAuth2 callback"""
    try:
        # Debug session state
        print(f"🔍 Session contents: {dict(session)}")
        print(f"🔍 Request state: {request.args.get('state')}")
        print(f"🔍 Session state: {session.get('state')}")
        
        # Ensure we have a state to compare
        if 'state' not in session:
            print("❌ No state in session")
            flash('Authentication failed. Please try again.', 'error')
            return redirect(url_for('login'))
        
        # Check state parameter
        request_state = request.args.get('state')
        session_state = session.get('state')
        
        # Try to get OAuth config from session first, then from persistent storage
        oauth_config = session.get('oauth_config')
        if not oauth_config:
            oauth_config = get_oauth_state(request_state)
            print(f"🔄 Using persistent OAuth config for state: {request_state}")
        
        if not oauth_config:
            print("❌ No OAuth config found in session or persistent storage")
            flash('Authentication failed. Please try again.', 'error')
            return redirect(url_for('login'))
        
        # Check state - if session state doesn't match, try persistent storage
        if session_state != request_state:
            persistent_config = get_oauth_state(request_state)
            if persistent_config:
                print(f"🔄 State mismatch in session, but found in persistent storage")
                oauth_config = persistent_config
            else:
                print(f"❌ State mismatch - Session: {session_state}, Request: {request_state}")
                flash('Authentication failed. Please try again.', 'error')
                return redirect(url_for('login'))
        
        # Recreate flow from stored config
        # Ensure we use the correct redirect URI for the callback
        redirect_uri = "http://127.0.0.1:8000/auth/google/callback"
        
        callback_flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": oauth_config['client_id'],
                    "client_secret": oauth_config['client_secret'],
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
        
        # Fix: Access the ID token correctly from credentials
        # According to Google's documentation, we should use credentials.id_token directly
        id_token_value = getattr(credentials, 'id_token', None)
            
        if not id_token_value:
            raise ValueError("Could not retrieve ID token from credentials")
        
        # Verify the token with clock skew tolerance
        id_info = id_token.verify_oauth2_token(
            id_token=id_token_value,
            request=request_session,
            audience=GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10  # Allow 10 seconds clock skew
        )
        
        # Extract user information
        user_info = {
            'id': id_info.get('sub'),
            'email': id_info.get('email'),
            'name': id_info.get('name'),
            'picture': id_info.get('picture')
        }
        
        print(f"✅ User authenticated: {user_info['email']}")
        
        # Get or create user
        user = get_user(user_info['id'])
        if not user:
            user = create_user(user_info)
            print(f"✅ Created new user: {user_info['email']}")
        
        # Login the user
        login_user(user)
        
        # Clean up session and persistent state
        session.pop('state', None)
        session.pop('oauth_config', None)
        
        # Clean up persistent state file
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    states = json.load(f)
                states.pop(request_state, None)
                with open(STATE_FILE, 'w') as f:
                    json.dump(states, f)
        except Exception as e:
            print(f"⚠️ Could not clean up persistent state: {e}")
        
        flash(f'Welcome {user.name}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"❌ Google auth callback error: {e}")
        print(f"❌ Request URL: {request.url}")
        print(f"❌ Request args: {request.args}")
        print(f"❌ Session state: {session.get('state', 'None')}")
        
        # Clean up session on error
        session.pop('state', None)
        session.pop('oauth_config', None)
        
        # Also try to clean up persistent state
        try:
            request_state = request.args.get('state')
            if request_state and os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    states = json.load(f)
                states.pop(request_state, None)
                with open(STATE_FILE, 'w') as f:
                    json.dump(states, f)
        except Exception:
            pass
        
        flash('Authentication failed. Please check your Google credentials and try again.', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard after login"""
    # Get user's analysis history
    try:
        from user_model import get_user_analyses
        analyses = get_user_analyses(current_user.id)
    except Exception as e:
        print(f"⚠️ Failed to retrieve analysis history: {e}")
        analyses = []
    
    # Pass the current user and analyses to the template
    return render_template('dashboard.html', user=current_user, analyses=analyses)

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    """Handle prediction requests"""
    try:
        # Initialize variables
        image_path = None
        filename = None
        
        # Check for camera capture
        captured_data = request.form.get('captured_image')
        if captured_data:
            # Process base64 image
            try:
                header, encoded = captured_data.split(',', 1)
                img_data = base64.b64decode(encoded)
                img = Image.open(BytesIO(img_data))
                filename = 'captured_image.png'
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img.save(image_path)
                print(f"✅ Camera image saved: {filename}")
            except Exception as e:
                print(f"❌ Camera capture error: {e}")
                return render_template('error.html', error="Failed to process camera image")
        else:
            # Handle file upload
            if 'file' not in request.files:
                return redirect(request.url)
            
            file = request.files['file']
            if file.filename == '':
                return redirect(request.url)
            
            # Fix: Check if file.filename is not None before calling secure_filename
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_path)
                print(f"✅ File uploaded: {filename}")
            else:
                return render_template('error.html', error="Invalid file type")
        
        # Make prediction
        results, error = predict_disease(image_path)
        if error:
            print(f"❌ Prediction error: {error}")
            return render_template('error.html', error=error)
        
        # Fix: Check if results is not None before processing
        if results is None:
            return render_template('error.html', error="Prediction failed - no results returned")
        
        # Separate banana types and diseases
        type_results = [(name, percent) for name, percent in results if name in banana_types]
        disease_results = [(name, percent) for name, percent in results if name not in banana_types]
        
        # Calculate health score based only on diseases (not types)
        health_score = 100 - max([result[1] for result in disease_results]) if disease_results else 100
        
        # Get detailed diseases (>30% probability)
        detailed_diseases = []
        for disease, percentage in disease_results:
            if percentage >= 30:
                info = disease_info.get(disease, {})
                # Only include diseases with remedies (to exclude types)
                if not info.get("is_type", False):
                    detailed_diseases.append({
                        "name": disease,
                        "percent": round(percentage, 2),
                        "cause": info.get("cause", "Not available"),
                        "effects": info.get("effects", "Not available"),
                        "remedies": info.get("remedies", []),
                        "medicines": info.get("medicines", [])
                    })
        
        print(f"✅ Prediction completed for {filename}")
        
        # Save analysis result to database
        try:
            # Prepare data to save
            results_data = {
                'disease_results': disease_results[:5],  # Top 5 results
                'detailed_diseases': detailed_diseases,
                'type_results': type_results,
                'health_score': round(health_score, 1)
            }
            
            # Save to database
            create_analysis_result(
                user_id=current_user.id,
                image_filename=filename,
                health_score=round(health_score, 1),
                results_data=results_data
            )
            print(f"✅ Analysis result saved for user {current_user.id}")
        except Exception as e:
            print(f"⚠️ Failed to save analysis result: {e}")
        
        return render_template('result.html',
                             image=filename,
                             percentages=disease_results,  # Show only diseases in percentages
                             health_score=round(health_score, 1),
                             detailed_diseases=detailed_diseases,
                             type_results=type_results)  # Pass type results to template
    
    except Exception as e:
        print(f"❌ General error in predict route: {e}")
        return render_template('error.html', error=f"Prediction failed: {str(e)}")

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    print(f"❌ Internal Server Error: {error}")
    return render_template('error.html', error="Internal server error occurred"), 500

@app.errorhandler(413)
def too_large(error):
    """Handle file too large errors"""
    return render_template('error.html', error="File too large. Please upload a smaller image."), 413

if __name__ == '__main__':
    print("🍌 Starting Banana Disease Detection App...")
    print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"🤖 Model loaded: {'Yes' if model else 'No'}")
    print(f"📊 Classes available: {len(class_names)}")
    app.run(debug=True, host='0.0.0.0', port=8000)
