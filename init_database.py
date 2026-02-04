"""
Script to initialize the database for the banana disease detection app.
Run this script before starting the application for the first time.
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from user_model import db, User, AnalysisResult
from config import Config

def create_app():
    """Create and configure the Flask app."""
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app

def init_database():
    """Initialize the database and create tables."""
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created successfully!")
        print("📁 Database file location: flask/banana_disease.db")
        
        # Show some info about the database
        user_count = User.query.count()
        analysis_count = AnalysisResult.query.count()
        print(f"📊 Current user count: {user_count}")
        print(f"📊 Current analysis count: {analysis_count}")

if __name__ == "__main__":
    init_database()