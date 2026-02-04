"""
Script to check the current database status.
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from user_model import db, User
from config import Config

def create_app():
    """Create and configure the Flask app."""
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app

def check_database():
    """Check the current database status."""
    app = create_app()
    
    with app.app_context():
        # Show some info about the database
        user_count = User.query.count()
        print(f"📊 Current user count in database: {user_count}")
        
        # Show all users
        users = User.query.all()
        print("\n👥 Users in database:")
        for user in users:
            print(f"  - {user.name} ({user.email}) - ID: {user.id}")

if __name__ == "__main__":
    check_database()