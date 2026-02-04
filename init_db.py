"""
Database initialization script for the banana disease detection app.
Run this script to create the database tables.
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app import app, db
from user_model import User

def init_db():
    """Initialize the database and create tables."""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")

if __name__ == "__main__":
    init_db()