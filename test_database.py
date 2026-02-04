"""
Test script to verify database integration.
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app import app, db
from user_model import User

def test_database():
    """Test database operations."""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database initialized successfully!")
        
        # Test creating a user
        test_user = User(
            id="test123",
            email="test@example.com",
            name="Test User",
            picture="https://example.com/picture.jpg"
        )
        
        # Add user to database
        db.session.add(test_user)
        db.session.commit()
        print("User created successfully!")
        
        # Test retrieving a user
        retrieved_user = User.query.get("test123")
        if retrieved_user:
            print(f"User retrieved: {retrieved_user.name} ({retrieved_user.email})")
        else:
            print("Failed to retrieve user")
        
        # Test getting user by email
        user_by_email = User.query.filter_by(email="test@example.com").first()
        if user_by_email:
            print(f"User found by email: {user_by_email.name}")
        else:
            print("Failed to find user by email")

if __name__ == "__main__":
    test_database()