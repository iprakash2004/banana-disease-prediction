"""
Script to examine the database contents in detail.
"""
import sys
import os
import sqlite3

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from user_model import db, User
from config import Config

def examine_database_detailed():
    """Examine the database in detail using direct SQLite connection."""
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'banana_disease.db')
    
    if not os.path.exists(db_path):
        print("❌ Database file not found!")
        return
    
    print(f"📁 Database file location: {db_path}")
    print(f"📊 Database file size: {os.path.getsize(db_path)} bytes")
    
    # Connect directly to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get table information
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print(f"\n📋 Tables in database:")
    for table in tables:
        print(f"  - {table[0]}")
    
    # Get schema for users table
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users';")
    schema = cursor.fetchone()
    if schema:
        print(f"\n📄 Users table schema:")
        print(f"  {schema[0]}")
    
    # Get user data
    cursor.execute("SELECT id, email, name, picture FROM users;")
    users = cursor.fetchall()
    print(f"\n👥 Users in database ({len(users)} total):")
    for user in users:
        print(f"  ID: {user[0]}")
        print(f"  Email: {user[1]}")
        print(f"  Name: {user[2]}")
        print(f"  Picture: {user[3][:50]}{'...' if len(user[3]) > 50 else ''}")
        print(f"  ---")
    
    conn.close()

def examine_database_with_orm():
    """Examine the database using SQLAlchemy ORM."""
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    
    with app.app_context():
        user_count = User.query.count()
        print(f"\n📊 Current user count (via ORM): {user_count}")
        
        users = User.query.all()
        print(f"\n👥 Users in database (via ORM):")
        for user in users:
            print(f"  - {user.name} ({user.email}) - ID: {user.id}")

if __name__ == "__main__":
    print("🔍 Examining database contents...")
    examine_database_detailed()
    examine_database_with_orm()