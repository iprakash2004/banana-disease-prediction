from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

# Initialize SQLAlchemy
db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(100), primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    picture = db.Column(db.String(200), nullable=True)
    
    # Relationship to analysis results
    analyses = db.relationship('AnalysisResult', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, id, email, name, picture):
        self.id = id
        self.email = email
        self.name = name
        self.picture = picture
        
    def get_id(self):
        return self.id
        
    def __repr__(self):
        return f'<User {self.email}>'

class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('users.id'), nullable=False)
    image_filename = db.Column(db.String(200), nullable=False)
    health_score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Store detailed results as JSON
    results_data = db.Column(db.Text, nullable=True)
    
    def __init__(self, user_id, image_filename, health_score, results_data=None):
        self.user_id = user_id
        self.image_filename = image_filename
        self.health_score = health_score
        self.results_data = json.dumps(results_data) if isinstance(results_data, (dict, list)) else results_data
    
    def __repr__(self):
        return f'<AnalysisResult {self.id} for User {self.user_id}>'

def get_user(user_id):
    return User.query.get(user_id)

def create_user(user_info):
    user = User(
        id=user_info['id'],
        email=user_info['email'],
        name=user_info['name'],
        picture=user_info.get('picture', '')
    )
    db.session.add(user)
    db.session.commit()
    return user

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

def create_analysis_result(user_id, image_filename, health_score, results_data):
    """Create a new analysis result record"""
    analysis = AnalysisResult(
        user_id=user_id,
        image_filename=image_filename,
        health_score=health_score,
        results_data=results_data
    )
    db.session.add(analysis)
    db.session.commit()
    return analysis

def get_user_analyses(user_id):
    """Get all analysis results for a user, ordered by date"""
    return AnalysisResult.query.filter_by(user_id=user_id).order_by(AnalysisResult.created_at.desc()).all()