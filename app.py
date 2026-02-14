"""
PhishGuard Flask API with Database Integration
Complete backend with ML inference and persistent storage
"""

import os
import time
import hashlib
from datetime import datetime, date
from flask import Flask, request, jsonify
from flask_cors import CORS
from models import db, ScanHistory, UserStatistics, ModelMetrics
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Flask application setup
app = Flask(__name__)
CORS(app)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "phishguard.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False  # Set to True for SQL debugging

# Initialize database
db.init_app(app)

# Model configuration
MODEL_VERSION = "v1.0.0"
MODEL_PATH = os.path.join(basedir, 'models', 'phishing_classifier.pkl')
VECTORIZER_PATH = os.path.join(basedir, 'models', 'tfidf_vectorizer.pkl')

# Global model and vectorizer (loaded on startup)
ml_model = None
vectorizer = None


def load_models():
    """Load ML model and vectorizer at application startup"""
    global ml_model, vectorizer
    
    try:
        with open(MODEL_PATH, 'rb') as f:
            ml_model = pickle.load(f)
        print(f"✓ ML model loaded successfully from {MODEL_PATH}")
        
        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)
        print(f"✓ Vectorizer loaded successfully from {VECTORIZER_PATH}")
        
    except FileNotFoundError as e:
        print(f"⚠ Warning: Model files not found. Using mock predictions.")
        ml_model = None
        vectorizer = None
    except Exception as e:
        print(f"✗ Error loading models: {str(e)}")
        ml_model = None
        vectorizer = None


def hash_message(text):
    """Generate SHA-256 hash of message for deduplication"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def classify_message(text):
    """
    Perform ML classification on the message
    Returns: (is_phishing, risk_score, confidence_level, prediction_time_ms)
    """
    start_time = time.time()
    
    if ml_model is None or vectorizer is None:
        # Mock prediction for testing without trained model
        risk_score = 0.75 if "urgent" in text.lower() or "click" in text.lower() else 0.25
        is_phishing = risk_score > 0.5
        confidence = "HIGH" if risk_score > 0.7 or risk_score < 0.3 else "MEDIUM"
    else:
        # Real ML inference
        features = vectorizer.transform([text])
        risk_score = ml_model.predict_proba(features)[0][1]  # Probability of phishing class
        is_phishing = risk_score > 0.5
        
        # Determine confidence level
        if risk_score > 0.8 or risk_score < 0.2:
            confidence = "HIGH"
        elif risk_score > 0.6 or risk_score < 0.4:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
    
    prediction_time = int((time.time() - start_time) * 1000)  # Convert to milliseconds
    
    return is_phishing, float(risk_score), confidence, prediction_time


def update_user_statistics(user_id, is_phishing, risk_score):
    """Update aggregated user statistics"""
    if not user_id:
        return
    
    stats = UserStatistics.query.get(user_id)
    
    if stats is None:
        # Create new statistics record
        stats = UserStatistics(
            user_id=user_id,
            total_scans=1,
            phishing_detected=1 if is_phishing else 0,
            safe_messages=0 if is_phishing else 1,
            average_risk_score=risk_score,
            highest_risk_score=risk_score,
            first_scan_date=datetime.utcnow(),
            last_scan_date=datetime.utcnow()
        )
        db.session.add(stats)
    else:
        # Update existing statistics
        stats.total_scans += 1
        if is_phishing:
            stats.phishing_detected += 1
        else:
            stats.safe_messages += 1
        
        # Update average risk score
        stats.average_risk_score = (
            (stats.average_risk_score * (stats.total_scans - 1) + risk_score) / stats.total_scans
        )
        
        # Update highest risk score
        if risk_score > stats.highest_risk_score:
            stats.highest_risk_score = risk_score
        
        stats.last_scan_date = datetime.utcnow()
    
    db.session.commit()


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connectivity
        from sqlalchemy import text
db.session.execute(text('SELECT 1'))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        'status': 'healthy',
        'model_loaded': ml_model is not None,
        'model_version': MODEL_VERSION,
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/api/scan', methods=['POST'])
def scan_message():
    """
    Main endpoint for scanning messages for phishing
    
    Request JSON:
    {
        "message": "Your message text here",
        "user_id": "optional_user_identifier",
        "device_id": "optional_device_identifier"
    }
    
    Response JSON:
    {
        "scan_id": 123,
        "is_phishing": true,
        "risk_score": 0.87,
        "confidence": "HIGH",
        "message": "Phishing detected",
        "timestamp": "2024-02-15T10:30:00"
    }
    """
    try:
        # Parse request
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({
                'error': 'Missing required field: message',
                'status': 'error'
            }), 400
        
        message_text = data['message'].strip()
        
        if not message_text:
            return jsonify({
                'error': 'Message cannot be empty',
                'status': 'error'
            }), 400
        
        user_id = data.get('user_id')
        device_id = data.get('device_id')
        
        # Perform ML classification
        is_phishing, risk_score, confidence, prediction_time = classify_message(message_text)
        
        # Create scan history record
        scan_record = ScanHistory(
            user_id=user_id,
            device_id=device_id,
            message_text=message_text,
            message_hash=hash_message(message_text),
            is_phishing=is_phishing,
            risk_score=risk_score,
            confidence_level=confidence,
            model_version=MODEL_VERSION,
            prediction_time_ms=prediction_time,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:200]
        )
        
        # Save to database
        db.session.add(scan_record)
        db.session.commit()
        
        # Update user statistics asynchronously (in production, use Celery or similar)
        update_user_statistics(user_id, is_phishing, risk_score)
        
        # Prepare response
        response_message = "Phishing detected - High risk!" if is_phishing else "Message appears safe"
        
        return jsonify({
            'scan_id': scan_record.id,
            'is_phishing': is_phishing,
            'risk_score': round(risk_score, 4),
            'confidence': confidence,
            'message': response_message,
            'prediction_time_ms': prediction_time,
            'timestamp': scan_record.created_at.isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': f'Internal server error: {str(e)}',
            'status': 'error'
        }), 500


@app.route('/api/history', methods=['GET'])
def get_scan_history():
    """
    Retrieve scan history for a user
    
    Query parameters:
    - user_id: Filter by user (required)
    - limit: Number of records (default: 50, max: 200)
    - offset: Pagination offset (default: 0)
    - phishing_only: Filter only phishing results (true/false)
    """
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({
                'error': 'Missing required parameter: user_id',
                'status': 'error'
            }), 400
        
        limit = min(int(request.args.get('limit', 50)), 200)
        offset = int(request.args.get('offset', 0))
        phishing_only = request.args.get('phishing_only', 'false').lower() == 'true'
        
        # Build query
        query = ScanHistory.query.filter_by(user_id=user_id)
        
        if phishing_only:
            query = query.filter_by(is_phishing=True)
        
        # Execute query with pagination
        scans = query.order_by(ScanHistory.created_at.desc())\
                     .limit(limit)\
                     .offset(offset)\
                     .all()
        
        total_count = query.count()
        
        return jsonify({
            'scans': [scan.to_dict() for scan in scans],
            'total_count': total_count,
            'limit': limit,
            'offset': offset,
            'has_more': (offset + limit) < total_count
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Error retrieving history: {str(e)}',
            'status': 'error'
        }), 500


@app.route('/api/statistics/<user_id>', methods=['GET'])
def get_user_statistics(user_id):
    """Retrieve aggregated statistics for a user"""
    try:
        stats = UserStatistics.query.get(user_id)
        
        if stats is None:
            return jsonify({
                'error': 'No statistics found for this user',
                'status': 'not_found'
            }), 404
        
        return jsonify({
            'statistics': stats.to_dict(),
            'status': 'success'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Error retrieving statistics: {str(e)}',
            'status': 'error'
        }), 500


@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """
    Submit user feedback on a prediction
    
    Request JSON:
    {
        "scan_id": 123,
        "feedback": "CORRECT" | "INCORRECT" | "UNSURE"
    }
    """
    try:
        data = request.get_json()
        
        scan_id = data.get('scan_id')
        feedback = data.get('feedback')
        
        if not scan_id or not feedback:
            return jsonify({
                'error': 'Missing required fields: scan_id, feedback',
                'status': 'error'
            }), 400
        
        if feedback not in ['CORRECT', 'INCORRECT', 'UNSURE']:
            return jsonify({
                'error': 'Invalid feedback value. Must be CORRECT, INCORRECT, or UNSURE',
                'status': 'error'
            }), 400
        
        # Update scan record
        scan = ScanHistory.query.get(scan_id)
        
        if scan is None:
            return jsonify({
                'error': 'Scan not found',
                'status': 'not_found'
            }), 404
        
        scan.user_feedback = feedback
        scan.feedback_timestamp = datetime.utcnow()
        
        # Update user statistics if applicable
        if scan.user_id:
            stats = UserStatistics.query.get(scan.user_id)
            if stats:
                stats.feedback_provided += 1
                if feedback == 'CORRECT':
                    stats.correct_predictions += 1
                elif feedback == 'INCORRECT':
                    stats.incorrect_predictions += 1
        
        db.session.commit()
        
        return jsonify({
            'message': 'Feedback recorded successfully',
            'status': 'success'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': f'Error submitting feedback: {str(e)}',
            'status': 'error'
        }), 500


@app.route('/api/analytics/dashboard', methods=['GET'])
def get_analytics_dashboard():
    """
    Retrieve system-wide analytics for admin dashboard
    """
    try:
        from sqlalchemy import func
        
        # Total scans
        total_scans = db.session.query(func.count(ScanHistory.id)).scalar()
        
        # Phishing vs Safe breakdown
        phishing_count = db.session.query(func.count(ScanHistory.id))\
            .filter_by(is_phishing=True).scalar()
        safe_count = total_scans - phishing_count
        
        # Average risk score
        avg_risk = db.session.query(func.avg(ScanHistory.risk_score)).scalar()
        
        # Recent scans (last 24 hours)
        from datetime import timedelta
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_scans = db.session.query(func.count(ScanHistory.id))\
            .filter(ScanHistory.created_at >= yesterday).scalar()
        
        # User statistics
        total_users = db.session.query(func.count(UserStatistics.user_id)).scalar()
        
        # Average inference time
        avg_inference = db.session.query(func.avg(ScanHistory.prediction_time_ms)).scalar()
        
        return jsonify({
            'total_scans': total_scans,
            'phishing_detected': phishing_count,
            'safe_messages': safe_count,
            'phishing_rate': round(phishing_count / total_scans * 100, 2) if total_scans > 0 else 0,
            'average_risk_score': round(avg_risk, 4) if avg_risk else 0,
            'scans_last_24h': recent_scans,
            'total_users': total_users,
            'average_inference_time_ms': round(avg_inference, 2) if avg_inference else 0,
            'model_version': MODEL_VERSION,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Error retrieving analytics: {str(e)}',
            'status': 'error'
        }), 500


def init_database():
    """Initialize database tables"""
    with app.app_context():
        db.create_all()
        print("✓ Database tables created successfully")


if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Load ML models
    load_models()
    
    # Run Flask application
    print("\n" + "="*60)
    print("PhishGuard API Server Starting...")
    print("="*60)
    print(f"Model Version: {MODEL_VERSION}")
    print(f"Database: phishguard.db")
    print(f"Server: http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
