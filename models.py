"""
PhishGuard Database Models
SQLAlchemy ORM models for persistent storage of phishing scans
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index

db = SQLAlchemy()


class ScanHistory(db.Model):
    """
    Stores complete history of all phishing scans
    Enables analytics, user history tracking, and audit trails
    """
    __tablename__ = 'scan_history'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # User identification (optional - for multi-user scenarios)
    user_id = db.Column(db.String(100), nullable=True, index=True)
    device_id = db.Column(db.String(100), nullable=True, index=True)
    
    # Scan input data
    message_text = db.Column(db.Text, nullable=False)
    message_hash = db.Column(db.String(64), nullable=True, index=True)  # SHA-256 for deduplication
    
    # ML Model predictions
    is_phishing = db.Column(db.Boolean, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    confidence_level = db.Column(db.String(20), nullable=True)  # LOW, MEDIUM, HIGH
    
    # Model metadata
    model_version = db.Column(db.String(50), nullable=True)
    prediction_time_ms = db.Column(db.Integer, nullable=True)  # Inference latency
    
    # Feature extraction (stored as JSON for flexibility)
    extracted_features = db.Column(db.JSON, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # User feedback (for model improvement)
    user_feedback = db.Column(db.String(20), nullable=True)  # CORRECT, INCORRECT, UNSURE
    feedback_timestamp = db.Column(db.DateTime, nullable=True)
    
    # Additional metadata
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 support
    user_agent = db.Column(db.String(200), nullable=True)
    
    # Composite indexes for common queries
    __table_args__ = (
        Index('idx_user_created', 'user_id', 'created_at'),
        Index('idx_phishing_risk', 'is_phishing', 'risk_score'),
        Index('idx_created_date', 'created_at'),
    )
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'device_id': self.device_id,
            'message_text': self.message_text,
            'is_phishing': self.is_phishing,
            'risk_score': round(self.risk_score, 4),
            'confidence_level': self.confidence_level,
            'model_version': self.model_version,
            'prediction_time_ms': self.prediction_time_ms,
            'extracted_features': self.extracted_features,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_feedback': self.user_feedback,
            'feedback_timestamp': self.feedback_timestamp.isoformat() if self.feedback_timestamp else None
        }
    
    def __repr__(self):
        return f'<ScanHistory {self.id}: {"PHISHING" if self.is_phishing else "SAFE"} ({self.risk_score:.2f})>'


class UserStatistics(db.Model):
    """
    Aggregated statistics per user for quick dashboard retrieval
    Updated periodically or on-demand
    """
    __tablename__ = 'user_statistics'
    
    user_id = db.Column(db.String(100), primary_key=True)
    
    # Scan counts
    total_scans = db.Column(db.Integer, default=0)
    phishing_detected = db.Column(db.Integer, default=0)
    safe_messages = db.Column(db.Integer, default=0)
    
    # Risk analysis
    average_risk_score = db.Column(db.Float, default=0.0)
    highest_risk_score = db.Column(db.Float, default=0.0)
    
    # User behavior
    first_scan_date = db.Column(db.DateTime, nullable=True)
    last_scan_date = db.Column(db.DateTime, nullable=True)
    
    # Feedback metrics
    feedback_provided = db.Column(db.Integer, default=0)
    correct_predictions = db.Column(db.Integer, default=0)
    incorrect_predictions = db.Column(db.Integer, default=0)
    
    # Metadata
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'total_scans': self.total_scans,
            'phishing_detected': self.phishing_detected,
            'safe_messages': self.safe_messages,
            'average_risk_score': round(self.average_risk_score, 4),
            'highest_risk_score': round(self.highest_risk_score, 4),
            'first_scan_date': self.first_scan_date.isoformat() if self.first_scan_date else None,
            'last_scan_date': self.last_scan_date.isoformat() if self.last_scan_date else None,
            'feedback_provided': self.feedback_provided,
            'correct_predictions': self.correct_predictions,
            'incorrect_predictions': self.incorrect_predictions,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<UserStats {self.user_id}: {self.total_scans} scans, {self.phishing_detected} phishing>'


class ModelMetrics(db.Model):
    """
    Tracks model performance metrics over time
    Useful for monitoring model drift and accuracy
    """
    __tablename__ = 'model_metrics'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    model_version = db.Column(db.String(50), nullable=False, index=True)
    
    # Performance metrics
    total_predictions = db.Column(db.Integer, default=0)
    phishing_predictions = db.Column(db.Integer, default=0)
    safe_predictions = db.Column(db.Integer, default=0)
    
    # Accuracy metrics (based on user feedback)
    true_positives = db.Column(db.Integer, default=0)
    false_positives = db.Column(db.Integer, default=0)
    true_negatives = db.Column(db.Integer, default=0)
    false_negatives = db.Column(db.Integer, default=0)
    
    # Computed metrics
    precision = db.Column(db.Float, nullable=True)
    recall = db.Column(db.Float, nullable=True)
    f1_score = db.Column(db.Float, nullable=True)
    
    # Timing metrics
    average_inference_time_ms = db.Column(db.Float, nullable=True)
    min_inference_time_ms = db.Column(db.Integer, nullable=True)
    max_inference_time_ms = db.Column(db.Integer, nullable=True)
    
    # Timestamps
    metric_date = db.Column(db.Date, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_model_date', 'model_version', 'metric_date'),
    )
    
    def calculate_metrics(self):
        """Calculate precision, recall, and F1 score from confusion matrix"""
        if self.true_positives + self.false_positives > 0:
            self.precision = self.true_positives / (self.true_positives + self.false_positives)
        else:
            self.precision = 0.0
            
        if self.true_positives + self.false_negatives > 0:
            self.recall = self.true_positives / (self.true_positives + self.false_negatives)
        else:
            self.recall = 0.0
            
        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
    
    def to_dict(self):
        return {
            'id': self.id,
            'model_version': self.model_version,
            'total_predictions': self.total_predictions,
            'phishing_predictions': self.phishing_predictions,
            'safe_predictions': self.safe_predictions,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'precision': round(self.precision, 4) if self.precision else None,
            'recall': round(self.recall, 4) if self.recall else None,
            'f1_score': round(self.f1_score, 4) if self.f1_score else None,
            'average_inference_time_ms': round(self.average_inference_time_ms, 2) if self.average_inference_time_ms else None,
            'metric_date': self.metric_date.isoformat() if self.metric_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<ModelMetrics {self.model_version} on {self.metric_date}: P={self.precision:.2f}, R={self.recall:.2f}>'
