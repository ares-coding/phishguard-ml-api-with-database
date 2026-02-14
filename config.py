"""
PhishGuard Configuration
Environment-specific settings for development, testing, and production
"""

import os
from datetime import timedelta


class Config:
    """Base configuration"""
    
    # Application
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    # Model Configuration
    MODEL_VERSION = "v1.0.0"
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'phishing_classifier.pkl')
    VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'models', 'tfidf_vectorizer.pkl')
    
    # API Settings
    CORS_ORIGINS = ["*"]  # Restrict in production
    MAX_CONTENT_LENGTH = 16 * 1024  # 16KB max request size
    
    # Rate Limiting (requests per minute)
    RATE_LIMIT_SCAN = 60
    RATE_LIMIT_HISTORY = 30
    
    # Data Retention (days)
    DATA_RETENTION_DAYS = 90
    ANONYMIZATION_DAYS = 180
    
    # Performance
    DATABASE_POOL_SIZE = 10
    DATABASE_POOL_TIMEOUT = 30
    DATABASE_POOL_RECYCLE = 3600


class DevelopmentConfig(Config):
    """Development environment configuration"""
    
    DEBUG = True
    TESTING = False
    
    # Database - SQLite for development
    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(basedir, "phishguard_dev.db")}'
    
    # Verbose logging
    SQLALCHEMY_ECHO = True
    
    # Relaxed security for development
    CORS_ORIGINS = ["*"]


class TestingConfig(Config):
    """Testing environment configuration"""
    
    DEBUG = False
    TESTING = True
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Fast testing
    DATABASE_POOL_SIZE = 1


class ProductionConfig(Config):
    """Production environment configuration"""
    
    DEBUG = False
    TESTING = False
    
    # Production database - PostgreSQL recommended
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///phishguard_prod.db'
    
    # Strict CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',')
    
    # Security headers
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Performance optimization
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'max_overflow': 0
    }


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Get configuration for specified environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
