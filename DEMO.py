#!/usr/bin/env python3
"""
PhishGuard System Demonstration
Visual overview of the complete database-integrated ML pipeline
"""

import os

def print_banner():
    """Print welcome banner"""
    print("\n" + "="*80)
    print("╔" + "═"*78 + "╗")
    print("║" + " "*15 + "PhishGuard: ML-Powered Phishing Detection System" + " "*15 + "║")
    print("║" + " "*20 + "with Database Integration & Android Client" + " "*17 + "║")
    print("╚" + "═"*78 + "╝")
    print("="*80 + "\n")


def show_architecture():
    """Display system architecture"""
    print("📊 SYSTEM ARCHITECTURE")
    print("-" * 80)
    print("""
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                        Android Mobile Client                             │
    │  • User Interface (Kotlin/Java)                                         │
    │  • Retrofit HTTP Client                                                 │
    │  • ViewModel + LiveData/StateFlow (MVVM Architecture)                   │
    └──────────────────────────────┬──────────────────────────────────────────┘
                                   │
                                   │ HTTP/JSON REST API
                                   ↓
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                         Flask Backend Server                             │
    │                                                                          │
    │  API Endpoints:                                                         │
    │  • POST /api/scan           → Classify message                          │
    │  • GET  /api/history        → Retrieve scan history                     │
    │  • GET  /api/statistics/:id → User analytics                            │
    │  • POST /api/feedback       → Submit user feedback                      │
    │  • GET  /api/analytics      → System dashboard                          │
    │  • GET  /health             → Health check                              │
    └──────────────────────────────┬──────────────────────────────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ↓                             ↓
    ┌───────────────────────────┐    ┌──────────────────────────────┐
    │   ML Classification       │    │   SQLite Database            │
    │                           │    │                              │
    │  • TF-IDF Vectorizer     │    │  Tables:                     │
    │  • Scikit-learn Model    │    │  • scan_history (primary)    │
    │  • Real-time Inference   │    │  • user_statistics (agg)     │
    │  • 10-50ms latency       │    │  • model_metrics (tracking)  │
    └───────────────────────────┘    └──────────────────────────────┘
    """)
    print("-" * 80 + "\n")


def show_data_flow():
    """Display data flow through the system"""
    print("🔄 DATA FLOW: Message Scan Operation")
    print("-" * 80)
    print("""
    [1] User opens app and enters suspicious message
         ↓
    [2] Android client calls PhishGuardRepository.scanMessage()
         ↓ Retrofit HTTP POST to /api/scan
    [3] Flask receives JSON: {message, user_id, device_id}
         ↓ Validate input
    [4] Load message into TF-IDF vectorizer
         ↓ Transform to feature vector
    [5] ML Model inference (scikit-learn classifier)
         ↓ Output: is_phishing=True, risk_score=0.87, confidence=HIGH
    [6] Create ScanHistory database record
         ↓ SQLAlchemy ORM: db.session.add(scan_record)
    [7] Update UserStatistics aggregated metrics
         ↓ Increment counters, update averages
    [8] Commit transaction to SQLite database
         ↓ Persistent storage confirmed
    [9] Return JSON response to Android client
         ↓ {scan_id, is_phishing, risk_score, confidence, message}
    [10] ViewModel updates UI state via StateFlow
         ↓ UI displays result with color-coded risk indicator
    """)
    print("-" * 80 + "\n")


def show_database_schema():
    """Display database schema"""
    print("💾 DATABASE SCHEMA (SQLite)")
    print("-" * 80)
    print("""
    Table: scan_history (Primary Data)
    ┌─────────────────────┬──────────────┬─────────────────────────────────┐
    │ Column              │ Type         │ Description                     │
    ├─────────────────────┼──────────────┼─────────────────────────────────┤
    │ id                  │ INTEGER (PK) │ Auto-increment primary key      │
    │ user_id             │ VARCHAR(100) │ User identifier [INDEXED]       │
    │ device_id           │ VARCHAR(100) │ Device identifier               │
    │ message_text        │ TEXT         │ Scanned message content         │
    │ message_hash        │ VARCHAR(64)  │ SHA-256 for deduplication [IDX] │
    │ is_phishing         │ BOOLEAN      │ Classification result           │
    │ risk_score          │ FLOAT        │ Probability 0.0-1.0             │
    │ confidence_level    │ VARCHAR(20)  │ LOW/MEDIUM/HIGH                 │
    │ model_version       │ VARCHAR(50)  │ Model version used              │
    │ prediction_time_ms  │ INTEGER      │ Inference latency               │
    │ created_at          │ DATETIME     │ Timestamp [INDEXED]             │
    │ user_feedback       │ VARCHAR(20)  │ CORRECT/INCORRECT/UNSURE        │
    │ feedback_timestamp  │ DATETIME     │ Feedback submission time        │
    │ ip_address          │ VARCHAR(45)  │ Client IP                       │
    │ user_agent          │ VARCHAR(200) │ Client user agent               │
    └─────────────────────┴──────────────┴─────────────────────────────────┘
    
    Indexes for Performance:
    • idx_user_created (user_id, created_at) → User history queries
    • idx_phishing_risk (is_phishing, risk_score) → Analytics
    • idx_created_date (created_at) → Time-series queries
    
    
    Table: user_statistics (Aggregated Metrics)
    ┌──────────────────────┬──────────────┬─────────────────────────────┐
    │ user_id (PK)         │ VARCHAR(100) │ User identifier             │
    │ total_scans          │ INTEGER      │ Count of all scans          │
    │ phishing_detected    │ INTEGER      │ Count of phishing messages  │
    │ safe_messages        │ INTEGER      │ Count of safe messages      │
    │ average_risk_score   │ FLOAT        │ Mean risk across scans      │
    │ highest_risk_score   │ FLOAT        │ Maximum risk encountered    │
    │ first_scan_date      │ DATETIME     │ First scan timestamp        │
    │ last_scan_date       │ DATETIME     │ Last scan timestamp         │
    │ feedback_provided    │ INTEGER      │ Feedback count              │
    │ correct_predictions  │ INTEGER      │ Correct feedback count      │
    │ incorrect_predictions│ INTEGER      │ Incorrect feedback count    │
    └──────────────────────┴──────────────┴─────────────────────────────┘
    
    Purpose: Fast dashboard queries without scanning full history
    """)
    print("-" * 80 + "\n")


def show_api_examples():
    """Display API request/response examples"""
    print("🌐 API ENDPOINT EXAMPLES")
    print("-" * 80)
    print("""
    Example 1: Scan a Message
    ─────────────────────────────────────────────────────────────
    Request:
      POST /api/scan
      Content-Type: application/json
      
      {
        "message": "URGENT: Your account has been compromised! Click here now!",
        "user_id": "user_12345",
        "device_id": "android_device_abc"
      }
    
    Response: (200 OK)
      {
        "scan_id": 1042,
        "is_phishing": true,
        "risk_score": 0.8947,
        "confidence": "HIGH",
        "message": "Phishing detected - High risk!",
        "prediction_time_ms": 18,
        "timestamp": "2024-02-15T14:32:10.123456"
      }
    
    
    Example 2: Get User Scan History
    ─────────────────────────────────────────────────────────────
    Request:
      GET /api/history?user_id=user_12345&limit=10&offset=0
    
    Response: (200 OK)
      {
        "scans": [
          {
            "id": 1042,
            "message_text": "URGENT: Your account...",
            "is_phishing": true,
            "risk_score": 0.8947,
            "confidence_level": "HIGH",
            "created_at": "2024-02-15T14:32:10.123456",
            "user_feedback": null
          },
          // ... more scans
        ],
        "total_count": 87,
        "limit": 10,
        "offset": 0,
        "has_more": true
      }
    
    
    Example 3: Get User Statistics
    ─────────────────────────────────────────────────────────────
    Request:
      GET /api/statistics/user_12345
    
    Response: (200 OK)
      {
        "statistics": {
          "user_id": "user_12345",
          "total_scans": 87,
          "phishing_detected": 12,
          "safe_messages": 75,
          "average_risk_score": 0.2341,
          "highest_risk_score": 0.8947,
          "first_scan_date": "2024-01-10T08:15:00",
          "last_scan_date": "2024-02-15T14:32:10",
          "feedback_provided": 23,
          "correct_predictions": 21,
          "incorrect_predictions": 2
        }
      }
    """)
    print("-" * 80 + "\n")


def show_android_integration():
    """Display Android integration example"""
    print("📱 ANDROID CLIENT INTEGRATION")
    print("-" * 80)
    print("""
    Kotlin ViewModel Example:
    ─────────────────────────────────────────────────────────────
    
    class PhishGuardViewModel : ViewModel() {
        private val repository = PhishGuardRepository()
        
        // UI State
        private val _scanResult = MutableStateFlow<ScanResult?>(null)
        val scanResult: StateFlow<ScanResult?> = _scanResult
        
        private val _isLoading = MutableStateFlow(false)
        val isLoading: StateFlow<Boolean> = _isLoading
        
        fun scanMessage(message: String, userId: String?, deviceId: String?) {
            viewModelScope.launch {
                _isLoading.value = true
                
                repository.scanMessage(message, userId, deviceId)
                    .onSuccess { response ->
                        _scanResult.value = ScanResult(
                            scanId = response.scanId,
                            isPhishing = response.isPhishing,
                            riskScore = response.riskScore,
                            confidence = response.confidence,
                            message = response.message
                        )
                    }
                    .onFailure { exception ->
                        // Handle error
                    }
                
                _isLoading.value = false
            }
        }
    }
    
    
    Activity/Fragment Usage:
    ─────────────────────────────────────────────────────────────
    
    class MainActivity : AppCompatActivity() {
        private val viewModel: PhishGuardViewModel by viewModels()
        
        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            
            // Observe scan result
            lifecycleScope.launch {
                viewModel.scanResult.collect { result ->
                    result?.let { displayResult(it) }
                }
            }
            
            // Observe loading state
            lifecycleScope.launch {
                viewModel.isLoading.collect { isLoading ->
                    progressBar.isVisible = isLoading
                }
            }
            
            // Scan button click
            scanButton.setOnClickListener {
                val message = messageEditText.text.toString()
                viewModel.scanMessage(
                    message = message,
                    userId = "user_12345",
                    deviceId = getDeviceId()
                )
            }
        }
    }
    """)
    print("-" * 80 + "\n")


def show_key_features():
    """Display key system features"""
    print("✨ KEY FEATURES & CAPABILITIES")
    print("-" * 80)
    print("""
    ✓ Real-time Phishing Detection
      • Sub-50ms inference latency
      • TF-IDF feature extraction + ML classification
      • Confidence scoring (LOW/MEDIUM/HIGH)
    
    ✓ Complete Data Persistence
      • Every scan stored in SQLite database
      • Full audit trail with timestamps
      • SHA-256 hashing for deduplication
    
    ✓ User Analytics Dashboard
      • Aggregated statistics per user
      • Phishing detection rate tracking
      • Risk score trending over time
    
    ✓ Feedback Loop for Model Improvement
      • Users can mark predictions as correct/incorrect
      • Feedback stored for model retraining
      • Accuracy metrics computed from feedback
    
    ✓ RESTful API Architecture
      • JSON request/response format
      • Comprehensive error handling
      • Health check endpoint for monitoring
    
    ✓ Android Client Integration
      • Retrofit HTTP client library
      • MVVM architecture with ViewModel
      • Kotlin coroutines for async operations
      • StateFlow for reactive UI updates
    
    ✓ Performance Optimized
      • Database indexing for fast queries
      • Connection pooling
      • Model loaded once at startup
      • Efficient query patterns
    
    ✓ Production Ready
      • Environment-specific configurations
      • Comprehensive error handling
      • Security considerations documented
      • Deployment guide included
    """)
    print("-" * 80 + "\n")


def show_file_structure():
    """Display project file structure"""
    print("📁 PROJECT FILE STRUCTURE")
    print("-" * 80)
    print("""
    phishguard_db/
    │
    ├── app.py                          # Main Flask application
    ├── models.py                       # SQLAlchemy database models
    ├── database_utils.py               # Query utilities & analytics
    ├── config.py                       # Environment configurations
    ├── requirements.txt                # Python dependencies
    ├── test_system.py                  # Test suite with sample data
    │
    ├── README.md                       # Complete documentation
    ├── PROJECT_STRUCTURE.md            # Detailed structure guide
    ├── DEMO.py                         # This demonstration file
    │
    ├── models/                         # ML model files
    │   ├── phishing_classifier.pkl     # Trained model
    │   └── tfidf_vectorizer.pkl        # Feature vectorizer
    │
    ├── android/                        # Android client
    │   └── PhishGuardApiService.kt     # Retrofit API integration
    │
    └── phishguard.db                   # SQLite database (auto-generated)
    """)
    print("-" * 80 + "\n")


def show_quick_start():
    """Display quick start instructions"""
    print("🚀 QUICK START GUIDE")
    print("-" * 80)
    print("""
    Backend Setup:
    ──────────────────────────────────────────────────────────────
    1. Install dependencies:
       $ pip install -r requirements.txt
    
    2. Start Flask server:
       $ python app.py
       
       Server will start on http://localhost:5000
    
    3. Test API:
       $ curl http://localhost:5000/health
       $ curl -X POST http://localhost:5000/api/scan \\
              -H "Content-Type: application/json" \\
              -d '{"message": "Test message", "user_id": "test"}'
    
    
    Android Setup:
    ──────────────────────────────────────────────────────────────
    1. Add Retrofit dependencies to build.gradle:
       implementation 'com.squareup.retrofit2:retrofit:2.9.0'
       implementation 'com.squareup.retrofit2:converter-gson:2.9.0'
    
    2. Update BASE_URL in PhishGuardApiService.kt:
       // For Android Emulator:
       private const val BASE_URL = "http://10.0.2.2:5000/"
       
       // For Real Device:
       private const val BASE_URL = "http://YOUR_SERVER_IP:5000/"
    
    3. Add Internet permission to AndroidManifest.xml:
       <uses-permission android:name="android.permission.INTERNET" />
    
    4. Integrate ViewModel in your Activity/Fragment
       (See PhishGuardApiService.kt for complete example)
    
    
    Testing with Sample Data:
    ──────────────────────────────────────────────────────────────
    $ python test_system.py
    
    This will:
    • Create database tables
    • Populate 200 sample scan records
    • Generate user statistics
    • Display analytics queries
    • Demonstrate API flow
    """)
    print("-" * 80 + "\n")


def show_deployment_notes():
    """Display deployment considerations"""
    print("🔧 DEPLOYMENT CONSIDERATIONS")
    print("-" * 80)
    print("""
    Production Deployment:
    ──────────────────────────────────────────────────────────────
    ✓ Use PostgreSQL instead of SQLite (recommended)
    ✓ Deploy with Gunicorn: gunicorn -w 4 app:app
    ✓ Set up Nginx reverse proxy with HTTPS
    ✓ Implement API authentication (JWT/OAuth)
    ✓ Configure rate limiting per IP/user
    ✓ Set up proper CORS whitelist
    ✓ Enable database connection pooling
    ✓ Implement log rotation and monitoring
    ✓ Set up automated database backups
    ✓ Configure data retention policies (GDPR)
    
    
    Security Hardening:
    ──────────────────────────────────────────────────────────────
    ✓ Input validation and sanitization
    ✓ SQL injection prevention (using ORM)
    ✓ XSS prevention in responses
    ✓ CSRF protection for state-changing operations
    ✓ Rate limiting to prevent abuse
    ✓ HTTPS enforcement (no HTTP)
    ✓ Secure session management
    ✓ Regular security audits
    
    
    Performance Optimization:
    ──────────────────────────────────────────────────────────────
    ✓ Database indexes on frequently queried columns
    ✓ Connection pooling (configured)
    ✓ Redis caching for frequent queries
    ✓ Async task queue (Celery) for heavy operations
    ✓ Model inference optimization
    ✓ Horizontal scaling with load balancer
    """)
    print("-" * 80 + "\n")


def main():
    """Main demonstration"""
    print_banner()
    
    print("This demonstration provides an overview of the PhishGuard system:")
    print("A complete end-to-end ML pipeline with database integration.\n")
    
    input("Press Enter to view System Architecture...")
    show_architecture()
    
    input("Press Enter to view Data Flow...")
    show_data_flow()
    
    input("Press Enter to view Database Schema...")
    show_database_schema()
    
    input("Press Enter to view API Examples...")
    show_api_examples()
    
    input("Press Enter to view Android Integration...")
    show_android_integration()
    
    input("Press Enter to view Key Features...")
    show_key_features()
    
    input("Press Enter to view File Structure...")
    show_file_structure()
    
    input("Press Enter to view Quick Start Guide...")
    show_quick_start()
    
    input("Press Enter to view Deployment Notes...")
    show_deployment_notes()
    
    print("="*80)
    print("✅ DEMONSTRATION COMPLETE")
    print("="*80)
    print("""
    Next Steps:
    
    1. Review the comprehensive documentation in README.md
    2. Examine the detailed project structure in PROJECT_STRUCTURE.md
    3. Explore the code files to understand implementation details
    4. Set up your development environment using the Quick Start guide
    5. Test the API endpoints with curl or Postman
    6. Integrate with your Android application
    
    For questions or issues, refer to the Troubleshooting section in README.md
    """)
    print("="*80 + "\n")


if __name__ == '__main__':
    main()
