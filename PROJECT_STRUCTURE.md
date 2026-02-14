# PhishGuard Project Structure

## Directory Organization

```
phishguard_db/
│
├── app.py                      # Main Flask application with REST API endpoints
├── models.py                   # SQLAlchemy database models (ORM)
├── database_utils.py           # Database query utilities and analytics
├── config.py                   # Environment-specific configurations
├── requirements.txt            # Python package dependencies
├── test_system.py              # Test suite with sample data generation
├── README.md                   # Comprehensive documentation
├── PROJECT_STRUCTURE.md        # This file
│
├── models/                     # Machine learning model files
│   ├── phishing_classifier.pkl # Trained classifier model
│   └── tfidf_vectorizer.pkl   # Text vectorizer
│
├── android/                    # Android client integration
│   └── PhishGuardApiService.kt # Retrofit API client + ViewModel
│
└── phishguard.db              # SQLite database (auto-generated)
```

## File Descriptions

### Core Backend Files

#### `app.py` (Main Application)
**Purpose:** Flask REST API server with ML inference and database integration

**Key Components:**
- Flask application initialization
- Database configuration and initialization
- ML model loading and inference
- REST API endpoints:
  - `/health` - Health check
  - `/api/scan` - Message scanning
  - `/api/history` - Scan history retrieval
  - `/api/statistics/<user_id>` - User statistics
  - `/api/feedback` - User feedback submission
  - `/api/analytics/dashboard` - System-wide analytics

**Dependencies:**
- Flask, Flask-CORS
- SQLAlchemy (via Flask-SQLAlchemy)
- scikit-learn (for ML inference)
- models.py, database_utils.py

**Key Functions:**
```python
load_models()                   # Load ML model at startup
classify_message(text)          # Perform phishing classification
update_user_statistics()        # Update aggregated user stats
scan_message()                  # Main API endpoint
```

---

#### `models.py` (Database Models)
**Purpose:** SQLAlchemy ORM models for database schema

**Tables Defined:**
1. **ScanHistory**: Complete audit trail of all scans
   - Primary data storage
   - Supports analytics and user feedback
   - Indexes for performance

2. **UserStatistics**: Aggregated user metrics
   - Pre-computed statistics
   - Fast dashboard queries
   - Updated on each scan

3. **ModelMetrics**: Model performance tracking
   - Accuracy metrics over time
   - Confusion matrix data
   - Inference timing statistics

**Key Methods:**
```python
to_dict()                       # Convert model to JSON-serializable dict
__repr__()                      # String representation for debugging
calculate_metrics()             # Compute precision, recall, F1 (ModelMetrics)
```

---

#### `database_utils.py` (Utilities)
**Purpose:** Advanced database queries, analytics, and data management

**Main Classes:**

1. **DatabaseQueries**: Common query patterns
   ```python
   get_recent_scans(hours, limit)
   get_high_risk_scans(threshold, limit)
   get_scans_by_date_range(start, end, user_id)
   get_duplicate_scans(user_id, limit)
   get_scans_with_feedback(type)
   ```

2. **AnalyticsEngine**: Statistical analysis
   ```python
   calculate_hourly_scan_volume(days)
   calculate_phishing_trends(days)
   get_risk_score_distribution(bins)
   get_top_users_by_scans(limit)
   get_model_accuracy_from_feedback()
   calculate_average_inference_time()
   ```

3. **DataManagement**: Data lifecycle operations
   ```python
   delete_old_scans(days)
   anonymize_old_data(days)          # GDPR compliance
   vacuum_database()
   export_scans_to_csv(path, dates)
   ```

---

#### `config.py` (Configuration)
**Purpose:** Environment-specific settings (dev/test/prod)

**Configuration Classes:**
- `Config`: Base configuration
- `DevelopmentConfig`: Local development settings
- `TestingConfig`: Test suite settings
- `ProductionConfig`: Production deployment settings

**Key Settings:**
- Database URIs
- Security keys
- CORS origins
- Rate limiting
- Data retention policies
- Performance tuning

---

#### `test_system.py` (Testing)
**Purpose:** Comprehensive test suite with sample data

**Main Functions:**
```python
populate_sample_data()          # Generate 200 sample scan records
display_sample_queries()        # Demonstrate query capabilities
display_system_overview()       # Show aggregate statistics
test_api_flow()                 # Simulate complete API usage
```

**Usage:**
```bash
python test_system.py
```

---

### Android Integration

#### `android/PhishGuardApiService.kt`
**Purpose:** Complete Android client integration with Retrofit

**Components:**

1. **Data Transfer Objects (DTOs):**
   - `ScanRequest` / `ScanResponse`
   - `ScanHistoryResponse` / `ScanHistoryItem`
   - `UserStatisticsResponse` / `UserStatistics`
   - `FeedbackRequest`
   - `AnalyticsDashboard`

2. **Retrofit API Interface:**
   ```kotlin
   interface PhishGuardApi {
       suspend fun scanMessage(request: ScanRequest): ScanResponse
       suspend fun getScanHistory(...): ScanHistoryResponse
       suspend fun getUserStatistics(userId: String): UserStatisticsResponse
       suspend fun submitFeedback(request: FeedbackRequest): Map<String, String>
       suspend fun getAnalyticsDashboard(): AnalyticsDashboard
       suspend fun healthCheck(): Map<String, Any>
   }
   ```

3. **Repository Pattern:**
   ```kotlin
   class PhishGuardRepository {
       suspend fun scanMessage(...): Result<ScanResponse>
       suspend fun getScanHistory(...): Result<ScanHistoryResponse>
       // ... other repository methods
   }
   ```

4. **ViewModel (MVVM):**
   ```kotlin
   class PhishGuardViewModel : ViewModel() {
       val scanResult: StateFlow<ScanResult?>
       val isLoading: StateFlow<Boolean>
       val error: StateFlow<String?>
       
       fun scanMessage(message: String, userId: String?, deviceId: String?)
       fun loadScanHistory(userId: String, phishingOnly: Boolean)
       fun loadUserStatistics(userId: String)
       fun submitFeedback(scanId: Int, feedback: String)
   }
   ```

---

## Data Flow Architecture

### 1. Message Scanning Flow

```
Android Client
    ↓ [HTTP POST /api/scan]
    ↓ JSON: {message, user_id, device_id}
Flask API
    ↓ [Extract & Validate]
Text Processing
    ↓ [TF-IDF Vectorization]
ML Model
    ↓ [Classification]
    ↓ Output: {is_phishing, risk_score, confidence}
Database
    ↓ [INSERT INTO scan_history]
    ↓ [UPDATE user_statistics]
Response
    ↓ [JSON Response]
Android Client
    ↓ [Display Result]
```

### 2. Database Query Flow

```
Android Client
    ↓ [HTTP GET /api/history?user_id=X]
Flask API
    ↓ [Parse Query Parameters]
DatabaseQueries
    ↓ [SQLAlchemy Query]
    ↓ SELECT * FROM scan_history 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
SQLite Database
    ↓ [Return Results]
Flask API
    ↓ [Serialize to JSON]
Android Client
    ↓ [Display in RecyclerView]
```

### 3. Analytics Dashboard Flow

```
Admin Request
    ↓ [HTTP GET /api/analytics/dashboard]
Flask API
    ↓ [Aggregate Queries]
    ├─ COUNT(*) FROM scan_history
    ├─ AVG(risk_score) FROM scan_history
    ├─ COUNT(*) WHERE created_at > 24h ago
    └─ COUNT DISTINCT user_id
Database
    ↓ [Return Aggregates]
Flask API
    ↓ [Compute Derived Metrics]
    ↓ JSON Response
Client
    ↓ [Visualize in Dashboard]
```

---

## Database Schema Relationships

```sql
scan_history (Primary Table)
│
├── user_id ──────► user_statistics (Aggregated)
│   └── One user → Many scans
│
├── model_version ─► model_metrics (Performance)
│   └── One version → Many daily metrics
│
└── message_hash ──► Deduplication Index
```

---

## API Request/Response Examples

### Scan Message
```http
POST /api/scan
Content-Type: application/json

{
  "message": "URGENT: Verify account now!",
  "user_id": "user123",
  "device_id": "device456"
}

→ Response (200 OK):
{
  "scan_id": 42,
  "is_phishing": true,
  "risk_score": 0.8742,
  "confidence": "HIGH",
  "message": "Phishing detected - High risk!",
  "prediction_time_ms": 15,
  "timestamp": "2024-02-15T10:30:00.000000"
}
```

### Get Scan History
```http
GET /api/history?user_id=user123&limit=10&offset=0&phishing_only=false

→ Response (200 OK):
{
  "scans": [ /* array of scan objects */ ],
  "total_count": 156,
  "limit": 10,
  "offset": 0,
  "has_more": true
}
```

---

## Development Workflow

### Initial Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize database
python app.py  # Creates tables automatically

# 3. Populate test data (optional)
python test_system.py

# 4. Start development server
python app.py
```

### Testing API
```bash
# Health check
curl http://localhost:5000/health

# Scan message
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"message": "Test message", "user_id": "test"}'

# Get history
curl "http://localhost:5000/api/history?user_id=test&limit=5"
```

### Android Development
```bash
# 1. Add Retrofit dependencies to build.gradle
# 2. Update BASE_URL in PhishGuardApiService.kt
#    - Emulator: http://10.0.2.2:5000/
#    - Device: http://YOUR_IP:5000/
# 3. Add Internet permission to AndroidManifest.xml
# 4. Integrate ViewModel in Activity/Fragment
```

---

## Deployment Checklist

### Production Deployment

- [ ] Update `config.py` with production settings
- [ ] Set `FLASK_ENV=production`
- [ ] Use PostgreSQL instead of SQLite (recommended)
- [ ] Configure proper SECRET_KEY
- [ ] Set up CORS whitelist
- [ ] Enable HTTPS
- [ ] Implement API authentication (JWT/OAuth)
- [ ] Set up rate limiting
- [ ] Configure log rotation
- [ ] Set up database backups
- [ ] Deploy with Gunicorn/uWSGI
- [ ] Use reverse proxy (Nginx/Apache)
- [ ] Monitor with logging/metrics
- [ ] Implement data retention policies

### Security Hardening

- [ ] Input validation and sanitization
- [ ] SQL injection prevention (✓ using ORM)
- [ ] XSS prevention
- [ ] CSRF protection
- [ ] Rate limiting per IP/user
- [ ] API key authentication
- [ ] HTTPS enforcement
- [ ] Data encryption at rest
- [ ] Regular security audits

---

## Performance Optimization

### Database Indexes (Already Implemented)
```sql
-- Composite indexes for common queries
CREATE INDEX idx_user_created ON scan_history(user_id, created_at);
CREATE INDEX idx_phishing_risk ON scan_history(is_phishing, risk_score);
CREATE INDEX idx_created_date ON scan_history(created_at);
CREATE INDEX message_hash ON scan_history(message_hash);
```

### Caching Strategies (Future)
- Redis for user statistics
- Memcached for frequent queries
- Application-level caching for analytics

### Scaling Considerations
- Database connection pooling (configured)
- Horizontal scaling with load balancer
- Separate read replicas for analytics
- Async task queue (Celery) for heavy operations

---

## Maintenance Tasks

### Regular Operations

**Daily:**
- Monitor API health endpoint
- Check error logs
- Review scan volume metrics

**Weekly:**
- Analyze model accuracy from feedback
- Review high-risk scans
- Check database size growth

**Monthly:**
- Database vacuum/optimization
- Export data for backup
- Review and update model if needed

**Quarterly:**
- Delete/anonymize old data (GDPR)
- Security audit
- Performance review

### Database Maintenance Scripts
```python
from database_utils import DataManagement

# Clean old data
DataManagement.delete_old_scans(days=90)
DataManagement.anonymize_old_data(days=180)
DataManagement.vacuum_database()

# Export for backup
DataManagement.export_scans_to_csv('backup.csv')
```

---

## Troubleshooting Guide

### Common Issues

**1. Database Locked Error**
```
Solution: SQLite doesn't handle high concurrency well.
- Use PostgreSQL for production
- Reduce concurrent connections
- Implement retry logic
```

**2. Model Not Found**
```
Solution: 
- Create models/ directory
- Add trained model files, or
- System will use mock predictions
```

**3. Android Can't Connect**
```
Solution:
- Emulator: Use 10.0.2.2 instead of localhost
- Device: Use computer's IP address
- Check firewall settings
- Verify Flask is running on 0.0.0.0
```

**4. Slow API Response**
```
Solution:
- Check database indexes
- Monitor query performance (EXPLAIN)
- Cache frequently accessed data
- Profile ML inference time
```

---

## Future Enhancements

### Planned Features
- [ ] Real-time threat intelligence integration
- [ ] Advanced NLP features (BERT embeddings)
- [ ] Multi-language support
- [ ] Email header analysis
- [ ] URL/link safety checking
- [ ] Batch scanning API
- [ ] Webhook notifications
- [ ] Admin dashboard web interface
- [ ] Model versioning and A/B testing
- [ ] GraphQL API option

### ML Improvements
- [ ] Active learning from user feedback
- [ ] Ensemble models
- [ ] Deep learning models (LSTM/Transformer)
- [ ] Feature importance visualization
- [ ] Explainable AI (LIME/SHAP)

---

## Additional Resources

### Documentation
- Flask: https://flask.palletsprojects.com/
- SQLAlchemy: https://docs.sqlalchemy.org/
- Retrofit: https://square.github.io/retrofit/
- scikit-learn: https://scikit-learn.org/

### Related Tools
- Postman: API testing
- DB Browser for SQLite: Database inspection
- Logcat: Android debugging
- Jupyter Notebook: ML model development

---

**Last Updated:** 2024-02-15  
**Version:** 1.0.0
