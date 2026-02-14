# PhishGuard: ML-Powered Phishing Detection System with Database Integration

A complete end-to-end machine learning pipeline for SMS/email phishing detection with Flask backend, SQLite database persistence, and Android client integration.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Android Client                           │
│  (User Interface + Retrofit API Client)                     │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/JSON
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Flask REST API                             │
│  • /api/scan - Message classification                       │
│  • /api/history - Scan history retrieval                    │
│  • /api/statistics - User analytics                         │
│  • /api/feedback - User feedback collection                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼                           ▼
┌──────────────────┐        ┌─────────────────┐
│  ML Model        │        │  SQLite Database │
│  (Scikit-learn)  │        │  • scan_history  │
│  • Vectorizer    │        │  • user_stats    │
│  • Classifier    │        │  • model_metrics │
└──────────────────┘        └─────────────────┘
```

## 📊 Database Schema

### Table: `scan_history`
Primary table storing all phishing scans with full audit trail.

| Column              | Type         | Description                           |
|---------------------|--------------|---------------------------------------|
| id                  | INTEGER      | Primary key (auto-increment)          |
| user_id             | VARCHAR(100) | User identifier (indexed)             |
| device_id           | VARCHAR(100) | Device identifier                     |
| message_text        | TEXT         | Scanned message content               |
| message_hash        | VARCHAR(64)  | SHA-256 hash for deduplication        |
| is_phishing         | BOOLEAN      | Prediction result                     |
| risk_score          | FLOAT        | Risk probability (0.0 - 1.0)          |
| confidence_level    | VARCHAR(20)  | LOW, MEDIUM, HIGH                     |
| model_version       | VARCHAR(50)  | Model version used                    |
| prediction_time_ms  | INTEGER      | Inference latency                     |
| extracted_features  | JSON         | Feature data (optional)               |
| created_at          | DATETIME     | Timestamp (indexed)                   |
| user_feedback       | VARCHAR(20)  | CORRECT, INCORRECT, UNSURE            |
| feedback_timestamp  | DATETIME     | Feedback submission time              |
| ip_address          | VARCHAR(45)  | Client IP address                     |
| user_agent          | VARCHAR(200) | Client user agent                     |

**Indexes:**
- `idx_user_created` (user_id, created_at)
- `idx_phishing_risk` (is_phishing, risk_score)
- `idx_created_date` (created_at)
- `message_hash` (for deduplication queries)

### Table: `user_statistics`
Aggregated user-level metrics for dashboard display.

| Column               | Type         | Description                          |
|----------------------|--------------|--------------------------------------|
| user_id              | VARCHAR(100) | Primary key                          |
| total_scans          | INTEGER      | Total scans performed                |
| phishing_detected    | INTEGER      | Number of phishing messages          |
| safe_messages        | INTEGER      | Number of safe messages              |
| average_risk_score   | FLOAT        | Average risk across all scans        |
| highest_risk_score   | FLOAT        | Highest risk score encountered       |
| first_scan_date      | DATETIME     | First scan timestamp                 |
| last_scan_date       | DATETIME     | Most recent scan timestamp           |
| feedback_provided    | INTEGER      | Count of feedback submissions        |
| correct_predictions  | INTEGER      | Count of correct predictions         |
| incorrect_predictions| INTEGER      | Count of incorrect predictions       |
| updated_at           | DATETIME     | Last update timestamp                |

### Table: `model_metrics`
Model performance tracking over time.

| Column                    | Type        | Description                       |
|---------------------------|-------------|-----------------------------------|
| id                        | INTEGER     | Primary key                       |
| model_version             | VARCHAR(50) | Model version (indexed)           |
| total_predictions         | INTEGER     | Total predictions made            |
| phishing_predictions      | INTEGER     | Phishing class predictions        |
| safe_predictions          | INTEGER     | Safe class predictions            |
| true_positives            | INTEGER     | TP count (from feedback)          |
| false_positives           | INTEGER     | FP count (from feedback)          |
| true_negatives            | INTEGER     | TN count (from feedback)          |
| false_negatives           | INTEGER     | FN count (from feedback)          |
| precision                 | FLOAT       | Computed precision                |
| recall                    | FLOAT       | Computed recall                   |
| f1_score                  | FLOAT       | Computed F1 score                 |
| average_inference_time_ms | FLOAT       | Average inference latency         |
| min_inference_time_ms     | INTEGER     | Minimum inference time            |
| max_inference_time_ms     | INTEGER     | Maximum inference time            |
| metric_date               | DATE        | Date of metrics (indexed)         |
| created_at                | DATETIME    | Creation timestamp                |

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip
- Android Studio (for client development)

### Backend Setup

1. **Clone and navigate to project:**
```bash
cd phishguard_db
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Create models directory (if using trained model):**
```bash
mkdir -p models
# Place your trained model files:
# - models/phishing_classifier.pkl
# - models/tfidf_vectorizer.pkl
```

4. **Initialize database:**
```bash
python app.py
```
The database will be automatically created on first run.

5. **Run the server:**
```bash
python app.py
```
Server will start on `http://localhost:5000`

### Android Client Setup

1. **Add dependencies to `build.gradle`:**
```gradle
dependencies {
    // Retrofit
    implementation 'com.squareup.retrofit2:retrofit:2.9.0'
    implementation 'com.squareup.retrofit2:converter-gson:2.9.0'
    
    // OkHttp
    implementation 'com.squareup.okhttp3:okhttp:4.12.0'
    implementation 'com.squareup.okhttp3:logging-interceptor:4.12.0'
    
    // Coroutines
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
    
    // ViewModel
    implementation 'androidx.lifecycle:lifecycle-viewmodel-ktx:2.6.2'
    implementation 'androidx.lifecycle:lifecycle-runtime-ktx:2.6.2'
}
```

2. **Add internet permission to `AndroidManifest.xml`:**
```xml
<uses-permission android:name="android.permission.INTERNET" />
```

3. **Update BASE_URL in `PhishGuardApiService.kt`:**
```kotlin
// For Android Emulator connecting to localhost:
private const val BASE_URL = "http://10.0.2.2:5000/"

// For real device (replace with your server IP):
private const val BASE_URL = "http://192.168.1.100:5000/"
```

4. **Integrate the API client in your Activity/Fragment** (see example in `PhishGuardApiService.kt`)

## 📡 API Reference

### Base URL
```
http://localhost:5000
```

### Endpoints

#### 1. Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_version": "v1.0.0",
  "database": "connected",
  "timestamp": "2024-02-15T10:30:00.000000"
}
```

---

#### 2. Scan Message
```http
POST /api/scan
Content-Type: application/json

{
  "message": "URGENT: Click here to verify your account immediately!",
  "user_id": "user123",
  "device_id": "device456"
}
```

**Response:**
```json
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

---

#### 3. Get Scan History
```http
GET /api/history?user_id=user123&limit=50&offset=0&phishing_only=false
```

**Response:**
```json
{
  "scans": [
    {
      "id": 42,
      "user_id": "user123",
      "message_text": "URGENT: Click here...",
      "is_phishing": true,
      "risk_score": 0.8742,
      "confidence_level": "HIGH",
      "model_version": "v1.0.0",
      "created_at": "2024-02-15T10:30:00.000000",
      "user_feedback": null
    }
  ],
  "total_count": 156,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

---

#### 4. Get User Statistics
```http
GET /api/statistics/user123
```

**Response:**
```json
{
  "statistics": {
    "user_id": "user123",
    "total_scans": 156,
    "phishing_detected": 23,
    "safe_messages": 133,
    "average_risk_score": 0.2341,
    "highest_risk_score": 0.9123,
    "first_scan_date": "2024-01-01T00:00:00.000000",
    "last_scan_date": "2024-02-15T10:30:00.000000",
    "feedback_provided": 45,
    "correct_predictions": 42,
    "incorrect_predictions": 3
  },
  "status": "success"
}
```

---

#### 5. Submit Feedback
```http
POST /api/feedback
Content-Type: application/json

{
  "scan_id": 42,
  "feedback": "CORRECT"
}
```

**Response:**
```json
{
  "message": "Feedback recorded successfully",
  "status": "success"
}
```

Feedback values: `CORRECT`, `INCORRECT`, `UNSURE`

---

#### 6. Analytics Dashboard
```http
GET /api/analytics/dashboard
```

**Response:**
```json
{
  "total_scans": 15623,
  "phishing_detected": 2341,
  "safe_messages": 13282,
  "phishing_rate": 14.98,
  "average_risk_score": 0.2145,
  "scans_last_24h": 234,
  "total_users": 456,
  "average_inference_time_ms": 12.34,
  "model_version": "v1.0.0",
  "timestamp": "2024-02-15T10:30:00.000000"
}
```

## 🔧 Advanced Usage

### Database Queries

```python
from database_utils import DatabaseQueries, AnalyticsEngine

# Get recent high-risk scans
high_risk = DatabaseQueries.get_high_risk_scans(risk_threshold=0.8, limit=10)

# Calculate phishing trends
trends = AnalyticsEngine.calculate_phishing_trends(days=30)

# Get model accuracy from user feedback
accuracy = AnalyticsEngine.get_model_accuracy_from_feedback()
```

### Data Management

```python
from database_utils import DataManagement

# Export data to CSV
DataManagement.export_scans_to_csv('export.csv', start_date, end_date)

# Delete old records (GDPR compliance)
deleted = DataManagement.delete_old_scans(days=90)

# Anonymize old data
anonymized = DataManagement.anonymize_old_data(days=180)
```

## 🧪 Testing

### Test API endpoints with curl:

```bash
# Health check
curl http://localhost:5000/health

# Scan a message
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"message": "URGENT: Verify your account now!", "user_id": "test_user"}'

# Get scan history
curl "http://localhost:5000/api/history?user_id=test_user&limit=10"

# Get user statistics
curl http://localhost:5000/api/statistics/test_user
```

## 📈 Production Deployment

### Using Gunicorn (Production WSGI Server)

```bash
# Install gunicorn
pip install gunicorn

# Run with 4 worker processes
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Environment Variables

Create a `.env` file:
```env
FLASK_ENV=production
DATABASE_URL=sqlite:///phishguard.db
MODEL_VERSION=v1.0.0
SECRET_KEY=your-secret-key-here
```

### Docker Deployment (Optional)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## 🔐 Security Considerations

1. **API Authentication**: Add JWT or API key authentication for production
2. **Rate Limiting**: Implement rate limiting to prevent abuse
3. **Input Validation**: All user inputs are validated and sanitized
4. **SQL Injection**: Using SQLAlchemy ORM prevents SQL injection
5. **CORS**: Configure CORS appropriately for your domains
6. **HTTPS**: Always use HTTPS in production
7. **Data Privacy**: Implement data retention and anonymization policies

## 📊 Performance Optimization

1. **Database Indexing**: Indexes on frequently queried columns (user_id, created_at)
2. **Connection Pooling**: SQLAlchemy connection pool configured
3. **Caching**: Consider Redis for frequently accessed statistics
4. **Async Processing**: Use Celery for heavy analytics tasks
5. **Model Loading**: Models loaded once at startup, not per request

## 🐛 Troubleshooting

### Issue: Model files not found
**Solution:** Create a `models` directory and add your trained model files, or the API will use mock predictions.

### Issue: Database locked errors
**Solution:** SQLite may have concurrency issues with high traffic. Consider PostgreSQL for production.

### Issue: Android client can't connect
**Solution:** 
- For emulator: Use `10.0.2.2` instead of `localhost`
- For device: Use your computer's IP address
- Check firewall settings

### Issue: Slow inference times
**Solution:**
- Optimize feature extraction
- Use model quantization
- Consider TensorFlow Lite for mobile deployment

## 📚 Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/)
- [Retrofit Documentation](https://square.github.io/retrofit/)
- [Scikit-learn](https://scikit-learn.org/)

## 📝 License

Apache-2.0 license - see LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please submit pull requests or open issues for bugs/features.

---

**Built with Passion and a lot of Coffee, for secure communication**

Author: Ares Coding 
