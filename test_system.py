"""
PhishGuard Test Script
Demonstrates the complete database-integrated system with sample data
"""

import os
import sys
from datetime import datetime, timedelta
import random

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, db
from models import ScanHistory, UserStatistics
from database_utils import DatabaseQueries, AnalyticsEngine, DataManagement


def populate_sample_data():
    """Generate sample scan data for testing"""
    print("\n" + "="*70)
    print("Populating Sample Data")
    print("="*70)
    
    # Sample messages (mix of phishing and safe)
    phishing_messages = [
        "URGENT: Your account has been compromised! Click here immediately: bit.ly/verify123",
        "You've won $10,000! Claim your prize now at winnow.com/claim",
        "Security Alert: Verify your identity within 24 hours or account will be locked",
        "Your package delivery failed. Update address: track-package.net/update",
        "IRS NOTICE: You owe $5,000 in back taxes. Pay immediately to avoid arrest",
        "Congratulations! You've been selected for a free iPhone 15. Click to claim!",
        "FINAL NOTICE: Your Netflix subscription has expired. Update payment info now",
        "Your bank account is suspended. Verify information: secure-bank-verify.com"
    ]
    
    safe_messages = [
        "Hey, are we still on for dinner tonight at 7pm?",
        "Thanks for your order! Your confirmation number is #12345",
        "Reminder: Your appointment is tomorrow at 2pm",
        "Great meeting today! Let's follow up next week",
        "Your package has been delivered to your front door",
        "Happy birthday! Hope you have an amazing day!",
        "Meeting rescheduled to Friday at 10am. See you there!",
        "Just checking in. How are you doing?",
        "Your flight is confirmed for tomorrow morning at 8:30am",
        "Thanks for subscribing to our newsletter!"
    ]
    
    # Generate users
    users = [f"user_{i}" for i in range(1, 11)]
    devices = [f"device_{chr(65+i)}" for i in range(5)]
    
    print(f"\nGenerating scan records...")
    
    scan_count = 0
    for i in range(200):  # Generate 200 scan records
        # Random timing over past 30 days
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        timestamp = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
        
        # Random user and device
        user_id = random.choice(users)
        device_id = random.choice(devices)
        
        # 30% chance of phishing message
        is_phishing = random.random() < 0.3
        
        if is_phishing:
            message_text = random.choice(phishing_messages)
            risk_score = random.uniform(0.6, 0.95)
        else:
            message_text = random.choice(safe_messages)
            risk_score = random.uniform(0.05, 0.45)
        
        # Determine confidence
        if risk_score > 0.8 or risk_score < 0.2:
            confidence = "HIGH"
        elif risk_score > 0.6 or risk_score < 0.4:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        # Random inference time
        prediction_time = random.randint(5, 50)
        
        # Create scan record
        scan = ScanHistory(
            user_id=user_id,
            device_id=device_id,
            message_text=message_text,
            is_phishing=is_phishing,
            risk_score=risk_score,
            confidence_level=confidence,
            model_version="v1.0.0",
            prediction_time_ms=prediction_time,
            created_at=timestamp,
            ip_address=f"192.168.1.{random.randint(1, 255)}",
            user_agent="PhishGuard Android/1.0"
        )
        
        # 40% chance of having user feedback
        if random.random() < 0.4:
            # 90% accuracy in feedback (mostly correct predictions)
            if random.random() < 0.9:
                scan.user_feedback = "CORRECT"
            else:
                scan.user_feedback = "INCORRECT"
            scan.feedback_timestamp = timestamp + timedelta(minutes=random.randint(1, 60))
        
        db.session.add(scan)
        scan_count += 1
        
        if scan_count % 50 == 0:
            print(f"  Created {scan_count} scan records...")
    
    db.session.commit()
    print(f"✓ Created {scan_count} scan records")
    
    # Generate user statistics
    print(f"\nGenerating user statistics...")
    for user_id in users:
        user_scans = ScanHistory.query.filter_by(user_id=user_id).all()
        
        if not user_scans:
            continue
        
        phishing_count = sum(1 for s in user_scans if s.is_phishing)
        safe_count = len(user_scans) - phishing_count
        avg_risk = sum(s.risk_score for s in user_scans) / len(user_scans)
        max_risk = max(s.risk_score for s in user_scans)
        
        feedback_count = sum(1 for s in user_scans if s.user_feedback)
        correct_count = sum(1 for s in user_scans if s.user_feedback == "CORRECT")
        incorrect_count = sum(1 for s in user_scans if s.user_feedback == "INCORRECT")
        
        stats = UserStatistics(
            user_id=user_id,
            total_scans=len(user_scans),
            phishing_detected=phishing_count,
            safe_messages=safe_count,
            average_risk_score=avg_risk,
            highest_risk_score=max_risk,
            first_scan_date=min(s.created_at for s in user_scans),
            last_scan_date=max(s.created_at for s in user_scans),
            feedback_provided=feedback_count,
            correct_predictions=correct_count,
            incorrect_predictions=incorrect_count
        )
        
        db.session.add(stats)
    
    db.session.commit()
    print(f"✓ Created statistics for {len(users)} users")
    
    print("="*70)


def display_sample_queries():
    """Demonstrate database queries"""
    print("\n" + "="*70)
    print("Sample Database Queries")
    print("="*70)
    
    # Query 1: Recent scans
    print("\n1. Recent Scans (Last 24 hours):")
    recent = DatabaseQueries.get_recent_scans(hours=24, limit=5)
    for scan in recent:
        print(f"   [{scan.created_at}] {'PHISHING' if scan.is_phishing else 'SAFE'} "
              f"(Risk: {scan.risk_score:.2f}) - {scan.message_text[:50]}...")
    
    # Query 2: High-risk scans
    print("\n2. High-Risk Scans (Risk > 0.8):")
    high_risk = DatabaseQueries.get_high_risk_scans(risk_threshold=0.8, limit=5)
    for scan in high_risk:
        print(f"   [User: {scan.user_id}] Risk: {scan.risk_score:.3f} - {scan.message_text[:50]}...")
    
    # Query 3: User statistics
    print("\n3. Top Users by Scan Count:")
    top_users = AnalyticsEngine.get_top_users_by_scans(limit=5)
    for stats in top_users:
        print(f"   {stats.user_id}: {stats.total_scans} scans, "
              f"{stats.phishing_detected} phishing ({stats.phishing_detected/stats.total_scans*100:.1f}%)")
    
    # Query 4: Model accuracy
    print("\n4. Model Accuracy (from user feedback):")
    accuracy = AnalyticsEngine.get_model_accuracy_from_feedback()
    print(f"   Total Feedback: {accuracy['total_feedback']}")
    print(f"   Correct Predictions: {accuracy['correct_predictions']}")
    print(f"   Incorrect Predictions: {accuracy['incorrect_predictions']}")
    print(f"   Accuracy: {accuracy['accuracy']:.2f}%")
    
    # Query 5: Phishing trends
    print("\n5. Phishing Detection Trends (Last 7 days):")
    trends = AnalyticsEngine.calculate_phishing_trends(days=7)
    for trend in trends[-7:]:  # Show last 7 days
        print(f"   {trend['date']}: {trend['total_scans']} scans, "
              f"{trend['phishing_count']} phishing ({trend['phishing_rate']:.1f}%)")
    
    # Query 6: Inference timing
    print("\n6. Model Inference Performance:")
    timing = AnalyticsEngine.calculate_average_inference_time()
    print(f"   Average: {timing['average_ms']:.2f}ms")
    print(f"   Range: {timing['min_ms']}ms - {timing['max_ms']}ms")
    print(f"   Total Predictions: {timing['total_predictions']}")
    
    print("="*70)


def display_system_overview():
    """Display overall system statistics"""
    print("\n" + "="*70)
    print("PhishGuard System Overview")
    print("="*70)
    
    from sqlalchemy import func
    
    # Total scans
    total_scans = db.session.query(func.count(ScanHistory.id)).scalar()
    print(f"\nTotal Scans: {total_scans:,}")
    
    # Phishing breakdown
    phishing_count = db.session.query(func.count(ScanHistory.id))\
        .filter_by(is_phishing=True).scalar()
    safe_count = total_scans - phishing_count
    print(f"Phishing Detected: {phishing_count:,} ({phishing_count/total_scans*100:.1f}%)")
    print(f"Safe Messages: {safe_count:,} ({safe_count/total_scans*100:.1f}%)")
    
    # Average risk
    avg_risk = db.session.query(func.avg(ScanHistory.risk_score)).scalar()
    print(f"\nAverage Risk Score: {avg_risk:.4f}")
    
    # User count
    user_count = db.session.query(func.count(UserStatistics.user_id)).scalar()
    print(f"Total Users: {user_count}")
    
    # Date range
    first_scan = db.session.query(func.min(ScanHistory.created_at)).scalar()
    last_scan = db.session.query(func.max(ScanHistory.created_at)).scalar()
    print(f"\nData Range: {first_scan} to {last_scan}")
    
    # Feedback statistics
    feedback_count = db.session.query(func.count(ScanHistory.id))\
        .filter(ScanHistory.user_feedback.isnot(None)).scalar()
    print(f"\nUser Feedback: {feedback_count:,} responses ({feedback_count/total_scans*100:.1f}%)")
    
    print("="*70)


def test_api_flow():
    """Simulate typical API usage flow"""
    print("\n" + "="*70)
    print("Simulated API Flow Test")
    print("="*70)
    
    from app import classify_message, hash_message, update_user_statistics
    
    test_user = "test_user_api"
    test_message = "URGENT: Your account will be closed! Click here: suspicious-link.com"
    
    print(f"\n1. Scanning message...")
    print(f"   User: {test_user}")
    print(f"   Message: {test_message}")
    
    # Classify message
    is_phishing, risk_score, confidence, pred_time = classify_message(test_message)
    
    print(f"\n2. Classification result:")
    print(f"   Is Phishing: {is_phishing}")
    print(f"   Risk Score: {risk_score:.4f}")
    print(f"   Confidence: {confidence}")
    print(f"   Prediction Time: {pred_time}ms")
    
    # Create scan record
    scan = ScanHistory(
        user_id=test_user,
        device_id="test_device",
        message_text=test_message,
        message_hash=hash_message(test_message),
        is_phishing=is_phishing,
        risk_score=risk_score,
        confidence_level=confidence,
        model_version="v1.0.0",
        prediction_time_ms=pred_time
    )
    
    db.session.add(scan)
    db.session.commit()
    
    print(f"\n3. Saved to database:")
    print(f"   Scan ID: {scan.id}")
    
    # Update statistics
    update_user_statistics(test_user, is_phishing, risk_score)
    
    print(f"\n4. Updated user statistics")
    
    # Retrieve user stats
    stats = UserStatistics.query.get(test_user)
    if stats:
        print(f"   Total Scans: {stats.total_scans}")
        print(f"   Phishing Detected: {stats.phishing_detected}")
        print(f"   Average Risk: {stats.average_risk_score:.4f}")
    
    print("="*70)


def main():
    """Main test execution"""
    print("\n")
    print("╔" + "═"*68 + "╗")
    print("║" + " "*20 + "PhishGuard Database Test Suite" + " "*18 + "║")
    print("╚" + "═"*68 + "╝")
    
    with app.app_context():
        # Check if database is empty
        scan_count = db.session.query(ScanHistory).count()
        
        if scan_count == 0:
            print("\n⚠ Database is empty. Populating with sample data...")
            populate_sample_data()
        else:
            print(f"\n✓ Database contains {scan_count} existing scan records")
            
            response = input("\nDo you want to add more sample data? (y/n): ")
            if response.lower() == 'y':
                populate_sample_data()
        
        # Display system overview
        display_system_overview()
        
        # Demonstrate queries
        display_sample_queries()
        
        # Test API flow
        test_api_flow()
    
    print("\n" + "="*70)
    print("Test Suite Complete!")
    print("="*70)
    print("\nNext steps:")
    print("1. Start the Flask server: python app.py")
    print("2. Test API endpoints with curl or Postman")
    print("3. Integrate with Android client")
    print("4. Review database contents: sqlite3 phishguard.db")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()
