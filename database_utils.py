"""
PhishGuard Database Utilities
Helper functions for complex queries, analytics, and data management
"""

from datetime import datetime, timedelta, date
from sqlalchemy import func, and_, or_
from models import db, ScanHistory, UserStatistics, ModelMetrics


class DatabaseQueries:
    """Collection of reusable database query functions"""
    
    @staticmethod
    def get_recent_scans(hours=24, limit=100):
        """
        Retrieve recent scans within the specified time window
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of results
            
        Returns:
            List of ScanHistory objects
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return ScanHistory.query\
            .filter(ScanHistory.created_at >= cutoff_time)\
            .order_by(ScanHistory.created_at.desc())\
            .limit(limit)\
            .all()
    
    @staticmethod
    def get_high_risk_scans(risk_threshold=0.8, limit=50):
        """
        Retrieve scans with risk score above threshold
        
        Args:
            risk_threshold: Minimum risk score (0.0 to 1.0)
            limit: Maximum number of results
            
        Returns:
            List of ScanHistory objects
        """
        return ScanHistory.query\
            .filter(ScanHistory.risk_score >= risk_threshold)\
            .order_by(ScanHistory.risk_score.desc())\
            .limit(limit)\
            .all()
    
    @staticmethod
    def get_scans_by_date_range(start_date, end_date, user_id=None):
        """
        Retrieve scans within a date range, optionally filtered by user
        
        Args:
            start_date: Start datetime
            end_date: End datetime
            user_id: Optional user filter
            
        Returns:
            List of ScanHistory objects
        """
        query = ScanHistory.query.filter(
            and_(
                ScanHistory.created_at >= start_date,
                ScanHistory.created_at <= end_date
            )
        )
        
        if user_id:
            query = query.filter(ScanHistory.user_id == user_id)
        
        return query.order_by(ScanHistory.created_at.desc()).all()
    
    @staticmethod
    def get_duplicate_scans(user_id=None, limit=100):
        """
        Find duplicate message scans based on message hash
        
        Args:
            user_id: Optional user filter
            limit: Maximum number of duplicate groups
            
        Returns:
            List of tuples: (message_hash, count, first_scan_date)
        """
        query = db.session.query(
            ScanHistory.message_hash,
            func.count(ScanHistory.id).label('count'),
            func.min(ScanHistory.created_at).label('first_scan')
        )
        
        if user_id:
            query = query.filter(ScanHistory.user_id == user_id)
        
        return query\
            .group_by(ScanHistory.message_hash)\
            .having(func.count(ScanHistory.id) > 1)\
            .order_by(func.count(ScanHistory.id).desc())\
            .limit(limit)\
            .all()
    
    @staticmethod
    def get_scans_with_feedback(feedback_type=None):
        """
        Retrieve scans that have user feedback
        
        Args:
            feedback_type: Optional filter ('CORRECT', 'INCORRECT', 'UNSURE')
            
        Returns:
            List of ScanHistory objects
        """
        query = ScanHistory.query.filter(
            ScanHistory.user_feedback.isnot(None)
        )
        
        if feedback_type:
            query = query.filter(ScanHistory.user_feedback == feedback_type)
        
        return query.order_by(ScanHistory.feedback_timestamp.desc()).all()


class AnalyticsEngine:
    """Advanced analytics and reporting functions"""
    
    @staticmethod
    def calculate_hourly_scan_volume(days=7):
        """
        Calculate scan volume by hour for the past N days
        
        Args:
            days: Number of days to analyze
            
        Returns:
            List of dicts with hour and scan count
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        results = db.session.query(
            func.strftime('%H', ScanHistory.created_at).label('hour'),
            func.count(ScanHistory.id).label('scan_count')
        ).filter(
            ScanHistory.created_at >= cutoff
        ).group_by('hour').all()
        
        return [{'hour': int(r.hour), 'scan_count': r.scan_count} for r in results]
    
    @staticmethod
    def calculate_phishing_trends(days=30):
        """
        Calculate daily phishing detection trends
        
        Args:
            days: Number of days to analyze
            
        Returns:
            List of dicts with date, total scans, and phishing count
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        results = db.session.query(
            func.date(ScanHistory.created_at).label('scan_date'),
            func.count(ScanHistory.id).label('total_scans'),
            func.sum(func.cast(ScanHistory.is_phishing, db.Integer)).label('phishing_count')
        ).filter(
            ScanHistory.created_at >= cutoff
        ).group_by('scan_date').order_by('scan_date').all()
        
        return [{
            'date': r.scan_date,
            'total_scans': r.total_scans,
            'phishing_count': r.phishing_count or 0,
            'phishing_rate': round((r.phishing_count or 0) / r.total_scans * 100, 2)
        } for r in results]
    
    @staticmethod
    def get_risk_score_distribution(bins=10):
        """
        Calculate risk score distribution histogram
        
        Args:
            bins: Number of histogram bins
            
        Returns:
            List of dicts with risk range and count
        """
        bin_size = 1.0 / bins
        results = []
        
        for i in range(bins):
            lower = i * bin_size
            upper = (i + 1) * bin_size
            
            count = ScanHistory.query.filter(
                and_(
                    ScanHistory.risk_score >= lower,
                    ScanHistory.risk_score < upper
                )
            ).count()
            
            results.append({
                'range': f'{lower:.2f}-{upper:.2f}',
                'count': count
            })
        
        return results
    
    @staticmethod
    def get_top_users_by_scans(limit=10):
        """
        Get users with most scans
        
        Args:
            limit: Number of top users to return
            
        Returns:
            List of UserStatistics objects
        """
        return UserStatistics.query\
            .order_by(UserStatistics.total_scans.desc())\
            .limit(limit)\
            .all()
    
    @staticmethod
    def get_model_accuracy_from_feedback():
        """
        Calculate model accuracy based on user feedback
        
        Returns:
            Dict with accuracy metrics
        """
        total_feedback = db.session.query(
            func.count(ScanHistory.id)
        ).filter(
            ScanHistory.user_feedback.isnot(None)
        ).scalar()
        
        if not total_feedback:
            return {
                'total_feedback': 0,
                'accuracy': None,
                'message': 'No feedback data available'
            }
        
        correct_predictions = db.session.query(
            func.count(ScanHistory.id)
        ).filter(
            ScanHistory.user_feedback == 'CORRECT'
        ).scalar()
        
        incorrect_predictions = db.session.query(
            func.count(ScanHistory.id)
        ).filter(
            ScanHistory.user_feedback == 'INCORRECT'
        ).scalar()
        
        accuracy = correct_predictions / (correct_predictions + incorrect_predictions) if (correct_predictions + incorrect_predictions) > 0 else 0
        
        return {
            'total_feedback': total_feedback,
            'correct_predictions': correct_predictions,
            'incorrect_predictions': incorrect_predictions,
            'accuracy': round(accuracy * 100, 2)
        }
    
    @staticmethod
    def calculate_average_inference_time():
        """
        Calculate average model inference time
        
        Returns:
            Dict with timing statistics
        """
        stats = db.session.query(
            func.avg(ScanHistory.prediction_time_ms).label('avg_time'),
            func.min(ScanHistory.prediction_time_ms).label('min_time'),
            func.max(ScanHistory.prediction_time_ms).label('max_time'),
            func.count(ScanHistory.id).label('total_predictions')
        ).filter(
            ScanHistory.prediction_time_ms.isnot(None)
        ).first()
        
        return {
            'average_ms': round(stats.avg_time, 2) if stats.avg_time else None,
            'min_ms': stats.min_time,
            'max_ms': stats.max_time,
            'total_predictions': stats.total_predictions
        }


class DataManagement:
    """Functions for data cleanup and maintenance"""
    
    @staticmethod
    def delete_old_scans(days=90):
        """
        Delete scan records older than specified days
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of deleted records
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        deleted = ScanHistory.query.filter(
            ScanHistory.created_at < cutoff
        ).delete()
        
        db.session.commit()
        return deleted
    
    @staticmethod
    def anonymize_old_data(days=180):
        """
        Anonymize user data older than specified days (GDPR compliance)
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of anonymized records
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        updated = ScanHistory.query.filter(
            ScanHistory.created_at < cutoff
        ).update({
            'user_id': None,
            'device_id': None,
            'ip_address': None,
            'user_agent': None
        })
        
        db.session.commit()
        return updated
    
    @staticmethod
    def vacuum_database():
        """
        Optimize database by reclaiming space (SQLite VACUUM)
        """
        db.session.execute('VACUUM')
        db.session.commit()
    
    @staticmethod
    def export_scans_to_csv(output_path, start_date=None, end_date=None):
        """
        Export scan history to CSV file
        
        Args:
            output_path: Path to output CSV file
            start_date: Optional start date filter
            end_date: Optional end date filter
            
        Returns:
            Number of records exported
        """
        import csv
        
        query = ScanHistory.query
        
        if start_date:
            query = query.filter(ScanHistory.created_at >= start_date)
        if end_date:
            query = query.filter(ScanHistory.created_at <= end_date)
        
        scans = query.order_by(ScanHistory.created_at).all()
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'id', 'user_id', 'device_id', 'message_text', 'is_phishing',
                'risk_score', 'confidence_level', 'model_version', 
                'prediction_time_ms', 'created_at', 'user_feedback'
            ])
            
            # Write data
            for scan in scans:
                writer.writerow([
                    scan.id,
                    scan.user_id,
                    scan.device_id,
                    scan.message_text,
                    scan.is_phishing,
                    scan.risk_score,
                    scan.confidence_level,
                    scan.model_version,
                    scan.prediction_time_ms,
                    scan.created_at.isoformat() if scan.created_at else None,
                    scan.user_feedback
                ])
        
        return len(scans)


# Example usage functions
def print_recent_analytics():
    """Print recent system analytics"""
    print("\n" + "="*60)
    print("PhishGuard System Analytics")
    print("="*60)
    
    # Recent scans
    recent = DatabaseQueries.get_recent_scans(hours=24)
    print(f"\nScans in last 24h: {len(recent)}")
    
    # Phishing rate
    phishing_count = sum(1 for s in recent if s.is_phishing)
    if recent:
        print(f"Phishing detection rate: {phishing_count/len(recent)*100:.1f}%")
    
    # Model accuracy from feedback
    accuracy = AnalyticsEngine.get_model_accuracy_from_feedback()
    if accuracy['accuracy'] is not None:
        print(f"\nModel accuracy (from feedback): {accuracy['accuracy']}%")
        print(f"Total feedback received: {accuracy['total_feedback']}")
    
    # Inference time
    timing = AnalyticsEngine.calculate_average_inference_time()
    if timing['average_ms']:
        print(f"\nAverage inference time: {timing['average_ms']:.2f}ms")
        print(f"Range: {timing['min_ms']}ms - {timing['max_ms']}ms")
    
    print("="*60 + "\n")


if __name__ == '__main__':
    # Example: Run analytics
    from app import app
    
    with app.app_context():
        print_recent_analytics()
