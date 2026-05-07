"""
Code Change Tracker Service
Tracks code changes and security scan results
"""
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any
import os

class CodeChangeTracker:
    """Tracks code changes and their security scan results"""
    
    def __init__(self, db_path: str = "code_changes.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database for storing code changes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table for code changes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                language TEXT,
                context TEXT,
                scan_results TEXT,
                detected_issues INTEGER DEFAULT 0
            )
        """)
        
        # Create indexes for faster querying
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON code_changes(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_language ON code_changes(language)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_code_hash ON code_changes(code_hash)")
        
        conn.commit()
        conn.close()
    
    def record_code_change(self, code_block: str, language: str = "unknown", scan_results: Dict = None):
        """Record a code change and its security scan results"""
        import hashlib
        
        # Calculate a hash of the code block to identify duplicates
        code_hash = hashlib.sha256(code_block.encode()).hexdigest()
        
        # Count detected issues
        detected_issues = len(scan_results.get("issues", [])) if scan_results else 0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert the code change record
        cursor.execute("""
            INSERT INTO code_changes 
            (timestamp, code_hash, language, context, scan_results, detected_issues)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            code_hash,
            language,
            scan_results.get("context", "unknown") if scan_results else "unknown",
            json.dumps(scan_results) if scan_results else "{}",
            detected_issues
        ))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about tracked code changes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total changes
        cursor.execute("SELECT COUNT(*) FROM code_changes")
        total_changes = cursor.fetchone()[0]
        
        # Changes by language
        cursor.execute("""
            SELECT language, COUNT(*) 
            FROM code_changes 
            GROUP BY language
        """)
        changes_by_language = dict(cursor.fetchall())
        
        # Changes with issues
        cursor.execute("SELECT COUNT(*) FROM code_changes WHERE detected_issues > 0")
        changes_with_issues = cursor.fetchone()[0]
        
        # Total issues detected
        cursor.execute("SELECT SUM(detected_issues) FROM code_changes")
        total_issues = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "total_changes": total_changes,
            "changes_with_issues": changes_with_issues,
            "total_issues_detected": total_issues,
            "changes_by_language": changes_by_language,
            "issue_rate": round(changes_with_issues / total_changes * 100, 2) if total_changes > 0 else 0
        }
    
    def get_recent_changes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent code changes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, language, detected_issues, scan_results
            FROM code_changes
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        changes = []
        for row in rows:
            changes.append({
                "timestamp": row[0],
                "language": row[1],
                "detected_issues": row[2],
                "scan_results": json.loads(row[3])
            })
        
        return changes
    
    def get_issue_summary(self) -> Dict[str, Any]:
        """Get a summary of detected issues"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get scan results for all changes with issues
        cursor.execute("""
            SELECT scan_results 
            FROM code_changes 
            WHERE detected_issues > 0
        """)
        rows = cursor.fetchall()
        
        conn.close()
        
        # Aggregate issue types
        issue_types = {}
        for row in rows:
            scan_results = json.loads(row[0])
            for issue in scan_results.get("issues", []):
                issue_title = issue.get("title", "Unknown")
                if issue_title in issue_types:
                    issue_types[issue_title] += 1
                else:
                    issue_types[issue_title] = 1
        
        return {
            "total_issue_types": len(issue_types),
            "issue_frequency": dict(sorted(issue_types.items(), key=lambda x: x[1], reverse=True))
        }