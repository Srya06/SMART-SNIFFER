"""
Alert storage and management
JSON and SQLite support
"""
import json
import sqlite3
import os
from datetime import datetime

class AlertStorage:
    def __init__(self, config):
        self.config = config
        self.json_file = config['storage']['alerts_json']
        self.db_file = config['storage']['alerts_db']
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.json_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
        
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    src_ip TEXT,
                    timestamp TEXT,
                    severity TEXT,
                    details TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def save_alert(self, alert):
        """Save alert to both JSON and database"""
        self._save_to_json(alert)
        self._save_to_database(alert)
    
    def _save_to_json(self, alert):
        """Save alert to JSON file"""
        try:
            alerts = []
            
            # Read existing alerts
            if os.path.exists(self.json_file):
                with open(self.json_file, 'r') as f:
                    alerts = json.load(f)
            
            # Add new alert
            alerts.append(alert)
            
            # Keep only recent alerts
            max_alerts = self.config['storage']['max_alerts_display']
            alerts = alerts[-max_alerts:]
            
            # Write back
            with open(self.json_file, 'w') as f:
                json.dump(alerts, f, indent=2)
                
        except Exception as e:
            print(f"JSON save error: {e}")
    
    def _save_to_database(self, alert):
        """Save alert to SQLite database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (id, type, src_ip, timestamp, severity, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert['id'],
                alert['type'],
                alert['src_ip'],
                alert['timestamp'],
                alert['severity'],
                alert['details']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Database save error: {e}")
    
    def load_alerts(self, limit=100):
        """Load alerts from database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'id': row[0],
                    'type': row[1],
                    'src_ip': row[2],
                    'timestamp': row[3],
                    'severity': row[4],
                    'details': row[5]
                })
            
            conn.close()
            return alerts
            
        except Exception as e:
            print(f"Database load error: {e}")
            return []