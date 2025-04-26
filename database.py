import mysql.connector
from mysql.connector import Error
import pandas as pd
from datetime import datetime, timedelta
import streamlit as st

class DatabaseManager:
    """
    Class for managing database connections and operations for the fraud detection system.
    This connects to a local MySQL database running on XAMPP.
    """
    
    def __init__(self, host="localhost", user="root", password="", database="fraud_detection"):
        """
        Initialize the database manager with connection parameters.
        Default values are typical for XAMPP installations.
        """
        self.host = host
        self.user = user
        self.password = password  # Default empty password for XAMPP
        self.database = database
        self.connection = None
    
    def connect(self):
        """
        Create a connection to the MySQL database.
        Returns True if connection successful, False otherwise.
        """
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            
            if self.connection.is_connected():
                return True
                
        except Error as e:
            st.error(f"Error connecting to MySQL database: {e}")
            # If database doesn't exist, try to create it
            if "Unknown database" in str(e):
                return self.create_database()
                
        return False
    
    def create_database(self):
        """
        Create the database if it doesn't exist.
        Returns True if successful, False otherwise.
        """
        try:
            # Connect to MySQL server without specifying database
            conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password
            )
            
            if conn.is_connected():
                cursor = conn.cursor()
                
                # Create database
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
                cursor.close()
                conn.close()
                
                # Connect to the newly created database
                return self.connect()
                
        except Error as e:
            st.error(f"Error creating database: {e}")
            
        return False
    
    def create_tables(self):
        """
        Create required tables if they don't exist.
        Returns True if successful, False otherwise.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return False
            
        try:
            cursor = self.connection.cursor()
            
            # Create users table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100),
                email VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                avg_transaction_amount FLOAT DEFAULT 0,
                total_transactions INT DEFAULT 0,
                risk_level VARCHAR(20) DEFAULT 'low'
            )
            """)
            
            # Create merchants table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS merchants (
                merchant_id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(100),
                domain VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                merchant_age_months INT DEFAULT 0,
                risk_category VARCHAR(20) DEFAULT 'normal'
            )
            """)
            
            # Create transactions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id VARCHAR(50) PRIMARY KEY,
                user_id VARCHAR(50),
                merchant_id VARCHAR(50),
                amount FLOAT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                device_id VARCHAR(50),
                ip_address VARCHAR(50),
                two_fa_completed BOOLEAN DEFAULT TRUE,
                billing_latitude FLOAT,
                billing_longitude FLOAT,
                device_latitude FLOAT,
                device_longitude FLOAT,
                risk_score FLOAT DEFAULT 0,
                rules_risk_score FLOAT DEFAULT 0,
                ml_risk_score FLOAT DEFAULT 0,
                is_flagged BOOLEAN DEFAULT FALSE,
                review_status VARCHAR(20) DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id)
            )
            """)
            
            # Create flagged_rules table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS flagged_rules (
                id INT AUTO_INCREMENT PRIMARY KEY,
                transaction_id VARCHAR(50),
                rule_name VARCHAR(100),
                rule_details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            )
            """)
            
            # Create actions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS recommended_actions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                transaction_id VARCHAR(50),
                action_description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) DEFAULT 'pending',
                FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            )
            """)
            
            # Create login_attempts table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(50),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT FALSE,
                ip_address VARCHAR(50),
                device_id VARCHAR(50),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """)
            
            # Create user_sessions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(50),
                device_id VARCHAR(50),
                ip_address VARCHAR(50),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_end DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            """)
            
            # Create recipient_flags table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS recipient_flags (
                id INT AUTO_INCREMENT PRIMARY KEY,
                recipient_id VARCHAR(50),
                reporter_user_id VARCHAR(50),
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_user_id) REFERENCES users(user_id)
            )
            """)
            
            # Commit changes
            self.connection.commit()
            cursor.close()
            
            return True
            
        except Error as e:
            st.error(f"Error creating tables: {e}")
            
        return False
    
    def insert_sample_data(self):
        """
        Insert sample data into the database for testing.
        Returns True if successful, False otherwise.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return False
            
        try:
            cursor = self.connection.cursor()
            
            # Check if users table already has data
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            
            # Only insert sample data if tables are empty
            if count > 0:
                return True
                
            # Insert sample users
            user_data = [
                ('U001', 'John Doe', 'john@example.com', 80.0),
                ('U002', 'Jane Smith', 'jane@example.com', 1000.0),
                ('U003', 'Bob Johnson', 'bob@example.com', 150.0),
                ('U004', 'Alice Brown', 'alice@example.com', 250.0),
                ('U005', 'Charlie Davis', 'charlie@example.com', 350.0),
                ('U006', 'Emma Wilson', 'emma@example.com', 1000.0),
                ('U007', 'Frank Miller', 'frank@example.com', 650.0),
                ('U008', 'Grace Lee', 'grace@example.com', 750.0),
                ('U009', 'Henry Garcia', 'henry@example.com', 850.0),
                ('U010', 'Isabella Martinez', 'isabella@example.com', 950.0),
                ('U011', 'Jack Robinson', 'jack@example.com', 1050.0),
            ]
            
            cursor.executemany("""
            INSERT INTO users (user_id, name, email, avg_transaction_amount)
            VALUES (%s, %s, %s, %s)
            """, user_data)
            
            # Insert sample merchants
            merchant_data = [
                ('M001', 'Regular Shop', 'regularshop.com', 24),
                ('M002', 'Grocery Store', 'grocerystore.com', 36),
                ('M003', 'Night Market', 'nightmarket.com', 12),
                ('M004', 'New Store', 'newstore.com', 2),
                ('M005', 'Tech Gadgets', 'techgadgets.com', 18),
                ('BADMERCHANT', 'Suspicious Vendor', 'suspiciousvendor.com', 1),
            ]
            
            cursor.executemany("""
            INSERT INTO merchants (merchant_id, name, domain, merchant_age_months)
            VALUES (%s, %s, %s, %s)
            """, merchant_data)
            
            # Insert sample transactions would be more complex due to the 
            # relationships and timestamp handling - we'll skip this for now
            # and implement it separately
            
            # Commit changes
            self.connection.commit()
            cursor.close()
            
            return True
            
        except Error as e:
            st.error(f"Error inserting sample data: {e}")
            
        return False
    
    def load_transactions(self, limit=1000):
        """
        Load transactions from the database.
        Returns a pandas DataFrame with transaction data.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return pd.DataFrame()
            
        try:
            query = f"""
            SELECT t.*, 
                   u.avg_transaction_amount as user_avg_amount,
                   m.merchant_age_months
            FROM transactions t
            JOIN users u ON t.user_id = u.user_id
            JOIN merchants m ON t.merchant_id = m.merchant_id
            ORDER BY t.timestamp DESC
            LIMIT {limit}
            """
            
            return pd.read_sql(query, self.connection)
            
        except Error as e:
            st.error(f"Error loading transactions: {e}")
            
        return pd.DataFrame()
    
    def load_users(self):
        """
        Load users from the database.
        Returns a pandas DataFrame with user data.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return pd.DataFrame()
            
        try:
            query = "SELECT * FROM users"
            return pd.read_sql(query, self.connection)
            
        except Error as e:
            st.error(f"Error loading users: {e}")
            
        return pd.DataFrame()
    
    def load_merchants(self):
        """
        Load merchants from the database.
        Returns a pandas DataFrame with merchant data.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return pd.DataFrame()
            
        try:
            query = "SELECT * FROM merchants"
            return pd.read_sql(query, self.connection)
            
        except Error as e:
            st.error(f"Error loading merchants: {e}")
            
        return pd.DataFrame()
    
    def save_transaction_results(self, transaction_data, risk_result):
        """
        Save transaction and fraud detection results to the database.
        
        Args:
            transaction_data: Dict with transaction details
            risk_result: Dict with risk analysis results
            
        Returns:
            True if successful, False otherwise
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return False
            
        try:
            cursor = self.connection.cursor()
            
            # Check if user exists, insert if not
            cursor.execute("SELECT 1 FROM users WHERE user_id = %s", (transaction_data.get('user_id'),))
            if not cursor.fetchone():
                cursor.execute("""
                INSERT INTO users (user_id, avg_transaction_amount)
                VALUES (%s, %s)
                """, (transaction_data.get('user_id'), transaction_data.get('user_avg_amount', 0)))
            
            # Check if merchant exists, insert if not
            cursor.execute("SELECT 1 FROM merchants WHERE merchant_id = %s", (transaction_data.get('merchant_id'),))
            if not cursor.fetchone():
                cursor.execute("""
                INSERT INTO merchants (merchant_id, merchant_age_months)
                VALUES (%s, %s)
                """, (transaction_data.get('merchant_id'), transaction_data.get('merchant_age_months', 0)))
            
            # Insert transaction
            cursor.execute("""
            INSERT INTO transactions 
            (transaction_id, user_id, merchant_id, amount, timestamp, device_id, ip_address, 
             two_fa_completed, billing_latitude, billing_longitude, device_latitude, device_longitude,
             risk_score, rules_risk_score, is_flagged)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            risk_score = VALUES(risk_score),
            rules_risk_score = VALUES(rules_risk_score),
            is_flagged = VALUES(is_flagged)
            """, (
                transaction_data.get('transaction_id'),
                transaction_data.get('user_id'),
                transaction_data.get('merchant_id'),
                transaction_data.get('amount'),
                transaction_data.get('timestamp'),
                transaction_data.get('device_id'),
                transaction_data.get('ip_address'),
                transaction_data.get('two_fa_completed', True),
                transaction_data.get('billing_location', {}).get('lat') if transaction_data.get('billing_location') else None,
                transaction_data.get('billing_location', {}).get('lon') if transaction_data.get('billing_location') else None,
                transaction_data.get('device_location', {}).get('lat') if transaction_data.get('device_location') else None,
                transaction_data.get('device_location', {}).get('lon') if transaction_data.get('device_location') else None,
                risk_result.get('risk_score'),
                risk_result.get('rules_risk_score', risk_result.get('risk_score')),
                risk_result.get('risk_score', 0) >= 70  # Flag if risk score is high
            ))
            
            # Insert flagged rules
            if risk_result.get('flags'):
                for flag in risk_result.get('flags'):
                    cursor.execute("""
                    INSERT INTO flagged_rules (transaction_id, rule_name, rule_details)
                    VALUES (%s, %s, %s)
                    """, (
                        transaction_data.get('transaction_id'),
                        flag.get('rule'),
                        flag.get('details')
                    ))
            
            # Insert recommended actions
            if risk_result.get('actions'):
                for action in risk_result.get('actions'):
                    cursor.execute("""
                    INSERT INTO recommended_actions (transaction_id, action_description)
                    VALUES (%s, %s)
                    """, (
                        transaction_data.get('transaction_id'),
                        action
                    ))
            
            # Update user stats
            cursor.execute("""
            UPDATE users 
            SET total_transactions = total_transactions + 1,
                avg_transaction_amount = ((avg_transaction_amount * total_transactions) + %s) / (total_transactions + 1)
            WHERE user_id = %s
            """, (
                transaction_data.get('amount'),
                transaction_data.get('user_id')
            ))
            
            # Commit changes
            self.connection.commit()
            cursor.close()
            
            return True
            
        except Error as e:
            st.error(f"Error saving transaction results: {e}")
            
        return False
    
    def get_recent_transactions_for_user(self, user_id, minutes=10, max_count=10):
        """
        Get recent transactions for a user within the specified time window.
        Useful for smurfing detection (Rule 5).
        
        Returns a list of transaction dicts.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return []
            
        try:
            # Calculate cutoff time
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            
            query = """
            SELECT * FROM transactions
            WHERE user_id = %s AND timestamp > %s
            ORDER BY timestamp DESC
            LIMIT %s
            """
            
            df = pd.read_sql(query, self.connection, params=(user_id, cutoff_time, max_count))
            
            # Convert DataFrame to list of dicts
            if len(df) > 0:
                return df.to_dict('records')
                
        except Error as e:
            st.error(f"Error getting recent transactions: {e}")
            
        return []
    
    def get_recent_login_attempts(self, user_id, minutes=5):
        """
        Get recent login attempts for a user within the specified time window.
        Useful for failed login detection (Rule 6).
        
        Returns a list of login attempt dicts.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return []
            
        try:
            # Calculate cutoff time
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            
            query = """
            SELECT * FROM login_attempts
            WHERE user_id = %s AND timestamp > %s
            ORDER BY timestamp DESC
            """
            
            df = pd.read_sql(query, self.connection, params=(user_id, cutoff_time))
            
            # Convert DataFrame to list of dicts
            if len(df) > 0:
                return df.to_dict('records')
                
        except Error as e:
            st.error(f"Error getting recent login attempts: {e}")
            
        return []
    
    def get_recent_user_sessions(self, user_id, minutes=10):
        """
        Get recent user sessions for device change detection (Rule 4).
        
        Returns a list of session dicts.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return []
            
        try:
            # Calculate cutoff time
            cutoff_time = datetime.now() - timedelta(minutes=minutes)
            
            query = """
            SELECT * FROM user_sessions
            WHERE user_id = %s AND timestamp > %s
            ORDER BY timestamp DESC
            """
            
            df = pd.read_sql(query, self.connection, params=(user_id, cutoff_time))
            
            # Convert DataFrame to list of dicts
            if len(df) > 0:
                return df.to_dict('records')
                
        except Error as e:
            st.error(f"Error getting recent user sessions: {e}")
            
        return []
    
    def get_flagged_recipients(self, days=30):
        """
        Get recipients flagged within the specified time window (Rule 10).
        
        Returns a dict mapping recipient_id to list of flag timestamps.
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
            
        if not self.connection:
            return {}
            
        try:
            # Calculate cutoff time
            cutoff_time = datetime.now() - timedelta(days=days)
            
            query = """
            SELECT recipient_id, timestamp
            FROM recipient_flags
            WHERE timestamp > %s
            ORDER BY timestamp DESC
            """
            
            df = pd.read_sql(query, self.connection, params=(cutoff_time,))
            
            # Group by recipient_id
            if len(df) > 0:
                result = {}
                for _, row in df.iterrows():
                    recipient_id = row['recipient_id']
                    if recipient_id not in result:
                        result[recipient_id] = []
                    result[recipient_id].append(row['timestamp'])
                return result
                
        except Error as e:
            st.error(f"Error getting flagged recipients: {e}")
            
        return {}
    
    def close_connection(self):
        """Close the database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            
    def __del__(self):
        """Destructor to ensure connection is closed."""
        self.close_connection()