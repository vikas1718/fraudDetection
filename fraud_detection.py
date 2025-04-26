import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from rules import FraudRules
from data_processor import DataProcessor

class FraudDetectionSystem:
    """
    Main fraud detection system integrating rules and data processing
    """
    def __init__(self):
        self.rules = FraudRules()
        self.data_processor = DataProcessor()
        self.transactions_history = pd.DataFrame()
        
    def load_data(self, transactions_data=None, users_data=None, merchants_data=None):
        """
        Load data into the system
        """
        self.data_processor.load_data(transactions_data, users_data, merchants_data)
        
        # If transactions data is provided, keep a copy
        if transactions_data is not None:
            self.transactions_history = transactions_data.copy()
    
    def analyze_transaction(self, transaction_data):
        """
        Analyze a single transaction for fraud indicators
        Returns:
        - risk_score: 0-100 value indicating fraud risk
        - flags: list of triggered rules
        - actions: recommended actions
        """
        # Prepare transaction data with necessary context
        processed_data = self.data_processor.prepare_transaction_for_analysis(transaction_data)
        
        # Calculate risk score using rules
        risk_score, flags, actions = self.rules.calculate_risk_score(processed_data)
        
        # Store result with transaction data
        result = {
            'transaction_data': transaction_data,
            'risk_score': risk_score,
            'flags': flags,
            'actions': actions,
            'analysis_time': datetime.now()
        }
        
        return result
    
    def get_fraud_metrics(self):
        """
        Get aggregated fraud metrics
        """
        return self.data_processor.aggregate_fraud_metrics()
    
    def get_top_flagged_transactions(self, limit=10):
        """
        Get top flagged transactions
        """
        return self.data_processor.get_top_flagged_transactions(limit)
    
    def evaluate_batch_transactions(self, transactions_batch):
        """
        Evaluate a batch of transactions for fraud
        """
        results = []
        
        for txn in transactions_batch:
            result = self.analyze_transaction(txn)
            results.append(result)
        
        # Create DataFrame from results
        results_df = pd.DataFrame([
            {
                'transaction_id': r['transaction_data'].get('transaction_id', ''),
                'user_id': r['transaction_data'].get('user_id', ''),
                'amount': r['transaction_data'].get('amount', 0),
                'timestamp': r['transaction_data'].get('timestamp', datetime.now()),
                'merchant_id': r['transaction_data'].get('merchant_id', ''),
                'risk_score': r['risk_score'],
                'flagged_rules': r['flags'],
                'recommended_actions': r['actions']
            }
            for r in results
        ])
        
        return results_df
