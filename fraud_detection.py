import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from rules import FraudRules
from data_processor import DataProcessor
from ml_model import FraudMLModel

class FraudDetectionSystem:
    """
    Main fraud detection system integrating rules and ML model for fraud detection
    """
    def __init__(self):
        self.rules = FraudRules()
        self.data_processor = DataProcessor()
        self.ml_model = FraudMLModel()
        self.transactions_history = pd.DataFrame()
        self.use_ml_model = False  # Flag to control whether ML model is used alongside rules
        
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
        rules_risk_score, flags, actions = self.rules.calculate_risk_score(processed_data)
        
        # Final risk score starts with the rules-based score
        final_risk_score = rules_risk_score
        
        # If ML model is enabled and trained, enhance the risk score
        if self.use_ml_model and self.ml_model.model_ready:
            # Create a transaction dict with all features for ML model
            ml_txn_data = processed_data.copy()
            # Add the rules risk score as a feature
            ml_txn_data['risk_score'] = rules_risk_score
            
            # Get enhanced risk score from ML model
            final_risk_score = self.ml_model.predict_with_rules(ml_txn_data, rules_risk_score)
            
            # If ML significantly increased the risk score and it wasn't already high risk
            if final_risk_score >= 70 and rules_risk_score < 70:
                flags.append({"rule": "ML Detection", "details": "Machine learning model detected suspicious patterns"})
                actions.append("Review transaction - flagged by ML model")
                
        # Store result with transaction data
        result = {
            'transaction_data': transaction_data,
            'risk_score': final_risk_score,
            'rules_risk_score': rules_risk_score,  # Store original rules score for comparison
            'flags': flags,
            'actions': actions,
            'analysis_time': datetime.now(),
            'ml_enhanced': self.use_ml_model and self.ml_model.model_ready
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
                'rules_risk_score': r.get('rules_risk_score', r['risk_score']),
                'ml_enhanced': r.get('ml_enhanced', False),
                'flagged_rules': r['flags'],
                'recommended_actions': r['actions']
            }
            for r in results
        ])
        
        return results_df
        
    def enable_ml_model(self, enable=True):
        """
        Enable or disable ML model enhancement
        """
        self.use_ml_model = enable
        return self.use_ml_model and self.ml_model.model_ready
        
    def train_ml_model(self, labeled_data=None):
        """
        Train the ML model using transaction data with fraud labels
        If labeled_data is not provided, it will use the transaction history
        with rule-based risk scores to create synthetic labels
        
        Returns:
            success (bool): Whether training was successful
        """
        if labeled_data is not None:
            # Use provided labeled data
            return self.ml_model.train(labeled_data)
            
        if self.transactions_history is None or len(self.transactions_history) == 0:
            # No training data available
            return False
            
        # Evaluate all transactions with rules to get risk scores
        evaluated_df = self.evaluate_batch_transactions(self.transactions_history.to_dict('records'))
        
        # Train model using the evaluated data
        return self.ml_model.train(evaluated_df)
        
    def get_ml_feature_importance(self):
        """
        Get feature importance from the ML model
        Returns None if model is not trained
        """
        if not self.ml_model.model_ready:
            return None
            
        return self.ml_model.get_feature_importance()
        
    def save_ml_model(self, filepath='fraud_ml_model.pkl'):
        """Save the trained ML model to a file"""
        return self.ml_model.save_model(filepath)
        
    def load_ml_model(self, filepath='fraud_ml_model.pkl'):
        """Load a trained ML model from a file"""
        success = self.ml_model.load_model(filepath)
        if success:
            # Auto-enable the ML model if loading was successful
            self.use_ml_model = True
        return success
