import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

class DataProcessor:
    """
    Class for processing and preparing transaction data
    """
    def __init__(self):
        # Initialize with empty data
        self.transactions_df = None
        self.users_df = None
        self.merchants_df = None
        
    def load_data(self, transactions_data=None, users_data=None, merchants_data=None):
        """
        Load data for analysis
        If data is provided, use it. Otherwise, display messaging that data needs to be loaded.
        """
        if transactions_data is not None:
            self.transactions_df = transactions_data
        
        if users_data is not None:
            self.users_df = users_data
            
        if merchants_data is not None:
            self.merchants_df = merchants_data
    
    def prepare_transaction_for_analysis(self, transaction_data):
        """
        Prepare a single transaction data dict for fraud rule analysis
        This would typically pull additional context from other data sources
        """
        # Add/calculate any additional fields needed for rule evaluation
        processed_data = transaction_data.copy()
        
        # Convert timestamp string to datetime if needed
        if isinstance(processed_data.get('timestamp'), str):
            processed_data['timestamp'] = datetime.fromisoformat(processed_data['timestamp'])
        elif 'timestamp' not in processed_data:
            processed_data['timestamp'] = datetime.now()
        
        return processed_data
    
    def get_user_transaction_stats(self, user_id):
        """
        Calculate transaction statistics for a user
        Returns a dict with:
        - avg_amount: average transaction amount
        - max_amount: maximum transaction amount
        - transaction_count: number of transactions
        - etc.
        """
        # If we have user transaction data
        if self.transactions_df is not None and 'user_id' in self.transactions_df.columns:
            user_txns = self.transactions_df[self.transactions_df['user_id'] == user_id]
            
            if len(user_txns) > 0:
                stats = {
                    'avg_amount': user_txns['amount'].mean(),
                    'max_amount': user_txns['amount'].max(),
                    'transaction_count': len(user_txns),
                    'last_transaction_time': user_txns['timestamp'].max()
                }
                return stats
        
        # Default values if no data
        return {
            'avg_amount': 1000,  # Default average
            'max_amount': 1000,
            'transaction_count': 0,
            'last_transaction_time': datetime.now() - timedelta(days=7)
        }
    
    def get_merchant_info(self, merchant_id):
        """
        Get information about a merchant
        """
        # If we have merchant data
        if self.merchants_df is not None and 'merchant_id' in self.merchants_df.columns:
            merchant = self.merchants_df[self.merchants_df['merchant_id'] == merchant_id]
            
            if len(merchant) > 0:
                return merchant.iloc[0].to_dict()
        
        # Default values if no data
        return {
            'merchant_id': merchant_id,
            'merchant_name': f"Merchant {merchant_id}",
            'merchant_age_months': 12,  # Default age in months
            'risk_category': 'unknown'
        }
    
    def get_transaction_context(self, transaction_id):
        """
        Get full context for a transaction
        """
        # If we have transaction data
        if self.transactions_df is not None:
            txn = self.transactions_df[self.transactions_df['transaction_id'] == transaction_id]
            
            if len(txn) > 0:
                txn_data = txn.iloc[0].to_dict()
                
                # Add user stats
                user_stats = self.get_user_transaction_stats(txn_data['user_id'])
                txn_data.update({
                    'user_avg_amount': user_stats['avg_amount'],
                    'user_max_amount': user_stats['max_amount'],
                })
                
                # Add merchant info
                merchant_info = self.get_merchant_info(txn_data['merchant_id'])
                txn_data.update({
                    'merchant_age_months': merchant_info['merchant_age_months'],
                    'merchant_risk_category': merchant_info['risk_category']
                })
                
                return txn_data
                
        # Return None if transaction not found
        return None
    
    def get_top_flagged_transactions(self, limit=10):
        """
        Get the top flagged transactions based on risk score
        """
        # If we have transaction data with risk scores
        if self.transactions_df is not None and 'risk_score' in self.transactions_df.columns:
            # Sort by risk score (descending) and take top N
            top_flagged = self.transactions_df.sort_values('risk_score', ascending=False).head(limit)
            return top_flagged
        
        # Return empty dataframe if no data
        return pd.DataFrame()
    
    def aggregate_fraud_metrics(self):
        """
        Aggregate fraud metrics for dashboard display
        """
        metrics = {}
        
        # If we have transaction data
        if self.transactions_df is not None and 'risk_score' in self.transactions_df.columns:
            # Total transactions
            metrics['total_transactions'] = len(self.transactions_df)
            
            # High risk transactions (risk score >= 70)
            high_risk = self.transactions_df[self.transactions_df['risk_score'] >= 70]
            metrics['high_risk_count'] = len(high_risk)
            metrics['high_risk_percentage'] = (len(high_risk) / len(self.transactions_df) * 100) if len(self.transactions_df) > 0 else 0
            
            # Medium risk transactions (30 <= risk score < 70)
            medium_risk = self.transactions_df[(self.transactions_df['risk_score'] >= 30) & (self.transactions_df['risk_score'] < 70)]
            metrics['medium_risk_count'] = len(medium_risk)
            
            # Low risk transactions (risk score < 30)
            low_risk = self.transactions_df[self.transactions_df['risk_score'] < 30]
            metrics['low_risk_count'] = len(low_risk)
            
            # Calculate average risk score
            metrics['avg_risk_score'] = self.transactions_df['risk_score'].mean()
            
            # Group by flagged rules if available
            if 'flagged_rules' in self.transactions_df.columns:
                rule_counts = {}
                for rules in self.transactions_df['flagged_rules']:
                    if isinstance(rules, list):
                        for rule in rules:
                            rule_name = rule.get('rule', 'Unknown')
                            rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
                
                metrics['rule_counts'] = rule_counts
        else:
            # Default metrics if no data
            metrics = {
                'total_transactions': 0,
                'high_risk_count': 0,
                'high_risk_percentage': 0,
                'medium_risk_count': 0,
                'low_risk_count': 0,
                'avg_risk_score': 0,
                'rule_counts': {}
            }
            
        return metrics
