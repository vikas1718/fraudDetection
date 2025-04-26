import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from datetime import datetime, timedelta
import pickle
import os

class FraudMLModel:
    """
    Machine Learning model for fraud detection that complements the rule-based system.
    This combines the power of ML with the explainability of rules.
    """
    
    def __init__(self):
        """Initialize the ML model"""
        self.model = None
        self.feature_columns = None
        self.scaler = StandardScaler()
        self.model_ready = False
        
    def prepare_features(self, transactions_df):
        """
        Extract and prepare features from transaction data for model training/prediction
        """
        if transactions_df is None or len(transactions_df) == 0:
            return None
            
        # Clone dataframe to avoid modifying the original
        df = transactions_df.copy()
        
        # Basic transaction features
        features = []
        
        # 1. Transaction amount features
        if 'amount' in df.columns:
            features.append('amount')
            
        # 2. Time-based features
        if 'timestamp' in df.columns:
            # Extract hour of day (capture night hour pattern - Rule 2)
            df['hour_of_day'] = df['timestamp'].dt.hour
            features.append('hour_of_day')
            
            # Is night hour (12 AM - 5 AM)? - Rule 2
            df['is_night_hour'] = df['hour_of_day'].apply(lambda x: 1 if 0 <= x < 5 else 0)
            features.append('is_night_hour')
            
            # Extract day of week
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            features.append('day_of_week')
        
        # 3. User history features
        if 'user_avg_amount' in df.columns:
            features.append('user_avg_amount')
            
            # Amount ratio (transaction amount / user average) - Rule 1
            df['amount_ratio'] = df['amount'] / df['user_avg_amount']
            features.append('amount_ratio')
            
            # Is unusual amount? (> 3x average) - Rule 1
            df['is_unusual_amount'] = df['amount_ratio'].apply(lambda x: 1 if x > 3.0 else 0)
            features.append('is_unusual_amount')
        
        # 4. Merchant features
        if 'merchant_age_months' in df.columns:
            features.append('merchant_age_months')
            
            # Is new merchant? (< 6 months) - Rule 3
            df['is_new_merchant'] = df['merchant_age_months'].apply(lambda x: 1 if x < 6 else 0)
            features.append('is_new_merchant')
        
        # 5. Authentication features - Rule 8
        if 'two_fa_completed' in df.columns:
            df['two_fa_completed'] = df['two_fa_completed'].astype(int)
            features.append('two_fa_completed')
        
        # 6. Location features - Rule 7
        # If we have location data, we could calculate distance
        # This is a simplified approach since real distance calculation is in the rules engine
        if 'location_mismatch' in df.columns:
            features.append('location_mismatch')
        
        # 7. Behavior pattern changes - Rule 9
        if 'current_pattern' in df.columns and 'historical_pattern' in df.columns:
            df['pattern_change'] = abs(df['current_pattern'] - df['historical_pattern']) / df['historical_pattern']
            features.append('pattern_change')
            
            # Is significant behavior change? (> 50%) - Rule 9
            df['is_behavior_change'] = df['pattern_change'].apply(lambda x: 1 if x >= 0.5 else 0)
            features.append('is_behavior_change')
            
        # 8. Risk score from rules engine
        if 'risk_score' in df.columns:
            features.append('risk_score')
        
        # Store feature columns for future prediction
        self.feature_columns = features
        
        # Extract features as numpy array
        X = df[features].values
        
        # Target variable (if available)
        y = None
        if 'is_fraud' in df.columns:
            y = df['is_fraud'].values
            
        return X, y, df
        
    def train(self, transactions_df, target_column='is_fraud'):
        """
        Train the ML model using transaction data
        If is_fraud column doesn't exist, it can use risk_score to create synthetic labels
        """
        if transactions_df is None or len(transactions_df) == 0:
            print("No training data provided")
            return False
            
        df = transactions_df.copy()
        
        # If no fraud labels exist but we have risk scores, create synthetic labels
        if target_column not in df.columns and 'risk_score' in df.columns:
            print("Creating synthetic fraud labels from risk scores")
            # Consider high risk transactions (risk_score >= 70) as fraudulent
            df['is_fraud'] = df['risk_score'].apply(lambda x: 1 if x >= 70 else 0)
            target_column = 'is_fraud'
        
        # If we still don't have target labels, we can't train
        if target_column not in df.columns:
            print("No target labels available for training")
            return False
            
        # Prepare features
        X, y, _ = self.prepare_features(df)
        
        if X is None or y is None:
            print("Failed to prepare features for training")
            return False
            
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Create and train model
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_prob = self.model.predict_proba(X_test_scaled)[:, 1]
        
        print("Model Training Results:")
        print(classification_report(y_test, y_pred))
        print("ROC AUC Score:", roc_auc_score(y_test, y_prob))
        
        self.model_ready = True
        return True
        
    def predict_fraud_probability(self, transaction_data):
        """
        Predict fraud probability for a single transaction or DataFrame of transactions
        Returns probability between 0-1
        """
        if not self.model_ready:
            return None
            
        # Convert single transaction to DataFrame if needed
        if isinstance(transaction_data, dict):
            transaction_data = pd.DataFrame([transaction_data])
            
        # Prepare features
        X, _, _ = self.prepare_features(transaction_data)
        
        if X is None:
            return None
            
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict probabilities
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        
        # If single transaction, return scalar
        if len(probabilities) == 1:
            return probabilities[0]
            
        return probabilities
        
    def predict_with_rules(self, transaction_data, rules_risk_score):
        """
        Combine ML model prediction with rules-based risk score
        Returns an enhanced risk score that leverages both approaches
        
        Args:
            transaction_data: Single transaction dict or DataFrame
            rules_risk_score: Risk score from rules engine (0-100)
            
        Returns:
            Enhanced risk score (0-100)
        """
        if not self.model_ready:
            return rules_risk_score
            
        # Get ML fraud probability
        ml_probability = self.predict_fraud_probability(transaction_data)
        
        if ml_probability is None:
            return rules_risk_score
            
        # Convert ML probability to 0-100 scale
        ml_score = ml_probability * 100
        
        # Blend the scores (equal weighting)
        # This can be adjusted based on reliability of each system
        blended_score = 0.5 * rules_risk_score + 0.5 * ml_score
        
        return min(100, blended_score)  # Cap at 100
        
    def save_model(self, filepath='fraud_ml_model.pkl'):
        """Save the trained model to a file"""
        if not self.model_ready:
            print("No trained model to save")
            return False
            
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_columns': self.feature_columns
            }, f)
            
        print(f"Model saved to {filepath}")
        return True
        
    def load_model(self, filepath='fraud_ml_model.pkl'):
        """Load a trained model from a file"""
        if not os.path.exists(filepath):
            print(f"Model file {filepath} not found")
            return False
            
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
                self.feature_columns = data['feature_columns']
                self.model_ready = True
                
            print(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
            
    def get_feature_importance(self):
        """Get feature importance from the model"""
        if not self.model_ready or self.feature_columns is None:
            return None
            
        # Get feature importance
        importance = self.model.feature_importances_
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'Feature': self.feature_columns,
            'Importance': importance
        })
        
        # Sort by importance
        importance_df = importance_df.sort_values('Importance', ascending=False)
        
        return importance_df