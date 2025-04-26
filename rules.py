import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class FraudRules:
    """
    Implementation of ScamPay's fraud detection rules
    """
    def __init__(self):
        # Rule parameters - these could be made configurable
        self.avg_amount_threshold = 3.0  # Flag transactions > 3x user's average amount
        self.night_hours_risk_increase = 0.2  # 20% risk increase during night hours (12-5 AM)
        self.new_merchant_age_months = 6  # Flag payments to new merchants (< 6 months)
        self.device_change_minutes = 10  # Block device ID/IP changes within 10 minutes
        self.smurfing_threshold_count = 5  # Number of small transactions to flag as smurfing
        self.smurfing_threshold_amount = 500  # Amount threshold for smurfing in INR
        self.smurfing_threshold_minutes = 10  # Time window for smurfing detection
        self.failed_login_threshold = 3  # Failed login attempts before requiring OTP
        self.failed_login_window_minutes = 5  # Time window for failed login attempts
        self.location_difference_threshold_km = 500  # Threshold for location mismatch
        self.behavior_pattern_change_threshold = 0.5  # 50% behavior pattern change threshold
        self.recipient_flag_threshold = 2  # Number of flags before auto-blocking recipient
        self.recipient_flag_days = 30  # Time window for recipient flags

    def rule1_unusual_amount(self, transaction_amount, user_avg_amount):
        """
        Rule 1: Flag transactions > 3x user's average amount
        """
        if transaction_amount > self.avg_amount_threshold * user_avg_amount:
            return True, f"Transaction amount (₹{transaction_amount}) is {transaction_amount/user_avg_amount:.1f}x higher than user average (₹{user_avg_amount})"
        return False, ""

    def rule2_night_hour_risk(self, transaction_time):
        """
        Rule 2: Increase risk score by 20% for transactions between 12-5 AM
        """
        hour = transaction_time.hour
        if 0 <= hour < 5:
            return True, f"Transaction occurred during high-risk hours ({hour}:00)"
        return False, ""

    def rule3_new_merchant(self, merchant_domain_age_months):
        """
        Rule 3: Flag payments to new merchants (domain age < 6 months)
        """
        if merchant_domain_age_months < self.new_merchant_age_months:
            return True, f"Payment to new merchant (domain age: {merchant_domain_age_months} months)"
        return False, ""

    def rule4_device_change(self, current_device_id, current_ip, user_sessions):
        """
        Rule 4: Block and verify when device ID/IP changes with transaction within 10 minutes
        """
        if user_sessions is None or len(user_sessions) == 0:
            return False, ""

        # Get recent sessions within threshold time
        now = datetime.now()
        recent_sessions = [
            s for s in user_sessions 
            if (now - s['timestamp']) < timedelta(minutes=self.device_change_minutes)
        ]
        
        for session in recent_sessions:
            if (session['device_id'] != current_device_id or 
                session['ip_address'] != current_ip):
                return True, f"Device/IP changed within {self.device_change_minutes} minutes"
        return False, ""

    def rule5_smurfing_detection(self, user_transactions):
        """
        Rule 5: Flag potential smurfing (5+ transactions under ₹500 within 10 minutes)
        """
        if user_transactions is None or len(user_transactions) < self.smurfing_threshold_count:
            return False, ""
            
        # Sort transactions by timestamp
        sorted_transactions = sorted(user_transactions, key=lambda x: x['timestamp'])
        
        # Check for small transactions within time window
        for i in range(len(sorted_transactions) - self.smurfing_threshold_count + 1):
            window_transactions = sorted_transactions[i:i+self.smurfing_threshold_count]
            
            # Check if all transactions are below threshold
            all_small = all(t['amount'] < self.smurfing_threshold_amount for t in window_transactions)
            
            # Check if time window is within threshold
            time_diff = (window_transactions[-1]['timestamp'] - 
                        window_transactions[0]['timestamp']).total_seconds() / 60
            
            if all_small and time_diff <= self.smurfing_threshold_minutes:
                return True, f"Detected {self.smurfing_threshold_count}+ small transactions within {self.smurfing_threshold_minutes} minutes"
        
        return False, ""

    def rule6_failed_login_attempts(self, recent_login_attempts):
        """
        Rule 6: Enforce OTP after 3 failed login attempts within 5 minutes
        """
        if recent_login_attempts is None:
            return False, ""
            
        # Count failed attempts within time window
        now = datetime.now()
        recent_failed = [
            a for a in recent_login_attempts
            if (a['success'] == False and 
                (now - a['timestamp']) < timedelta(minutes=self.failed_login_window_minutes))
        ]
        
        if len(recent_failed) >= self.failed_login_threshold:
            return True, f"Detected {len(recent_failed)} failed login attempts within {self.failed_login_window_minutes} minutes"
        return False, ""

    def rule7_location_mismatch(self, billing_location, device_location):
        """
        Rule 7: Flag when billing address and device location differ by 500+ km
        """
        if billing_location is None or device_location is None:
            return False, ""
            
        # Simple Haversine distance calculation
        def haversine_distance(lat1, lon1, lat2, lon2):
            R = 6371  # Earth radius in kilometers
            dLat = np.radians(lat2 - lat1)
            dLon = np.radians(lon2 - lon1)
            a = (np.sin(dLat/2) * np.sin(dLat/2) + 
                np.cos(np.radians(lat1)) * np.cos(np.radians(lat2)) * 
                np.sin(dLon/2) * np.sin(dLon/2))
            c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1-a))
            distance = R * c
            return distance
        
        distance = haversine_distance(
            billing_location['lat'], billing_location['lon'],
            device_location['lat'], device_location['lon']
        )
        
        if distance >= self.location_difference_threshold_km:
            return True, f"Location mismatch: device and billing address {int(distance)} km apart"
        return False, ""

    def rule8_incomplete_2fa(self, two_fa_completed):
        """
        Rule 8: Auto-reject transactions without completed 2FA
        """
        if not two_fa_completed:
            return True, "Transaction attempted without completed 2FA"
        return False, ""

    def rule9_behavior_change(self, current_pattern, historical_pattern):
        """
        Rule 9: Raise anomaly alerts for 50% behavior pattern changes
        """
        if historical_pattern is None or current_pattern is None:
            return False, ""
            
        # Calculate pattern difference (simplified)
        pattern_diff = abs(current_pattern - historical_pattern) / historical_pattern
        
        if pattern_diff >= self.behavior_pattern_change_threshold:
            return True, f"Behavior pattern changed by {pattern_diff*100:.1f}%"
        return False, ""

    def rule10_flagged_recipient(self, recipient_id, flagged_recipients):
        """
        Rule 10: Auto-block recipients flagged 2+ times in last 30 days
        """
        if flagged_recipients is None or recipient_id not in flagged_recipients:
            return False, ""
            
        recent_flags = flagged_recipients[recipient_id]
        now = datetime.now()
        recent_count = sum(1 for flag_time in recent_flags 
                         if (now - flag_time) < timedelta(days=self.recipient_flag_days))
        
        if recent_count >= self.recipient_flag_threshold:
            return True, f"Recipient flagged {recent_count} times in the last {self.recipient_flag_days} days"
        return False, ""

    def calculate_risk_score(self, transaction_data):
        """
        Calculate an overall risk score based on all rules
        Returns:
            - risk_score: numeric value from 0-100
            - flags: list of triggered rules with explanations
            - actions: recommended actions 
        """
        base_score = 0
        flags = []
        actions = []
        
        # Apply Rule 1: Unusual Amount
        triggered, message = self.rule1_unusual_amount(
            transaction_data.get('amount', 0), 
            transaction_data.get('user_avg_amount', 1)
        )
        if triggered:
            base_score += 25
            flags.append({"rule": "Unusual Amount", "details": message})
            actions.append("Send verification SMS to user")
        
        # Apply Rule 2: Night Hour Risk
        triggered, message = self.rule2_night_hour_risk(
            transaction_data.get('timestamp', datetime.now())
        )
        if triggered:
            # Increase overall risk score by 20%
            base_score = base_score * 1.2
            flags.append({"rule": "Night Hour Risk", "details": message})
        
        # Apply Rule 3: New Merchant
        triggered, message = self.rule3_new_merchant(
            transaction_data.get('merchant_age_months', 0)
        )
        if triggered:
            base_score += 15
            flags.append({"rule": "New Merchant", "details": message})
            actions.append("Verify merchant details")
        
        # Apply Rule 4: Device Change
        triggered, message = self.rule4_device_change(
            transaction_data.get('device_id', ''),
            transaction_data.get('ip_address', ''),
            transaction_data.get('user_sessions', [])
        )
        if triggered:
            base_score += 30
            flags.append({"rule": "Device Change", "details": message})
            actions.append("Block transaction and require verification")
        
        # Apply Rule 5: Smurfing Detection
        triggered, message = self.rule5_smurfing_detection(
            transaction_data.get('user_recent_transactions', [])
        )
        if triggered:
            base_score += 40
            flags.append({"rule": "Smurfing Pattern", "details": message})
            actions.append("Flag account for review")
        
        # Apply Rule 6: Failed Login Attempts
        triggered, message = self.rule6_failed_login_attempts(
            transaction_data.get('login_attempts', [])
        )
        if triggered:
            base_score += 20
            flags.append({"rule": "Failed Logins", "details": message})
            actions.append("Require OTP verification")
        
        # Apply Rule 7: Location Mismatch
        triggered, message = self.rule7_location_mismatch(
            transaction_data.get('billing_location', None),
            transaction_data.get('device_location', None)
        )
        if triggered:
            base_score += 35
            flags.append({"rule": "Location Mismatch", "details": message})
            actions.append("Request additional identity verification")
        
        # Apply Rule 8: Incomplete 2FA
        triggered, message = self.rule8_incomplete_2fa(
            transaction_data.get('two_fa_completed', False)
        )
        if triggered:
            base_score = 100  # Auto-reject
            flags.append({"rule": "Incomplete 2FA", "details": message})
            actions.append("Reject transaction")
        
        # Apply Rule 9: Behavior Change
        triggered, message = self.rule9_behavior_change(
            transaction_data.get('current_pattern', 0),
            transaction_data.get('historical_pattern', 0)
        )
        if triggered:
            base_score += 25
            flags.append({"rule": "Behavior Change", "details": message})
            actions.append("Require additional verification steps")
        
        # Apply Rule 10: Flagged Recipient
        triggered, message = self.rule10_flagged_recipient(
            transaction_data.get('recipient_id', ''),
            transaction_data.get('flagged_recipients', {})
        )
        if triggered:
            base_score = 100  # Auto-block
            flags.append({"rule": "Flagged Recipient", "details": message})
            actions.append("Block transaction")
        
        # Cap the risk score at 100
        risk_score = min(100, base_score)
        
        return risk_score, flags, actions
