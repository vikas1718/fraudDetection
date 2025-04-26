import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.express as px
import json

from fraud_detection import FraudDetectionSystem
from visualization import FraudVisualizer

# Set page configuration
st.set_page_config(
    page_title="ScamPay Fraud Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize the fraud detection system and visualizer
@st.cache_resource
def get_fraud_system():
    return FraudDetectionSystem()

@st.cache_resource
def get_visualizer():
    return FraudVisualizer()

fraud_system = get_fraud_system()
visualizer = get_visualizer()

# Helper function to create a sample transaction
def create_sample_transaction(
    transaction_id=None,
    user_id=None,
    amount=None,
    timestamp=None,
    merchant_id=None,
    device_id=None,
    ip_address=None,
    merchant_age_months=None,
    user_avg_amount=None,
    device_location=None,
    billing_location=None,
    two_fa_completed=None
):
    # Generate default values for any missing fields
    if transaction_id is None:
        transaction_id = f"TX{int(datetime.now().timestamp())}"
    if user_id is None:
        user_id = "U12345"
    if amount is None:
        amount = 1000.0
    if timestamp is None:
        timestamp = datetime.now()
    if merchant_id is None:
        merchant_id = "M67890"
    if device_id is None:
        device_id = "D54321"
    if ip_address is None:
        ip_address = "192.168.1.1"
    if merchant_age_months is None:
        merchant_age_months = 12
    if user_avg_amount is None:
        user_avg_amount = 1000.0
    if device_location is None:
        device_location = {"lat": 40.7128, "lon": -74.0060}  # NYC
    if billing_location is None:
        billing_location = {"lat": 40.7128, "lon": -74.0060}  # NYC
    if two_fa_completed is None:
        two_fa_completed = True
        
    # Create and return the transaction dict
    transaction = {
        "transaction_id": transaction_id,
        "user_id": user_id,
        "amount": amount,
        "timestamp": timestamp,
        "merchant_id": merchant_id,
        "device_id": device_id,
        "ip_address": ip_address,
        "merchant_age_months": merchant_age_months,
        "user_avg_amount": user_avg_amount,
        "device_location": device_location,
        "billing_location": billing_location,
        "two_fa_completed": two_fa_completed,
        # Additional fields that might be needed by rules
        "user_sessions": [],
        "user_recent_transactions": [],
        "login_attempts": [],
        "current_pattern": 1.0,
        "historical_pattern": 1.0,
        "recipient_id": "REC12345",
        "flagged_recipients": {}
    }
    
    return transaction

# Generate sample transaction data if not already in session state
if 'sample_transactions' not in st.session_state:
    st.session_state.sample_transactions = []
    
    # Create various sample transactions that trigger different rules
    
    # Normal transaction
    st.session_state.sample_transactions.append(
        create_sample_transaction(
            transaction_id="TX001",
            user_id="U001",
            amount=100,
            timestamp=datetime.now() - timedelta(hours=2),
            merchant_age_months=24,
            user_avg_amount=80
        )
    )
    
    # High amount transaction (Rule 1)
    st.session_state.sample_transactions.append(
        create_sample_transaction(
            transaction_id="TX002",
            user_id="U002",
            amount=5000,
            timestamp=datetime.now() - timedelta(hours=4),
            user_avg_amount=1000
        )
    )
    
    # Night hours transaction (Rule 2)
    night_time = datetime.now().replace(hour=2, minute=30)
    st.session_state.sample_transactions.append(
        create_sample_transaction(
            transaction_id="TX003",
            user_id="U003",
            amount=200,
            timestamp=night_time,
            user_avg_amount=150
        )
    )
    
    # New merchant transaction (Rule 3)
    st.session_state.sample_transactions.append(
        create_sample_transaction(
            transaction_id="TX004",
            user_id="U004",
            amount=300,
            timestamp=datetime.now() - timedelta(hours=6),
            merchant_age_months=2,
            user_avg_amount=250
        )
    )
    
    # Device change transaction (Rule 4)
    device_change_txn = create_sample_transaction(
        transaction_id="TX005",
        user_id="U005",
        amount=400,
        timestamp=datetime.now() - timedelta(minutes=5),
        device_id="NEWDEVICE",
        user_avg_amount=350
    )
    # Add a prior session with different device
    device_change_txn["user_sessions"] = [
        {
            "device_id": "OLDDEVICE",
            "ip_address": "10.0.0.1",
            "timestamp": datetime.now() - timedelta(minutes=2)
        }
    ]
    st.session_state.sample_transactions.append(device_change_txn)
    
    # Smurfing pattern transaction (Rule 5)
    smurfing_txn = create_sample_transaction(
        transaction_id="TX006",
        user_id="U006",
        amount=100,
        timestamp=datetime.now(),
        user_avg_amount=1000
    )
    # Add recent small transactions
    recent_txns = []
    for i in range(5):
        recent_txns.append({
            "amount": 90 + i,
            "timestamp": datetime.now() - timedelta(minutes=i)
        })
    smurfing_txn["user_recent_transactions"] = recent_txns
    st.session_state.sample_transactions.append(smurfing_txn)
    
    # Failed login attempts transaction (Rule 6)
    failed_login_txn = create_sample_transaction(
        transaction_id="TX007",
        user_id="U007",
        amount=700,
        timestamp=datetime.now() - timedelta(hours=1),
        user_avg_amount=650
    )
    # Add failed login attempts
    login_attempts = []
    for i in range(4):
        login_attempts.append({
            "success": False,
            "timestamp": datetime.now() - timedelta(minutes=i*2)
        })
    failed_login_txn["login_attempts"] = login_attempts
    st.session_state.sample_transactions.append(failed_login_txn)
    
    # Location mismatch transaction (Rule 7)
    location_mismatch_txn = create_sample_transaction(
        transaction_id="TX008",
        user_id="U008",
        amount=800,
        timestamp=datetime.now() - timedelta(hours=3),
        user_avg_amount=750
    )
    # Set different billing and device locations
    location_mismatch_txn["billing_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
    location_mismatch_txn["device_location"] = {"lat": 34.0522, "lon": -118.2437}  # LA
    st.session_state.sample_transactions.append(location_mismatch_txn)
    
    # Incomplete 2FA transaction (Rule 8)
    st.session_state.sample_transactions.append(
        create_sample_transaction(
            transaction_id="TX009",
            user_id="U009",
            amount=900,
            timestamp=datetime.now() - timedelta(hours=5),
            user_avg_amount=850,
            two_fa_completed=False
        )
    )
    
    # Behavior change transaction (Rule 9)
    behavior_change_txn = create_sample_transaction(
        transaction_id="TX010",
        user_id="U010",
        amount=1000,
        timestamp=datetime.now() - timedelta(hours=7),
        user_avg_amount=950
    )
    # Set changed behavior pattern
    behavior_change_txn["current_pattern"] = 1.8
    behavior_change_txn["historical_pattern"] = 1.0
    st.session_state.sample_transactions.append(behavior_change_txn)
    
    # Flagged recipient transaction (Rule 10)
    flagged_recipient_txn = create_sample_transaction(
        transaction_id="TX011",
        user_id="U011",
        amount=1100,
        timestamp=datetime.now() - timedelta(hours=8),
        user_avg_amount=1050
    )
    # Set flagged recipient
    flagged_recipient_txn["recipient_id"] = "BADRECIPIENT"
    flagged_recipient_txn["flagged_recipients"] = {
        "BADRECIPIENT": [
            datetime.now() - timedelta(days=1),
            datetime.now() - timedelta(days=5),
            datetime.now() - timedelta(days=15)
        ]
    }
    st.session_state.sample_transactions.append(flagged_recipient_txn)
    
    # Add a few more normal transactions
    for i in range(12, 20):
        st.session_state.sample_transactions.append(
            create_sample_transaction(
                transaction_id=f"TX0{i}",
                user_id=f"U0{i}",
                amount=i * 50,
                timestamp=datetime.now() - timedelta(hours=i % 12),
                user_avg_amount=i * 40
            )
        )

# Process the sample transactions if not already done
if 'processed_transactions' not in st.session_state:
    results = []
    for txn in st.session_state.sample_transactions:
        result = fraud_system.analyze_transaction(txn)
        results.append(result)
    
    # Convert results to DataFrame
    data = []
    for r in results:
        txn = r['transaction_data']
        data.append({
            'transaction_id': txn.get('transaction_id', ''),
            'user_id': txn.get('user_id', ''),
            'amount': txn.get('amount', 0),
            'timestamp': txn.get('timestamp', datetime.now()),
            'merchant_id': txn.get('merchant_id', ''),
            'risk_score': r['risk_score'],
            'flagged_rules': r['flags'],
            'recommended_actions': r['actions']
        })
    
    st.session_state.processed_transactions = pd.DataFrame(data)

# App title and description
st.title("🛡️ ScamPay Fraud Detection Dashboard")
st.markdown("""
This dashboard demonstrates ScamPay's fraud detection system implementing 10 specific fraud detection rules.
Monitor transactions, analyze risk patterns, and identify potential fraud in real-time.
""")

# Main dashboard tabs
tab1, tab2, tab3, tab4 = st.tabs(["Dashboard Overview", "Transaction Analysis", "Rule Testing", "Database Management"])

# Tab 1: Dashboard Overview
with tab1:
    # Metrics section
    st.header("Fraud Detection Metrics")
    
    # Calculate metrics from the processed transactions
    metrics = {
        'total_transactions': len(st.session_state.processed_transactions),
        'high_risk_count': len(st.session_state.processed_transactions[st.session_state.processed_transactions['risk_score'] >= 70]),
        'high_risk_percentage': len(st.session_state.processed_transactions[st.session_state.processed_transactions['risk_score'] >= 70]) / len(st.session_state.processed_transactions) * 100,
        'medium_risk_count': len(st.session_state.processed_transactions[(st.session_state.processed_transactions['risk_score'] >= 30) & (st.session_state.processed_transactions['risk_score'] < 70)]),
        'low_risk_count': len(st.session_state.processed_transactions[st.session_state.processed_transactions['risk_score'] < 30]),
        'avg_risk_score': st.session_state.processed_transactions['risk_score'].mean()
    }
    
    # Display metrics
    visualizer.create_metrics_dashboard(metrics)
    
    # Charts section
    st.subheader("Fraud Detection Visualizations")
    
    # Create two columns for charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk distribution chart
        fig1 = visualizer.plot_risk_distribution(st.session_state.processed_transactions)
        if fig1:
            st.plotly_chart(fig1, use_container_width=True)
        
        # Rule trigger frequency chart
        fig3 = visualizer.plot_rule_trigger_frequency(st.session_state.processed_transactions)
        if fig3:
            st.plotly_chart(fig3, use_container_width=True)
    
    with col2:
        # Risk timeline chart
        fig2 = visualizer.plot_risk_timeline(st.session_state.processed_transactions)
        if fig2:
            st.plotly_chart(fig2, use_container_width=True)
        
        # Hourly risk chart
        fig4 = visualizer.plot_hourly_transaction_risk(st.session_state.processed_transactions)
        if fig4:
            st.plotly_chart(fig4, use_container_width=True)
    
    # High risk transactions table
    st.subheader("High Risk Transactions")
    high_risk_txns = st.session_state.processed_transactions[st.session_state.processed_transactions['risk_score'] >= 70].sort_values('risk_score', ascending=False)
    
    if len(high_risk_txns) > 0:
        # Format the table for display
        display_df = high_risk_txns[['transaction_id', 'user_id', 'amount', 'timestamp', 'risk_score']].copy()
        display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        display_df.columns = ['Transaction ID', 'User ID', 'Amount', 'Timestamp', 'Risk Score']
        st.dataframe(display_df, use_container_width=True)
    else:
        st.info("No high-risk transactions detected")

# Tab 2: Transaction Analysis
with tab2:
    st.header("Transaction Analysis")
    
    # Transaction selection
    transaction_options = st.session_state.processed_transactions['transaction_id'].tolist()
    selected_transaction = st.selectbox(
        "Select a transaction for detailed analysis:",
        transaction_options
    )
    
    # Get the selected transaction data
    if selected_transaction:
        txn_data = st.session_state.processed_transactions[
            st.session_state.processed_transactions['transaction_id'] == selected_transaction
        ].iloc[0]
        
        # Show transaction details and risk analysis
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Transaction Details")
            details = pd.DataFrame({
                'Field': ['Transaction ID', 'User ID', 'Amount', 'Timestamp', 'Merchant ID'],
                'Value': [
                    txn_data['transaction_id'],
                    txn_data['user_id'],
                    f"₹{txn_data['amount']:.2f}",
                    txn_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    txn_data['merchant_id']
                ]
            })
            st.dataframe(details, hide_index=True, use_container_width=True)
            
            # Flagged rules
            st.subheader("Flagged Rules")
            flagged_rules = txn_data['flagged_rules']
            if len(flagged_rules) > 0:
                for rule in flagged_rules:
                    st.warning(f"**{rule['rule']}**: {rule['details']}")
            else:
                st.success("No rules triggered for this transaction")
            
            # Recommended actions
            st.subheader("Recommended Actions")
            actions = txn_data['recommended_actions']
            if len(actions) > 0:
                for action in actions:
                    st.info(action)
            else:
                st.success("No actions recommended for this transaction")
        
        with col2:
            st.subheader("Risk Score")
            risk_gauge = visualizer.create_risk_gauge(txn_data['risk_score'])
            st.plotly_chart(risk_gauge, use_container_width=True)
            
            # Risk category
            risk_level = "Low Risk"
            risk_color = "green"
            if txn_data['risk_score'] >= 70:
                risk_level = "High Risk"
                risk_color = "red"
            elif txn_data['risk_score'] >= 30:
                risk_level = "Medium Risk"
                risk_color = "orange"
                
            st.markdown(f"<h3 style='color:{risk_color}'>{risk_level}</h3>", unsafe_allow_html=True)
    
    # Transaction list
    st.subheader("All Transactions")
    # Format the dataframe for display
    display_all = st.session_state.processed_transactions[['transaction_id', 'user_id', 'amount', 'timestamp', 'risk_score']].copy()
    display_all['timestamp'] = display_all['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    display_all.columns = ['Transaction ID', 'User ID', 'Amount', 'Timestamp', 'Risk Score']
    st.dataframe(display_all, use_container_width=True)

# Tab 3: Rule Testing
with tab3:
    st.header("Fraud Rule Testing")
    st.markdown("""
    Test individual transactions against the 10 fraud detection rules. Adjust parameters to see how they affect the risk score.
    """)
    
    # Form for entering transaction details
    with st.form("transaction_test_form"):
        st.subheader("Transaction Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            amount = st.number_input("Transaction Amount (₹)", min_value=1.0, value=1000.0, step=100.0)
            user_avg_amount = st.number_input("User's Average Transaction Amount (₹)", min_value=1.0, value=1000.0, step=100.0)
            merchant_age = st.number_input("Merchant Domain Age (months)", min_value=0, value=12, step=1)
            transaction_time = st.time_input("Transaction Time", value=datetime.now().time())
            two_fa_completed = st.checkbox("2FA Completed", value=True)
        
        with col2:
            # Device change options
            st.subheader("Device Change")
            recent_device_change = st.checkbox("Recent Device Change (within 10 min)", value=False)
            
            # Location options
            st.subheader("Location")
            location_options = st.radio(
                "Billing vs Device Location",
                ["Same location", "Different cities (< 500km)", "Different cities (> 500km)"]
            )
            
            # Behavior pattern
            st.subheader("Behavior Pattern")
            behavior_change_pct = st.slider("Behavior Pattern Change %", 0, 100, 0)
            
            # Failed login attempts
            failed_logins = st.number_input("Recent Failed Login Attempts", 0, 10, 0)
            
            # Recipient flagged
            recipient_flags = st.number_input("Recipient Previous Flags (30 days)", 0, 5, 0)
        
        # Small transactions for smurfing detection
        st.subheader("Recent Small Transactions (for Smurfing Detection)")
        enable_smurfing = st.checkbox("Enable Recent Small Transactions", value=False)
        if enable_smurfing:
            small_txn_count = st.slider("Number of Recent Small Transactions", 1, 10, 5)
        else:
            small_txn_count = 0
        
        # Submit button
        submitted = st.form_submit_button("Test Transaction")
    
    # Process the test transaction when submitted
    if submitted:
        # Create transaction data object
        test_txn = {
            "transaction_id": f"TEST{int(datetime.now().timestamp())}",
            "user_id": "TEST_USER",
            "amount": amount,
            "timestamp": datetime.combine(datetime.now().date(), transaction_time),
            "merchant_id": "TEST_MERCHANT",
            "device_id": "TEST_DEVICE",
            "ip_address": "192.168.1.1",
            "merchant_age_months": merchant_age,
            "user_avg_amount": user_avg_amount,
            "two_fa_completed": two_fa_completed,
            "current_pattern": 1.0 + (behavior_change_pct / 100),
            "historical_pattern": 1.0,
            "recipient_id": "TEST_RECIPIENT",
            "flagged_recipients": {},
            "user_sessions": [],
            "user_recent_transactions": [],
            "login_attempts": []
        }
        
        # Handle device change
        if recent_device_change:
            test_txn["user_sessions"] = [
                {
                    "device_id": "DIFFERENT_DEVICE",
                    "ip_address": "10.0.0.1",
                    "timestamp": datetime.now() - timedelta(minutes=5)
                }
            ]
        
        # Handle location
        if location_options == "Same location":
            test_txn["billing_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
            test_txn["device_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
        elif location_options == "Different cities (< 500km)":
            test_txn["billing_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
            test_txn["device_location"] = {"lat": 39.9526, "lon": -75.1652}  # Philadelphia
        else:
            test_txn["billing_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
            test_txn["device_location"] = {"lat": 34.0522, "lon": -118.2437}  # LA
        
        # Handle failed logins
        if failed_logins > 0:
            test_txn["login_attempts"] = [
                {"success": False, "timestamp": datetime.now() - timedelta(minutes=i*1)}
                for i in range(1, failed_logins+1)
            ]
        
        # Handle recipient flags
        if recipient_flags > 0:
            test_txn["flagged_recipients"] = {
                "TEST_RECIPIENT": [
                    datetime.now() - timedelta(days=i*5)
                    for i in range(1, recipient_flags+1)
                ]
            }
        
        # Handle smurfing
        if small_txn_count > 0:
            test_txn["user_recent_transactions"] = [
                {"amount": 100, "timestamp": datetime.now() - timedelta(minutes=i)}
                for i in range(1, small_txn_count+1)
            ]
        
        # Analyze the transaction
        result = fraud_system.analyze_transaction(test_txn)
        
        # Display results
        st.subheader("Analysis Results")
        
        # Create columns for the results
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Flagged rules
            st.write("**Triggered Rules:**")
            if len(result['flags']) > 0:
                for rule in result['flags']:
                    st.warning(f"**{rule['rule']}**: {rule['details']}")
            else:
                st.success("No rules triggered for this transaction")
            
            # Recommended actions
            st.write("**Recommended Actions:**")
            if len(result['actions']) > 0:
                for action in result['actions']:
                    st.info(action)
            else:
                st.success("No actions recommended for this transaction")
        
        with col2:
            # Risk score gauge
            risk_gauge = visualizer.create_risk_gauge(result['risk_score'])
            st.plotly_chart(risk_gauge, use_container_width=True)
            
            # Risk category
            risk_level = "Low Risk"
            risk_color = "green"
            if result['risk_score'] >= 70:
                risk_level = "High Risk"
                risk_color = "red"
            elif result['risk_score'] >= 30:
                risk_level = "Medium Risk"
                risk_color = "orange"
                
            st.markdown(f"<h3 style='color:{risk_color}'>{risk_level}</h3>", unsafe_allow_html=True)
            
            st.metric("Risk Score", f"{result['risk_score']:.1f}")

# Sidebar
st.sidebar.title("ScamPay Fraud Detection")
st.sidebar.image("https://freesvg.org/img/1545709034.png", width=100)  # Shield icon

# ML Model Controls in sidebar
st.sidebar.header("Machine Learning Model")
if st.sidebar.checkbox("Enable ML Model Enhancement", value=fraud_system.use_ml_model):
    fraud_system.enable_ml_model(True)
    
    # Show ML model status
    if fraud_system.ml_model.model_ready:
        st.sidebar.success("ML model is trained and active")
        
        # Option to view feature importance
        if st.sidebar.button("View Feature Importance"):
            feature_importance = fraud_system.get_ml_feature_importance()
            if feature_importance is not None:
                st.sidebar.dataframe(feature_importance)
            else:
                st.sidebar.warning("Feature importance not available")
    else:
        st.sidebar.warning("ML model is not yet trained")
        
        # Train model button
        if st.sidebar.button("Train ML Model"):
            with st.sidebar:
                with st.spinner("Training ML model..."):
                    success = fraud_system.train_ml_model()
                    
                if success:
                    st.success("ML model trained successfully!")
                else:
                    st.error("Failed to train ML model")
else:
    fraud_system.enable_ml_model(False)
    st.sidebar.info("Using rules-based detection only")

# System information in sidebar
st.sidebar.header("System Information")
st.sidebar.markdown("""
The ScamPay fraud detection system implements 10 specific rules:

1. Flag transactions > 3x user's average amount
2. Increase risk score by 20% for transactions between 12-5 AM
3. Flag payments to new merchants (domain age < 6 months)
4. Block and verify when device ID/IP changes with transaction within 10 minutes
5. Flag potential smurfing (5+ transactions under ₹500 within 10 minutes)
6. Enforce OTP after 3 failed login attempts within 5 minutes
7. Flag when billing address and device location differ by 500+ km
8. Auto-reject transactions without completed 2FA
9. Raise anomaly alerts for 50% behavior pattern changes
10. Auto-block recipients flagged 2+ times in last 30 days
""")

# Risk level explanation
st.sidebar.header("Risk Levels")
st.sidebar.markdown("""
- **Low Risk (0-30)**: Transaction appears normal
- **Medium Risk (30-70)**: Additional verification recommended
- **High Risk (70-100)**: Transaction may be fraudulent
""")

# Tab 4: Database Management
with tab4:
    st.header("Database Management")
    st.markdown("""
    Connect to your MySQL database (XAMPP) and manage transactions and settings.
    """)
    
    # MySQL connection settings
    st.subheader("Database Connection")
    
    # Create columns for connection settings
    col1, col2 = st.columns(2)
    
    with col1:
        host = st.text_input("Database Host", value="localhost")
        user = st.text_input("Database User", value="root")
        password = st.text_input("Database Password", value="", type="password")
    
    with col2:
        database = st.text_input("Database Name", value="fraud_detection")
        st.write("Default port: 3306")
        test_connection = st.button("Test Connection")
    
    if test_connection:
        # Update connection settings
        fraud_system.data_processor.db.host = host
        fraud_system.data_processor.db.user = user
        fraud_system.data_processor.db.password = password
        fraud_system.data_processor.db.database = database
        
        # Try to connect
        if fraud_system.data_processor.db.connect():
            st.success(f"Successfully connected to MySQL database '{database}' on {host}")
            # Create tables if they don't exist
            if fraud_system.data_processor.db.create_tables():
                st.success("Database tables created/verified successfully")
            else:
                st.error("Failed to create database tables")
        else:
            st.error(f"Failed to connect to MySQL database '{database}' on {host}")
    
    # Database operations
    st.subheader("Database Operations")
    
    # Create tabs for different operations
    db_tab1, db_tab2, db_tab3 = st.tabs(["View Data", "Add Test Data", "Import/Export"])
    
    # Tab 1: View Data
    with db_tab1:
        st.write("View data from the database:")
        table_options = ["transactions", "users", "merchants", "flagged_rules", "recommended_actions"]
        selected_table = st.selectbox("Select table to view:", table_options)
        
        if st.button("Load Data"):
            try:
                # Connect to database
                if fraud_system.data_processor.db.connect():
                    # Load data from selected table
                    query = f"SELECT * FROM {selected_table} LIMIT 100"
                    df = pd.read_sql(query, fraud_system.data_processor.db.connection)
                    
                    if len(df) > 0:
                        st.dataframe(df)
                    else:
                        st.info(f"No data found in table '{selected_table}'")
                else:
                    st.error("Failed to connect to database")
            except Exception as e:
                st.error(f"Error loading data: {e}")
    
    # Tab 2: Add Test Data
    with db_tab2:
        st.write("Generate and add test transactions to the database:")
        
        # Form for test data generation
        with st.form("generate_test_data_form"):
            num_transactions = st.number_input("Number of test transactions to generate:", min_value=1, max_value=100, value=10)
            include_fraud = st.checkbox("Include fraudulent transactions", value=True)
            fraud_percentage = st.slider("Percentage of fraudulent transactions:", 0, 100, 30) if include_fraud else 0
            
            st.subheader("Transaction Parameters")
            min_amount = st.number_input("Minimum amount:", min_value=1, value=50)
            max_amount = st.number_input("Maximum amount:", min_value=min_amount, value=5000)
            
            # Add button to generate and insert test data
            generate_button = st.form_submit_button("Generate and Insert Test Data")
        
        if generate_button:
            # Function to generate a single random transaction
            import random
            
            def generate_random_transaction(idx, fraudulent=False):
                # Generate a random transaction with potential fraud indicators based on the 10 rules
                now = datetime.now()
                
                # Basic transaction data
                txn = {
                    "transaction_id": f"GEN{int(now.timestamp())}_{idx}",
                    "user_id": f"U{random.randint(1, 20):03d}",
                    "amount": random.uniform(min_amount, max_amount),
                    "timestamp": now - timedelta(minutes=random.randint(0, 1440)),  # Random time within last 24 hours
                    "merchant_id": f"M{random.randint(1, 10):03d}",
                    "device_id": f"D{random.randint(1, 30):03d}",
                    "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "two_fa_completed": True,
                    "user_avg_amount": random.uniform(500, 2000),
                    "merchant_age_months": random.randint(1, 48)
                }
                
                # Default locations - same place
                txn["billing_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
                txn["device_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
                
                # If this should be a fraudulent transaction, add fraud indicators
                if fraudulent:
                    # Choose random fraud indicators
                    fraud_type = random.choice([
                        "unusual_amount", "night_hour", "new_merchant", "device_change",
                        "smurfing", "failed_login", "location_mismatch", "incomplete_2fa",
                        "behavior_change", "flagged_recipient"
                    ])
                    
                    if fraud_type == "unusual_amount":
                        # Rule 1: Unusual amount (>3x average)
                        txn["amount"] = txn["user_avg_amount"] * random.uniform(3.5, 10.0)
                    
                    elif fraud_type == "night_hour":
                        # Rule 2: Night hour transaction (12 AM - 5 AM)
                        night_time = now.replace(hour=random.randint(0, 4), minute=random.randint(0, 59))
                        txn["timestamp"] = night_time
                    
                    elif fraud_type == "new_merchant":
                        # Rule 3: New merchant (< 6 months)
                        txn["merchant_age_months"] = random.randint(0, 5)
                    
                    elif fraud_type == "device_change":
                        # Rule 4: Device change
                        txn["user_sessions"] = [{
                            "device_id": f"DIFF_DEV_{random.randint(1, 99)}",
                            "ip_address": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                            "timestamp": now - timedelta(minutes=random.randint(1, 9))
                        }]
                    
                    elif fraud_type == "smurfing":
                        # Rule 5: Smurfing (multiple small transactions)
                        txn["amount"] = random.uniform(50, 499)
                        txn["user_recent_transactions"] = [
                            {"amount": random.uniform(50, 499), "timestamp": now - timedelta(minutes=i)}
                            for i in range(1, random.randint(5, 10))
                        ]
                    
                    elif fraud_type == "failed_login":
                        # Rule 6: Failed login attempts
                        txn["login_attempts"] = [
                            {"success": False, "timestamp": now - timedelta(minutes=i)}
                            for i in range(1, random.randint(3, 6))
                        ]
                    
                    elif fraud_type == "location_mismatch":
                        # Rule 7: Location mismatch (> 500 km)
                        txn["billing_location"] = {"lat": 40.7128, "lon": -74.0060}  # NYC
                        txn["device_location"] = {"lat": 34.0522, "lon": -118.2437}  # LA
                    
                    elif fraud_type == "incomplete_2fa":
                        # Rule 8: Incomplete 2FA
                        txn["two_fa_completed"] = False
                    
                    elif fraud_type == "behavior_change":
                        # Rule 9: Behavior change
                        txn["current_pattern"] = 1.8
                        txn["historical_pattern"] = 1.0
                    
                    elif fraud_type == "flagged_recipient":
                        # Rule 10: Flagged recipient
                        txn["recipient_id"] = "FLAGGED_RECIPIENT"
                        txn["flagged_recipients"] = {
                            "FLAGGED_RECIPIENT": [
                                now - timedelta(days=random.randint(1, 29))
                                for _ in range(random.randint(2, 5))
                            ]
                        }
                
                return txn
            
            # Generate transactions
            with st.spinner(f"Generating and analyzing {num_transactions} transactions..."):
                num_fraud = int(num_transactions * fraud_percentage / 100) if include_fraud else 0
                num_normal = num_transactions - num_fraud
                
                # Generate normal transactions
                normal_txns = [generate_random_transaction(i, False) for i in range(num_normal)]
                
                # Generate fraudulent transactions
                fraud_txns = [generate_random_transaction(i + num_normal, True) for i in range(num_fraud)]
                
                # Combine and shuffle
                all_txns = normal_txns + fraud_txns
                random.shuffle(all_txns)
                
                # Process each transaction
                results = []
                for i, txn in enumerate(all_txns):
                    result = fraud_system.analyze_transaction(txn)
                    results.append(result)
                    
                    # Update progress
                    progress_pct = (i + 1) / len(all_txns)
                    st.progress(progress_pct)
            
            # Show results summary
            st.success(f"Generated and processed {num_transactions} transactions")
            
            # Count fraud detection results
            high_risk = sum(1 for r in results if r['risk_score'] >= 70)
            medium_risk = sum(1 for r in results if 30 <= r['risk_score'] < 70)
            low_risk = sum(1 for r in results if r['risk_score'] < 30)
            
            # Display statistics
            st.subheader("Generation Results")
            col1, col2, col3 = st.columns(3)
            col1.metric("High Risk", high_risk, f"{high_risk/num_transactions*100:.1f}%")
            col2.metric("Medium Risk", medium_risk, f"{medium_risk/num_transactions*100:.1f}%")
            col3.metric("Low Risk", low_risk, f"{low_risk/num_transactions*100:.1f}%")
            
            # Update session state with new data
            fraud_system.data_processor.load_data()  # Reload data from database
            
            # Convert new results to DataFrame for display
            new_txns_df = pd.DataFrame([
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
            
            # Display summary of new transactions
            st.subheader("Generated Transactions")
            display_df = new_txns_df[['transaction_id', 'user_id', 'amount', 'timestamp', 'risk_score']].copy()
            display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            display_df.columns = ['Transaction ID', 'User ID', 'Amount', 'Timestamp', 'Risk Score']
            st.dataframe(display_df, use_container_width=True)
    
    # Tab 3: Import/Export
    with db_tab3:
        st.write("Import or export data to/from the database:")
        
        # Export data
        st.subheader("Export Data")
        export_table = st.selectbox("Select table to export:", table_options)
        
        if st.button("Export to CSV"):
            try:
                # Connect to database
                if fraud_system.data_processor.db.connect():
                    # Load data from selected table
                    query = f"SELECT * FROM {export_table}"
                    df = pd.read_sql(query, fraud_system.data_processor.db.connection)
                    
                    if len(df) > 0:
                        # Convert to CSV
                        csv = df.to_csv(index=False)
                        
                        # Offer download link
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name=f"{export_table}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info(f"No data found in table '{export_table}'")
                else:
                    st.error("Failed to connect to database")
            except Exception as e:
                st.error(f"Error exporting data: {e}")
        
        # Import data
        st.subheader("Import Data")
        st.write("Feature coming soon...")

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown("© 2023 ScamPay Fraud Detection System")
