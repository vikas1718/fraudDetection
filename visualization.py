import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

class FraudVisualizer:
    """
    Class for visualizing fraud detection results
    """
    
    def plot_risk_distribution(self, transactions_df):
        """
        Create risk score distribution chart
        """
        if transactions_df is None or len(transactions_df) == 0 or 'risk_score' not in transactions_df.columns:
            st.warning("No transaction data available for risk distribution visualization")
            return None
            
        # Create risk categories
        risk_bins = [0, 30, 70, 100]
        risk_labels = ['Low Risk', 'Medium Risk', 'High Risk']
        
        # Add risk category column
        df = transactions_df.copy()
        df['risk_category'] = pd.cut(df['risk_score'], bins=risk_bins, labels=risk_labels, include_lowest=True)
        
        # Count transactions by risk category
        risk_counts = df['risk_category'].value_counts().reset_index()
        risk_counts.columns = ['Risk Category', 'Count']
        
        # Set category order
        risk_counts['Risk Category'] = pd.Categorical(
            risk_counts['Risk Category'], 
            categories=risk_labels,
            ordered=True
        )
        risk_counts = risk_counts.sort_values('Risk Category')
        
        # Create color map
        color_map = {'Low Risk': 'green', 'Medium Risk': 'orange', 'High Risk': 'red'}
        
        # Create bar chart
        fig = px.bar(
            risk_counts, 
            x='Risk Category', 
            y='Count',
            color='Risk Category',
            color_discrete_map=color_map,
            title='Transaction Risk Distribution'
        )
        
        return fig
    
    def plot_risk_timeline(self, transactions_df):
        """
        Create timeline of transaction risk scores
        """
        if transactions_df is None or len(transactions_df) == 0 or 'risk_score' not in transactions_df.columns:
            st.warning("No transaction data available for risk timeline visualization")
            return None
            
        # Ensure we have timestamp column
        if 'timestamp' not in transactions_df.columns:
            st.warning("Transaction data missing timestamp information")
            return None
            
        # Copy and sort by timestamp
        df = transactions_df.copy()
        df = df.sort_values('timestamp')
        
        # Create risk categories for coloring
        risk_bins = [0, 30, 70, 100]
        risk_labels = ['Low Risk', 'Medium Risk', 'High Risk']
        df['risk_category'] = pd.cut(df['risk_score'], bins=risk_bins, labels=risk_labels, include_lowest=True)
        
        # Create color map
        color_map = {'Low Risk': 'green', 'Medium Risk': 'orange', 'High Risk': 'red'}
        
        # Create scatter plot
        fig = px.scatter(
            df,
            x='timestamp',
            y='risk_score',
            color='risk_category',
            color_discrete_map=color_map,
            hover_data=['transaction_id', 'amount', 'user_id'],
            title='Transaction Risk Score Timeline'
        )
        
        # Update layout
        fig.update_layout(
            xaxis_title='Time',
            yaxis_title='Risk Score',
            yaxis=dict(range=[0, 100])
        )
        
        return fig
    
    def plot_rule_trigger_frequency(self, transactions_df):
        """
        Create bar chart of rule trigger frequency
        """
        if (transactions_df is None or len(transactions_df) == 0 or 
            'flagged_rules' not in transactions_df.columns):
            st.warning("No rule trigger data available for visualization")
            return None
            
        # Extract and count rule triggers
        rule_counts = {}
        
        for _, row in transactions_df.iterrows():
            flagged_rules = row.get('flagged_rules', [])
            if isinstance(flagged_rules, list):
                for rule in flagged_rules:
                    if isinstance(rule, dict) and 'rule' in rule:
                        rule_name = rule['rule']
                        rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
        
        # Convert to DataFrame
        if not rule_counts:
            st.warning("No rules triggered in the provided transactions")
            return None
            
        rules_df = pd.DataFrame({
            'Rule': list(rule_counts.keys()),
            'Frequency': list(rule_counts.values())
        })
        
        # Sort by frequency
        rules_df = rules_df.sort_values('Frequency', ascending=False)
        
        # Create bar chart
        fig = px.bar(
            rules_df,
            x='Rule',
            y='Frequency',
            title='Fraud Rule Trigger Frequency',
            color='Frequency',
            color_continuous_scale='Reds'
        )
        
        # Update layout
        fig.update_layout(
            xaxis_title='Rule Type',
            yaxis_title='Number of Triggers',
            xaxis={'categoryorder': 'total descending'}
        )
        
        return fig
    
    def plot_amount_vs_risk(self, transactions_df):
        """
        Plot scatter chart of transaction amount vs risk score
        """
        if (transactions_df is None or len(transactions_df) == 0 or 
            'risk_score' not in transactions_df.columns or
            'amount' not in transactions_df.columns):
            st.warning("Required transaction data missing for amount vs risk visualization")
            return None
            
        # Create risk categories for coloring
        df = transactions_df.copy()
        risk_bins = [0, 30, 70, 100]
        risk_labels = ['Low Risk', 'Medium Risk', 'High Risk']
        df['risk_category'] = pd.cut(df['risk_score'], bins=risk_bins, labels=risk_labels, include_lowest=True)
        
        # Create scatter plot
        fig = px.scatter(
            df,
            x='amount',
            y='risk_score',
            color='risk_category',
            color_discrete_map={'Low Risk': 'green', 'Medium Risk': 'orange', 'High Risk': 'red'},
            hover_data=['transaction_id', 'user_id'],
            title='Transaction Amount vs Risk Score'
        )
        
        # Update layout
        fig.update_layout(
            xaxis_title='Transaction Amount',
            yaxis_title='Risk Score',
            yaxis=dict(range=[0, 100])
        )
        
        return fig
    
    def create_risk_gauge(self, risk_score):
        """
        Create a gauge chart for displaying risk score
        """
        # Define color zones
        green_zone = [0, 30]
        yellow_zone = [30, 70]
        red_zone = [70, 100]
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Risk Score"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "darkgray"},
                'steps': [
                    {'range': green_zone, 'color': "green"},
                    {'range': yellow_zone, 'color': "yellow"},
                    {'range': red_zone, 'color': "red"},
                ],
                'threshold': {
                    'line': {'color': "black", 'width': 4},
                    'thickness': 0.75,
                    'value': risk_score
                }
            }
        ))
        
        # Update layout
        fig.update_layout(
            height=300,
            margin=dict(l=10, r=10, t=50, b=10)
        )
        
        return fig
    
    def plot_hourly_transaction_risk(self, transactions_df):
        """
        Plot average risk score by hour of day
        """
        if (transactions_df is None or len(transactions_df) == 0 or 
            'risk_score' not in transactions_df.columns or
            'timestamp' not in transactions_df.columns):
            st.warning("Required transaction data missing for hourly risk visualization")
            return None
            
        # Extract hour from timestamp
        df = transactions_df.copy()
        df['hour'] = df['timestamp'].dt.hour
        
        # Calculate average risk by hour
        hourly_risk = df.groupby('hour')['risk_score'].mean().reset_index()
        
        # Fill in missing hours with zeros
        all_hours = pd.DataFrame({'hour': range(24)})
        hourly_risk = pd.merge(all_hours, hourly_risk, on='hour', how='left').fillna(0)
        
        # Create line chart
        fig = px.line(
            hourly_risk,
            x='hour',
            y='risk_score',
            title='Average Risk Score by Hour of Day',
            markers=True
        )
        
        # Highlight night hours (12-5 AM)
        fig.add_vrect(
            x0=0, x1=5,
            fillcolor="red", opacity=0.2,
            layer="below", line_width=0,
            annotation_text="High Risk Hours (12-5 AM)",
            annotation_position="top left"
        )
        
        # Update layout
        fig.update_layout(
            xaxis_title='Hour of Day',
            yaxis_title='Average Risk Score',
            xaxis=dict(tickmode='linear', tick0=0, dtick=1),
            yaxis=dict(range=[0, 100])
        )
        
        return fig
    
    def create_metrics_dashboard(self, metrics):
        """
        Create a set of metric cards for the dashboard
        """
        if metrics is None:
            st.warning("No metrics data available")
            return
            
        # Create columns for metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                label="Total Transactions", 
                value=f"{metrics.get('total_transactions', 0):,}"
            )
            
        with col2:
            st.metric(
                label="High Risk Transactions", 
                value=f"{metrics.get('high_risk_count', 0):,}",
                delta=f"{metrics.get('high_risk_percentage', 0):.1f}% of total"
            )
            
        with col3:
            st.metric(
                label="Average Risk Score", 
                value=f"{metrics.get('avg_risk_score', 0):.1f}"
            )
