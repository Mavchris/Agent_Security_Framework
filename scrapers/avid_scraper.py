"""
Dashboard 1: Threat Intelligence Overview
High-level metrics and visualizations for all audiences
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os

def get_db_connection():
    """Get database connection with absolute path"""
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'threats.db')
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_all_threats():
    """Get all threats from database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM threats ORDER BY id DESC')
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return threats
    except Exception as e:
        st.error(f"Database error: {e}")
        return []

def get_stats():
    """Get comprehensive statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total count
        cursor.execute('SELECT COUNT(*) FROM threats')
        total = cursor.fetchone()[0]
        
        # By type
        cursor.execute('SELECT threat_type, COUNT(*) as count FROM threats GROUP BY threat_type')
        by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        # By source
        cursor.execute('SELECT source, COUNT(*) as count FROM threats GROUP BY source')
        by_source = {row[0]: row[1] for row in cursor.fetchall()}
        
        # By severity
        cursor.execute('SELECT severity, COUNT(*) as count FROM threats GROUP BY severity WHERE severity != "unknown"')
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            'total': total,
            'by_type': by_type,
            'by_source': by_source,
            'by_severity': by_severity
        }
    except Exception as e:
        st.error(f"Stats error: {e}")
        return {}

def show():
    """Display Overview Dashboard"""
    
    st.markdown("""
        <div style='text-align: center; margin-bottom: 30px;'>
            <h1>📊 Threat Intelligence Overview</h1>
            <p style='font-size: 16px; color: #666;'>High-level metrics and threat distribution</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Load data
    threats = get_all_threats()
    stats = get_stats()
    
    if not threats or not stats:
        st.error("❌ Unable to load data from database")
        st.info("💡 Make sure to run: python pipeline/process.py")
        return
    
    # KPI Row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🎯 Total Threats",
            value=stats.get('total', 0),
            delta="497 unique",
            delta_color="off"
        )
    
    with col2:
        critical_high = (stats.get('by_severity', {}).get('critical', 0) + 
                        stats.get('by_severity', {}).get('high', 0))
        st.metric(
            label="🔴 Critical/High",
            value=critical_high,
            delta="Requires attention",
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            label="📚 Sources",
            value=len(stats.get('by_source', {})),
            delta="7 intelligence sources",
            delta_color="off"
        )
    
    with col4:
        st.metric(
            label="🏷️ Categories",
            value=len(stats.get('by_type', {})),
            delta="6 threat types",
            delta_color="off"
        )
    
    st.divider()
    
    # Charts Row 1
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Threats by Type")
        by_type_df = pd.DataFrame(
            list(stats.get('by_type', {}).items()),
            columns=['Type', 'Count']
        ).sort_values('Count', ascending=False)
        
        fig = px.bar(
            by_type_df,
            x='Type',
            y='Count',
            color='Count',
            color_continuous_scale='Reds',
            text='Count',
            title=None
        )
        fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("📍 Distribution by Source")
        by_source_df = pd.DataFrame(
            list(stats.get('by_source', {}).items()),
            columns=['Source', 'Count']
        )
        
        fig = px.pie(
            by_source_df,
            names='Source',
            values='Count',
            title=None,
            hole=0.3
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    st.divider()
    
    # Charts Row 2
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("⚠️ Severity Distribution")
        by_severity_df = pd.DataFrame(
            list(stats.get('by_severity', {}).items()),
            columns=['Severity', 'Count']
        )
        
        color_map = {
            'critical': '#ff4757', 
            'high': '#ffa502', 
            'medium': '#ffd93d', 
            'low': '#6bcf7f',
            'unknown': '#999999'
        }
        
        fig = px.bar(
            by_severity_df,
            x='Severity',
            y='Count',
            color='Severity',
            color_discrete_map=color_map,
            text='Count',
            title=None
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🏆 Top 10 Threats")
        top_10 = pd.DataFrame([
            {
                'ID': t['threat_id'],
                'Title': t['title'][:35] + '...' if len(t['title']) > 35 else t['title'],
                'Type': t['threat_type'],
                'Source': t['source'],
                'Severity': t.get('severity', 'unknown')
            }
            for t in threats[:10]
        ])
        
        st.dataframe(top_10, use_container_width=True, hide_index=True)
    
    st.divider()
    
    # Export Section
    st.subheader("📥 Export Data")
    col1, col2 = st.columns(2)
    
    with col1:
        csv = pd.DataFrame(threats).to_csv(index=False)
        st.download_button(
            label="📥 Download All Threats (CSV)",
            data=csv,
            file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with col2:
        import json
        json_data = json.dumps(threats, indent=2, default=str)
        st.download_button(
            label="📥 Download All Threats (JSON)",
            data=json_data,
            file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    # Footer
    st.divider()
    st.markdown(
        f"""
        <div style='text-align: center; color: #666;'>
        <small>Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | {stats.get('total', 0)} Unique Threats | 7 Intelligence Sources</small>
        </div>
        """,
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    show()