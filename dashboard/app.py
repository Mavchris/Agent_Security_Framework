"""
Agent Security Intelligence Dashboard
Interactive Streamlit dashboard for threat intelligence
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json

# Page config
st.set_page_config(
    page_title="Agent Security Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database path
DB_PATH = 'data/threats.db'

def get_db_connection():
    """Get database connection - NO CACHING"""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        st.error(f"❌ Database connection error: {e}")
        return None

def get_all_threats():
    """Get all threats from database"""
    try:
        conn = get_db_connection()
        if not conn:
            return []
        
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM threats ORDER BY id DESC')
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return threats
    except Exception as e:
        st.error(f"❌ Error fetching threats: {e}")
        return []

def get_stats():
    """Get threat statistics"""
    try:
        conn = get_db_connection()
        if not conn:
            return {}
        
        cursor = conn.cursor()
        
        # Total count
        cursor.execute('SELECT COUNT(*) FROM threats')
        total = cursor.fetchone()[0]
        
        # Count by type
        cursor.execute('SELECT threat_type, COUNT(*) as count FROM threats GROUP BY threat_type')
        by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Count by source
        cursor.execute('SELECT source, COUNT(*) as count FROM threats GROUP BY source')
        by_source = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            'total': total,
            'by_type': by_type,
            'by_source': by_source,
        }
    except Exception as e:
        st.error(f"❌ Error fetching stats: {e}")
        return {}

# ============================================
# MAIN APP
# ============================================

st.title("🛡️ Agent Security Intelligence Dashboard")
st.markdown("**Real-time threat intelligence for AI agents in production**")

# Sidebar filters
st.sidebar.header("Filters")
threat_type_filter = st.sidebar.multiselect(
    "Threat Type",
    options=["prompt_injection", "tool_abuse", "data_leakage", "model_extraction", "behavioral_anomaly", "other"],
    default=None
)

source_filter = st.sidebar.multiselect(
    "Source",
    options=["CVE", "GitHub", "ArXiv"],
    default=None
)

# Get data
with st.spinner("Loading data..."):
    threats = get_all_threats()
    stats = get_stats()

if not threats:
    st.error("❌ No threats found in database. Please run the pipeline first.")
    st.stop()

# Filter threats
filtered_threats = threats
if threat_type_filter:
    filtered_threats = [t for t in filtered_threats if t['threat_type'] in threat_type_filter]
if source_filter:
    filtered_threats = [t for t in filtered_threats if t['source'] in source_filter]

# ============================================
# TAB 1 : OVERVIEW
# ============================================

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["📊 Overview", "🔍 Threats Catalog", "📈 Risk Matrix", "🚨 Alerts", "📋 Reports"]
)

with tab1:
    st.subheader("Threat Intelligence Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Threats",
            value=stats.get('total', 0),
        )
    
    with col2:
        critical = len([t for t in threats if t['threat_type'] in ['prompt_injection', 'tool_abuse']])
        st.metric(
            label="Critical/High",
            value=critical,
        )
    
    with col3:
        st.metric(
            label="Sources",
            value=len(stats.get('by_source', {})),
        )
    
    with col4:
        st.metric(
            label="Categories",
            value=len(stats.get('by_type', {})),
        )
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Threats by type
        by_type_data = stats.get('by_type', {})
        if by_type_data:
            by_type_df = pd.DataFrame(
                list(by_type_data.items()),
                columns=['Threat Type', 'Count']
            )
            fig = px.bar(
                by_type_df,
                x='Threat Type',
                y='Count',
                title="Threats by Type",
                color='Count',
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Threats by source
        by_source_data = stats.get('by_source', {})
        if by_source_data:
            by_source_df = pd.DataFrame(
                list(by_source_data.items()),
                columns=['Source', 'Count']
            )
            fig = px.pie(
                by_source_df,
                names='Source',
                values='Count',
                title="Distribution by Source"
            )
            st.plotly_chart(fig, use_container_width=True)

# ============================================
# TAB 2 : THREATS CATALOG
# ============================================

with tab2:
    st.subheader("Threats Catalog")
    st.markdown(f"**Showing {len(filtered_threats)} of {len(threats)} threats**")
    
    # Create dataframe
    if filtered_threats:
        threats_df = pd.DataFrame([
            {
                'ID': t['threat_id'],
                'Title': t['title'][:50] + '...' if len(t['title']) > 50 else t['title'],
                'Type': t['threat_type'],
                'Source': t['source'],
            }
            for t in filtered_threats
        ])
        
        st.dataframe(
            threats_df,
            use_container_width=True,
            hide_index=True,
        )
        
        # Download button
        csv = threats_df.to_csv(index=False)
        st.download_button(
            label="📥 Download as CSV",
            data=csv,
            file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No threats match your filters")

# ============================================
# TAB 3 : RISK MATRIX
# ============================================

with tab3:
    st.subheader("Risk Matrix")
    st.markdown("**Vulnerability assessment by threat type and source**")
    
    # Create risk matrix data
    threat_types = list(stats.get('by_type', {}).keys())
    sources = list(stats.get('by_source', {}).keys())
    
    if threat_types and sources:
        matrix_data = []
        for threat_type in threat_types:
            row = []
            for source in sources:
                count = len([t for t in threats if t['threat_type'] == threat_type and t['source'] == source])
                row.append(count)
            matrix_data.append(row)
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=matrix_data,
            x=sources,
            y=threat_types,
            colorscale='Reds',
            text=matrix_data,
            texttemplate='%{text}',
            textfont={"size": 12},
        ))
        
        fig.update_layout(
            title="Threat Distribution Heatmap",
            xaxis_title="Source",
            yaxis_title="Threat Type",
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)

# ============================================
# TAB 4 : ALERTS
# ============================================

with tab4:
    st.subheader("Security Alerts")
    st.markdown("**Active threats requiring attention**")
    
    # High priority threats
    critical_threats = [t for t in threats if t['threat_type'] in ['prompt_injection', 'tool_abuse']]
    
    if critical_threats:
        st.warning(f"⚠️ **{len(critical_threats)} high-priority threats detected**")
        
        for threat in critical_threats[:10]:  # Show top 10
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.markdown(f"**{threat['threat_id']}** - {threat['title'][:60]}")
            with col2:
                threat_type_color = "🔴" if threat['threat_type'] == 'prompt_injection' else "🟠"
                st.markdown(f"{threat_type_color} {threat['threat_type']}")
            with col3:
                st.markdown(f"📍 {threat['source']}")
            
            st.divider()
    else:
        st.success("✅ No critical threats detected")

# ============================================
# TAB 5 : REPORTS
# ============================================

with tab5:
    st.subheader("Threat Intelligence Reports")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Threats", stats.get('total', 0))
    with col2:
        st.metric("Threat Types", len(stats.get('by_type', {})))
    with col3:
        st.metric("Data Sources", len(stats.get('by_source', {})))
    
    st.markdown("---")
    
    # Summary by threat type
    st.subheader("Threat Distribution Summary")
    by_type = stats.get('by_type', {})
    total = stats.get('total', 1)
    
    for threat_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total) * 100
        st.markdown(f"**{threat_type}** : {count} threats ({percentage:.1f}%)")
    
    st.markdown("---")
    
    # Export options
    st.subheader("Export Data")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON export
        json_data = json.dumps(threats, indent=2, default=str)
        st.download_button(
            label="📥 Download as JSON",
            data=json_data,
            file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    with col2:
        st.info("💡 Use this data for threat analysis and reporting")

# ============================================
# FOOTER
# ============================================

st.markdown("---")
st.markdown(
    "**Agent Security Intelligence Framework** | "
    "Last updated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
)