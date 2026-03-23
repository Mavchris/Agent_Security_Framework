"""
Main Dashboard - Professional Security Intelligence Interface
Like Mitre Detect, Nessus but for Agent Security
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import os
# Page config - Professional style
st.set_page_config(
    page_title="Agent Security Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={"About": "Agent Security Intelligence Framework v1.0"}
)

# Custom CSS for professional look
st.markdown("""
<style>
    .main {
        padding: 0rem 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .alert-critical { background-color: #ff4757; color: white; padding: 15px; border-radius: 5px; }
    .alert-high { background-color: #ffa502; color: white; padding: 15px; border-radius: 5px; }
    .alert-medium { background-color: #ffd93d; color: black; padding: 15px; border-radius: 5px; }
    .alert-low { background-color: #6bcf7f; color: white; padding: 15px; border-radius: 5px; }
</style>
""", unsafe_allow_html=True)

# Database functions
@st.cache_resource


def get_db_connection():
    """Get database connection"""
    # Get absolute path
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'threats.db')
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
    except:
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
    except:
        return {}

# ============================================
# MAIN INTERFACE
# ============================================

# Header
st.markdown("""
    <div style='text-align: center; margin-bottom: 30px;'>
        <h1>🛡️ Agent Security Intelligence Platform</h1>
        <p style='font-size: 18px; color: #666;'>Real-time Threat Intelligence & Agent Vulnerability Assessment</p>
    </div>
""", unsafe_allow_html=True)

# Load data
threats = get_all_threats()
stats = get_stats()

# Sidebar
with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    
    # Navigation
    page = st.radio(
        "Select View",
        ["🏠 Dashboard", "🔍 Threats", "📊 Analytics", "🚨 Alerts", "📋 Reports"],
        label_visibility="collapsed"
    )
    
    # Filters
    st.markdown("### 🔎 Filters")
    threat_type_filter = st.multiselect(
        "Threat Type",
        options=list(stats.get('by_type', {}).keys()),
        default=None
    )
    
    source_filter = st.multiselect(
        "Source",
        options=list(stats.get('by_source', {}).keys()),
        default=None
    )
    
    severity_filter = st.multiselect(
        "Severity",
        options=list(stats.get('by_severity', {}).keys()),
        default=None
    )
    
    # Apply filters
    filtered_threats = threats
    if threat_type_filter:
        filtered_threats = [t for t in filtered_threats if t['threat_type'] in threat_type_filter]
    if source_filter:
        filtered_threats = [t for t in filtered_threats if t['source'] in source_filter]
    if severity_filter:
        filtered_threats = [t for t in filtered_threats if t.get('severity') in severity_filter]

# ============================================
# PAGE 1: MAIN DASHBOARD
# ============================================

if page == "🏠 Dashboard":
    
    # KPI Row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🎯 Total Threats",
            value=stats.get('total', 0),
            delta="45 unique",
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
            delta="6 intelligence sources",
            delta_color="off"
        )
    
    with col4:
        st.metric(
            label="🏷️ Categories",
            value=len(stats.get('by_type', {})),
            delta="6 threat types",
            delta_color="off"
        )
    
    
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
        fig.update_layout(height=400, xaxis_tickangle=-45)
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
        
        color_map = {'critical': '#ff4757', 'high': '#ffa502', 'medium': '#ffd93d', 'low': '#6bcf7f'}
        
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
        st.subheader("📊 Top 10 Threats")
        top_10 = pd.DataFrame([
            {
                'ID': t['threat_id'],
                'Title': t['title'][:40],
                'Type': t['threat_type'],
                'Source': t['source']
            }
            for t in threats[:10]
        ])
        
        st.dataframe(top_10, use_container_width=True, hide_index=True)

# ============================================
# PAGE 2: THREATS CATALOG
# ============================================

elif page == "🔍 Threats":
    
    st.subheader("🔍 Threats Catalog")
    st.markdown(f"**Total: {len(filtered_threats)} threats** (filtered from {len(threats)})")
    
    # Search
    search = st.text_input("🔎 Search threats by ID or title...", "")
    if search:
        filtered_threats = [
            t for t in filtered_threats 
            if search.lower() in t['threat_id'].lower() or 
               search.lower() in t['title'].lower()
        ]
    
    # Display threats
    if filtered_threats:
        for idx, threat in enumerate(filtered_threats[:20], 1):  # Show 20 max
            severity = threat.get('severity', 'unknown')
            severity_color = {
                'critical': '🔴', 'high': '🟠', 
                'medium': '🟡', 'low': '🟢', 'unknown': '⚪'
            }.get(severity, '⚪')
            
            with st.expander(f"{severity_color} [{threat['threat_id']}] {threat['title'][:60]}"):
                col1, col2 = st.columns([1, 1])
                
                with col1:
                    st.markdown(f"**Description:**\n{threat.get('description', 'N/A')}")
                    st.markdown(f"**Type:** `{threat['threat_type']}`")
                    st.markdown(f"**Source:** `{threat['source']}`")
                
                with col2:
                    st.markdown(f"**Test Payload:**\n```\n{threat.get('test_payload', 'N/A')}\n```")
                    st.markdown(f"**Severity:** {severity}")
                    if threat.get('url'):
                        st.markdown(f"**[View Source →]({threat['url']})")
    else:
        st.info("No threats match your filters")
    
    # Export button
    csv = pd.DataFrame(filtered_threats).to_csv(index=False)
    st.download_button(
        label="📥 Download as CSV",
        data=csv,
        file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

# ============================================
# PAGE 3: ANALYTICS
# ============================================

elif page == "📊 Analytics":
    
    st.subheader("📊 Threat Intelligence Analytics")
    
    # Risk Matrix
    st.markdown("### Risk Matrix")
    
    threat_types = list(stats.get('by_type', {}).keys())
    sources = list(stats.get('by_source', {}).keys())
    
    matrix_data = []
    for threat_type in threat_types:
        row = []
        for source in sources:
            count = len([
                t for t in threats 
                if t['threat_type'] == threat_type and t['source'] == source
            ])
            row.append(count)
        matrix_data.append(row)
    
    fig = go.Figure(data=go.Heatmap(
        z=matrix_data,
        x=sources,
        y=threat_types,
        colorscale='Reds',
        text=matrix_data,
        texttemplate='%{text}',
        textfont={"size": 12}
    ))
    
    fig.update_layout(
        title="Threat Distribution Heatmap",
        xaxis_title="Source",
        yaxis_title="Threat Type",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Trends
    st.markdown("### Threat Statistics")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Most Common Threat", max(stats.get('by_type', {}).items(), key=lambda x: x[1])[0], "")
    
    with col2:
        st.metric("Top Source", max(stats.get('by_source', {}).items(), key=lambda x: x[1])[0], "")
    
    with col3:
        st.metric("Highest Severity", max(stats.get('by_severity', {}).items(), key=lambda x: x[1])[0] if stats.get('by_severity') else "N/A", "")

# ============================================
# PAGE 4: ALERTS
# ============================================

elif page == "🚨 Alerts":
    
    st.subheader("🚨 Active Alerts & Threats")
    
    # Critical threats
    critical_threats = [t for t in threats if t.get('severity') == 'critical']
    high_threats = [t for t in threats if t.get('severity') == 'high']
    
    st.markdown(f"### 🔴 Critical Threats ({len(critical_threats)})")
    
    if critical_threats:
        for threat in critical_threats[:5]:
            st.error(f"**{threat['threat_id']}** - {threat['title']}\n\n{threat['description'][:100]}...")
    else:
        st.success("No critical threats detected")
    
    st.markdown(f"### 🟠 High Severity Threats ({len(high_threats)})")
    
    if high_threats:
        for threat in high_threats[:5]:
            st.warning(f"**{threat['threat_id']}** - {threat['title']}")
    else:
        st.info("No high severity threats")

# ============================================
# PAGE 5: REPORTS
# ============================================

elif page == "📋 Reports":
    
    st.subheader("📋 Security Reports")
    
    st.markdown("### Executive Summary")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Threats Identified", stats.get('total', 0))
    with col2:
        st.metric("Intelligence Sources", len(stats.get('by_source', {})))
    with col3:
        st.metric("Threat Categories", len(stats.get('by_type', {})))
    
    st.divider()
    
    st.markdown("### Threat Distribution Report")
    
    report_df = pd.DataFrame([
        {
            'Threat Type': threat_type,
            'Count': count,
            'Percentage': f"{count/stats.get('total', 1)*100:.1f}%"
        }
        for threat_type, count in sorted(stats.get('by_type', {}).items(), key=lambda x: x[1], reverse=True)
    ])
    
    st.dataframe(report_df, use_container_width=True, hide_index=True)
    
    st.divider()
    
    # Export reports
    st.markdown("### 📥 Export Options")
    
    col1, col2 = st.columns(2)
    
    with col1:
        json_data = json.dumps(threats, indent=2, default=str)
        st.download_button(
            label="Download Full Report (JSON)",
            data=json_data,
            file_name=f"threat_intelligence_report_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json"
        )
    
    with col2:
        csv_data = pd.DataFrame(threats).to_csv(index=False)
        st.download_button(
            label="Download Threat List (CSV)",
            data=csv_data,
            file_name=f"threat_list_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )

# Footer
st.divider()
st.markdown(
    f"""
    <div style='text-align: center; color: #666;'>
    <small>Agent Security Intelligence Framework | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | 45 Unique Threats Tracked</small>
    </div>
    """,
    unsafe_allow_html=True
)