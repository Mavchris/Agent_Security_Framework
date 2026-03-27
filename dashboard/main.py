"""
Main Dashboard - Navigation Hub
Access all 3 dashboards from here
"""

import streamlit as st

# Page config
st.set_page_config(
    page_title="Agent Security Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# HEADER
# ============================================

st.markdown("""
    <div style='text-align: center; margin-bottom: 40px;'>
        <h1>🛡️ Agent Security Intelligence Platform</h1>
        <p style='font-size: 18px; color: #666;'>Complete threat intelligence and agent security framework</p>
    </div>
""", unsafe_allow_html=True)

# ============================================
# NAVIGATION CARDS
# ============================================

st.markdown("""
<style>
    .dashboard-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 30px;
        border-radius: 10px;
        color: white;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .dashboard-card h2 {
        margin-top: 0;
    }
    .dashboard-card p {
        margin: 10px 0;
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class='dashboard-card'>
        <h2>📊 Dashboard 1: Overview</h2>
        <p><strong>Threat Intelligence at a Glance</strong></p>
        <p>High-level metrics, threat distribution, and statistics</p>
        <ul style='font-size: 12px;'>
            <li>219 Total Threats</li>
            <li>KPI Cards</li>
            <li>Distribution Charts</li>
            <li>Top 10 Threats Table</li>
            <li>CSV/JSON Export</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("📊 Open Dashboard 1", use_container_width=True, key="dash1"):
        st.switch_page("pages/overview.py")

with col2:
    st.markdown("""
    <div class='dashboard-card'>
        <h2>🔍 Dashboard 2: Catalog</h2>
        <p><strong>Detailed Threat Browse & Search</strong></p>
        <p>Complete threat catalog with filters and details</p>
        <ul style='font-size: 12px;'>
            <li>All 219 Threats</li>
            <li>Multi-filter (Type/Source/Severity)</li>
            <li>Full-text Search</li>
            <li>Expandable Details</li>
            <li>Pagination & Export</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("🔍 Open Dashboard 2", use_container_width=True, key="dash2"):
        st.switch_page("pages/catalog.py")

with col3:
    st.markdown("""
    <div class='dashboard-card'>
        <h2>⚙️ Dashboard 3: Operations</h2>
        <p><strong>Agent Testing & Monitoring</strong></p>
        <p>Test your agents and monitor production systems</p>
        <ul style='font-size: 12px;'>
            <li>Agent Vulnerability Testing</li>
            <li>Test Reports</li>
            <li>Production Monitoring</li>
            <li>Real-time Alerts</li>
            <li>Trend Analysis</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("⚙️ Open Dashboard 3", use_container_width=True, key="dash3"):
        st.switch_page("pages/operations.py")

# ============================================
# STATISTICS
# ============================================

st.divider()

st.markdown("### 📈 Platform Statistics")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Threats", "219", "From 7 CTI sources")

with col2:
    st.metric("Threat Types", "9", "Categories")

with col3:
    st.metric("Intelligence Sources", "6", "Active feeds")

with col4:
    st.metric("Classification", "46%", "High-quality")

with col5:
    st.metric("Coverage", "93%", "Analyzed threats")

# ============================================
# QUICK LINKS
# ============================================

st.divider()

st.markdown("### 🔗 Quick Links")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("#### Intelligence")
    st.markdown("""
    - [NVD (NIST)](https://nvd.nist.gov/) - Vulnerabilities
    - [MITRE ATT&CK](https://attack.mitre.org/) - Techniques
    - [ArXiv](https://arxiv.org/) - Academic Papers
    """)

with col2:
    st.markdown("#### Threat Data")
    st.markdown("""
    - [GitHub Security](https://github.com/security) - Advisories
    - [Censys](https://censys.io/) - Internet Exposure
    - [OpenCTI](https://www.opencti.io/) - Intelligence
    """)

with col3:
    st.markdown("#### Documentation")
    st.markdown("""
    - [README](../README.md)
    - [Architecture](../docs/architecture.md)
    - [Contributing](../CONTRIBUTING.md)
    """)

# ============================================
# FOOTER
# ============================================

st.divider()

st.markdown("""
    <div style='text-align: center; color: #666;'>
        <small>Agent Security Intelligence Framework | v1.0 | 
        <a href='https://github.com/Mavchris/Agent_Security_Framework'>GitHub</a>
        </small>
    </div>
""", unsafe_allow_html=True)
