"""
Main Dashboard - Navigation Hub
Access all 3 dashboards from here
"""

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.style import icon, load_theme  # noqa: E402

# Page config
st.set_page_config(
    page_title="Agent Security Intelligence Platform",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

load_theme()

# ============================================
# HEADER
# ============================================

st.markdown(
    f"""
    <div class='asif-hero'>
        {icon('shield', size=36)}
        <h1 class='asif-h1' style='margin-top:12px;'>Agent Security Intelligence Platform</h1>
        <p class='asif-subtitle'>Complete threat intelligence and agent security framework</p>
    </div>
    """,
    unsafe_allow_html=True
)

# ============================================
# NAVIGATION CARDS
# ============================================

cards = [
    {
        "icon": "bar-chart",
        "title": "Intelligence",
        "subtitle": "Threat Intelligence at a Glance",
        "desc": "High-level metrics, threat distribution.",
        "features": [
            "Total threats & KPI cards",
            "Distribution charts",
            "Recent threats table",
        ],
        "page": "pages/intelligence.py",
        "key": "dash1",
    },
    {
        "icon": "search",
        "title": "Catalog",
        "subtitle": "Detailed Threat Browse & Search",
        "desc": "Complete threat catalog with filters and details.",
        "features": [
            "All threats",
            "Multi-filter (type / source / severity)",
            
            "Pagination & export",
        ],
        "page": "pages/catalog.py",
        "key": "dash2",
    },
    {
        "icon": "settings",
        "title": "Operations",
        "subtitle": "Agent Testing & Monitoring",
        "desc": "Test your agents and monitor production systems.",
        "features": [
            "Agent vulnerability testing",
            "Test reports",
            "Production monitoring",
            "Real-time alerts",
        ],
        "page": "pages/operations.py",
        "key": "dash3",
    },
]

col1, col2, col3 = st.columns(3, gap="large")

for col, card in zip((col1, col2, col3), cards):
    with col:
        features_html = "".join(f"<li>{f}</li>" for f in card["features"])
        st.markdown(
            f"""
            <div class='nav-card'>
                <div class='nav-card-icon'>{icon(card['icon'], size=24)}</div>
                <p class='nav-card-title'>{card['title']}</p>
                <p class='asif-caption' style='margin-bottom:10px;'>{card['subtitle']}</p>
                <p class='nav-card-desc'>{card['desc']}</p>
                <ul class='nav-card-features'>{features_html}</ul>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Open dashboard", use_container_width=True, key=card["key"], type="secondary"):
            st.switch_page(card["page"])

# ============================================
# STATISTICS
# ============================================

st.divider()

st.markdown("<div class='asif-section-title'>Platform Statistics</div>", unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Threats", "226", "From 7 CTI sources")

with col2:
    st.metric("Threat Types", "8", "Categories")

with col3:
    st.metric("Intelligence Sources", "7", "Active feeds")

with col4:
    st.metric("Classification", "46%", "High-quality")

with col5:
    st.metric("Coverage", "93%", "Analyzed threats")

# ============================================
# QUICK LINKS
# ============================================

st.divider()

st.markdown("<div class='asif-section-title'>Quick Links</div>", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("<p class='asif-caption'>Intelligence</p>", unsafe_allow_html=True)
    st.markdown("""
    - [NVD (NIST)](https://nvd.nist.gov/) - Vulnerabilities
    - [MITRE ATT&CK](https://attack.mitre.org/) - Techniques
    - [ArXiv](https://arxiv.org/) - Academic Papers
    """)

with col2:
    st.markdown("<p class='asif-caption'>Threat Data</p>", unsafe_allow_html=True)
    st.markdown("""
    - [GitHub Security](https://github.com/security) - Advisories
    - [Censys](https://censys.io/) - Internet Exposure
    - [OpenCTI](https://www.opencti.io/) - Intelligence
    """)

with col3:
    st.markdown("<p class='asif-caption'>Documentation</p>", unsafe_allow_html=True)
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
    <div style='text-align: center; color: var(--text-tertiary);'>
        <small>Agent Security Intelligence Framework | v1.0 |
        <a href='https://github.com/Mavchris/Agent_Security_Framework'>GitHub</a>
        </small>
    </div>
""", unsafe_allow_html=True)
