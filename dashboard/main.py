"""
Main Dashboard - Navigation Hub
Access all 3 dashboards from here
"""

import json
import os
import sqlite3
import sys
from datetime import datetime

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.style import icon, kpi_card, load_theme, mini_card  # noqa: E402

# Page config
st.set_page_config(
    page_title="Agent Security Intelligence Platform",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

load_theme()

# ============================================
# LIVE DATA
# ============================================

@st.cache_resource
def get_db_connection():
    """DB connection, reused across reruns - queries below still run
    fresh on every page load, so these numbers can't go stale like the
    hardcoded ones this replaced."""
    conn = sqlite3.connect('data/threats.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@st.cache_data(ttl=30)
def get_platform_stats():
    """Real counts from data/threats.db. Cached for 30s - short on purpose:
    this dashboard previously showed genuinely hardcoded numbers (fixed
    earlier this session), so a long or unbounded TTL here specifically
    risks recreating the same "looks live but isn't" symptom. The real
    data only changes on an orchestrator run (daily/weekly) or a manual
    agent registration, so even 30s is generous re: actual freshness
    need - it's chosen for safety margin, not because the data changes
    that fast."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM threats')
        total_threats = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(DISTINCT threat_type) FROM threats')
        threat_types = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(DISTINCT source) FROM threats')
        sources = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM threats WHERE ai_relevant = 1')
        ai_relevant = cursor.fetchone()[0]

        try:
            cursor.execute('SELECT COUNT(*) FROM registered_agents WHERE is_active = 1')
            active_agents = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            # registered_agents may not exist yet on an older data/threats.db
            # that hasn't had the migration script run against it.
            active_agents = 0

        return {
            'total_threats': total_threats,
            'threat_types': threat_types,
            'sources': sources,
            'ai_relevant': ai_relevant,
            'ai_relevant_pct': (ai_relevant / total_threats * 100) if total_threats > 0 else 0,
            'active_agents': active_agents,
        }
    except Exception as e:
        st.error(f"Error loading platform stats: {e}")
        return None


def get_last_update_info():
    """When the data was last actually refreshed - the stats above are
    always computed live, but the underlying data only changes when the
    orchestrator runs, so this is the number that answers "how fresh is
    this?"."""
    try:
        with open('logs/orchestrator_metrics.json', 'r') as f:
            metrics = json.load(f)
        last_run = metrics.get('last_run_time')
        if last_run:
            dt = datetime.fromisoformat(last_run)
            return {
                'last_run': dt.strftime('%Y-%m-%d %H:%M UTC'),
                'total_runs': metrics.get('total_runs', 0),
                'successful_runs': metrics.get('successful_runs', 0),
            }
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        pass
    return None

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

update_info = get_last_update_info()
if update_info:
    st.markdown(
        f"<div class='asif-section-title'>Platform Statistics"
        f"<span class='asif-caption' style='font-weight:500;'>"
        f"Last updated {update_info['last_run']} "
        f"({update_info['successful_runs']}/{update_info['total_runs']} runs succeeded)"
        f"</span></div>",
        unsafe_allow_html=True
    )
else:
    st.markdown(
        "<div class='asif-section-title'>Platform Statistics"
        "<span class='asif-caption' style='font-weight:500;'>"
        "No orchestrator run recorded yet"
        "</span></div>",
        unsafe_allow_html=True
    )

stats = get_platform_stats()

if stats:
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            kpi_card("Total Threats", stats['total_threats'], severity="accent"),
            unsafe_allow_html=True
        )

    with col2:
        st.markdown(
            kpi_card("Threat Categories", stats['threat_types'], severity="neutral"),
            unsafe_allow_html=True
        )

    with col3:
        st.markdown(
            kpi_card("Intelligence Sources", stats['sources'], severity="neutral"),
            unsafe_allow_html=True
        )

    with col4:
        st.markdown(
            kpi_card(
                "AI-Relevant",
                f"{stats['ai_relevant_pct']:.0f}%",
                severity="accent",
                trend="neutral",
                trend_label=f"{stats['ai_relevant']} threats",
            ),
            unsafe_allow_html=True
        )

    with col5:
        st.markdown(
            kpi_card(
                "Registered Agents",
                stats['active_agents'],
                severity="low" if stats['active_agents'] > 0 else "neutral",
            ),
            unsafe_allow_html=True
        )

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
    # Relative links to local .md files don't resolve to anything when
    # rendered in a running Streamlit app (the browser navigates relative
    # to the page URL, not the filesystem) - these point at the actual
    # files on GitHub instead, and the Architecture path is corrected
    # (the file is ARCHITECTURE.md at the repo root, not docs/architecture.md).
    _repo = "https://github.com/Mavchris/Agent_Security_Framework/blob/main"
    st.markdown(f"""
    - [README]({_repo}/README.md)
    - [Architecture]({_repo}/ARCHITECTURE.md)
    - [Contributing]({_repo}/CONTRIBUTING.md)
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
