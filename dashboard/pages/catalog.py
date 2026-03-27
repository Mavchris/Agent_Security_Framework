"""
Dashboard 2: Detailed Threat Catalog
Browse, filter, and search all 219 threats
"""

import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime

# Page config
st.set_page_config(
    page_title="Threat Catalog",
    page_icon="🔍",
    layout="wide"
)

# ============================================
# DATABASE FUNCTIONS
# ============================================

@st.cache_resource
def get_db_connection():
    """Get database connection"""
    db_path = 'data/threats.db'
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def get_all_threats():
    """Get all threats"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM threats ORDER BY id DESC')
        threats = [dict(row) for row in cursor.fetchall()]
        return threats
    except Exception as e:
        st.error(f"Error loading threats: {e}")
        return []

def get_filter_options():
    """Get unique values for filters"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT DISTINCT threat_type FROM threats ORDER BY threat_type')
        types = [row[0] for row in cursor.fetchall()]
        
        cursor.execute('SELECT DISTINCT source FROM threats ORDER BY source')
        sources = [row[0] for row in cursor.fetchall()]
        
        cursor.execute('SELECT DISTINCT severity FROM threats WHERE severity != "unknown" ORDER BY severity')
        severities = [row[0] for row in cursor.fetchall()]
        
        return types, sources, severities
    except Exception as e:
        st.error(f"Error loading filters: {e}")
        return [], [], []

# ============================================
# LOAD DATA
# ============================================

threats = get_all_threats()
threat_types, sources, severities = get_filter_options()

# ============================================
# HEADER
# ============================================

st.markdown("""
    <div style='text-align: center; margin-bottom: 30px;'>
        <h1>🔍 Threat Catalog</h1>
        <p style='font-size: 16px; color: #666;'>Browse and search all AI agent security threats</p>
    </div>
""", unsafe_allow_html=True)

# ============================================
# FILTERS SECTION
# ============================================

st.subheader("🔎 Filters & Search")

col1, col2, col3 = st.columns(3)

with col1:
    selected_types = st.multiselect(
        "Threat Type",
        options=threat_types,
        default=[]
    )

with col2:
    selected_sources = st.multiselect(
        "Source",
        options=sources,
        default=[]
    )

with col3:
    selected_severities = st.multiselect(
        "Severity",
        options=severities,
        default=[]
    )

# Search box
search_term = st.text_input("🔎 Search by ID or Title...")

# Apply filters button
col1, col2 = st.columns([1, 5])
with col1:
    apply_filters = st.button("🔎 APPLY FILTERS", use_container_width=True)
with col2:
    reset_filters = st.button("🔄 RESET", use_container_width=True)

# ============================================
# FILTERING LOGIC
# ============================================

filtered_threats = threats.copy()

# Apply type filter
if selected_types:
    filtered_threats = [t for t in filtered_threats if t['threat_type'] in selected_types]

# Apply source filter
if selected_sources:
    filtered_threats = [t for t in filtered_threats if t['source'] in selected_sources]

# Apply severity filter
if selected_severities:
    filtered_threats = [t for t in filtered_threats if t.get('severity') in selected_severities]

# Apply search filter
if search_term:
    filtered_threats = [
        t for t in filtered_threats
        if search_term.lower() in t['threat_id'].lower() or
           search_term.lower() in t['title'].lower()
    ]

# ============================================
# RESULTS INFO
# ============================================

st.divider()
st.markdown(f"**Results: {len(filtered_threats)} threats** (from {len(threats)} total)")

# ============================================
# DISPLAY THREATS
# ============================================

if filtered_threats:
    # Pagination
    per_page = 20
    total_pages = (len(filtered_threats) + per_page - 1) // per_page
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        page = st.selectbox(
            "Page",
            options=range(1, total_pages + 1),
            format_func=lambda x: f"Page {x} of {total_pages}"
        )
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_threats = filtered_threats[start_idx:end_idx]
    
    # Display threats
    for threat in page_threats:
        severity = threat.get('severity', 'unknown')
        severity_color = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'unknown': '⚪'
        }.get(severity, '⚪')
        
        with st.expander(
            f"{severity_color} [{threat['threat_id']}] {threat['title'][:60]}",
            expanded=False
        ):
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.markdown("### Details")
                st.markdown(f"**ID:** `{threat['threat_id']}`")
                st.markdown(f"**Type:** `{threat['threat_type']}`")
                st.markdown(f"**Source:** `{threat['source']}`")
                st.markdown(f"**Severity:** {severity_color} {severity}")
                
                if threat.get('url'):
                    st.markdown(f"**[📖 View Source]({threat['url']})")
            
            with col2:
                st.markdown("### Description & Payload")
                st.markdown(threat.get('description', 'N/A'))
                
                if threat.get('test_payload'):
                    st.markdown("**Test Payload:**")
                    st.code(threat['test_payload'], language='text')
            
            # Detection keywords
            st.markdown("### Detection Keywords")
            if threat.get('detection_keywords'):
                keywords = threat.get('detection_keywords')
                if isinstance(keywords, str):
                    import json
                    try:
                        keywords = json.loads(keywords)
                    except:
                        keywords = [keywords]
                
                cols = st.columns(4)
                for idx, kw in enumerate(keywords):
                    with cols[idx % 4]:
                        st.info(f"🏷️ {kw}")
            else:
                st.info("No keywords")

else:
    st.warning("⚠️ No threats match your filters")

st.divider()

# ============================================
# EXPORT SECTION
# ============================================

st.subheader("📥 Export Filtered Results")

col1, col2 = st.columns(2)

with col1:
    csv_data = pd.DataFrame(filtered_threats).to_csv(index=False)
    st.download_button(
        label="📥 Download as CSV",
        data=csv_data,
        file_name=f"threats_catalog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

with col2:
    import json
    json_data = json.dumps(filtered_threats, indent=2, default=str)
    st.download_button(
        label="📥 Download as JSON",
        data=json_data,
        file_name=f"threats_catalog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )

# ============================================
# FOOTER
# ============================================

st.divider()
st.markdown(
    f"""
    <div style='text-align: center; color: #666;'>
    <small>Threat Catalog | {len(threats)} Total Threats | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</small>
    </div>
    """,
    unsafe_allow_html=True
)
