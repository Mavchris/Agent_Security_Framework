"""
Dashboard 3: Agent Testing & Monitoring (UPDATED)
Test agents against threats + Monitor production agents
Integrated with AgentVulnerabilityScanner and Agent Wrappers
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import json
import sys
import os
from datetime import datetime, timedelta

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Page config
st.set_page_config(
    page_title="Agent Operations",
    page_icon="⚙️",
    layout="wide"
)

# ============================================
# IMPORTS
# ============================================

try:
    from testing.agent_wrappers import get_agent_wrapper
    from testing.agent_scanner import AgentVulnerabilityScanner
except ImportError as e:
    st.error(f"Import Error: {e}")

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
        cursor.execute('SELECT * FROM threats')
        threats = [dict(row) for row in cursor.fetchall()]
        return threats
    except Exception as e:
        st.error(f"Error: {e}")
        return []

# ============================================
# LOAD DATA
# ============================================

threats = get_all_threats()

# ============================================
# HEADER
# ============================================

st.markdown("""
    <div style='text-align: center; margin-bottom: 30px;'>
        <h1>⚙️ Agent Operations Dashboard</h1>
        <p style='font-size: 16px; color: #666;'>Test agents and monitor production systems</p>
    </div>
""", unsafe_allow_html=True)

# ============================================
# TABS
# ============================================

tab1, tab2 = st.tabs(["▶️ Test Agent", "📊 Monitor Production"])

# ============================================
# TAB 1: TEST AGENT (UPDATED WITH REAL SCANNER)
# ============================================

with tab1:
    st.subheader("▶️ Test Your Agent Against All Threats")
    
    # Agent selection
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        agent_type = st.selectbox(
            "Choose Agent Type",
            ["Mock (Demo)", "Claude", "GPT-4", "Llama (Local)", "Mistral", "HuggingFace", "Custom"],
            help="Select the type of agent to test"
        )
    
    with col2:
        agent_name = st.text_input("Agent Name", value="my_agent", help="Name for your agent")
    
    with col3:
        test_button = st.button("▶️ RUN SCAN", use_container_width=True, key="run_test")
    
    st.divider()
    
    # Agent-specific configurations
    agent_config = {}
    
    if agent_type == "Mock (Demo)":
        agent_config = {"type": "mock"}
        st.info("🎭 Using Mock agent for demonstration (no API calls)")
    
    elif agent_type == "Claude":
        agent_config = {"type": "claude"}
        st.info("🔑 Requires ANTHROPIC_API_KEY environment variable")
    
    elif agent_type == "GPT-4":
        model = st.selectbox("Model", ["gpt-4", "gpt-3.5-turbo"])
        agent_config = {"type": "openai", "model": model}
        st.info("🔑 Requires OPENAI_API_KEY environment variable")
    
    elif agent_type == "Llama (Local)":
        model = st.text_input("Model name", value="llama2", help="Ollama model name")
        agent_config = {"type": "llama", "model": model}
        st.info("💻 Requires Ollama running locally (ollama serve)")
    
    elif agent_type == "Mistral":
        agent_config = {"type": "mistral"}
        st.info("🔑 Requires MISTRAL_API_KEY environment variable")
    
    elif agent_type == "HuggingFace":
        model = st.text_input(
            "Model name",
            value="mistralai/Mistral-7B-Instruct-v0.1",
            help="HuggingFace model identifier"
        )
        agent_config = {"type": "hf", "model_name": model}
        st.info("💾 Downloads model locally (may be large)")
    
    elif agent_type == "Custom":
        st.warning("⚠️ Custom agent must be a Python class with a query() method")
        custom_code = st.text_area(
            "Enter your agent code",
            height=200,
            help="Class with query(prompt) method"
        )
        agent_config = {"type": "custom", "code": custom_code}
    
    st.divider()
    
    # RUN SCAN
    if test_button:
        try:
            st.info(f"🔄 Initializing {agent_type} agent...")
            
            # Create agent wrapper
            agent = get_agent_wrapper(**agent_config)
            
            st.info(f"🔄 Scanning agent '{agent_name}' against {len(threats)} threats...")
            
            # Progress placeholder
            progress_placeholder = st.empty()
            status_placeholder = st.empty()
            
            # Scan with progress
            scanner = AgentVulnerabilityScanner(agent, db_path='data/threats.db')
            results = scanner.scan_all_threats(verbose=False)
            
            # Update progress
            progress_placeholder.progress(100)
            status_placeholder.text("✅ Scan complete!")
            
            st.divider()
            st.subheader("📊 Test Results")
            
            # KPI Cards
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "Vulnerability Score",
                    f"{results['vulnerability_score']:.1f}%",
                    delta="Overall Risk"
                )
            
            with col2:
                st.metric(
                    "Vulnerabilities Found",
                    len(results['vulnerabilities']),
                    delta="Threats"
                )
            
            with col3:
                st.metric(
                    "Safe Threats",
                    len(results['safe_threats']),
                    delta="Detected"
                )
            
            with col4:
                st.metric(
                    "Total Tested",
                    results['total_threats'],
                    delta="Coverage"
                )
            
            st.divider()
            
            # Vulnerability by threat type
            st.subheader("🔴 Vulnerability by Threat Type")
            
            type_data = []
            for ttype, stats in results['by_type'].items():
                vuln_pct = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
                type_data.append({
                    'Threat Type': ttype,
                    'Vulnerable': stats['vulnerable'],
                    'Safe': stats['total'] - stats['vulnerable'],
                    'Total': stats['total'],
                    'Risk %': vuln_pct
                })
            
            type_df = pd.DataFrame(type_data).sort_values('Risk %', ascending=False)
            
            fig = px.bar(
                type_df,
                x='Threat Type',
                y=['Vulnerable', 'Safe'],
                barmode='stack',
                color_discrete_map={'Vulnerable': '#ff4757', 'Safe': '#6bcf7f'},
                title="Vulnerability by Threat Type"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.divider()
            
            # Vulnerability by severity
            st.subheader("⚠️ Vulnerability by Severity")
            
            severity_data = []
            for severity, stats in results['by_severity'].items():
                vuln_pct = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
                severity_data.append({
                    'Severity': severity,
                    'Vulnerable': stats['vulnerable'],
                    'Safe': stats['total'] - stats['vulnerable'],
                    'Total': stats['total'],
                    'Risk %': vuln_pct
                })
            
            severity_df = pd.DataFrame(severity_data)
            severity_order = ['critical', 'high', 'medium', 'low']
            severity_df['Severity'] = pd.Categorical(
                severity_df['Severity'],
                categories=severity_order,
                ordered=True
            )
            severity_df = severity_df.sort_values('Severity')
            
            fig = px.bar(
                severity_df,
                x='Severity',
                y=['Vulnerable', 'Safe'],
                barmode='stack',
                color_discrete_map={'Vulnerable': '#ff4757', 'Safe': '#6bcf7f'},
                title="Vulnerability by Severity"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.divider()
            
            # Top vulnerabilities
            st.subheader("🔴 Top 10 Vulnerabilities")
            
            if results['vulnerabilities']:
                vuln_list = []
                for idx, vuln in enumerate(results['vulnerabilities'][:10], 1):
                    vuln_list.append({
                        '#': idx,
                        'ID': vuln['threat_id'],
                        'Title': vuln['title'][:40],
                        'Type': vuln['type'],
                        'Severity': vuln['severity']
                    })
                
                vuln_df = pd.DataFrame(vuln_list)
                st.dataframe(vuln_df, use_container_width=True, hide_index=True)
            else:
                st.success("✅ No vulnerabilities found! Agent is secure.")
            
            st.divider()
            
            # Recommendations
            st.subheader("💡 Recommendations")
            
            recommendations = [
                "🔒 Implement input validation for all user inputs",
                "🛡️ Add prompt injection filtering",
                "📊 Monitor API abuse patterns",
                "🔑 Rotate API keys regularly",
                "📝 Log all agent interactions",
                "🔄 Regular security updates",
                "👥 Security awareness training"
            ]
            
            for rec in recommendations:
                st.info(rec)
            
            st.divider()
            
            # Export reports
            st.subheader("📥 Export Reports")
            
            col1, col2 = st.columns(2)
            
            # JSON Export
            with col1:
                report_json = json.dumps({
                    'agent_name': agent_name,
                    'agent_type': agent_type,
                    'timestamp': datetime.now().isoformat(),
                    'results': {
                        'total_threats': results['total_threats'],
                        'vulnerability_score': results['vulnerability_score'],
                        'vulnerabilities_found': len(results['vulnerabilities']),
                        'safe_threats': len(results['safe_threats']),
                        'by_type': results['by_type'],
                        'by_severity': results['by_severity']
                    },
                    'top_vulnerabilities': [
                        {
                            'id': v['threat_id'],
                            'title': v['title'],
                            'type': v['type'],
                            'severity': v['severity']
                        }
                        for v in results['vulnerabilities'][:10]
                    ]
                }, indent=2, default=str)
                
                st.download_button(
                    label="📥 Download Report (JSON)",
                    data=report_json,
                    file_name=f"agent_test_{agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            
            # CSV Export
            with col2:
                vuln_df_export = pd.DataFrame(results['vulnerabilities'])
                if not vuln_df_export.empty:
                    csv_data = vuln_df_export[['threat_id', 'title', 'type', 'severity']].to_csv(index=False)
                    st.download_button(
                        label="📥 Download Vulnerabilities (CSV)",
                        data=csv_data,
                        file_name=f"vulnerabilities_{agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
        
        except Exception as e:
            st.error(f"❌ Error during scan: {str(e)}")
            st.info("💡 Tips:\n- Mock agent needs no setup\n- Claude needs ANTHROPIC_API_KEY\n- Llama needs Ollama running locally")

# ============================================
# TAB 2: MONITOR PRODUCTION
# ============================================

with tab2:
    st.subheader("📊 Production Monitoring")
    
    # Agent status
    st.markdown("### 🟢 Agent Health Status")
    
    col1, col2, col3, col4 = st.columns(4)
    
    agents = [
        {'name': 'Agent-1', 'status': 'healthy', 'uptime': 99.9, 'alerts': 2},
        {'name': 'Agent-2', 'status': 'healthy', 'uptime': 99.5, 'alerts': 5},
        {'name': 'Agent-3', 'status': 'warning', 'uptime': 98.2, 'alerts': 12},
    ]
    
    for idx, agent in enumerate(agents):
        status_emoji = '🟢' if agent['status'] == 'healthy' else '🟠'
        with st.columns(4)[idx]:
            st.metric(
                f"{status_emoji} {agent['name']}",
                f"{agent['uptime']}%",
                delta=f"{agent['alerts']} alerts"
            )
    
    st.divider()
    
    # Real-time alerts
    st.markdown("### 🚨 Real-time Alerts")
    
    alert_filter = st.selectbox(
        "Filter by severity",
        ["All", "Critical", "High", "Medium", "Low"]
    )
    
    alerts_data = [
        {'time': '14:32', 'severity': 'Critical', 'agent': 'Agent-1', 'threat': 'Prompt Injection Attempt', 'status': '🔴'},
        {'time': '14:28', 'severity': 'High', 'agent': 'Agent-2', 'threat': 'Unauthorized Tool Access', 'status': '🟠'},
        {'time': '14:15', 'severity': 'Medium', 'agent': 'Agent-3', 'threat': 'API Rate Limit Exceeded', 'status': '🟡'},
        {'time': '14:05', 'severity': 'High', 'agent': 'Agent-1', 'threat': 'Data Exfiltration Attempt', 'status': '🟠'},
        {'time': '13:42', 'severity': 'Low', 'agent': 'Agent-2', 'threat': 'Unusual Request Pattern', 'status': '🟢'},
    ]
    
    alerts_df = pd.DataFrame(alerts_data)
    
    if alert_filter != "All":
        alerts_df = alerts_df[alerts_df['severity'] == alert_filter]
    
    for idx, alert in alerts_df.iterrows():
        st.warning(f"{alert['status']} **{alert['time']}** | {alert['severity']} | {alert['agent']} | {alert['threat']}")
    
    st.divider()
    
    # Threat detection trends
    st.markdown("### 📈 Threat Detection Trends (Last 7 days)")
    
    dates = pd.date_range(start='2025-03-20', periods=7, freq='D')
    trend_data = pd.DataFrame({
        'Date': dates,
        'Prompt Injection': [5, 7, 6, 8, 9, 11, 13],
        'Tool Abuse': [2, 1, 3, 2, 4, 3, 5],
        'API Abuse': [1, 2, 1, 3, 2, 4, 3],
        'Other': [3, 4, 5, 6, 7, 8, 9]
    })
    
    fig = px.line(
        trend_data,
        x='Date',
        y=['Prompt Injection', 'Tool Abuse', 'API Abuse', 'Other'],
        title="Detection Trends",
        markers=True
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    st.divider()
    
    # Quick actions
    st.markdown("### ⚡ Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔒 Lock Agent-1", use_container_width=True):
            st.success("✅ Agent-1 locked")
    
    with col2:
        if st.button("📋 View Logs", use_container_width=True):
            st.info("📋 Loading logs...")
    
    with col3:
        if st.button("🔄 Restart Agent", use_container_width=True):
            st.info("🔄 Restarting...")
    
    with col4:
        if st.button("📧 Alert Team", use_container_width=True):
            st.success("✅ Alert sent")

# ============================================
# FOOTER
# ============================================

st.divider()
st.markdown(
    f"""
    <div style='text-align: center; color: #666;'>
    <small>Agent Operations Dashboard | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Powered by AgentSecurityFramework</small>
    </div>
    """,
    unsafe_allow_html=True
)