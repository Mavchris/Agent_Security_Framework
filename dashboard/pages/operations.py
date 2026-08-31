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
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.style import (  # noqa: E402
    apply_plotly_theme, badge, icon, info_banner, load_theme, mini_card, score_card,
    status_dot_html,
)

# Page config
st.set_page_config(
    page_title="Agent Operations",
    page_icon=None,
    layout="wide"
)

load_theme()

# ============================================
# IMPORTS
# ============================================

try:
    from testing.agent_wrappers import get_agent_wrapper
    from testing.agent_scanner import AgentVulnerabilityScanner
    from core.agent_registry import build_wrapper, deactivate_agent, list_agents, register_agent
    from core.auth import verify_key
    from core import scan_store
    from monitoring import monitoring_store
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
# HEADER
# ============================================

st.markdown(
    """
    <h1 class='asif-h1'>Agent Operations</h1>
    <p class='asif-subtitle'>Test agents and monitor production systems</p>
    """,
    unsafe_allow_html=True
)

# ============================================
# API KEY GATE
# ============================================
# Every action on this page - registering/listing/deactivating agents,
# running a scan, reading production monitoring data - is sensitive (see
# SECURITY.md, the Vague that added named API keys). The catalog pages
# (Intelligence, Catalog) stay public; this whole page does not, so it's
# gated as a single unit rather than per-tab/per-button.
#
# The key is checked once per browser session, not on every click: a
# validated session only remembers the resulting *label* in
# st.session_state, never the raw key. This means a key revoked mid-session
# stays effective in a tab that already unlocked until that tab's session
# ends (browser close, or Streamlit session expiry) - a deliberate
# trade-off for not re-prompting/re-checking on every interaction; see
# SECURITY.md for this limitation if a faster-acting revocation is ever
# needed.

if not st.session_state.get("api_key_label"):
    st.markdown(
        info_banner(
            "This page manages registered agents, runs scans against them, and "
            "reads production monitoring data - all of it requires a named API "
            "key. Enter yours below (see scripts/maintenance/create_api_key.py "
            "if you don't have one)."
        ),
        unsafe_allow_html=True,
    )

    with st.form("api_key_gate_form"):
        candidate_key = st.text_input("API key", type="password", key="api_key_gate_input")
        unlock_submitted = st.form_submit_button("Unlock")

    if unlock_submitted:
        label = verify_key(candidate_key)
        if label:
            st.session_state["api_key_label"] = label
            st.rerun()
        else:
            st.error("Invalid or inactive API key.")

    st.stop()

key_label = st.session_state["api_key_label"]

threats = get_all_threats()

# ============================================
# SHARED: AGENT REGISTRATION FORM
# ============================================

def render_registration_form(key_prefix):
    """"Register a new agent" form, shared by the "Test Agent" and
    "Monitor Production" tabs so registration isn't gated behind a
    specific tab. Two explicit entry paths - "My own agent" locks
    straight to remote_http, "Reference baseline model" shows the 6
    quick types - see the Vague that split this out to stop users
    registering a raw Claude/GPT-4 thinking it was their own agent.

    key_prefix must be unique per call site: both tabs' widgets exist
    in the same script run simultaneously (Streamlit renders all tab
    content on every rerun, it only hides the inactive tab visually),
    so identical widget keys across two calls would collide.
    """
    success_key = f"{key_prefix}_last_registered_agent"
    if st.session_state.get(success_key):
        st.success(f"Agent '{st.session_state.pop(success_key)}' registered.")

    reg_path = st.radio(
        "What do you want to register?",
        ["My own agent", "Reference baseline model"],
        key=f"{key_prefix}_register_agent_path",
        help=(
            "\"My own agent\" connects to YOUR agent over HTTP - its system "
            "prompt, tools and business logic included. \"Reference baseline "
            "model\" tests a raw model via a generic API key, not your own agent."
        ),
    )

    if reg_path == "My own agent":
        reg_agent_type = "remote_http"
        st.markdown(
            info_banner(
                "For an agent that only exists as a local script/function, see "
                "docs/examples/local_agent_http_wrapper.py for a minimal example of "
                "exposing it as a local HTTP endpoint first, then register it here "
                "pointing to that local URL."
            ),
            unsafe_allow_html=True,
        )
    else:
        reg_type_label = st.selectbox(
            "Reference model",
            ["Mock", "Claude", "GPT-4 (OpenAI)", "Llama (Local)", "Mistral", "HuggingFace"],
            key=f"{key_prefix}_register_agent_type",
        )
        reg_type_map = {
            "Mock": "mock",
            "Claude": "claude",
            "GPT-4 (OpenAI)": "openai",
            "Llama (Local)": "llama",
            "Mistral": "mistral",
            "HuggingFace": "huggingface",
        }
        reg_agent_type = reg_type_map[reg_type_label]
        st.markdown(
            "<p style='color:var(--text-tertiary);font-size:13px;margin:-4px 0 12px;'>"
            "Tests the raw model via a generic API key — without your system "
            "prompt, tools, or business logic. Useful as a comparison baseline, "
            "not for scanning your own agent."
            "</p>",
            unsafe_allow_html=True,
        )

    with st.form(f"{key_prefix}_register_agent_form", clear_on_submit=True):
        reg_name = st.text_input("Agent name", key=f"{key_prefix}_reg_name")
        reg_environment = st.text_input(
            "Environment (optional)", placeholder="production / staging / test",
            key=f"{key_prefix}_reg_environment",
        )

        reg_config = {}
        if reg_agent_type == "openai":
            reg_config["model"] = st.selectbox(
                "Model", ["gpt-4", "gpt-3.5-turbo"], key=f"{key_prefix}_reg_openai_model"
            )
        elif reg_agent_type == "llama":
            reg_config["model"] = st.text_input(
                "Model name", value="llama2", key=f"{key_prefix}_reg_llama_model"
            )
        elif reg_agent_type == "huggingface":
            reg_config["model_name"] = st.text_input(
                "Model name", value="mistralai/Mistral-7B-Instruct-v0.1",
                key=f"{key_prefix}_reg_hf_model",
            )
        elif reg_agent_type == "remote_http":
            reg_config["endpoint_url"] = st.text_input(
                "Endpoint URL", placeholder="https://agent.internal/query",
                key=f"{key_prefix}_reg_endpoint_url",
            )
            col_a, col_b = st.columns(2)
            with col_a:
                reg_config["request_field"] = st.text_input(
                    "Request field", value="prompt", key=f"{key_prefix}_reg_request_field"
                )
            with col_b:
                reg_config["response_field"] = st.text_input(
                    "Response field", value="response", key=f"{key_prefix}_reg_response_field"
                )
            reg_config["auth_env_var"] = st.text_input(
                "Auth env var name (optional)",
                placeholder="MY_AGENT_TOKEN",
                help="The name of an environment variable in config/.env.local holding "
                     "a bearer token - never the token itself.",
                key=f"{key_prefix}_reg_auth_env_var",
            )
            reg_verify_ssl = st.checkbox(
                "Verify TLS certificate", value=True, key=f"{key_prefix}_reg_verify_ssl"
            )
            reg_config["verify_ssl"] = reg_verify_ssl
            if reg_verify_ssl:
                reg_config["ca_cert_path"] = st.text_input(
                    "Internal CA bundle path (optional)",
                    placeholder="/etc/ssl/internal-ca.pem",
                    key=f"{key_prefix}_reg_ca_cert_path",
                )
            else:
                st.markdown(
                    info_banner(
                        "TLS verification disabled - traffic to this agent won't be "
                        "protected against interception. Every call will log a warning.",
                        "alert-triangle",
                    ),
                    unsafe_allow_html=True,
                )

        # No key= here: a form can only have one submit button, and each
        # of the two forms this function renders already has its own
        # unique name (f"{key_prefix}_register_agent_form" above), which
        # Streamlit uses to disambiguate identically-labeled buttons in
        # different forms - a widget-level key would be redundant. Also
        # avoids depending on Streamlit 1.49+ (key= on this widget wasn't
        # added until then; see requirements.txt's streamlit pin history).
        register_submitted = st.form_submit_button("Register Agent")

    if register_submitted:
        if not reg_name:
            st.error("Agent name is required.")
        else:
            clean_config = {k: v for k, v in reg_config.items() if v not in (None, "")}
            try:
                register_agent(
                    reg_name, reg_agent_type,
                    config=clean_config,
                    environment=reg_environment or None,
                )
                # st.rerun() below discards any st.success() called before
                # it, so the confirmation is shown after the rerun instead
                # (see the session_state check at the top of this function).
                st.session_state[success_key] = reg_name
                st.rerun()
            except ValueError as e:
                st.error(str(e))


# ============================================
# TABS
# ============================================

tab1, tab2 = st.tabs(["Test Agent", "Monitor Production"])

# ============================================
# TAB 1: TEST AGENT (UPDATED WITH REAL SCANNER)
# ============================================

with tab1:
    st.markdown(
        f"<div class='asif-section-title'>{icon('play', size=18)} Test Your Agent Against All Threats</div>",
        unsafe_allow_html=True
    )

    agent_source = st.radio(
        "Agent source",
        ["Quick type (no registration)", "Registered agent"],
        horizontal=True,
        help="Quick type: one-off test, nothing saved. Registered agent: pick one you've saved below.",
        key="agent_source",
    )

    registered_agents = list_agents()
    selected_registered_agent = None

    with st.container(border=True):
        if agent_source == "Quick type (no registration)":
            # Agent selection
            col1, col2, col3 = st.columns([2, 1, 1])

            with col1:
                agent_type = st.selectbox(
                    "Choose Agent Type",
                    ["Mock (Demo)", "Claude", "GPT-4", "Llama (Local)", "Mistral", "HuggingFace"],
                    help="Select the type of agent to test"
                )

            with col2:
                agent_name = st.text_input("Agent Name", value="my_agent", help="Name for your agent")

            with col3:
                st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
                test_button = st.button("Run Scan", use_container_width=True, key="run_test", type="primary")

            # Agent-specific configurations
            agent_config = {}

            if agent_type == "Mock (Demo)":
                agent_config = {"agent_type": "mock"}
                st.markdown(info_banner("Using Mock agent for demonstration (no API calls)"), unsafe_allow_html=True)

            elif agent_type == "Claude":
                agent_config = {"agent_type": "claude"}
                st.markdown(info_banner("Requires ANTHROPIC_API_KEY environment variable"), unsafe_allow_html=True)

            elif agent_type == "GPT-4":
                model = st.selectbox("Model", ["gpt-4", "gpt-3.5-turbo"])
                agent_config = {"agent_type": "openai", "model": model}
                st.markdown(info_banner("Requires OPENAI_API_KEY environment variable"), unsafe_allow_html=True)

            elif agent_type == "Llama (Local)":
                model = st.text_input("Model name", value="llama2", help="Ollama model name")
                agent_config = {"agent_type": "llama", "model": model}
                st.markdown(info_banner("Requires Ollama running locally (ollama serve)"), unsafe_allow_html=True)

            elif agent_type == "Mistral":
                agent_config = {"agent_type": "mistral"}
                st.markdown(info_banner("Requires MISTRAL_API_KEY environment variable"), unsafe_allow_html=True)

            elif agent_type == "HuggingFace":
                model = st.text_input(
                    "Model name",
                    value="mistralai/Mistral-7B-Instruct-v0.1",
                    help="HuggingFace model identifier"
                )
                agent_config = {"agent_type": "hf", "model_name": model}
                st.markdown(info_banner("Downloads model locally (may be large)"), unsafe_allow_html=True)

        else:
            agent_config = {}
            if not registered_agents:
                st.markdown(
                    info_banner(
                        "No agents registered yet - use the form below to register one.",
                        "alert-triangle",
                    ),
                    unsafe_allow_html=True,
                )
                agent_name = None
                agent_type = None
                test_button = False
            else:
                col1, col2 = st.columns([3, 1])
                with col1:
                    labels = [
                        f"{a['name']} ({a['agent_type']}"
                        + (f", {a['environment']}" if a['environment'] else "")
                        + ")"
                        for a in registered_agents
                    ]
                    selected_label = st.selectbox(
                        "Choose a registered agent", labels, key="registered_agent_select"
                    )
                    selected_registered_agent = registered_agents[labels.index(selected_label)]
                with col2:
                    st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
                    test_button = st.button(
                        "Run Scan", use_container_width=True, key="run_test_registered", type="primary"
                    )
                agent_name = selected_registered_agent["name"]
                agent_type = selected_registered_agent["agent_type"]

    with st.expander("Register a new agent"):
        render_registration_form("test_agent")

    # RUN SCAN
    if test_button:
        scan_row = None
        try:
            st.markdown(info_banner(f"Initializing {agent_type} agent..."), unsafe_allow_html=True)

            # Create agent wrapper
            if selected_registered_agent is not None:
                agent = build_wrapper(selected_registered_agent)
            else:
                agent = get_agent_wrapper(**agent_config)

            # Same scan_results persistence POST /scan writes to (see
            # core/scan_store.py) - attributed to the key that unlocked
            # this dashboard session, same as registering/deactivating an
            # agent already is. status transitions pending -> running ->
            # completed/failed even though this runs synchronously in the
            # request (no BackgroundTasks here - Streamlit has no
            # equivalent, the page just blocks until the script finishes),
            # so a scan triggered from the dashboard is indistinguishable
            # via GET /scan/results/{id} from one triggered via POST /scan.
            scan_row = scan_store.create_scan(
                agent_name=agent_name,
                agent_id=selected_registered_agent['id'] if selected_registered_agent else None,
                triggered_by_key_label=key_label,
            )
            scan_store.mark_running(scan_row['id'])

            st.markdown(
                info_banner(f"Scanning agent '{agent_name}' against {len(threats)} threats..."),
                unsafe_allow_html=True
            )

            # Progress placeholder
            progress_placeholder = st.empty()
            status_placeholder = st.empty()

            # Scan with progress
            scanner = AgentVulnerabilityScanner(agent, db_path='data/threats.db')
            results = scanner.scan_all_threats(verbose=False)

            scan_store.mark_completed(scan_row['id'], results)

            # Update progress
            progress_placeholder.progress(100)
            status_placeholder.markdown(
                f"<span class='badge badge-low'>{icon('check-circle', size=14)} "
                f"Scan complete (#{scan_row['id']})</span>",
                unsafe_allow_html=True
            )

            st.divider()
            st.markdown("<div class='asif-section-title'>Test Results</div>", unsafe_allow_html=True)

            # KPI Cards
            col1, col2, col3, col4, col5 = st.columns(5)

            with col1:
                st.markdown(
                    score_card("Vulnerability Score", results['vulnerability_score']),
                    unsafe_allow_html=True
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
                    "Technical Errors",
                    len(results['technical_errors']),
                    delta="Not scored" if results['technical_errors'] else None,
                    help="Threats that couldn't actually be tested (network/rate-limit/timeout after retries) - excluded from the vulnerability score, not counted as either vulnerable or safe.",
                )

            with col5:
                st.metric(
                    "Total Tested",
                    results['total_threats'],
                    delta="Coverage"
                )

            st.divider()

            # Vulnerability by threat type
            st.markdown("<div class='asif-section-title'>Vulnerability by Threat Type</div>", unsafe_allow_html=True)

            type_data = []
            for ttype, stats in results['by_type'].items():
                testable = stats['total'] - stats['errors']
                vuln_pct = (stats['vulnerable'] / testable * 100) if testable > 0 else 0
                type_data.append({
                    'Threat Type': ttype,
                    'Vulnerable': stats['vulnerable'],
                    'Safe': testable - stats['vulnerable'],
                    'Technical Errors': stats['errors'],
                    'Total': stats['total'],
                    'Risk %': vuln_pct
                })

            type_df = pd.DataFrame(type_data).sort_values('Risk %', ascending=False)

            fig = px.bar(
                type_df,
                x='Threat Type',
                y=['Vulnerable', 'Safe', 'Technical Errors'],
                barmode='stack',
                color_discrete_map={'Vulnerable': '#DC2626', 'Safe': '#16A34A', 'Technical Errors': '#9CA3AF'},
                title="Vulnerability by Threat Type"
            )
            apply_plotly_theme(fig)
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

            st.divider()

            # Vulnerability by severity
            st.markdown("<div class='asif-section-title'>Vulnerability by Severity</div>", unsafe_allow_html=True)

            severity_data = []
            for severity, stats in results['by_severity'].items():
                testable = stats['total'] - stats['errors']
                vuln_pct = (stats['vulnerable'] / testable * 100) if testable > 0 else 0
                severity_data.append({
                    'Severity': severity,
                    'Vulnerable': stats['vulnerable'],
                    'Safe': testable - stats['vulnerable'],
                    'Technical Errors': stats['errors'],
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
                y=['Vulnerable', 'Safe', 'Technical Errors'],
                barmode='stack',
                color_discrete_map={'Vulnerable': '#DC2626', 'Safe': '#16A34A', 'Technical Errors': '#9CA3AF'},
                title="Vulnerability by Severity"
            )
            apply_plotly_theme(fig)
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

            st.divider()

            # Top vulnerabilities
            st.markdown("<div class='asif-section-title'>Top 10 Vulnerabilities</div>", unsafe_allow_html=True)

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
                st.markdown(
                    f"<div class='info-banner'>{icon('check-circle', size=18)}"
                    f"<span>No vulnerabilities found. Agent is secure.</span></div>",
                    unsafe_allow_html=True
                )

            st.divider()

            # Recommendations
            st.markdown("<div class='asif-section-title'>Recommendations</div>", unsafe_allow_html=True)

            recommendations = [
                "Implement input validation for all user inputs",
                "Add prompt injection filtering",
                "Monitor API abuse patterns",
                "Rotate API keys regularly",
                "Log all agent interactions",
                "Regular security updates",
                "Security awareness training",
            ]

            rec_items = "".join(f"<li>{rec}</li>" for rec in recommendations)
            st.markdown(
                f"<div class='asif-card'><ul class='nav-card-features' "
                f"style='margin:0;'>{rec_items}</ul></div>",
                unsafe_allow_html=True
            )

            st.divider()

            # Export reports
            st.markdown("<div class='asif-section-title'>Export Reports</div>", unsafe_allow_html=True)

            col1, col2 = st.columns(2)

            # JSON Export
            with col1:
                report_json = json.dumps({
                    'scan_id': scan_row['id'],
                    'agent_name': agent_name,
                    'agent_type': agent_type,
                    'timestamp': datetime.now().isoformat(),
                    'results': {
                        'total_threats': results['total_threats'],
                        'vulnerability_score': results['vulnerability_score'],
                        'vulnerabilities_found': len(results['vulnerabilities']),
                        'safe_threats': len(results['safe_threats']),
                        'technical_errors': len(results['technical_errors']),
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
                    label="Download Report (JSON)",
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
                        label="Download Vulnerabilities (CSV)",
                        data=csv_data,
                        file_name=f"vulnerabilities_{agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )

        except Exception as e:
            if scan_row is not None:
                scan_store.mark_failed(scan_row['id'], str(e))
            st.error(f"Error during scan: {str(e)}")
            st.markdown(
                info_banner(
                    "Tips: Mock agent needs no setup - Claude needs ANTHROPIC_API_KEY - "
                    "Llama needs Ollama running locally"
                ),
                unsafe_allow_html=True
            )

# ============================================
# TAB 2: MONITOR PRODUCTION
# ============================================

with tab2:
    st.markdown("<div class='asif-section-title'>Production Monitoring</div>", unsafe_allow_html=True)

    with st.expander("Register a new agent"):
        render_registration_form("monitor")

    monitored_agents = list_agents()

    # Reads straight from monitoring_store (data/monitoring.db) - the same
    # persistence api/app.py's /monitoring/* endpoints write to, so this
    # tab reflects real production activity logged from any process, not
    # a separate, dashboard-only view.

    if not monitored_agents:
        st.markdown(
            info_banner(
                "No agents registered yet - use the form above to register one.",
                "alert-triangle",
            ),
            unsafe_allow_html=True,
        )
    else:
        # Agent status
        st.markdown(
            f"<div class='asif-section-title' style='font-size:16px;'>"
            f"{status_dot_html('healthy')} Agent Health Status</div>",
            unsafe_allow_html=True
        )

        cols = st.columns(min(4, len(monitored_agents)))
        for idx, agent in enumerate(monitored_agents):
            stats = monitoring_store.get_statistics(agent['name'])
            status = 'healthy' if stats['alert_rate'] <= 30 else 'warning'
            with cols[idx % len(cols)]:
                st.markdown(
                    f"""
                    <div class='kpi-card severity-{"low" if status == "healthy" else "medium"}'>
                        <p class='kpi-label'>{status_dot_html(status)} {agent['name']}</p>
                        <p class='kpi-value' style='font-size:28px;'>{stats['total_requests_logged']}</p>
                        <div class='kpi-trend neutral'><span>{stats['total_alerts']} alerts</span></div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.divider()

        # Recent alerts, aggregated across all registered agents' session monitors
        st.markdown("<div class='asif-section-title'>Recent Alerts</div>", unsafe_allow_html=True)

        alert_filter = st.selectbox(
            "Filter by severity",
            ["All", "critical", "high", "medium", "low"]
        )

        all_alerts = []
        for agent in monitored_agents:
            for alert in monitoring_store.get_alerts(agent_name=agent['name'], limit=20):
                all_alerts.append({**alert, "agent_display_name": agent["name"]})
        all_alerts.sort(key=lambda a: a["created_at"], reverse=True)

        if alert_filter != "All":
            all_alerts = [a for a in all_alerts if a["severity"] == alert_filter]

        with st.container(border=True):
            if not all_alerts:
                st.markdown(
                    "<p style='color:var(--text-tertiary);margin:0;'>"
                    "No alerts yet - log requests for a registered agent "
                    "(POST /monitoring/log-request) to populate this.</p>",
                    unsafe_allow_html=True
                )
            for alert in all_alerts[:20]:
                st.markdown(
                    f"""
                    <div style='display:flex;align-items:center;gap:12px;padding:8px 0;
                                border-bottom:1px solid var(--border);font-size:14px;'>
                        <span class='mono' style='color:var(--text-tertiary);min-width:150px;'>{alert['created_at']}</span>
                        {badge(alert['severity'].upper(), alert['severity'])}
                        <span style='color:var(--text-secondary);min-width:120px;'>{alert['agent_display_name']}</span>
                        <span style='color:var(--text-primary);'>{alert['message']}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.divider()

        # Agent actions - real, wired to the registry and this session's monitors
        st.markdown("<div class='asif-section-title'>Agent Actions</div>", unsafe_allow_html=True)

        action_labels = [a['name'] for a in monitored_agents]
        selected_action_label = st.selectbox("Select agent", action_labels, key="monitor_action_agent")
        selected_action_agent = monitored_agents[action_labels.index(selected_action_label)]

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("Run Health Check", use_container_width=True):
                stats = monitoring_store.get_statistics(selected_action_agent['name'])
                if stats['total_requests_logged'] == 0:
                    st.info(f"{selected_action_agent['name']}: no requests logged yet.")
                elif stats['alert_rate'] > 30:
                    st.warning(
                        f"{selected_action_agent['name']}: alert rate "
                        f"{stats['alert_rate']:.1f}% - degraded."
                    )
                else:
                    st.success(
                        f"{selected_action_agent['name']}: healthy "
                        f"({stats['alert_rate']:.1f}% alert rate)."
                    )

        with col2:
            if st.button("View Monitoring History", use_container_width=True):
                logs = monitoring_store.get_logs(agent_name=selected_action_agent['name'], limit=20)
                if not logs:
                    st.info("No requests logged for this agent.")
                else:
                    history_df = pd.DataFrame([
                        {
                            "Time": log["created_at"],
                            "Alert": log["alert_triggered"],
                            "Risk": log["risk_level"],
                        }
                        for log in logs
                    ])
                    st.dataframe(history_df, use_container_width=True, hide_index=True)

        with col3:
            if st.button("Deactivate Monitoring", use_container_width=True):
                deactivate_agent(selected_action_agent["id"])
                st.success(f"{selected_action_agent['name']} deactivated.")
                st.rerun()

# ============================================
# FOOTER
# ============================================

st.divider()
st.markdown(
    f"""
    <div style='text-align: center; color: var(--text-tertiary);'>
    <small>Agent Operations Dashboard | Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Powered by AgentSecurityFramework</small>
    </div>
    """,
    unsafe_allow_html=True
)
