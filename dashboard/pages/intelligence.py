"""
Dashboard Intelligence Veille
Fusionné: Overview (vue d'ensemble) + Veille (monitoring orchestrateur)
"""

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import json
from datetime import datetime, timedelta
from pathlib import Path
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.style import (  # noqa: E402
    ACCENT, SEVERITY_COLORS, apply_plotly_theme, kpi_card, mini_card, load_theme,
    status_dot_html,
)

st.set_page_config(
    page_title="Intelligence Veille",
    page_icon=None,
    layout="wide"
)

load_theme()

# ============================================
# FONCTIONS
# ============================================

@st.cache_resource
def get_db_connection():
    """Obtenir connexion BD"""
    conn = sqlite3.connect('data/threats.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def get_threat_stats():
    """Obtenir statistiques menaces"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total
        cursor.execute('SELECT COUNT(*) FROM threats')
        total = cursor.fetchone()[0]

        # Par sévérité
        cursor.execute('SELECT severity, COUNT(*) FROM threats GROUP BY severity')
        by_severity = dict(cursor.fetchall())

        # Par type
        cursor.execute('SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type')
        by_type = dict(cursor.fetchall())

        # Par source
        cursor.execute('SELECT source, COUNT(*) FROM threats GROUP BY source')
        by_source = dict(cursor.fetchall())

        return {
            'total': total,
            'by_severity': by_severity,
            'by_type': by_type,
            'by_source': by_source
        }
    except Exception as e:
        st.error(f"Erreur: {e}")
        return None

def get_orchestrator_metrics():
    """Obtenir métriques orchestrateur"""
    try:
        metrics_file = 'logs/orchestrator_metrics.json'
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return None

def get_latest_threats(limit=10):
    """Obtenir les menaces les plus récentes"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT threat_id, title, threat_type, severity, source, created_at
            FROM threats
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        threats = [dict(row) for row in cursor.fetchall()]
        return threats
    except Exception as e:
        st.error(f"Erreur: {e}")
        return []

def get_threat_trends(days=30):
    """Obtenir les tendances menaces"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM threats
            WHERE created_at >= datetime('now', '-' || ? || ' days')
            GROUP BY DATE(created_at)
            ORDER BY date
        ''', (days,))

        data = cursor.fetchall()
        df = pd.DataFrame(data, columns=['date', 'count'])
        return df
    except:
        return pd.DataFrame()

def get_pipeline_logs(lines=50):
    """Obtenir les logs du pipeline"""
    try:
        log_file = 'logs/orchestrator.log'
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                logs = f.readlines()[-lines:]
                return ''.join(logs)
    except:
        pass
    return "Pas de logs disponibles"

# ============================================
# HEADER
# ============================================

st.markdown(
    """
    <h1 class='asif-h1'>Veille Menaces sur Agent IA</h1>
    <p class='asif-subtitle'>Vue d'ensemble + Monitoring automatisé des menaces agents IA</p>
    """,
    unsafe_allow_html=True
)

# ============================================
# TABS
# ============================================

tab1, tab2, tab3, tab4 = st.tabs([
    "Vue d'Ensemble",
    "Menaces Récentes",
    "Orchestrateur",
    "Logs"
])

# ============================================
# TAB 1: VUE D'ENSEMBLE (Overview + Veille)
# ============================================

with tab1:
    stats = get_threat_stats()

    if stats:
        # ========== SECTION 1 : KPI Cards ==========
        st.markdown("<div class='asif-section-title'>Métriques Principales</div>", unsafe_allow_html=True)

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.markdown(
                kpi_card("Total Menaces", stats['total'], severity="accent",
                         trend="neutral", trend_label="Base de données"),
                unsafe_allow_html=True
            )

        with col2:
            critical = stats['by_severity'].get('critical', 0)
            st.markdown(
                kpi_card("Critiques", critical, severity="critical",
                         trend="neutral", trend_label="Urgence MAX"),
                unsafe_allow_html=True
            )

        with col3:
            high = stats['by_severity'].get('high', 0)
            st.markdown(
                kpi_card("Hautes", high, severity="high",
                         trend="neutral", trend_label="À surveiller"),
                unsafe_allow_html=True
            )

        with col4:
            sources = len(stats['by_source'])
            st.markdown(
                kpi_card("Sources CTI", sources, severity="neutral",
                         trend="neutral", trend_label="Actives"),
                unsafe_allow_html=True
            )

        with col5:
            categories = len(stats['by_type'])
            st.markdown(
                kpi_card("Catégories", categories, severity="neutral",
                         trend="neutral", trend_label="Classifiées"),
                unsafe_allow_html=True
            )

        st.divider()

        # ========== SECTION 2 : Orchestrateur Status ==========
        metrics = get_orchestrator_metrics()

        orchestrator_status = "healthy"
        if metrics:
            failed = metrics.get('failed_runs', 0)
            orchestrator_status = "healthy" if failed == 0 else "warning"

        st.markdown(
            f"<div class='asif-section-title'>{status_dot_html(orchestrator_status)} "
            f"État de l'Orchestrateur</div>",
            unsafe_allow_html=True
        )

        if metrics:
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.markdown(
                    kpi_card("Exécutions", metrics.get('total_runs', 0), severity="accent",
                             trend="neutral", trend_label="Total"),
                    unsafe_allow_html=True
                )

            with col2:
                successful = metrics.get('successful_runs', 0)
                st.markdown(
                    kpi_card("Réussies", successful, severity="low",
                             trend="neutral", trend_label="OK"),
                    unsafe_allow_html=True
                )

            with col3:
                failed = metrics.get('failed_runs', 0)
                st.markdown(
                    kpi_card("Échouées", failed, severity="critical" if failed > 0 else "neutral",
                             trend="neutral", trend_label=""),
                    unsafe_allow_html=True
                )

            with col4:
                total = metrics.get('total_runs', 1)
                success_rate = (successful / total * 100) if total > 0 else 0
                st.markdown(
                    kpi_card("Taux Succès", f"{success_rate:.1f}%", severity="accent",
                             trend="neutral", trend_label="Performance"),
                    unsafe_allow_html=True
                )

            st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

            # Infos complémentaires
            col1, col2 = st.columns(2)

            with col1:
                st.markdown(
                    mini_card("clock", "Dernière exécution", metrics.get('last_run_time', 'Jamais')),
                    unsafe_allow_html=True
                )

            with col2:
                st.markdown(
                    mini_card("calendar", "Prochaine", "Quotidien 02:00 UTC · Hebdo Lundi 10:00 UTC"),
                    unsafe_allow_html=True
                )
        else:
            st.warning("Orchestrateur pas encore exécuté. Lancez: python orchestrator.py --test")

        st.divider()

        # ========== SECTION 3 : Charts Distributions ==========
        st.markdown("<div class='asif-section-title'>Distributions des Menaces</div>", unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        # Chart Sévérité
        with col1:
            severity_df = pd.DataFrame(
                list(stats['by_severity'].items()),
                columns=['Sévérité', 'Nombre']
            ).sort_values('Nombre', ascending=False)

            fig_severity = px.bar(
                severity_df,
                x='Sévérité',
                y='Nombre',
                color='Sévérité',
                color_discrete_map=SEVERITY_COLORS,
                title="Par Sévérité"
            )
            apply_plotly_theme(fig_severity, legend=False)
            st.plotly_chart(fig_severity, use_container_width=True)

        # Chart Type
        with col2:
            type_df = pd.DataFrame(
                list(stats['by_type'].items()),
                columns=['Type', 'Nombre']
            ).sort_values('Nombre', ascending=False)

            fig_type = px.bar(
                type_df,
                x='Type',
                y='Nombre',
                title="Par Type de Menace"
            )
            apply_plotly_theme(fig_type, legend=False)
            fig_type.update_traces(marker_color=ACCENT)
            st.plotly_chart(fig_type, use_container_width=True)

        # Chart Source (Pie)
        source_df = pd.DataFrame(
            list(stats['by_source'].items()),
            columns=['Source', 'Nombre']
        ).sort_values('Nombre', ascending=False)

        fig_source = px.pie(
            source_df,
            names='Source',
            values='Nombre',
            title="Distribution par Source CTI",
            color_discrete_sequence=[ACCENT, "#0D0D0F", "#6B6B74", "#A0A0A8", "#D8D8DC", "#4B5563", "#93A5C7"]
        )
        apply_plotly_theme(fig_source)
        st.plotly_chart(fig_source, use_container_width=True)

        st.divider()

        # ========== SECTION 4 : Tendances ==========
        st.markdown("<div class='asif-section-title'>Tendances et Analyse</div>", unsafe_allow_html=True)

        days = st.slider("Analyser sur X jours", 7, 90, 30)

        trends = get_threat_trends(days=days)

        if not trends.empty:
            fig_trends = px.line(
                trends,
                x='date',
                y='count',
                title=f"Menaces collectées (derniers {days} jours)",
                markers=True
            )
            apply_plotly_theme(fig_trends, legend=False)
            fig_trends.update_traces(line_color=ACCENT, marker_color=ACCENT)
            fig_trends.update_xaxes(title_text="Date")
            fig_trends.update_yaxes(title_text="Nombre de menaces")
            st.plotly_chart(fig_trends, use_container_width=True)

            # Statistiques détaillées
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Total collectées", len(trends))

            with col2:
                if len(trends) > 0:
                    avg = trends['count'].mean()
                    st.metric("Moyenne/jour", f"{avg:.1f}")

            with col3:
                if len(trends) > 0:
                    max_date = trends.loc[trends['count'].idxmax()]
                    st.metric("Pic collectes", f"{int(max_date['count'])} ({max_date['date']})")

# ============================================
# TAB 2: MENACES RÉCENTES
# ============================================

with tab2:
    st.markdown("<div class='asif-section-title'>Menaces Récentes</div>", unsafe_allow_html=True)

    latest = get_latest_threats(limit=100)

    if latest:
        # Filtres
        col1, col2 = st.columns(2)

        with col1:
            threat_types = ['Toutes'] + sorted(set(t['threat_type'] for t in latest))
            selected_type = st.selectbox("Filtrer par type", threat_types)

        with col2:
            severities = ['Toutes'] + sorted(set(t['severity'] for t in latest))
            selected_severity = st.selectbox("Filtrer par sévérité", severities)

        # Filtrer
        filtered = latest
        if selected_type != 'Toutes':
            filtered = [t for t in filtered if t['threat_type'] == selected_type]
        if selected_severity != 'Toutes':
            filtered = [t for t in filtered if t['severity'] == selected_severity]

        # Afficher tableau
        df = pd.DataFrame([
            {
                'ID': t['threat_id'],
                'Titre': t['title'][:50],
                'Type': t['threat_type'],
                'Sévérité': t['severity'],
                'Source': t['source'],
                'Date': t['created_at'][:10]
            }
            for t in filtered
        ])

        st.dataframe(df, use_container_width=True, hide_index=True)

        st.caption(f"{len(filtered)} menaces affichées")

        # Export
        col1, col2 = st.columns(2)

        with col1:
            csv = df.to_csv(index=False)
            st.download_button(
                "Télécharger CSV",
                csv,
                f"threats_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )

        with col2:
            json_data = json.dumps([dict(t) for t in filtered], indent=2, default=str)
            st.download_button(
                "Télécharger JSON",
                json_data,
                f"threats_{datetime.now().strftime('%Y%m%d')}.json",
                "application/json"
            )
    else:
        st.info("Aucune menace trouvée")

# ============================================
# TAB 3: ORCHESTRATEUR
# ============================================

with tab3:
    metrics = get_orchestrator_metrics()

    if metrics:
        # Statut global
        status = "healthy" if metrics['failed_runs'] == 0 else "warning"
        status_label = "HEALTHY" if status == "healthy" else "WARNING"
        st.markdown(
            f"<div class='asif-section-title'>{status_dot_html(status)} {status_label}</div>",
            unsafe_allow_html=True
        )

        # Métriques détaillées
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(
                kpi_card("Exécutions Totales", metrics.get('total_runs', 0), severity="accent"),
                unsafe_allow_html=True
            )

        with col2:
            st.markdown(
                kpi_card("Réussies", metrics.get('successful_runs', 0), severity="low"),
                unsafe_allow_html=True
            )

        with col3:
            failed = metrics.get('failed_runs', 0)
            st.markdown(
                kpi_card("Échouées", failed, severity="critical" if failed > 0 else "neutral"),
                unsafe_allow_html=True
            )

        with col4:
            total = metrics.get('total_runs', 1)
            success_rate = (metrics.get('successful_runs', 0) / total * 100) if total > 0 else 0
            st.markdown(
                kpi_card("Taux Succès", f"{success_rate:.1f}%", severity="accent"),
                unsafe_allow_html=True
            )

        st.divider()

        # Informations
        st.markdown("<div class='asif-section-title'>Informations</div>", unsafe_allow_html=True)

        info_col1, info_col2 = st.columns(2)

        with info_col1:
            st.markdown("<p class='asif-caption'>Dernière exécution</p>", unsafe_allow_html=True)
            st.code(metrics.get('last_run_time', 'Jamais'))

            st.markdown("<p class='asif-caption'>Menaces collectées (dernier run)</p>", unsafe_allow_html=True)
            st.code(f"{metrics.get('last_threats_collected', 0)} menaces")

        with info_col2:
            st.markdown("<p class='asif-caption'>Prochains jobs</p>", unsafe_allow_html=True)
            st.code("Quotidien: 02:00 UTC\nHebdomadaire: Lundi 10:00 UTC\nHealth Check: Chaque heure")

            st.markdown("<p class='asif-caption'>Fichiers logs</p>", unsafe_allow_html=True)
            st.code("logs/orchestrator.log\nlogs/orchestrator_metrics.json\nlogs/weekly_report_*.json")

        st.divider()

        # Actions
        st.markdown("<div class='asif-section-title'>Actions Manuelles</div>", unsafe_allow_html=True)

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("Run Pipeline Quotidien"):
                st.info("Commande: python orchestrator.py --run-daily")

        with col2:
            if st.button("Run Pipeline Hebdomadaire"):
                st.info("Commande: python orchestrator.py --run-weekly")

        with col3:
            if st.button("Rafraîchir", key="refresh_orch"):
                st.rerun()

    else:
        st.warning("Orchestrateur pas encore exécuté")
        st.info("Pour démarrer: python orchestrator.py --test")

# ============================================
# TAB 4: LOGS
# ============================================

with tab4:
    st.markdown("<div class='asif-section-title'>Logs de l'Orchestrateur</div>", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])

    with col1:
        lines_to_show = st.slider("Nombre de lignes à afficher", 10, 200, 50)

    with col2:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        if st.button("Rafraîchir", key="refresh_logs"):
            st.rerun()

    logs = get_pipeline_logs(lines=lines_to_show)

    st.code(logs, language="text")

    st.divider()

    # Télécharger logs complets
    if st.button("Télécharger les logs complets"):
        try:
            with open('logs/orchestrator.log', 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            st.download_button(
                "Télécharger",
                log_content,
                f"orchestrator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
                "text/plain"
            )
        except:
            st.error("Erreur lors de la lecture des logs")

# ============================================
# FOOTER
# ============================================

st.divider()
st.markdown(
    f"""
    <div style='text-align: center; color: var(--text-tertiary);'>
    <small>Dashboard Intelligence Veille | Actualisé: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
    Orchestrateur automatisé: Quotidien 02:00 UTC + Hebdo Lundi 10:00 UTC</small>
    </div>
    """,
    unsafe_allow_html=True
)
