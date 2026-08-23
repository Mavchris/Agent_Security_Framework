"""
Shared theming utilities for all ASIF Streamlit pages.
Central place for: CSS injection, inline SVG icons, small HTML component
builders (badges, KPI cards, status dot, banners) and the shared Plotly
layout template. Pure presentation — no data/business logic lives here.
"""

from pathlib import Path

import streamlit as st

# ============================================================
# PATHS
# ============================================================

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_THEME_CSS_PATH = _PROJECT_ROOT / "assets" / "theme.css"

# ============================================================
# SEVERITY TOKENS (must match assets/theme.css)
# ============================================================

SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#D97706",
    "low": "#16A34A",
    "unknown": "#A0A0A8",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

ACCENT = "#2563EB"
TEXT_SECONDARY = "#6B6B74"
BORDER = "#E7E7EA"

# ============================================================
# THEME LOADING
# ============================================================

def load_theme():
    """Inject the central stylesheet. Call once, right after st.set_page_config()."""
    css = _THEME_CSS_PATH.read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


# ============================================================
# INLINE ICONS (outline style, no emoji, no external dependency)
# ============================================================

_ICON_PATHS = {
    "shield": '<path d="M12 2 4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5l-8-3Z"/>',
    "bar-chart": '<path d="M3 3v18h18"/><rect x="7" y="12" width="3" height="6"/><rect x="13" y="8" width="3" height="10"/><rect x="19" y="14" width="0" height="4"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>',
    "play": '<path d="M6 3.5v17l14-8.5-14-8.5Z"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 16v-5"/><path d="M12 8h.01"/>',
    "alert-triangle": '<path d="M10.3 3.9 1.8 18a1.8 1.8 0 0 0 1.5 2.7h17.4a1.8 1.8 0 0 0 1.5-2.7L13.7 3.9a1.8 1.8 0 0 0-3.4 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    "check-circle": '<path d="M22 11.1V12a10 10 0 1 1-6-9.2"/><path d="m9 11 3 3L22 4"/>',
    "refresh": '<path d="M21 12a9 9 0 0 1-15.3 6.4L3 16"/><path d="M3 12a9 9 0 0 1 15.3-6.4L21 8"/><path d="M3 22v-6h6"/><path d="M21 2v6h-6"/>',
    "download": '<path d="M12 3v13"/><path d="m7 11 5 5 5-5"/><path d="M5 21h14"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "mail": '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 6 10 7 10-7"/>',
    "clipboard": '<rect x="6" y="4" width="12" height="17" rx="2"/><path d="M9 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M9 11h6"/><path d="M9 15h6"/>',
    "tag": '<path d="M12.6 2H4a2 2 0 0 0-2 2v8.6a2 2 0 0 0 .6 1.4l9 9a2 2 0 0 0 2.8 0l7.6-7.6a2 2 0 0 0 0-2.8l-9-9A2 2 0 0 0 12.6 2Z"/><circle cx="7.5" cy="7.5" r="1.2"/>',
    "external-link": '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
    "calendar": '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4"/><path d="M8 2v4"/><path d="M3 10h18"/>',
    "activity": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    "arrow-up": '<path d="M12 19V5"/><path d="m5 12 7-7 7 7"/>',
    "arrow-down": '<path d="M12 5v14"/><path d="m19 12-7 7-7-7"/>',
    "server": '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01"/><path d="M6 17h.01"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.2 1.2"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.2-1.2"/>',
}


def icon(name: str, size: int = 20, color: str = "currentColor", stroke_width: float = 1.8) -> str:
    """Return an inline outline SVG icon as an HTML string."""
    path = _ICON_PATHS.get(name, _ICON_PATHS["info"])
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="{stroke_width}" '
        f'stroke-linecap="round" stroke-linejoin="round">{path}</svg>'
    )


# ============================================================
# HTML COMPONENT BUILDERS
# ============================================================

def severity_class(severity: str) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
        (severity or "").lower(), "neutral"
    )


def badge(text: str, severity: str = "neutral") -> str:
    cls = severity_class(severity)
    return f'<span class="badge badge-{cls}">{text}</span>'


def status_dot_html(status: str = "healthy", label: str = "") -> str:
    """status: healthy | warning | error"""
    label_html = f"<span>{label}</span>" if label else ""
    return f'<span class="status-dot-wrap"><span class="status-dot {status}"></span>{label_html}</span>'


def kpi_card(label: str, value, severity: str = "neutral", trend: str = None, trend_label: str = None) -> str:
    """severity: neutral | critical | high | medium | low | accent
       trend: up | down | neutral (optional)"""
    trend_html = ""
    if trend:
        arrow = "arrow-up" if trend == "up" else "arrow-down" if trend == "down" else None
        arrow_svg = icon(arrow, size=12) if arrow else ""
        trend_html = (
            f'<div class="kpi-trend {trend}">{arrow_svg}<span>{trend_label or ""}</span></div>'
        )
    return f"""
    <div class="kpi-card severity-{severity}">
        <p class="kpi-label">{label}</p>
        <p class="kpi-value">{value}</p>
        {trend_html}
    </div>
    """


def info_banner(text: str, icon_name: str = "info") -> str:
    return f'<div class="info-banner">{icon(icon_name, size=18)}<span>{text}</span></div>'


def mini_card(icon_name: str, label: str, value: str) -> str:
    return f"""
    <div class="mini-card">
        {icon(icon_name, size=18)}
        <div>
            <p class="mini-card-label">{label}</p>
            <p class="mini-card-value">{value}</p>
        </div>
    </div>
    """


def page_header(title: str, subtitle: str = "") -> str:
    subtitle_html = f'<p class="asif-subtitle">{subtitle}</p>' if subtitle else ""
    return f'<h1 class="asif-h1">{title}</h1>{subtitle_html}'


def section_title(text: str, icon_name: str = None) -> str:
    icon_html = icon(icon_name, size=18, color=TEXT_SECONDARY) if icon_name else ""
    return f'<div class="asif-section-title">{icon_html}{text}</div>'


# ============================================================
# PLOTLY THEME
# ============================================================

def apply_plotly_theme(fig, legend: bool = True):
    """Apply the shared light/minimal template to a Plotly figure in place."""
    fig.update_layout(
        template="plotly_white",
        font=dict(family="Inter, sans-serif", color="#0D0D0F", size=13),
        title_font=dict(family="Inter, sans-serif", size=15, color="#0D0D0F"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=48, b=10),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="left",
            x=0,
            font=dict(color=TEXT_SECONDARY, size=12),
        ) if legend else dict(),
        showlegend=legend,
        colorway=[ACCENT, "#0D0D0F", "#6B6B74", "#A0A0A8", "#D8D8DC"],
    )
    fig.update_xaxes(gridcolor=BORDER, zerolinecolor=BORDER, showline=True, linecolor=BORDER)
    fig.update_yaxes(gridcolor=BORDER, zerolinecolor=BORDER, showline=False)
    return fig
