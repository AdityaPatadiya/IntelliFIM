"""Renderer: matplotlib chart -> SVG bytes; Jinja2 + WeasyPrint -> PDF bytes.

Pattern:
  render_chart(rows, title)  ->  bytes (SVG)
  render_html(context)       ->  str   (HTML)
  render_pdf(html)           ->  bytes (PDF)
"""
from __future__ import annotations

import io
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")     # MUST be before matplotlib.pyplot import
import matplotlib.pyplot as plt   # noqa: E402

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML


logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "htm", "xml"]),
)


def render_chart(rows: list[tuple[str, float]], *, title: str) -> bytes:
    """Render a top-hosts-by-max-score bar chart to SVG bytes."""
    fig, ax = plt.subplots(figsize=(8, 4), dpi=100)
    if not rows:
        ax.text(0.5, 0.5, "No data in range", ha="center", va="center",
                transform=ax.transAxes, color="#888", fontsize=14)
        ax.set_xticks([])
        ax.set_yticks([])
    else:
        hosts = [r[0] for r in rows]
        scores = [r[1] for r in rows]
        ax.barh(hosts, scores, color="#c0392b")
        ax.invert_yaxis()
        ax.set_xlabel("Max threat score")
        ax.set_xlim(0, max(100.0, max(scores) * 1.1))
        for i, v in enumerate(scores):
            ax.text(v + 1, i, f"{v:.1f}", va="center", fontsize=9)
    ax.set_title(title)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="svg")
    plt.close(fig)
    return buf.getvalue()


def render_html(context: dict) -> str:
    template = _env.get_template("security_summary.html.j2")
    return template.render(**context)


def render_pdf(html: str) -> bytes:
    return HTML(string=html).write_pdf()
