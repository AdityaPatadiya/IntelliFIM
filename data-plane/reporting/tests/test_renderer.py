"""Renderer tests — chart SVG bytes, Jinja2 HTML, WeasyPrint PDF bytes."""
from __future__ import annotations

from reporting.renderer import render_chart, render_html, render_pdf


def test_render_chart_returns_svg_bytes():
    rows = [("hostA", 80.0), ("hostB", 50.0), ("hostC", 10.0)]
    svg = render_chart(rows, title="Top hosts")
    # SVG must start with <?xml ...?> or <svg ...>; just sanity check
    assert svg.startswith(b"<?xml") or svg.startswith(b"<svg"), svg[:80]
    # Hosts should appear in the SVG text
    assert b"hostA" in svg


def test_render_chart_handles_empty_data():
    svg = render_chart([], title="Top hosts")
    assert svg.startswith(b"<?xml") or svg.startswith(b"<svg")
    assert b"No data" in svg


def test_render_html_contains_expected_strings():
    html = render_html({
        "title": "My Report",
        "range_start": "2030-01-01T00:00:00+00:00",
        "range_end": "2030-01-02T00:00:00+00:00",
        "generated_at": "2030-01-01T12:00:00+00:00",
        "generated_by": "alice",
        "stats": {
            "approvals_total": 3,
            "approvals_by_state": {"PENDING": 1, "EXECUTED": 2},
            "approvals_by_priority": {"HIGH": 2, "LOW": 1},
            "scores_total": 10,
            "unique_hosts": 2,
        },
        "chart_svg_b64": "PHN2Zy8+",   # tiny fake base64
        "approvals": [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "host_id": "001", "priority": "HIGH", "score": 42.0,
                "last_reason": "r", "state": "EXECUTED",
                "created_at": "2030-01-01T01:00:00+00:00",
                "decided_at": "2030-01-01T01:05:00+00:00",
                "decided_by": "alice",
            },
        ],
    })
    assert "My Report" in html
    assert "alice" in html
    assert "001" in html
    assert "EXECUTED" in html
    assert "data:image/svg+xml;base64,PHN2Zy8+" in html


def test_render_pdf_starts_with_pdf_magic():
    """End-to-end: minimal HTML → PDF bytes start with %PDF-."""
    html = "<html><body><h1>Hi</h1></body></html>"
    pdf = render_pdf(html)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 200
