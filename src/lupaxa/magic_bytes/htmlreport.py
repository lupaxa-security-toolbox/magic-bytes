"""Self-contained HTML reports. File-derived text is escaped and never executed."""

from __future__ import annotations

import html

from lupaxa.magic_bytes.models import CATALOGUE_VERSION, VALIDATOR_VERSION, Region


def page(title: str, body: str) -> str:
    """Wrap a fragment in an offline document with no external assets."""
    safe_title = html.escape(title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
body {{ font: 15px/1.4 sans-serif; margin: 1.5rem; color: #1b1b1b; background: #fff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.3rem 0.5rem; text-align: left; vertical-align: top; }}
.bar {{ display: flex; height: 28px; width: 100%; background: #f3f3f3; }}
.seg {{ height: 100%; overflow: hidden; }}
.warn {{ color: #6a4a00; }}
</style>
</head>
<body>
<h1>{safe_title}</h1>
<p>Catalogue {html.escape(CATALOGUE_VERSION)}, validators {html.escape(VALIDATOR_VERSION)}.
This page does not load remote resources.</p>
{body}
</body>
</html>
"""


def escape(value: object) -> str:
    """Escape one value for HTML text."""
    return html.escape(str(value), quote=True)


def region_table(regions: list[Region]) -> str:
    """Render regions, including overlaps, as a static table and a scaled bar."""
    if not regions:
        return "<p>No regions.</p>"
    span = max(region.end for region in regions) or 1
    colours = ["#4c78a8", "#f58518", "#54a24b", "#e45756", "#72b7b2", "#b279a2"]
    parts = ['<div class="bar">']
    for index, region in enumerate(regions):
        width = max(0.4, (region.length / span) * 100)
        colour = colours[index % len(colours)]
        parts.append(
            f'<div class="seg" style="width:{width:.4f}%;background:{colour}" title="{escape(region.name)}"></div>'
        )
    header = (
        "</div><table><thead><tr><th>Start</th><th>End</th><th>Length</th>"
        "<th>Type</th><th>Name</th><th>Status</th><th>Description</th></tr></thead><tbody>"
    )
    parts.append(header)
    for region in regions:
        parts.append(
            "<tr>"
            f"<td>{region.start}</td><td>{region.end}</td><td>{region.length}</td>"
            f"<td>{escape(region.region_type)}</td><td>{escape(region.name)}</td>"
            f"<td>{escape(region.status)}</td><td>{escape(region.description)}</td>"
            "</tr>"
        )
    parts.append("</tbody></table>")
    return "".join(parts)


def entropy_chart(rows: list[tuple[int, float]]) -> str:
    """Render block entropy as a static bar list."""
    items = []
    for offset, value in rows:
        width = max(0.0, min(100.0, (value / 8) * 100))
        bar = f'<span class="seg" style="display:inline-block;width:{width:.2f}%;background:#4c78a8">{value:.3f}</span>'
        items.append(f"<div>{escape(offset)} {bar}</div>")
    return "<p>Entropy is bits per byte, from 0 to 8. High entropy is not evidence of encryption.</p>" + "".join(items)
