#!/usr/bin/env python3
"""
Credence Badge Generator — SVG badges for README embeds.

Usage:
    python badge_generator.py <score> <verdict> [output.svg]
    python badge_generator.py 92 APPROVED badge.svg
    python badge_generator.py --from-summary scan-summary.json badge.svg
"""

import json
import sys


def generate_badge(score: int | None, verdict: str) -> str:
    """Generate an SVG badge showing trust score and verdict."""

    if score is not None and score >= 80:
        color = "#4ade80"
        bg = "#0f5132"
    elif score is not None and score >= 50:
        color = "#D06030"
        bg = "#5c2d0e"
    elif score is not None:
        color = "#ef4444"
        bg = "#7f1d1d"
    else:
        color = "#808080"
        bg = "#333333"

    label = "credence"
    value = f"{score}/100 {verdict}" if score is not None else verdict

    # Calculate widths (approximate)
    label_width = len(label) * 7 + 12
    value_width = len(value) * 6.5 + 12
    total_width = label_width + value_width

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#333"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{bg}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="IBM Plex Mono,DejaVu Sans,Verdana,Geneva,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="{label_width / 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_width / 2}" y="14" fill="#fff">{label}</text>
    <text aria-hidden="true" x="{label_width + value_width / 2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{label_width + value_width / 2}" y="14" fill="{color}">{value}</text>
  </g>
</svg>"""


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <score> <verdict> [output.svg]")
        print(f"       {sys.argv[0]} --from-summary scan-summary.json [output.svg]")
        sys.exit(1)

    if sys.argv[1] == "--from-summary":
        with open(sys.argv[2]) as f:
            summary = json.load(f)
        score = summary.get("trust_score")
        verdict = summary.get("thinktank_verdict", "PENDING")
        output = sys.argv[3] if len(sys.argv) > 3 else "/tmp/credence-badge.svg"
    else:
        score = int(sys.argv[1]) if sys.argv[1] != "null" else None
        verdict = sys.argv[2] if len(sys.argv) > 2 else "PENDING"
        output = sys.argv[3] if len(sys.argv) > 3 else "/tmp/credence-badge.svg"

    svg = generate_badge(score, verdict)
    with open(output, 'w') as f:
        f.write(svg)
    print(f"Badge generated: {output}")


if __name__ == "__main__":
    main()
