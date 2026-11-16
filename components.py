"""
UI Components and Visualizations for the Phishing Email Analyzer
Includes SVG Gauge Chart, Alert Banners, and Keyword Highlighter.
"""

import math
import html
import re
from typing import Dict, List, Any


def render_svg_gauge(score: int, verdict: str, verdict_color: str) -> str:
    """
    Generate a responsive, retina-sharp SVG Speedometer Gauge Chart.
    - Zero external dependencies
    - Gradient arcs for Safe (Green), Suspicious (Orange), High Risk (Red)
    - Dynamic needle rotation based on score (0-100)
    - Integrated risk classification badge
    """
    score = max(0, min(100, int(score)))
    
    # Dimensions
    width = 340
    height = 230
    cx = 170
    cy = 165
    r = 115
    stroke_w = 18
    
    def polar_to_cartesian(center_x, center_y, radius, angle_in_degrees):
        angle_in_radians = (angle_in_degrees) * math.pi / 180.0
        return (
            center_x + (radius * math.cos(angle_in_radians)),
            center_y - (radius * math.sin(angle_in_radians))
        )

    def describe_arc(x, y, radius, start_angle, end_angle):
        start = polar_to_cartesian(x, y, radius, start_angle)
        end = polar_to_cartesian(x, y, radius, end_angle)
        large_arc_flag = "0" if abs(end_angle - start_angle) <= 180 else "1"
        return f"M {start[0]:.2f} {start[1]:.2f} A {radius} {radius} 0 {large_arc_flag} 1 {end[0]:.2f} {end[1]:.2f}"

    # Arc 1: Safe 0 - 30 (180 deg to 126 deg)
    arc_safe = describe_arc(cx, cy, r, 180, 126)
    # Arc 2: Suspicious 30 - 70 (126 deg to 54 deg)
    arc_warn = describe_arc(cx, cy, r, 126, 54)
    # Arc 3: Danger 70 - 100 (54 deg to 0 deg)
    arc_danger = describe_arc(cx, cy, r, 54, 0)
    
    # Background full track
    arc_bg = describe_arc(cx, cy, r, 180, 0)

    # Needle position: 0 -> 180 deg, 100 -> 0 deg
    needle_angle = 180.0 - (score / 100.0) * 180.0
    needle_rad = needle_angle * math.pi / 180.0
    
    # Needle tip and base corners
    needle_len = r - 12
    tip_x = cx + needle_len * math.cos(needle_rad)
    tip_y = cy - needle_len * math.sin(needle_rad)
    
    # Perpendicular base width
    base_w = 7
    base_left_x = cx + base_w * math.cos(needle_rad + math.pi / 2)
    base_left_y = cy - base_w * math.sin(needle_rad + math.pi / 2)
    base_right_x = cx + base_w * math.cos(needle_rad - math.pi / 2)
    base_right_y = cy - base_w * math.sin(needle_rad - math.pi / 2)

    # Ticks marks at 0, 25, 50, 75, 100
    ticks = []
    tick_values = [(0, "0"), (30, "30"), (70, "70"), (100, "100")]
    for val, label in tick_values:
        deg = 180.0 - (val / 100.0) * 180.0
        p_inner = polar_to_cartesian(cx, cy, r - stroke_w / 2 - 3, deg)
        p_outer = polar_to_cartesian(cx, cy, r + stroke_w / 2 + 5, deg)
        p_text = polar_to_cartesian(cx, cy, r - stroke_w / 2 - 14, deg)
        ticks.append(f'<line x1="{p_inner[0]:.1f}" y1="{p_inner[1]:.1f}" x2="{p_outer[0]:.1f}" y2="{p_outer[1]:.1f}" stroke="rgba(148, 163, 184, 0.4)" stroke-width="2" />')
        ticks.append(f'<text x="{p_text[0]:.1f}" y="{p_text[1]:.1f}" fill="#94A3B8" font-size="10" font-family="system-ui, sans-serif" font-weight="600" text-anchor="middle" dominant-baseline="middle">{label}</text>')
    
    ticks_markup = "\n".join(ticks)

    svg = f"""
    <div style="display: flex; justify-content: center; align-items: center; margin: 10px 0;">
      <svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" style="max-width: 100%; height: auto; filter: drop-shadow(0px 8px 16px rgba(0,0,0,0.12));">
        <defs>
          <linearGradient id="safeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#10B981" />
            <stop offset="100%" stop-color="#34D399" />
          </linearGradient>
          <linearGradient id="warnGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#F59E0B" />
            <stop offset="100%" stop-color="#FBBF24" />
          </linearGradient>
          <linearGradient id="dangerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#F43F5E" />
            <stop offset="100%" stop-color="#EF4444" />
          </linearGradient>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <!-- Track Background -->
        <path d="{arc_bg}" fill="none" stroke="rgba(148, 163, 184, 0.15)" stroke-width="{stroke_w + 4}" stroke-linecap="round" />

        <!-- Gauge Zones -->
        <path d="{arc_safe}" fill="none" stroke="url(#safeGrad)" stroke-width="{stroke_w}" stroke-linecap="round" />
        <path d="{arc_warn}" fill="none" stroke="url(#warnGrad)" stroke-width="{stroke_w}" />
        <path d="{arc_danger}" fill="none" stroke="url(#dangerGrad)" stroke-width="{stroke_w}" stroke-linecap="round" />

        <!-- Tick Marks & Numbers -->
        {ticks_markup}

        <!-- Needle -->
        <polygon points="{base_left_x:.1f},{base_left_y:.1f} {tip_x:.1f},{tip_y:.1f} {base_right_x:.1f},{base_right_y:.1f}"
                 fill="{verdict_color}" filter="url(#glow)" />
        
        <!-- Needle Pivot Center -->
        <circle cx="{cx}" cy="{cy}" r="11" fill="#1E293B" stroke="{verdict_color}" stroke-width="3" />
        <circle cx="{cx}" cy="{cy}" r="4" fill="#FFFFFF" />

        <!-- Score readout -->
        <text x="{cx}" y="{cy + 34}" fill="#0F172A" font-size="28" font-family="system-ui, -apple-system, sans-serif" font-weight="800" text-anchor="middle" dominant-baseline="middle">
          {score} <tspan font-size="15" font-weight="500" fill="#64748B">/ 100</tspan>
        </text>

        <!-- Dynamic Verdict Pill -->
        <g transform="translate({cx}, {cy + 54})">
          <rect x="-85" y="-12" width="170" height="24" rx="12" fill="{verdict_color}22" stroke="{verdict_color}" stroke-width="1.5" />
          <text x="0" y="2" fill="{verdict_color}" font-size="11" font-family="system-ui, sans-serif" font-weight="700" letter-spacing="0.5" text-anchor="middle" dominant-baseline="middle">
            {verdict}
          </text>
        </g>
      </svg>
    </div>
    """
    return svg


def render_breakdown_bars(breakdown: Dict[str, int]) -> str:
    """Render sleek modern HTML progress bars for risk breakdown categories."""
    max_vals = {
        "Sender & Headers": 50,
        "Links & URLs": 45,
        "Urgency & Psychological Coercion": 40,
        "Attachments": 40,
        "Subject / Structure": 15
    }
    
    html_lines = ['<div style="margin: 12px 0 20px 0;">']
    for cat, val in breakdown.items():
        max_v = max_vals.get(cat, 50)
        pct = min(100, int((val / max_v) * 100))
        
        # Color based on severity
        if pct >= 65:
            bar_color = "#EF4444"
        elif pct >= 30:
            bar_color = "#F59E0B"
        elif pct > 0:
            bar_color = "#3B82F6"
        else:
            bar_color = "#10B981"
            
        html_lines.append(f"""
        <div style="margin-bottom: 10px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px; font-weight: 600; margin-bottom: 3px;">
            <span style="color: #334155;">{cat}</span>
            <span style="color: {bar_color}; font-weight: 700;">+{val} pts <span style="font-weight: 400; color: #94A3B8;">(max {max_v})</span></span>
          </div>
          <div style="background: rgba(148, 163, 184, 0.2); border-radius: 999px; height: 8px; overflow: hidden;">
            <div style="background: {bar_color}; width: {pct}%; height: 100%; border-radius: 999px; transition: width 0.5s ease;"></div>
          </div>
        </div>
        """)
    html_lines.append('</div>')
    return "\n".join(html_lines)


def highlight_keywords_in_text(raw_text: str, categories_matches: Dict[str, Any]) -> str:
    """
    Produce an HTML snippet where flagged urgency, threat, and credential keywords
    are highlighted with distinctive colored badges for intuitive visual review.
    """
    if not raw_text:
        return "<em>No body text available.</em>"

    escaped = html.escape(raw_text)

    # Collect all keywords to highlight
    badge_colors = {
        "Urgency & Deadlines": ("#FEF3C7", "#92400E", "#F59E0B"), # yellow
        "Fear & Account Penalties": ("#FEE2E2", "#991B1B", "#EF4444"), # red
        "Credential & Verification Demands": ("#EDE9FE", "#5B21B6", "#8B5CF6"), # purple
        "Financial & Wire Lures": ("#DCFCE7", "#166534", "#22C55E"), # green
        "Call to Action / Generic Traps": ("#E0F2FE", "#075985", "#0EA5E9") # blue
    }

    # Flatten and sort keywords by length descending so longer phrases match first
    kw_to_category = {}
    for cat_name, cat_data in categories_matches.items():
        for item in cat_data.get("matches", []):
            kw = item["keyword"]
            kw_to_category[kw] = cat_name

    sorted_kws = sorted(kw_to_category.keys(), key=lambda x: len(x), reverse=True)

    for kw in sorted_kws:
        cat = kw_to_category[kw]
        bg, text_color, border = badge_colors.get(cat, ("#FEF3C7", "#92400E", "#F59E0B"))
        
        # Replace occurrences in text case-insensitively using regex
        pattern = re.compile(r'\b(' + re.escape(kw) + r')\b', re.IGNORECASE)
        replacement = f'<mark style="background-color: {bg}; color: {text_color}; border: 1px solid {border}; border-radius: 4px; padding: 1px 5px; font-weight: 600;" title="{cat}">\\1</mark>'
        escaped = pattern.sub(replacement, escaped)

    # Convert newlines to HTML breaks
    formatted = escaped.replace("\r\n", "<br>").replace("\n", "<br>")
    return f"""
    <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 13px; line-height: 1.6; max-height: 380px; overflow-y: auto; color: #1E293B;">
      {formatted}
    </div>
    """
