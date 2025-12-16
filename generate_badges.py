#!/usr/bin/env python3
"""
Badge Generator for Credence Registry

Generates SVG badges for verified MCP servers
"""

def generate_badge(status: str, trust_score: float) -> str:
    """
    Generate SVG badge based on verification status and trust score
    
    Args:
        status: 'verified', 'flagged', or 'rejected'
        trust_score: Float between 0.0 and 1.0
    
    Returns:
        SVG markup as string
    """
    
    # Color schemes
    colors = {
        'verified': {
            'bg': '#4caf50',
            'text': 'Verified',
            'icon': '✓'
        },
        'flagged': {
            'bg': '#ff9800',
            'text': 'Flagged',
            'icon': '⚠'
        },
        'rejected': {
            'bg': '#f44336',
            'text': 'Rejected',
            'icon': '✕'
        }
    }
    
    config = colors.get(status, colors['flagged'])
    score_display = f"{int(trust_score * 100)}%"
    
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="200" height="35" role="img" aria-label="Credence: {config['text']}">
    <title>Credence: {config['text']}</title>
    <linearGradient id="badge-gradient" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="badge-clip">
        <rect width="200" height="35" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#badge-clip)">
        <rect width="85" height="35" fill="#555"/>
        <rect x="85" width="115" height="35" fill="{config['bg']}"/>
        <rect width="200" height="35" fill="url(#badge-gradient)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="12">
        <text x="42.5" y="21" fill="#010101" fill-opacity=".3">Credence</text>
        <text x="42.5" y="20">Credence</text>
        <text x="142.5" y="21" fill="#010101" fill-opacity=".3">{config['icon']} {config['text']}</text>
        <text x="142.5" y="20">{config['icon']} {config['text']}</text>
    </g>
</svg>'''
    
    return svg


def generate_detailed_badge(server_id: str, status: str, trust_score: float, version: str) -> str:
    """Generate more detailed badge with version and score"""
    
    colors = {
        'verified': '#4caf50',
        'flagged': '#ff9800',
        'rejected': '#f44336'
    }
    
    color = colors.get(status, colors['flagged'])
    score_text = f"{int(trust_score * 100)}%"
    
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="280" height="90" role="img">
    <title>Credence Security - {server_id}</title>
    <rect width="280" height="90" fill="#ffffff" stroke="#e0e0e0" stroke-width="2" rx="6"/>
    
    <!-- Logo/Icon Area -->
    <circle cx="30" cy="30" r="18" fill="{color}"/>
    <text x="30" y="37" text-anchor="middle" fill="#ffffff" font-family="Arial" font-size="20" font-weight="bold">C</text>
    
    <!-- Main Content -->
    <text x="60" y="25" font-family="Arial" font-size="14" font-weight="bold" fill="#333">Credence Verified</text>
    <text x="60" y="45" font-family="Arial" font-size="11" fill="#666">{server_id}</text>
    
    <!-- Status -->
    <rect x="10" y="55" width="120" height="25" fill="{color}" rx="3"/>
    <text x="70" y="72" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold" fill="#ffffff">{status.upper()}</text>
    
    <!-- Trust Score -->
    <rect x="140" y="55" width="130" height="25" fill="#f5f5f5" stroke="#e0e0e0" stroke-width="1" rx="3"/>
    <text x="160" y="72" font-family="Arial" font-size="11" fill="#666">Trust Score:</text>
    <text x="250" y="72" text-anchor="end" font-family="Arial" font-size="12" font-weight="bold" fill="{color}">{score_text}</text>
</svg>'''
    
    return svg


if __name__ == '__main__':
    # Generate example badges
    print("Generating example badges...")
    
    # Simple badges
    with open('/home/claude/badge-verified.svg', 'w') as f:
        f.write(generate_badge('verified', 0.95))
    
    with open('/home/claude/badge-flagged.svg', 'w') as f:
        f.write(generate_badge('flagged', 0.72))
    
    with open('/home/claude/badge-rejected.svg', 'w') as f:
        f.write(generate_badge('rejected', 0.45))
    
    # Detailed badge
    with open('/home/claude/badge-detailed.svg', 'w') as f:
        f.write(generate_detailed_badge('example/mcp-server', 'verified', 0.95, '1.0.0'))
    
    print("✓ Badges generated in /home/claude/")
    print("  - badge-verified.svg")
    print("  - badge-flagged.svg") 
    print("  - badge-rejected.svg")
    print("  - badge-detailed.svg")
