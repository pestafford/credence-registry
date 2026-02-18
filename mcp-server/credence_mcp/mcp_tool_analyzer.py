#!/usr/bin/env python3
"""
Credence MCP Tool Analyzer — Deep analysis of MCP tool definitions.

Static analysis checks (bucket 1 — no LLM required):
  1. Unicode zero-width character detection
  2. Prompt injection patterns in descriptions (12 patterns)
  3. Sensitive filesystem path references in descriptions (13 patterns)
  4. Description length analysis (warn >500, critical >1500 chars)
  5. Excessive whitespace abuse (horizontal + vertical padding)
  6. Schema poisoning — parameter names, required array, param descriptions, enums
  7. Tool name collision detection (exact match against 44 official tools)
  8. Typosquatting detection (Levenshtein distance against official tools)
  9. Priority claiming in descriptions (5 patterns)
  10. Permission scope analysis (filesystem, network, env, exec, db, crypto)
  11. Dynamic description loading detection (6 patterns)
  12. Version/time/env-gated conditional registration (4 patterns)
  13. Tool description hashing (SHA-256 per tool for rug pull detection)

Deferred to deliberation-mcp (bucket 3 — requires adversarial reasoning):
  - ATPA: output poisoning via error handlers, return values, follow-up prompts
  - Cross-tool contamination: descriptions referencing/influencing other tools
  - Intent analysis for typosquats vs. innocent typos

Usage:
    python mcp_tool_analyzer.py /path/to/mcp-server-repo [output.json]

Outputs: tool-analysis.json
"""

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ── Known MCP Server Tool Names (collision detection) ────────────

KNOWN_OFFICIAL_TOOLS = {
    # Anthropic reference servers
    "read_file", "write_file", "list_directory", "search_files", "move_file",
    "get_file_info", "read_multiple_files", "create_directory",
    "list_allowed_directories",
    "query", "execute", "list_tables", "describe_table",
    "brave_web_search", "brave_local_search",
    "fetch", "fetch_url",
    "create_or_update_file", "search_repositories", "create_repository",
    "get_file_contents", "push_files", "create_issue", "create_pull_request",
    "fork_repository", "create_branch", "list_commits", "list_issues",
    "search_code", "search_issues",
    "puppeteer_navigate", "puppeteer_screenshot", "puppeteer_click",
    "puppeteer_fill", "puppeteer_evaluate",
    "send_message", "list_channels", "search_messages",
    "list_objects", "get_object", "put_object",
    "search", "get_contents", "ask",
}

# ── Suspicious Patterns ──────────────────────────────────────────

# Zero-width and invisible Unicode characters
ZERO_WIDTH_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\u200e': 'LEFT-TO-RIGHT MARK',
    '\u200f': 'RIGHT-TO-LEFT MARK',
    '\u2060': 'WORD JOINER',
    '\u2061': 'FUNCTION APPLICATION',
    '\u2062': 'INVISIBLE TIMES',
    '\u2063': 'INVISIBLE SEPARATOR',
    '\u2064': 'INVISIBLE PLUS',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE (BOM)',
    '\u00ad': 'SOFT HYPHEN',
    '\u034f': 'COMBINING GRAPHEME JOINER',
    '\u061c': 'ARABIC LETTER MARK',
    '\u180e': 'MONGOLIAN VOWEL SEPARATOR',
}

# Prompt injection / instruction patterns in descriptions
INJECTION_PATTERNS = [
    (r'ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)', 'PROMPT_INJECTION_OVERRIDE'),
    (r'system\s+prompt', 'SYSTEM_PROMPT_REFERENCE'),
    (r'you\s+(must|should|are|will)\s+(always|never)', 'BEHAVIORAL_DIRECTIVE'),
    (r'do\s+not\s+(tell|reveal|mention|disclose)', 'SECRECY_DIRECTIVE'),
    (r'<\s*(script|img|iframe|object|embed)', 'HTML_INJECTION'),
    (r'for\s+security.*read.*(?:ssh|\.ssh/|id_rsa|\.env|credentials)', 'CREDENTIAL_HARVESTING_LANGUAGE'),
    (r'include\s+(the\s+)?(fingerprint|key|token|password|secret)\s+in\s+(the\s+)?response', 'EXFILTRATION_LANGUAGE'),
    (r'verify.*identity.*by.*reading', 'SOCIAL_ENGINEERING_LANGUAGE'),
    (r'always\s+(include|attach|send|forward)', 'UNCONDITIONAL_ACTION_DIRECTIVE'),
    (r'<\s*IMPORTANT\s*>|<\s*SYSTEM\s*>|<\s*INSTRUCTION\s*>', 'XML_TAG_DIRECTIVE'),
    (r'before\s+any\s+(other|tool|action|step)', 'PRIORITY_OVERRIDE_DIRECTIVE'),
    (r'\bsecretly\b|covert(ly)?|hidden\s+(from|without)|without\s+(the\s+)?user\s+knowing', 'COVERT_ACTION_LANGUAGE'),
]

# Filesystem paths that should not appear in tool descriptions
# (presence in descriptions suggests credential harvesting / data exfiltration framing)
SUSPICIOUS_PATH_PATTERNS = [
    (r'~/\.ssh|~/.ssh|/\.ssh/', 'SSH_KEY_PATH'),
    (r'/etc/passwd|/etc/shadow', 'SYSTEM_CREDENTIALS_PATH'),
    (r'~/\.aws|~/.aws|\.aws/credentials', 'AWS_CREDENTIALS_PATH'),
    (r'~/\.gnupg|~/.gnupg|\.gnupg/', 'GPG_KEY_PATH'),
    (r'~/\.config|~/.config|/\.config/', 'USER_CONFIG_PATH'),
    (r'/etc/hosts|/etc/resolv', 'SYSTEM_CONFIG_PATH'),
    (r'\$HOME/|%USERPROFILE%|%APPDATA%', 'HOME_DIR_REFERENCE'),
    (r'~/.bashrc|~/.zshrc|~/.profile|~/\.bash_history', 'SHELL_CONFIG_PATH'),
    (r'~/.kube|kubeconfig|\.kube/config', 'KUBERNETES_CONFIG_PATH'),
    (r'~/.docker|docker.*config\.json', 'DOCKER_CONFIG_PATH'),
    (r'\.env\b|\.env\.local|\.env\.prod', 'ENV_FILE_REFERENCE'),
    (r'id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts', 'SSH_KEY_FILE'),
    (r'keychain|keystore|wallet\.dat', 'KEYSTORE_REFERENCE'),
]

# Priority claiming patterns — tool trying to override other tools
PRIORITY_CLAIM_PATTERNS = [
    (r'prefer(red)?\s+(this|tool|method|approach)', 'CLAIMS_PREFERENCE'),
    (r'use\s+(this\s+)?(instead|rather\s+than|over|in\s+place\s+of)', 'CLAIMS_REPLACEMENT'),
    (r'(best|correct|proper|official|recommended)\s+(way|method|tool|approach)\s+(to|for)', 'CLAIMS_AUTHORITY'),
    (r'(supersedes?|replaces?|deprecates?)\s+(the\s+)?(default|built.?in|official|standard)', 'CLAIMS_SUPERSEDING'),
    (r'(more|most)\s+(secure|safe|reliable|accurate)\s+than', 'CLAIMS_SUPERIORITY'),
]

# Permission scope indicators
PERMISSION_PATTERNS = {
    'filesystem': [
        r'read_file|write_file|open\(|Path\(|os\.path|fs\.|readFile|writeFile|mkdir|rmdir|unlink',
        r'\.read\(\)|\.write\(|file_get_contents|fopen|fwrite',
    ],
    'network': [
        r'requests\.|httpx\.|urllib|fetch\(|axios|http\.get|http\.post|socket\.',
        r'net\.connect|dns\.lookup|resolve\(|gethostbyname',
    ],
    'environment': [
        r'os\.environ|process\.env|getenv|ENV\[|System\.getenv',
        r'\.env\b|dotenv|config\(\)',
    ],
    'execution': [
        r'subprocess|os\.system|exec\(|eval\(|child_process|spawn\(|popen',
        r'__import__|importlib|compile\(.*exec|pty\.spawn',
    ],
    'database': [
        r'sqlite|postgres|mysql|mongodb|redis|SELECT\s|INSERT\s|UPDATE\s|DELETE\s',
        r'\.query\(|\.execute\(|cursor\.',
    ],
    'crypto_keys': [
        r'private.?key|secret.?key|api.?key|token|password|credential',
        r'ssh.*key|pgp|gpg|encrypt|decrypt|signing.?key',
        r'wallet\.dat|keystore|mnemonic|seed.?phrase',
    ],
    'financial': [
        r'@solana/web3\.js|solders|ethers|web3(?:\.py)?|brownie|hardhat|anchor|spl-token',
        r'sendTransaction|send_transaction|signTransaction|sign_transaction|transfer\s*\(',
        r'jupiter|raydium|uniswap|pancakeswap|orca|serum|metaplex',
        r'(?:wallet|address|recipient)\s*[=:]\s*["\'](?:[1-9A-HJ-NP-Za-km-z]{32,50}|0x[0-9a-fA-F]{40})',
    ],
}

# Dynamic description loading patterns
DYNAMIC_DESC_PATTERNS = [
    (r'(fetch|get|load|download|request)\s*\(.*?(description|desc|tool_desc|help_text)', 'DYNAMIC_FETCH_DESCRIPTION'),
    (r'description\s*=\s*(await\s+)?(fetch|get|load|requests)', 'DESCRIPTION_FROM_REMOTE'),
    (r'(description|tool_description).*=.*f["\'].*\{', 'FSTRING_DESCRIPTION'),
    (r'description.*=.*format\(', 'FORMAT_STRING_DESCRIPTION'),
    (r'description.*=.*\+\s*[a-zA-Z_]', 'CONCATENATED_DESCRIPTION'),
    (r'os\.environ.*description|getenv.*desc', 'DESCRIPTION_FROM_ENV'),
]

# Description length threshold — suspiciously long descriptions may hide content
DESCRIPTION_LENGTH_WARN = 500
DESCRIPTION_LENGTH_CRITICAL = 1500

# Excessive whitespace — pushing content out of visible area
WHITESPACE_RUN_THRESHOLD = 40  # consecutive spaces/tabs
NEWLINE_RUN_THRESHOLD = 8      # consecutive blank lines


# ── Analysis Results ─────────────────────────────────────────────

@dataclass
class ToolFinding:
    tool_name: str
    file_path: str
    line_number: int
    finding_type: str  # UNICODE, INJECTION, COLLISION, PERMISSION, DYNAMIC, SCHEMA
    severity: str      # critical, high, medium, low, info
    description: str
    evidence: str = ""


@dataclass
class ToolDescriptor:
    name: str
    description: str
    description_hash: str
    file_path: str
    line_number: int
    permissions: list = field(default_factory=list)


@dataclass
class AnalysisReport:
    tool_files_found: int = 0
    tools_analyzed: int = 0
    description_hashes: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    permissions_summary: dict = field(default_factory=dict)
    warning_count: int = 0
    critical_count: int = 0


# ── Analysis Functions ───────────────────────────────────────────

def find_tool_files(repo_path: Path) -> list[Path]:
    """Find files likely containing MCP tool definitions."""
    tool_files = []
    patterns = [
        '**/*.py', '**/*.ts', '**/*.js', '**/*.mts', '**/*.mjs',
        '**/*.json',  # tool manifests
    ]
    for pattern in patterns:
        for path in repo_path.glob(pattern):
            if '.git' in path.parts or 'node_modules' in path.parts:
                continue
            try:
                content = path.read_text(errors='replace')
                # Heuristic: does this file define MCP tools?
                # These keywords are specific to MCP tool registration patterns.
                # Deliberately excludes generic terms like 'description:' that
                # appear in non-tool files and would cause file-level checks
                # (permissions, version gates, dynamic loading) to over-report.
                if any(kw in content for kw in [
                    '@mcp.tool', 'server.tool', 'ListToolsResult',
                    'registerTool', 'inputSchema',
                ]) or ('"tools"' in content and '"name"' in content):
                    tool_files.append(path)
            except Exception:
                continue
    return tool_files


def extract_tool_descriptions(file_path: Path, repo_path: Path) -> list[ToolDescriptor]:
    """Extract tool names and descriptions from a file."""
    tools = []
    content = file_path.read_text(errors='replace')
    rel_path = str(file_path.relative_to(repo_path))

    # Python: @mcp.tool decorator or tool registration
    #
    # IMPORTANT: No re.DOTALL here. DOTALL causes catastrophic backtracking
    # where .*? in the decorator pattern bridges across tool boundaries when
    # the immediate def has no docstring, stealing docstrings from later tools.
    # Trade-off: multi-line docstrings capture first line only in pass 1a;
    # block-style docstrings handled by pass 1b.
    #
    # Pass 1a: inline docstrings ("""text""" on same line as opening quotes)
    py_with_doc = re.compile(
        r'@mcp\.tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\'][^\n]*\)\s*\n'
        r'(?:@\w+[^\n]*\n)*'
        r'(?:async\s+)?def\s+\w+[^\n]*:\s*\n'
        r'[ \t]*(?:"""([^"]*?)"""|\'\'\'([^\']*?)\'\'\')',
    )
    found_names = set()
    for m in py_with_doc.finditer(content):
        name = m.group(1)
        desc = m.group(2) or m.group(3) or ""
        line = content[:m.start()].count('\n') + 1
        desc_hash = hashlib.sha256(desc.strip().encode('utf-8')).hexdigest()
        tools.append(ToolDescriptor(name, desc.strip(), desc_hash, rel_path, line))
        found_names.add(name)

    # Pass 1b: block-style docstrings (opening """ on its own line)
    # e.g.:
    #   def foo():
    #       """
    #       Description text here.
    #       """
    py_block_doc = re.compile(
        r'@mcp\.tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\'][^\n]*\)\s*\n'
        r'(?:@\w+[^\n]*\n)*'
        r'(?:async\s+)?def\s+\w+[^\n]*:\s*\n'
        r'[ \t]*"""\s*\n([\s\S]*?)"""',
    )
    for m in py_block_doc.finditer(content):
        name = m.group(1)
        if name in found_names:
            continue
        desc = m.group(2) or ""
        # Clean up indentation from block docstring
        desc_lines = [l.strip() for l in desc.strip().split('\n')]
        desc = ' '.join(l for l in desc_lines if l)
        line = content[:m.start()].count('\n') + 1
        desc_hash = hashlib.sha256(desc.encode('utf-8')).hexdigest()
        tools.append(ToolDescriptor(name, desc, desc_hash, rel_path, line))
        found_names.add(name)

    # Pass 2: tools WITHOUT docstrings (still need ToolDescriptor for
    # collision/typosquat/name checks — just no description to analyze)
    py_no_doc = re.compile(
        r'@mcp\.tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']',
    )
    for m in py_no_doc.finditer(content):
        name = m.group(1)
        if name not in found_names:
            line = content[:m.start()].count('\n') + 1
            desc_hash = hashlib.sha256(b'').hexdigest()
            tools.append(ToolDescriptor(name, "", desc_hash, rel_path, line))
            found_names.add(name)

    # TypeScript/JS: server.tool() or registerTool
    # No DOTALL — same cross-boundary backtracking risk as Python extraction
    ts_pattern = re.compile(
        r'(?:server\.tool|registerTool)\s*\(\s*["\']([^"\']+)["\']'
        r'(?:[^\n]*?description\s*[:=]\s*["\']([^"\']*)["\'])?',
    )
    for m in ts_pattern.finditer(content):
        name = m.group(1)
        desc = m.group(2) or ""
        line = content[:m.start()].count('\n') + 1
        desc_hash = hashlib.sha256(desc.strip().encode('utf-8')).hexdigest()
        tools.append(ToolDescriptor(name, desc.strip(), desc_hash, rel_path, line))

    # JSON: tool definitions in manifests
    if file_path.suffix == '.json':
        try:
            data = json.loads(content)
            json_tools = data.get('tools', [])
            if isinstance(json_tools, list):
                for i, t in enumerate(json_tools):
                    if isinstance(t, dict) and 'name' in t:
                        name = t['name']
                        desc = t.get('description', '')
                        desc_hash = hashlib.sha256(desc.strip().encode('utf-8')).hexdigest()
                        tools.append(ToolDescriptor(name, desc.strip(), desc_hash, rel_path, i))
        except (json.JSONDecodeError, AttributeError):
            pass

    return tools


def check_unicode(content: str, file_path: str) -> list[ToolFinding]:
    """Detect invisible Unicode characters."""
    findings = []
    for line_num, line in enumerate(content.split('\n'), 1):
        for char, name in ZERO_WIDTH_CHARS.items():
            if char in line:
                count = line.count(char)
                findings.append(ToolFinding(
                    tool_name="*",
                    file_path=file_path,
                    line_number=line_num,
                    finding_type="UNICODE",
                    severity="high",
                    description=f"Invisible Unicode character: {name} (U+{ord(char):04X}) found {count} time(s)",
                    evidence=repr(line.strip()[:120])
                ))
    return findings


def check_injection(tool: ToolDescriptor) -> list[ToolFinding]:
    """Check tool description for prompt injection patterns."""
    findings = []
    for pattern, label in INJECTION_PATTERNS:
        matches = re.findall(pattern, tool.description, re.IGNORECASE)
        if matches:
            findings.append(ToolFinding(
                tool_name=tool.name,
                file_path=tool.file_path,
                line_number=tool.line_number,
                finding_type="INJECTION",
                severity="critical" if label in (
                    'PROMPT_INJECTION_OVERRIDE', 'CREDENTIAL_HARVESTING_LANGUAGE',
                    'EXFILTRATION_LANGUAGE'
                ) else "high",
                description=f"Suspicious pattern in tool description: {label}",
                evidence=tool.description[:200]
            ))
    return findings


def check_name_collision(tool: ToolDescriptor) -> list[ToolFinding]:
    """Check if tool name collides with known official tools."""
    findings = []
    name_lower = tool.name.lower().replace('-', '_')

    for official in KNOWN_OFFICIAL_TOOLS:
        if name_lower == official.lower():
            findings.append(ToolFinding(
                tool_name=tool.name,
                file_path=tool.file_path,
                line_number=tool.line_number,
                finding_type="COLLISION",
                severity="medium",
                description=f"Tool name '{tool.name}' collides with known official tool '{official}'. "
                           f"May impersonate or shadow the official tool.",
                evidence=""
            ))
    return findings


def check_permissions(content: str, file_path: str, repo_path: Path) -> dict[str, list]:
    """Analyze what permissions/capabilities the code claims."""
    permissions = {}
    for scope, patterns in PERMISSION_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                if scope not in permissions:
                    permissions[scope] = []
                permissions[scope].extend(matches[:5])  # Cap evidence
    return permissions


def check_dynamic_descriptions(content: str, file_path: str, repo_path: Path) -> list[ToolFinding]:
    """Check for descriptions loaded at runtime."""
    findings = []
    rel_path = str(Path(file_path).relative_to(repo_path)) if repo_path else file_path
    for line_num, line in enumerate(content.split('\n'), 1):
        for pattern, label in DYNAMIC_DESC_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(ToolFinding(
                    tool_name="*",
                    file_path=rel_path,
                    line_number=line_num,
                    finding_type="DYNAMIC",
                    severity="high",
                    description=f"Dynamic description loading detected: {label}. "
                               f"Tool descriptions should be static — dynamic loading enables rug pulls.",
                    evidence=line.strip()[:150]
                ))
    return findings


def check_schema_poisoning(content: str, file_path: str, repo_path: Path) -> list[ToolFinding]:
    """Check for schema manipulation patterns."""
    findings = []
    rel_path = str(Path(file_path).relative_to(repo_path)) if repo_path else file_path

    # Check for additionalProperties not set to false (allows hidden fields)
    add_props_re = re.compile(
        r'["\']?additionalProperties["\']?\s*[:=]\s*(?:true|True)',
        re.IGNORECASE
    )
    if add_props_re.search(content):
        line_num = next(
            (i + 1 for i, l in enumerate(content.split('\n'))
             if 'additionalProperties' in l and re.search(r'true', l, re.IGNORECASE)),
            0
        )
        findings.append(ToolFinding(
            tool_name="*",
            file_path=rel_path,
            line_number=line_num,
            finding_type="SCHEMA",
            severity="medium",
            description="additionalProperties set to true — allows hidden fields in input",
            evidence=""
        ))

    # Check for overly permissive type: "any" or no type constraint
    if re.search(r'"type"\s*:\s*"any"', content):
        findings.append(ToolFinding(
            tool_name="*",
            file_path=rel_path,
            line_number=0,
            finding_type="SCHEMA",
            severity="low",
            description="Schema uses type 'any' — weak input validation",
            evidence=""
        ))

    # ── Deep schema checks (parameter-level) ─────────────

    lines = content.split('\n')

    # Parameter names containing instruction-like text
    # Only flag names that combine multiple suspicious terms (e.g. system_prompt_override)
    # or use terms that are specifically injection-oriented (inject, override + prompt/instruction)
    SUSPICIOUS_PARAM_PATTERN = re.compile(
        r'["\'](\w*(?:system_prompt|prompt_override|prompt_injection|instruction_override|'
        r'system_instruction|inject_context|override_prompt|admin_override|'
        r'sudo_exec|root_exec|exec_inject|command_inject)\w*)["\']'
        r'\s*[:\{]',
        re.IGNORECASE
    )
    for i, line in enumerate(lines, 1):
        for m in SUSPICIOUS_PARAM_PATTERN.finditer(line):
            param_name = m.group(1)
            findings.append(ToolFinding(
                tool_name="*",
                file_path=rel_path,
                line_number=i,
                finding_type="SCHEMA",
                severity="medium",
                description=f"Parameter name '{param_name}' contains injection-oriented term combination. "
                           f"May be designed to trick agents into injecting attacker-controlled text.",
                evidence=line.strip()[:150]
            ))

    # Required array containing non-parameter / instruction entries
    required_re = re.compile(
        r'"required"\s*:\s*\[(.*?)\]',
        re.DOTALL
    )
    for m in required_re.finditer(content):
        required_block = m.group(1)
        # Look for entries that are suspiciously long or contain spaces (not normal param names)
        entries = re.findall(r'"([^"]+)"', required_block)
        for entry in entries:
            if ' ' in entry or len(entry) > 40:
                line_num = content[:m.start()].count('\n') + 1
                findings.append(ToolFinding(
                    tool_name="*",
                    file_path=rel_path,
                    line_number=line_num,
                    finding_type="SCHEMA",
                    severity="high",
                    description=f"Required array contains suspicious entry: '{entry[:60]}'. "
                               f"Normal parameter names don't contain spaces or exceed 40 chars.",
                    evidence=entry[:100]
                ))

    # Parameter descriptions with embedded directives
    # Look for "description": "..." entries in JSON schemas that contain injection patterns
    param_desc_re = re.compile(
        r'"description"\s*:\s*"([^"]{80,})"',
        re.IGNORECASE
    )
    for m in param_desc_re.finditer(content):
        desc_text = m.group(1)
        for inj_pattern, inj_label in INJECTION_PATTERNS:
            if re.search(inj_pattern, desc_text, re.IGNORECASE):
                line_num = content[:m.start()].count('\n') + 1
                findings.append(ToolFinding(
                    tool_name="*",
                    file_path=rel_path,
                    line_number=line_num,
                    finding_type="SCHEMA",
                    severity="high",
                    description=f"Parameter description contains injection pattern: {inj_label}. "
                               f"Input schema descriptions can influence agent behavior.",
                    evidence=desc_text[:150]
                ))
                break  # One finding per param description is enough

    # Enum values containing instruction text
    enum_re = re.compile(r'"enum"\s*:\s*\[(.*?)\]', re.DOTALL)
    for m in enum_re.finditer(content):
        enum_block = m.group(1)
        enum_values = re.findall(r'"([^"]+)"', enum_block)
        for val in enum_values:
            if len(val) > 50 or re.search(r'(ignore|system|prompt|must|always|never|secret)', val, re.IGNORECASE):
                line_num = content[:m.start()].count('\n') + 1
                findings.append(ToolFinding(
                    tool_name="*",
                    file_path=rel_path,
                    line_number=line_num,
                    finding_type="SCHEMA",
                    severity="medium",
                    description=f"Enum value contains suspicious content: '{val[:60]}'. "
                               f"Enum values should be short identifiers, not instruction text.",
                    evidence=val[:100]
                ))

    return findings


# ── New Bucket-1 Checks ──────────────────────────────────────────

def check_description_length(tool: ToolDescriptor) -> list[ToolFinding]:
    """Flag suspiciously long tool descriptions that may hide injected content."""
    findings = []
    desc_len = len(tool.description)

    if desc_len > DESCRIPTION_LENGTH_CRITICAL:
        findings.append(ToolFinding(
            tool_name=tool.name,
            file_path=tool.file_path,
            line_number=tool.line_number,
            finding_type="TPA",
            severity="high",
            description=f"Tool description is {desc_len} characters — critically long. "
                       f"Descriptions over {DESCRIPTION_LENGTH_CRITICAL} chars may hide injected "
                       f"instructions below the visible area of tool listings.",
            evidence=f"First 100: {tool.description[:100]}... Last 100: ...{tool.description[-100:]}"
        ))
    elif desc_len > DESCRIPTION_LENGTH_WARN:
        findings.append(ToolFinding(
            tool_name=tool.name,
            file_path=tool.file_path,
            line_number=tool.line_number,
            finding_type="TPA",
            severity="medium",
            description=f"Tool description is {desc_len} characters — unusually long. "
                       f"Typical MCP tool descriptions are under {DESCRIPTION_LENGTH_WARN} chars.",
            evidence=tool.description[:200]
        ))

    return findings


def check_whitespace_abuse(tool: ToolDescriptor) -> list[ToolFinding]:
    """Detect excessive whitespace in descriptions used to push content off-screen."""
    findings = []
    desc = tool.description

    # Consecutive spaces or tabs (pushing text horizontally)
    space_runs = re.findall(r'[ \t]{' + str(WHITESPACE_RUN_THRESHOLD) + r',}', desc)
    if space_runs:
        findings.append(ToolFinding(
            tool_name=tool.name,
            file_path=tool.file_path,
            line_number=tool.line_number,
            finding_type="TPA",
            severity="high",
            description=f"Description contains {len(space_runs)} run(s) of {WHITESPACE_RUN_THRESHOLD}+ "
                       f"consecutive whitespace characters. Content after the whitespace may be "
                       f"hidden from human review but visible to the LLM.",
            evidence=f"Longest run: {len(max(space_runs, key=len))} chars"
        ))

    # Consecutive newlines (pushing text vertically)
    newline_runs = re.findall(r'\n{' + str(NEWLINE_RUN_THRESHOLD) + r',}', desc)
    if newline_runs:
        findings.append(ToolFinding(
            tool_name=tool.name,
            file_path=tool.file_path,
            line_number=tool.line_number,
            finding_type="TPA",
            severity="high",
            description=f"Description contains {len(newline_runs)} run(s) of {NEWLINE_RUN_THRESHOLD}+ "
                       f"consecutive newlines. Content below may be hidden in UI but read by the agent.",
            evidence=f"Longest run: {len(max(newline_runs, key=len))} blank lines"
        ))

    return findings


def check_suspicious_paths(tool: ToolDescriptor) -> list[ToolFinding]:
    """Detect references to sensitive filesystem paths in tool descriptions."""
    findings = []
    for pattern, label in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, tool.description, re.IGNORECASE):
            findings.append(ToolFinding(
                tool_name=tool.name,
                file_path=tool.file_path,
                line_number=tool.line_number,
                finding_type="TPA",
                severity="critical" if label in (
                    'SSH_KEY_PATH', 'SSH_KEY_FILE', 'SYSTEM_CREDENTIALS_PATH',
                    'AWS_CREDENTIALS_PATH', 'GPG_KEY_PATH'
                ) else "high",
                description=f"Tool description references sensitive path: {label}. "
                           f"Legitimate tools rarely reference specific credential "
                           f"or config paths in their descriptions.",
                evidence=tool.description[:200]
            ))
    return findings


def check_priority_claims(tool: ToolDescriptor) -> list[ToolFinding]:
    """Detect descriptions that claim priority over other tools."""
    findings = []
    for pattern, label in PRIORITY_CLAIM_PATTERNS:
        if re.search(pattern, tool.description, re.IGNORECASE):
            findings.append(ToolFinding(
                tool_name=tool.name,
                file_path=tool.file_path,
                line_number=tool.line_number,
                finding_type="COLLISION",
                severity="medium",
                description=f"Tool description claims priority: {label}. "
                           f"Third-party tools should not direct agents to prefer them "
                           f"over official or default tools.",
                evidence=tool.description[:200]
            ))
    return findings


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def check_typosquatting(tool: ToolDescriptor) -> list[ToolFinding]:
    """Detect tool names that are suspiciously close to official tools (typosquatting)."""
    findings = []
    name_lower = tool.name.lower().replace('-', '_')

    for official in KNOWN_OFFICIAL_TOOLS:
        official_lower = official.lower()

        # Skip exact matches — those are caught by check_name_collision
        if name_lower == official_lower:
            continue

        # Only check names that are close in length (typosquats are similar length)
        len_diff = abs(len(name_lower) - len(official_lower))
        if len_diff > 3:
            continue

        dist = _levenshtein(name_lower, official_lower)

        # Thresholds: 1 edit for short names (≤8 chars), 2 edits for longer names
        threshold = 1 if len(official_lower) <= 8 else 2

        if 0 < dist <= threshold:
            findings.append(ToolFinding(
                tool_name=tool.name,
                file_path=tool.file_path,
                line_number=tool.line_number,
                finding_type="COLLISION",
                severity="high",
                description=f"Tool name '{tool.name}' is {dist} edit(s) from official tool "
                           f"'{official}'. Possible typosquatting — may confuse agents into "
                           f"calling this tool instead of the official one.",
                evidence=f"Distance: {dist}, Threshold: {threshold}"
            ))

    return findings


def check_version_gates(content: str, file_path: str, repo_path: Path) -> list[ToolFinding]:
    """Detect conditional tool registration that could enable rug pulls.
    
    Uses a sliding context window because the conditional and the tool
    registration are typically on adjacent lines, not the same line.
    """
    findings = []
    rel_path = str(Path(file_path).relative_to(repo_path)) if repo_path else file_path
    lines = content.split('\n')

    # Patterns that indicate conditional gates
    gate_patterns = [
        (r'if\s+.*(?:version|VERSION|__version__)\s*[><=!]', 'VERSION_GATED'),
        (r'if\s+.*(?:date|time|datetime|timestamp)\s*[><=!]', 'TIME_GATED'),
        (r'if\s+.*(?:os\.environ|process\.env|getenv|ENV\[)', 'ENV_GATED'),
    ]

    # Patterns that indicate tool registration — only specific MCP registration
    # calls, not generic assignments like 'description =' or '"name":' which
    # produce false positives when env/version checks appear near unrelated code.
    tool_patterns = [
        r'@mcp\.tool', r'server\.tool', r'registerTool',
        r'add_tool', r'register_tool', r'tool_definition',
    ]

    # Scan with a context window: if a gate pattern appears within 4 lines
    # of a tool registration pattern, flag it
    CONTEXT_WINDOW = 4

    for i, line in enumerate(lines):
        for gate_re, gate_label in gate_patterns:
            if re.search(gate_re, line, re.IGNORECASE):
                # Check surrounding lines for tool registration
                window_start = max(0, i - 1)
                window_end = min(len(lines), i + CONTEXT_WINDOW + 1)
                window = '\n'.join(lines[window_start:window_end])

                for tool_re in tool_patterns:
                    if re.search(tool_re, window, re.IGNORECASE):
                        findings.append(ToolFinding(
                            tool_name="*",
                            file_path=rel_path,
                            line_number=i + 1,
                            finding_type="DYNAMIC",
                            severity="high",
                            description=f"Conditional tool registration detected: {gate_label}. "
                                       f"Tool behavior that changes based on version, time, or "
                                       f"environment variables can enable post-attestation rug pulls.",
                            evidence=line.strip()[:150]
                        ))
                        break  # One finding per gate line
                break  # One gate pattern match per line

    # Also check for ternary/inline conditional tool definitions
    for i, line in enumerate(lines, 1):
        if re.search(r'(?:tool|register|description)\s*=.*if\s+.*else\s+', line, re.IGNORECASE):
            findings.append(ToolFinding(
                tool_name="*",
                file_path=rel_path,
                line_number=i,
                finding_type="DYNAMIC",
                severity="high",
                description="Conditional ternary tool definition detected. "
                           "Tool names or descriptions that change at runtime "
                           "can enable post-attestation rug pulls.",
                evidence=line.strip()[:150]
            ))

    return findings


# ── Crypto / Financial Operations ─────────────────────────────────

_CRYPTO_PATTERNS = [
    (
        re.compile(
            r'(?:sendTransaction|send_transaction|signAndSend|sign_and_send|'
            r'transfer\s*\(|\.send\s*\(.*(?:lamports|value|amount))',
            re.IGNORECASE,
        ),
        "CRYPTO_TRANSACTION_SEND",
        "Crypto transaction send/transfer operation detected",
    ),
    (
        re.compile(
            r'(?:~/|/home/|expanduser|%USERPROFILE%|\.bob-p2p)'
            r'.*(?:wallet\.dat|keystore|private.?key|seed\.txt|mnemonic|\.keys)',
            re.IGNORECASE,
        ),
        "CRYPTO_KEY_FILE_ACCESS",
        "Access to crypto key/wallet file in home directory",
    ),
    (
        re.compile(
            r'(?:buy_?token|sell_?token|purchase_?token|'
            r'(?:jupiter|raydium|uniswap|pancakeswap|orca).*(?:swap|exchange|route))',
            re.IGNORECASE,
        ),
        "CRYPTO_TOKEN_PURCHASE",
        "Crypto token purchase/swap operation detected",
    ),
    (
        re.compile(
            r'(?:wallet|address|recipient|dest(?:ination)?|to_addr)\s*[=:]\s*["\']'
            r'(?:[1-9A-HJ-NP-Za-km-z]{32,50}|0x[0-9a-fA-F]{40})["\']',
        ),
        "CRYPTO_HARDCODED_ADDRESS",
        "Hardcoded crypto wallet address in assignment context",
    ),
]


def check_crypto_operations(content: str, file_path: str, repo_path: Path) -> list[ToolFinding]:
    """Detect cryptocurrency/financial operations in MCP tool code."""
    findings = []
    rel_path = str(Path(file_path).relative_to(repo_path)) if repo_path else file_path

    for line_num, line in enumerate(content.split('\n'), 1):
        for pattern, label, description in _CRYPTO_PATTERNS:
            if pattern.search(line):
                findings.append(ToolFinding(
                    tool_name="*",
                    file_path=rel_path,
                    line_number=line_num,
                    finding_type="TPA",
                    severity="high",
                    description=f"{description}. {label} — "
                               f"financial operations in MCP tools require explicit "
                               f"user consent and should match the tool's declared purpose.",
                    evidence=line.strip()[:150]
                ))
                break  # One finding per line max
    return findings


# ── Main Analysis ────────────────────────────────────────────────

def analyze_repo(repo_path: str) -> dict:
    """Run full MCP tool analysis on a repository."""
    repo = Path(repo_path).resolve()
    report = AnalysisReport()

    if not repo.is_dir():
        return {"error": f"Not a directory: {repo_path}"}

    # Find tool files
    tool_files = find_tool_files(repo)
    report.tool_files_found = len(tool_files)

    all_findings = []
    all_tools = []
    all_permissions = {}

    for tf in tool_files:
        try:
            content = tf.read_text(errors='replace')
            rel_path = str(tf.relative_to(repo))
        except Exception:
            continue

        # Extract tool definitions
        tools = extract_tool_descriptions(tf, repo)
        all_tools.extend(tools)

        # Check Unicode in entire file
        all_findings.extend(check_unicode(content, rel_path))

        # Check each tool
        for tool in tools:
            all_findings.extend(check_injection(tool))
            all_findings.extend(check_name_collision(tool))
            all_findings.extend(check_description_length(tool))
            all_findings.extend(check_whitespace_abuse(tool))
            all_findings.extend(check_suspicious_paths(tool))
            all_findings.extend(check_priority_claims(tool))
            all_findings.extend(check_typosquatting(tool))

        # Check file-level patterns
        all_findings.extend(check_dynamic_descriptions(content, str(tf), repo))
        all_findings.extend(check_schema_poisoning(content, str(tf), repo))
        all_findings.extend(check_version_gates(content, str(tf), repo))
        all_findings.extend(check_crypto_operations(content, str(tf), repo))

        # Permission analysis
        perms = check_permissions(content, str(tf), repo)
        for scope, evidence in perms.items():
            if scope not in all_permissions:
                all_permissions[scope] = []
            all_permissions[scope].extend(evidence)

    # Build report
    report.tools_analyzed = len(all_tools)
    report.findings = [asdict(f) for f in all_findings]
    report.description_hashes = {t.name: t.description_hash for t in all_tools}
    report.permissions_summary = {k: len(v) for k, v in all_permissions.items()}
    report.warning_count = sum(1 for f in all_findings if f.severity in ('medium', 'low', 'info'))
    report.critical_count = sum(1 for f in all_findings if f.severity in ('critical', 'high'))

    return asdict(report)


# ── CLI Entry Point ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/mcp-server-repo [output.json]")
        sys.exit(1)

    repo_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/mcp-tool-analysis.json"

    report = analyze_repo(repo_path)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Summary to stdout
    print(f"Tool files found:  {report.get('tool_files_found', 0)}")
    print(f"Tools analyzed:    {report.get('tools_analyzed', 0)}")
    print(f"Critical/High:     {report.get('critical_count', 0)}")
    print(f"Warnings:          {report.get('warning_count', 0)}")
    print(f"Permissions:       {report.get('permissions_summary', {})}")
    print(f"Description hashes: {len(report.get('description_hashes', {}))}")
    print(f"\nOutput: {output_path}")

    # Exit code: non-zero if critical findings
    if report.get('critical_count', 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
