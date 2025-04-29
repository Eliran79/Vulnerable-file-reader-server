import re
from typing import List, Dict, Any, Tuple

# Search patterns for subprocess vulnerabilities
SUBPROCESS_PATTERNS = [
    r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(\s*(?:f[\"'].*?[\"']|[^,]*?\+.*?|.*?\.format\(.*?\))\s*,\s*shell\s*=\s*True",
    r"os\.(?:system|popen)\s*\(\s*(?:f[\"'].*?[\"']|[^,]*?\+.*?|.*?\.format\(.*?\))",
]

# MCP server specific patterns
MCP_SERVER_PATTERNS = [
    r"class\s+\w*MCP\w*Server",
    r"class\s+\w*ModelContextProtocol\w*",
    r"from\s+.*?mcp\s+import",
    r"import\s+.*?mcp",
    r"ModelContextProtocol",
    r"MCP_SERVER",
    r"mcp_server",
    r"mcp_handler",
]

# Risky patterns - not always vulnerable but worth checking
COMMAND_CONSTRUCTION_PATTERNS = [
    r"command\s*=\s*(?:f[\"'].*?[\"']|[^\"';]*?\+.*?|.*?\.format\(.*?\))",
    r"cmd\s*=\s*(?:f[\"'].*?[\"']|[^\"';]*?\+.*?|.*?\.format\(.*?\))",
]

def is_mcp_server_file(content: str) -> bool:
    """
    Determine if a file is likely part of an MCP server implementation.
    """
    for pattern in MCP_SERVER_PATTERNS:
        if re.search(pattern, content):
            return True
    return False

def analyze_content(content: str, patterns: List[str]) -> List[Tuple[str, int]]:
    """
    Analyze text content for vulnerable patterns.
    Returns list of (matched_pattern, line_number) tuples.
    """
    findings = []
    lines = content.split("\n")
    
    for i, line in enumerate(lines):
        for pattern in patterns:
            if re.search(pattern, line):
                findings.append((line.strip(), i + 1))
    
    return findings

def print_vulnerabilities_report(vulnerable_repos: Dict[str, Any]) -> None:
    """Print a report of vulnerabilities found in repositories."""
    print("\n===== VULNERABLE MCP SERVER REPOSITORIES =====")
    if not vulnerable_repos:
        print("No vulnerabilities found in any repository.")
        return
        
    for repo_name, data in vulnerable_repos.items():
        if not data.get("files"):
            continue
            
        print(f"\nRepository: {repo_name}")
        print(f"URL: {data.get('url', 'N/A')}")
        print(f"Vulnerable Files: {len(data['files'])}")
        
        # Count MCP files with vulnerabilities
        mcp_files_with_vulns = sum(1 for file in data['files'] if file.get("is_mcp_file", False))
        print(f"MCP Server Files with Vulnerabilities: {mcp_files_with_vulns}")
        
        for file_info in data['files']:
            print(f"\n  - File: {file_info['path']}")
            if 'url' in file_info:
                print(f"    URL: {file_info['url']}")
            print(f"    MCP Server File: {'Yes' if file_info.get('is_mcp_file', False) else 'No'}")
            
            if file_info.get("subprocess_findings"):
                print("    Definite Vulnerabilities:")
                for line, line_number in file_info["subprocess_findings"]:
                    print(f"      Line {line_number}: {line}")
            
            if file_info.get("potential_findings"):
                print("    Potential Issues:")
                for line, line_number in file_info["potential_findings"]:
                    print(f"      Line {line_number}: {line}")
