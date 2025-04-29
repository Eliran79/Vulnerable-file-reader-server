import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Tuple

from scanner_base import (
    SUBPROCESS_PATTERNS, MCP_SERVER_PATTERNS, COMMAND_CONSTRUCTION_PATTERNS,
    is_mcp_server_file, analyze_content, print_vulnerabilities_report
)

def clone_repository(repo_url: str, target_dir: str) -> bool:
    """Clone a repository to the target directory."""
    try:
        print(f"Cloning {repo_url}...")
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir], 
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        return False

def analyze_file(file_path: str) -> Tuple[bool, List[Tuple[str, int]], List[Tuple[str, int]]]:
    """
    Analyze a file for vulnerable patterns.
    Returns (is_mcp_file, subprocess_findings, potential_findings)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False, [], []
    
    # Check if this is an MCP server file
    is_mcp_file = is_mcp_server_file(content)
    
    # Check for vulnerabilities
    subprocess_findings = analyze_content(content, SUBPROCESS_PATTERNS)
    potential_findings = analyze_content(content, COMMAND_CONSTRUCTION_PATTERNS)
    
    return is_mcp_file, subprocess_findings, potential_findings

def scan_directory(directory: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Recursively scan a directory for Python files.
    """
    findings = {
        "subprocess_vulnerabilities": [],
        "potential_issues": [],
        "mcp_files": []
    }
    
    for root, _, files in os.walk(directory):
        # Skip common directories that are unlikely to contain application code
        if any(skip_dir in root for skip_dir in [
            "node_modules", "venv", "env", ".git", "__pycache__", "dist", "build"
        ]):
            continue
        
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory)
                
                # Analyze the file
                is_mcp_file, subprocess_findings, potential_findings = analyze_file(file_path)
                
                if is_mcp_file:
                    findings["mcp_files"].append({
                        "file": relative_path,
                        "path": file_path
                    })
                
                # Add subprocess vulnerabilities if found
                if subprocess_findings:
                    findings["subprocess_vulnerabilities"].append({
                        "file": relative_path,
                        "path": file_path,
                        "findings": subprocess_findings,
                        "is_mcp_file": is_mcp_file
                    })
                
                # Add potential issues if found
                if potential_findings:
                    findings["potential_issues"].append({
                        "file": relative_path,
                        "path": file_path,
                        "findings": potential_findings,
                        "is_mcp_file": is_mcp_file
                    })
    return findings


def format_repo_url(repo_identifier: str) -> str:
    """Ensure the repo identifier is a full HTTPS URL."""
    if repo_identifier.startswith("https://") or repo_identifier.startswith("http://"):
        return repo_identifier
    elif "/" in repo_identifier and not repo_identifier.startswith("github.com"):
        # Assume owner/repo format
        return f"https://github.com/{repo_identifier}"
    elif repo_identifier.startswith("github.com"):
         # Assume github.com/owner/repo format
        return f"https://{repo_identifier}"
    else:
        # Cannot determine format, return as is and let git handle it (or fail)
        print(f"Warning: Could not determine format for repository identifier '{repo_identifier}'. Attempting clone as is.")
        return repo_identifier

def scan_repos_for_vulnerabilities(repos_to_scan: List[str]) -> None:
    """
    Clones and scans a list of repositories for command injection vulnerabilities.
    Accepts full URLs or 'owner/repo' format.
    """
    if not repos_to_scan:
        print("No repositories selected for scanning.")
        return

    # Create temporary directory for cloning
    temp_dir = tempfile.mkdtemp()
    print(f"Created temporary directory: {temp_dir}")
    
    try:
        vulnerable_repos = {}

        print(f"\nScanning {len(repos_to_scan)} selected repositories...")

        for repo_identifier in repos_to_scan:
            repo_url = format_repo_url(repo_identifier)
            # Use a simple name extraction for the temp directory, handling potential '.git' suffix
            repo_name_for_dir = repo_identifier.split('/')[-1].replace('.git', '')
            repo_dir = os.path.join(temp_dir, repo_name_for_dir)

            # Clone repository
            if not clone_repository(repo_url, repo_dir):
                print(f"Skipping {repo_identifier} due to cloning error.")
                continue

            # Scan the cloned repository
            print(f"\n--- Scanning {repo_identifier} ({repo_url}) ---")
            findings = scan_directory(repo_dir)

            # Check if we found MCP files or vulnerabilities
            mcp_files_found = bool(findings["mcp_files"])
            vulns_found = bool(findings["subprocess_vulnerabilities"] or findings["potential_issues"])

            if mcp_files_found:
                 print(f"Found {len(findings['mcp_files'])} potential MCP server file(s).")

            if vulns_found:
                print(f"Found potential vulnerabilities in {repo_identifier}.")
                # Use the original identifier provided by user/search as the key
                vulnerable_repos[repo_identifier] = {
                    "files": [],
                    "url": repo_url, # Store the actual URL used for cloning
                    "is_mcp_server": mcp_files_found # Mark if MCP files were also found
                }

                # Consolidate findings per file
                file_findings_map = {}

                # Add subprocess vulnerabilities
                for item in findings["subprocess_vulnerabilities"]:
                    path = item["file"]
                    if path not in file_findings_map:
                        file_findings_map[path] = {"subprocess_findings": [], "potential_findings": [], "is_mcp_file": item["is_mcp_file"]}
                    file_findings_map[path]["subprocess_findings"].extend(item["findings"])

                # Add potential issues
                for item in findings["potential_issues"]:
                    path = item["file"]
                    if path not in file_findings_map:
                         file_findings_map[path] = {"subprocess_findings": [], "potential_findings": [], "is_mcp_file": item["is_mcp_file"]}
                    file_findings_map[path]["potential_findings"].extend(item["findings"])

                # Add consolidated findings to the report structure
                for path, details in file_findings_map.items():
                    vulnerable_repos[repo_identifier]["files"].append({
                        "path": path,
                        "subprocess_findings": details["subprocess_findings"],
                        "potential_findings": details["potential_findings"],
                        "is_mcp_file": details["is_mcp_file"]
                    })

            elif mcp_files_found:
                 print(f"No specific vulnerabilities found in {repo_identifier}, but MCP files were present.")
            else:
                 print(f"No MCP files or vulnerabilities found in {repo_identifier}.")

            # Optional: Clean up individual repo dir after scan to save space if scanning many repos
            # print(f"Cleaning up temporary directory for {repo_identifier}: {repo_dir}")
            # shutil.rmtree(repo_dir) # Be careful enabling this if debugging needed

        # Print final vulnerability report
        print_vulnerabilities_report(vulnerable_repos)
    
    finally:
        # Clean up: remove temporary directory
        print(f"Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir)
