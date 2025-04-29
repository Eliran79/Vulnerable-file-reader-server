#!/usr/bin/env python3
"""
MCP Vulnerability Scanner

This script discovers potential MCP repositories on GitHub and then scans selected 
repositories locally for command injection vulnerabilities.
"""

import argparse
import sys
from typing import List, Set

# Attempt imports and provide guidance if they fail
try:
    from github_scanner import search_github_for_mcp_repos
except ImportError:
    print("Error: github_scanner.py not found. Make sure it's in the same directory.")
    sys.exit(1)

try:
    from local_scanner import scan_repos_for_vulnerabilities, format_repo_url
except ImportError:
    print("Error: local_scanner.py not found. Make sure it's in the same directory.")
    sys.exit(1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Discover and scan GitHub repositories for command injection vulnerabilities in MCP servers."
    )

    # Add repository arguments (optional, bypasses discovery/selection)
    parser.add_argument(
        "--repos",
        nargs="+",
        help="Optional: Space-separated list of repository URLs or 'owner/repo' names to scan directly, bypassing discovery."
    )

    # Add max repositories limit (for discovery phase)
    parser.add_argument(
        "--max-repos",
        type=int,
        default=20, # Increased default for discovery
        help="Maximum number of potential repositories to find on GitHub during the discovery phase (default: 20)."
    )

    # Add verbose flag (currently unused, but kept for potential future use)
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (currently unused)."
    )

    return parser.parse_args()

def select_repositories_to_scan(found_repos: List[str]) -> List[str]:
    """
    Interactively prompts the user to select repositories from a list.
    Allows selection by number, 'all', URL, or 'owner/repo' format.
    """
    if not found_repos:
        print("No potential repositories found during discovery.")
        return []

    print("\n--- Repository Selection ---")
    print("Found the following potential MCP repositories on GitHub:")
    for i, repo_name in enumerate(found_repos):
        print(f"  {i+1}: {repo_name}")

    selected_repos: Set[str] = set()
    print("\nEnter repository numbers (e.g., 1 3 5), 'all', full URLs (https://...),")
    print("or 'owner/repo' names (one per line, blank line to finish):")

    while True:
        try:
            entry = input("> ").strip()
            if not entry:
                break # Finished entering

            if entry.lower() == 'all':
                print("Selecting all discovered repositories.")
                selected_repos.update(found_repos)
                # Keep prompting in case user wants to add more specific ones not found
                continue

            # Try parsing as space-separated numbers first
            try:
                indices = [int(x) - 1 for x in entry.split()]
                valid_selection = True
                for index in indices:
                    if 0 <= index < len(found_repos):
                        selected_repo = found_repos[index]
                        print(f"Selected: {selected_repo}")
                        selected_repos.add(selected_repo)
                    else:
                        print(f"Invalid number: {index + 1}. Please choose from 1 to {len(found_repos)}.")
                        valid_selection = False
                if valid_selection:
                     continue # Move to next input line if numbers were processed
            except ValueError:
                # Not numbers, treat as a single URL or owner/repo
                pass

            # Treat as a single URL or owner/repo name
            # Basic validation/formatting can happen here or later
            print(f"Adding: {entry}")
            selected_repos.add(entry)

        except EOFError: # Handle Ctrl+D
             break
        except KeyboardInterrupt:
             print("\nSelection interrupted.")
             return [] # Return empty list if interrupted

    return sorted(list(selected_repos))


def main():
    """Main function to discover, select, and scan repositories."""
    args = parse_arguments()
    repos_to_scan = []

    if args.repos:
        print(f"Scanning repositories provided via command line: {', '.join(args.repos)}")
        # Use the provided list directly, formatting happens in local_scanner
        repos_to_scan = args.repos
    else:
        # --- Discovery Phase ---
        try:
            found_repos = search_github_for_mcp_repos(args.max_repos)
        except Exception as e:
            print(f"\nError during GitHub repository discovery: {e}")
            print("Please check your network connection and GitHub token.")
            sys.exit(1)

        # --- Selection Phase ---
        if not found_repos:
             print("Could not find any potential repositories on GitHub.")
             sys.exit(0)

        repos_to_scan = select_repositories_to_scan(found_repos)


    # --- Scanning Phase ---
    if repos_to_scan:
        try:
            scan_repos_for_vulnerabilities(repos_to_scan)
        except Exception as e:
            print(f"\nAn error occurred during local scanning: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        print("\nNo repositories selected or provided for scanning.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Exiting.")
        sys.exit(0)
