# MCP-ShellGuard: Command Injection Vulnerability Scanner for Model Context Protocol Servers

A specialized security tool to discover and scan for potential command injection vulnerabilities in MCP (Model Context Protocol) server implementations.

## ⚠️ Disclaimer ⚠️

This tool is provided for **educational and demonstration purposes only**. It was developed as a learning exercise and **not by a security specialist**.

The detection mechanism relies on **simple pattern matching (regular expressions)** and is **not exhaustive**. It may produce **false positives** (flagging safe code) or **false negatives** (missing complex vulnerabilities).

**Always manually verify any findings.** Do not rely solely on this tool for security assessments.

## Description

This scanner first uses the GitHub API to discover public repositories that might contain MCP server implementations based on common keywords. It then interactively prompts the user to select which of the discovered repositories (or provide others) should be scanned. The selected repositories are cloned locally into a temporary directory, and their Python files are scanned for code patterns associated with command injection vulnerabilities (e.g., using `subprocess` with `shell=True` and dynamically constructed commands).

## Features

- **GitHub Discovery:** Uses the GitHub Code Search API to find potential MCP repositories.
- **Interactive Selection:** Allows users to choose which discovered repositories to scan, or provide their own list.
- **Local Analysis:** Clones selected repositories locally for scanning.
- **Pattern-Based Detection:** Uses regular expressions to identify:
    - Potential MCP server files.
    - Code patterns indicative of command injection risks (`subprocess` with `shell=True`, `os.system`, dynamic command strings).
- **Reporting:** Summarizes findings, listing potentially vulnerable files and code lines.

## Requirements

- Python 3.8+
- Git (for local scanning)
- Required Python packages:
  - requests
  - python-dotenv (for GitHub API scanning)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/Vulnerable-file-reader-server.git
cd Vulnerable-file-reader-server
```

2. Install dependencies:
```bash
pip install requests python-dotenv
```

3. Create a `.env` file with your GitHub token (required for repository discovery):
```
GITHUB_TOKEN=your_github_token_here
```

## Usage

### Basic Usage

Run the scanner with default settings:

```bash
python main_scanner.py
```

This will:
1. Use the GitHub API to discover potential MCP repositories
2. Present the findings for interactive selection
3. Clone and scan the selected repositories for vulnerabilities

### Direct Repository Scanning

To bypass discovery and scan specific repositories directly:

```bash
# Using full URLs
python main_scanner.py --repos https://github.com/owner1/repo1 https://github.com/owner2/repo2

# Or using owner/repo format
python main_scanner.py --repos owner1/repo1 owner2/repo2
```

### Discovery Options

Control the maximum number of repositories to discover (default: 20):

```bash
python main_scanner.py --max-repos 30
```

Note: The `--verbose` flag is currently reserved for future use.

## File Structure

- `main_scanner.py`: Main entry point, handles repository discovery, selection, and orchestration
- `scanner_base.py`: Core scanning logic and vulnerability detection patterns
- `github_scanner.py`: GitHub API repository discovery implementation
- `local_scanner.py`: Local repository cloning and scanning implementation

## How It Works

1. **Repository Discovery** (via GitHub API):
   - Uses the GitHub Code Search API to find repositories containing MCP-related keywords
   - Searches for terms like "ModelContextProtocol", "MCP server", "mcp_server"
   - Respects rate limits and handles API pagination

2. **Interactive Selection**:
   - Displays discovered repositories with numbered options
   - Users can select repositories by:
     - Entering numbers (e.g., "1 3 5")
     - Typing "all" to select everything
     - Providing full URLs or owner/repo names
     - Entering multiple selections one per line

3. **Local Analysis**:
   - Creates a temporary directory for cloning
   - Clones selected repositories using git
   - Scans Python files for:
     - MCP server patterns (imports, class definitions)
     - Command injection vulnerabilities
   - Cleans up temporary files after scanning

4. **Pattern-Based Detection**:
   - Uses regular expressions to identify risky patterns
   - **Simple but Limited Approach:**
     - Looks for `subprocess` calls with `shell=True`
     - Identifies dynamic command string construction
     - Checks for `os.system` and `os.popen` usage
     - Detects string formatting in command strings
   - **Limitations:**
     - May miss complex vulnerabilities
     - Could flag safe code as risky
     - Does not analyze data flow
     - Cannot detect all injection vectors

5. **Results Reporting**:
   - Groups findings by repository
   - Distinguishes between MCP and non-MCP files
   - Shows file paths and line numbers
   - Displays the actual code snippets flagged

## Example Output

```
=== VULNERABLE MCP SERVER REPOSITORIES ===

Repository: owner/mcp-server-example
URL: https://github.com/owner/mcp-server-example
Vulnerable Files: 2
MCP Server Files with Vulnerabilities: 1

  - File: src/server/handler.py
    MCP Server File: Yes
    Definite Vulnerabilities:
      Line 156: command = f"cat {file_path}"
      Line 157: result = subprocess.check_output(command, shell=True)
    Potential Issues:
      Line 203: cmd = f"python {script_path} --input={user_data}"

  - File: tests/test_commands.py
    MCP Server File: No
    Potential Issues:
      Line 45: test_cmd = f"echo {test_input} | grep pattern"

Repository: another-owner/mcp-impl
URL: https://github.com/another-owner/mcp-impl
Vulnerable Files: 1
MCP Server Files with Vulnerabilities: 1

  - File: mcp_server.py
    MCP Server File: Yes
    Definite Vulnerabilities:
      Line 89: os.system(f"chmod +x {script_name}")
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
