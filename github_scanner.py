import requests
import time
import os
import sys
from typing import List, Dict, Any, Set
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get GitHub token from environment variable
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Headers for GitHub API
headers = {
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
    "Accept": "application/vnd.github.v3+json",
}

def search_github_code(query: str, max_results: int, language: str = "python") -> List[Dict[Any, Any]]:
    """
    Search GitHub for code matching the query with rate limit handling.
    Stops after finding max_results or exhausting search pages.
    """
    url = "https://api.github.com/search/code"
    params = {
        "q": f"{query} language:{language}",
        "per_page": 100, # Request max allowed per page
    }

    results = []
    page = 1
    retrieved_count = 0

    print(f"Searching GitHub for: '{query}'...")

    while True:
        # Check if we have enough results already
        if retrieved_count >= max_results:
            print(f"Reached max results limit ({max_results}). Stopping search for this query.")
            break

        params["page"] = page
        try:
            response = requests.get(url, headers=headers, params=params)
        except requests.exceptions.RequestException as e:
            print(f"Network error during GitHub search: {e}")
            break # Stop searching on network errors

        if response.status_code == 403 and "rate limit exceeded" in response.text.lower():
            try:
                # Get rate limit info
                rate_info = requests.get("https://api.github.com/rate_limit", headers=headers).json()
                reset_time = rate_info.get("resources", {}).get("search", {}).get("reset", 0)
                current_time = time.time()
                wait_time = max(reset_time - current_time, 0) + 5  # Add 5 seconds buffer

                if wait_time > 300:  # If wait time > 5 minutes
                    print(f"Rate limit exceeded. Need to wait {wait_time/60:.1f} minutes. Stopping search.")
                    break
                else:
                    print(f"Rate limit exceeded. Waiting {wait_time:.1f} seconds before retrying...")
                    time.sleep(wait_time)
                    continue  # Retry the same request
            except requests.exceptions.RequestException as e:
                print(f"Network error while checking rate limit: {e}")
                break # Stop searching on network errors
            except Exception as e:
                 print(f"Error processing rate limit info: {e}")
                 break # Stop if we can't process rate limit
        elif response.status_code != 200:
            print(f"GitHub API Error: {response.status_code} - {response.text}")
            # Don't retry on non-rate-limit errors for the same page
            break

        try:
            data = response.json()
            items = data.get("items", [])
            if not items: # No more items on this page or any subsequent page
                 print(f"No more results found for '{query}' on page {page}.")
                 break

            results.extend(items)
            retrieved_count += len(items)
            print(f"Found {len(items)} results on page {page} (Total: {retrieved_count}/{max_results})")

            # Check if we've reached the last page according to GitHub's response
            if 'next' not in response.links:
                print("Reached the last page of results for this query.")
                break

            page += 1
            # Be respectful of the API rate limits
            time.sleep(2) # Short delay between pages

        except ValueError as e: # Catch JSON decoding errors
            print(f"Error decoding JSON response: {e}")
            break # Stop if response is not valid JSON
        except Exception as e:
            print(f"An unexpected error occurred during result processing: {e}")
            break # Stop on other unexpected errors

    return results


def search_github_for_mcp_repos(max_results: int) -> List[str]:
    """
    Search GitHub for potential MCP repositories using multiple queries.
    Returns a list of unique repository names ('owner/repo').
    """
    # Check for GitHub token early
    if not GITHUB_TOKEN or GITHUB_TOKEN == "YOUR_GITHUB_TOKEN_HERE":
        print("Warning: No valid GitHub token found in environment variables.")
        print("You may hit rate limits quickly. Consider adding a token to your .env file.")
        print("See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token")
        # Don't exit here, let the search proceed but warn the user

    print(f"\nSearching GitHub for potential MCP repositories (max {max_results} total)...")
    mcp_search_queries = [
        '"ModelContextProtocol"', # More specific
        '"MCP server"',
        '"mcp_server"',
        '"model context protocol"',
        '"MCP handler"'
    ]

    found_repos: Set[str] = set()
    total_found_count = 0

    for query in mcp_search_queries:
        if total_found_count >= max_results:
            print("Reached overall max results limit. Stopping further searches.")
            break

        # Calculate remaining results needed for this query
        remaining_results_needed = max_results - total_found_count
        if remaining_results_needed <= 0: break # Should not happen due to outer check, but safe

        results = search_github_code(query, remaining_results_needed)
        newly_found_in_query = 0
        for result in results:
            try:
                repo_name = result["repository"]["full_name"]
                if repo_name not in found_repos:
                    found_repos.add(repo_name)
                    total_found_count += 1
                    newly_found_in_query += 1
                    if total_found_count >= max_results:
                        break # Stop processing results if max hit
            except KeyError:
                print(f"Warning: Skipping result with missing repository information: {result.get('html_url', 'N/A')}")
            except Exception as e:
                print(f"Warning: Error processing search result {result.get('html_url', 'N/A')}: {e}")

        print(f"Found {newly_found_in_query} new unique repositories from query '{query}'. Total unique: {total_found_count}")
        # Add a delay between different search queries
        if total_found_count < max_results:
             time.sleep(5)

    print(f"\nFinished GitHub search. Found {total_found_count} unique potential MCP repositories.")
    return sorted(list(found_repos))
