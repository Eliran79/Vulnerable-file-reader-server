from mcp.server.fastmcp import FastMCP
import os
import subprocess

# Define the "safe" directory where files should be
SAFE_DIRECTORY = "/tmp/safe"

# Create an MCP server with a custom name
mcp = FastMCP("File Reader")

@mcp.tool()
def read_file(file_name: str) -> str:
    """
    Read the file from the operating system
    
    This implementation is vulnerable to command injection as it doesn't
    properly sanitize the file_name parameter before using it in a shell command.
    """
    try:
        # VULNERABLE: No proper path validation
        # Just a superficial check that the path contains the safe directory name
        if SAFE_DIRECTORY not in file_name:
            return f"Error: Can only read files from {SAFE_DIRECTORY}"
        
        # EXTREMELY VULNERABLE: Directly executing the file_name as part of a shell command
        # This allows for command injection using shell metacharacters like ;, |, &&, etc.
        command = f"cat {file_name}"
        print(f"Executing command: {command}")
        
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        # Return both stdout and stderr to help with debugging
        return f"Error: {e}. Output: {e.output.decode('utf-8') if e.output else 'No output'}"
    except Exception as e:
        # Return error message
        return f"Error: {str(e)}"

@mcp.resource("file_name://{file_name}")
def file_resource(file_name: str) -> str:
    """
    Expose file data as a resource.
    Returns a string with the current file content for the given filename.
    """
    file_content = read_file(file_name)
    
    # Check if the result starts with "Error"
    if file_content.startswith("Error"):
        return file_content
    
    return f"Content of file '{file_name}':\n{file_content}"

if __name__ == "__main__":
    # Create the safe directory if it doesn't exist
    os.makedirs(SAFE_DIRECTORY, exist_ok=True)
    
    # Create a test file in the safe directory
    test_file_path = os.path.join(SAFE_DIRECTORY, "test.txt")
    with open(test_file_path, 'w') as f:
        f.write("This is a test file in the safe directory.")
    
    print(f"MCP Server starting. Safe directory is {SAFE_DIRECTORY}")
    print("WARNING: This server contains deliberate security vulnerabilities!")
    print("Example exploitation: try '/tmp/safe/test.txt; whoami' to execute commands")
    
    # Run the MCP server
    mcp.run()