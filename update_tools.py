#!/usr/bin/env python3
"""Script to update all SSH MCP tools to require hostname parameter."""

import re

def update_tools():
    """Update all tools to require hostname parameter."""
    
    # Read the server file
    with open('/opt/llm-rag-mcp/mcp-servers/ssh-mcp-server/src/ssh_mcp_server/server.py', 'r') as f:
        content = f.read()
    
    # Pattern to match function definitions with hostname: str = None
    pattern = r'def (\w+)\([^)]*hostname: str = None[^)]*\)'
    
    # Find all functions that need updating
    functions = re.findall(pattern, content)
    print(f"Found {len(functions)} functions to update: {functions}")
    
    # Update each function
    for func_name in functions:
        # Pattern for the specific function
        func_pattern = rf'(def {func_name}\([^)]*)hostname: str = None([^)]*\))'
        
        # Replace with required hostname
        replacement = r'\1hostname: str\2'
        content = re.sub(func_pattern, replacement, content)
        
        # Update the docstring to mark hostname as REQUIRED
        docstring_pattern = rf'(def {func_name}\([^)]*\)\s*"""[^"]*hostname: Server hostname or IP \(defaults to SSH_HOST env var\)[^"]*""")'
        docstring_replacement = r'\1'.replace('(defaults to SSH_HOST env var)', '(REQUIRED)')
        content = re.sub(docstring_pattern, docstring_replacement, content)
        
        print(f"Updated function: {func_name}")
    
    # Update all references to use hostname directly instead of creds
    # Pattern for creds usage
    creds_pattern = r'creds = get_credentials\(host\)\s*if not creds:\s*return f"❌ No credentials found for \{host\}[^"]*"\s*with SSHClient\(creds\.hostname, creds\.username, creds\.password, creds\.key_file, creds\.port\)'
    
    # Replace with direct usage
    creds_replacement = '''user = DEFAULT_USER
        pwd = DEFAULT_PASSWORD
        key = DEFAULT_KEY_FILE
        port = DEFAULT_PORT
        
        if not user or (not pwd and not key):
            return "❌ Missing credentials. Please set SSH_USER and SSH_PASSWORD/SSH_KEY_FILE environment variables."
        
        with SSHClient(hostname, user, pwd, key, port)'''
    
    content = re.sub(creds_pattern, creds_replacement, content, flags=re.DOTALL)
    
    # Update variable references from host to hostname
    content = re.sub(r'\bhost\b(?!name)', 'hostname', content)
    
    # Write back the updated content
    with open('/opt/llm-rag-mcp/mcp-servers/ssh-mcp-server/src/ssh_mcp_server/server.py', 'w') as f:
        f.write(content)
    
    print("All tools updated successfully!")

if __name__ == "__main__":
    update_tools()
