#!/usr/bin/env python3
"""SSH MCP Server - Simplified version for testing."""

import base64
import hashlib
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

from mcp.server.fastmcp import FastMCP
from .ssh_client import SSHClient

# Load environment variables
load_dotenv()

# Initialize MCP server
mcp = FastMCP("SSH MCP Server")

# Default server configuration
DEFAULT_USER = os.environ.get('SSH_USER', 'root')
DEFAULT_PASSWORD = os.environ.get('SSH_PASSWORD')
DEFAULT_KEY_FILE = os.environ.get('SSH_KEY_FILE')
DEFAULT_PORT = int(os.environ.get('SSH_PORT', '22'))
AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')

# In-memory store for pending PKCE authorization codes: {code: {..., expires_at}}
_pending_codes: Dict[str, Dict[str, Any]] = {}


class BearerAuthMiddleware:
    """Optional bearer auth middleware for all incoming HTTP requests."""

    def __init__(self, app, auth_token: Optional[str]):
        self.app = app
        self.auth_token = auth_token

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not self.auth_token:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("latin1")
        expected = f"Bearer {self.auth_token}"

        if auth_header != expected:
            response = JSONResponse(
                {"detail": "Unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"}
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


def _purge_expired_codes() -> None:
    """Remove expired authorization codes from the in-memory store."""
    now = time.time()
    expired = [code for code, data in _pending_codes.items() if data["expires_at"] < now]
    for code in expired:
        _pending_codes.pop(code, None)


def _pkce_challenge(verifier: str) -> str:
    """Compute the S256 code challenge for a given code verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def authorize(request: Request):
    """OAuth 2.0 authorization endpoint (authorization code + PKCE)."""
    params = request.query_params

    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    state = params.get("state")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method", "S256")

    # Validate required parameters
    missing = [p for p in ("client_id", "redirect_uri", "state", "code_challenge") if not params.get(p)]
    if missing:
        return JSONResponse(
            {"error": "invalid_request", "error_description": f"Missing parameters: {', '.join(missing)}"},
            status_code=400
        )

    if code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Only code_challenge_method=S256 is supported"},
            status_code=400
        )

    if not CLIENT_ID or client_id != CLIENT_ID:
        return JSONResponse(
            {"error": "unauthorized_client"},
            status_code=401
        )

    # Generate a cryptographically secure authorization code
    code = secrets.token_urlsafe(32)
    _purge_expired_codes()
    _pending_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 60,
    }

    separator = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{separator}code={code}&state={state}"
    return RedirectResponse(url=location, status_code=302)


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 token endpoint — supports authorization_code (PKCE) and client_credentials."""
    if not AUTH_TOKEN:
        return JSONResponse({"error": "server_misconfigured"}, status_code=503)

    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = await request.json()
        else:
            form_data = await request.form()
            payload = dict(form_data)
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = payload.get("grant_type", "")
    no_cache_headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}

    # --- Authorization Code + PKCE grant ---
    if grant_type == "authorization_code":
        code = payload.get("code")
        code_verifier = payload.get("code_verifier")
        client_id = payload.get("client_id")
        redirect_uri = payload.get("redirect_uri")

        missing = [p for p in ("code", "code_verifier", "client_id", "redirect_uri") if not payload.get(p)]
        if missing:
            return JSONResponse(
                {"error": "invalid_request", "error_description": f"Missing: {', '.join(missing)}"},
                status_code=400
            )

        _purge_expired_codes()
        record = _pending_codes.get(code)

        if not record:
            return JSONResponse({"error": "invalid_grant", "error_description": "Unknown or expired code"}, status_code=400)

        if time.time() > record["expires_at"]:
            _pending_codes.pop(code, None)
            return JSONResponse({"error": "invalid_grant", "error_description": "Authorization code expired"}, status_code=400)

        if client_id != record["client_id"]:
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})

        if redirect_uri != record["redirect_uri"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

        if not secrets.compare_digest(_pkce_challenge(code_verifier), record["code_challenge"]):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

        # Code is single-use
        _pending_codes.pop(code, None)

        return JSONResponse(
            {"access_token": AUTH_TOKEN, "token_type": "Bearer"},
            headers=no_cache_headers
        )

    # --- Client credentials grant (retained for backward compatibility) ---
    if grant_type == "client_credentials" or grant_type == "":
        if not CLIENT_ID or not CLIENT_SECRET:
            return JSONResponse({"error": "server_misconfigured"}, status_code=503)

        client_id = payload.get("client_id")
        client_secret = payload.get("client_secret")

        id_ok = CLIENT_ID and secrets.compare_digest(client_id or "", CLIENT_ID)
        secret_ok = CLIENT_SECRET and secrets.compare_digest(client_secret or "", CLIENT_SECRET)
        if not id_ok or not secret_ok:
            return JSONResponse(
                {"error": "invalid_client"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"}
            )

        return JSONResponse(
            {"access_token": AUTH_TOKEN, "token_type": "Bearer"},
            headers=no_cache_headers
        )

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


def _handle_error(error: Exception, operation: str) -> str:
    """Handle and format errors."""
    error_msg = str(error)
    if "Authentication failed" in error_msg:
        return f"❌ Authentication failed for {operation}. Please check SSH credentials in environment variables."
    elif "Connection refused" in error_msg:
        return f"❌ Connection refused for {operation}. Server may be down or SSH not running."
    elif "No such file or directory" in error_msg:
        return f"❌ File or directory not found for {operation}."
    else:
        return f"❌ Error during {operation}: {error_msg}"


# Basic Connection Tools
@mcp.tool()
def test_ssh_connection(hostname: str, username: str = None, password: str = None, key_file: str = None, port: int = None) -> str:
    """Test SSH connection to a Linux server.
    
    Args:
        hostname: Server hostname or IP (REQUIRED)
        username: SSH username (defaults to SSH_USER env var)
        password: SSH password (defaults to SSH_PASSWORD env var)
        key_file: Path to SSH private key (defaults to SSH_KEY_FILE env var)
        port: SSH port (defaults to SSH_PORT env var)
    
    Returns:
        Connection status message
    """
    try:
        # Use provided values or fall back to environment/defaults
        user = username or DEFAULT_USER
        pwd = password or DEFAULT_PASSWORD
        key = key_file or DEFAULT_KEY_FILE
        ssh_port = port or DEFAULT_PORT
        
        if not user or (not pwd and not key):
            return "❌ Missing credentials. Please provide username and either password or key_file, or set SSH_USER and SSH_PASSWORD/SSH_KEY_FILE environment variables."
        
        with SSHClient(hostname, user, pwd, key, ssh_port).connection() as client:
            # Test basic command
            exit_code, stdout, stderr = client.execute_command("echo 'SSH connection successful'")
            if exit_code == 0:
                return f"✅ Successfully connected to {hostname} as {user}"
            else:
                return f"❌ Connection established but command failed: {stderr}"
                
    except Exception as e:
        return _handle_error(e, "SSH connection test")


@mcp.tool()
def get_server_info(hostname: str) -> str:
    """Get comprehensive system information from a Linux server.
    
    Args:
        hostname: Server hostname or IP (REQUIRED)
    
    Returns:
        Formatted system information
    """
    try:
        user = DEFAULT_USER
        pwd = DEFAULT_PASSWORD
        key = DEFAULT_KEY_FILE
        port = DEFAULT_PORT
        
        if not user or (not pwd and not key):
            return "❌ Missing credentials. Please set SSH_USER and SSH_PASSWORD/SSH_KEY_FILE environment variables."
        
        with SSHClient(hostname, user, pwd, key, port).connection() as client:
            info = client.get_system_info()
            
            result = f"🖥️  **System Information for {hostname}**\n\n"
            
            if 'uname' in info:
                result += f"**OS:** {info['uname']}\n\n"
            
            if 'uptime' in info:
                result += f"**Uptime:** {info['uptime']}\n\n"
            
            if 'cpu_info' in info:
                result += f"**CPU Information:**\n```\n{info['cpu_info']}\n```\n\n"
            
            if 'memory_info' in info:
                result += f"**Memory Information:**\n```\n{info['memory_info']}\n```\n\n"
            
            if 'disk_info' in info:
                result += f"**Disk Usage:**\n```\n{info['disk_info']}\n```\n\n"
            
            if 'network_info' in info:
                result += f"**Network Interfaces:**\n```\n{info['network_info']}\n```\n"
            
            if 'error' in info:
                result += f"⚠️  Some information could not be retrieved: {info['error']}"
            
            return result
            
    except Exception as e:
        return _handle_error(e, "getting server information")


@mcp.tool()
def execute_command(command: str, hostname: str, use_sudo: bool = False, sudo_password: str = None, confirm: bool = False) -> str:
    """Execute a command on a Linux server.
    
    Args:
        command: Command to execute
        hostname: Server hostname or IP (REQUIRED)
        use_sudo: Whether to execute with sudo privileges
        sudo_password: Sudo password (if different from SSH password)
        confirm: REQUIRED for destructive operations (file modification, deletion, service restart)
    
    Returns:
        Command output and exit status
    """
    # Check if command is potentially destructive
    destructive_patterns = [
        r'\b(rm|del|delete|remove|unlink)\b',  # File deletion
        r'\b(mv|move|rename)\b',  # File movement
        r'\b(cp|copy)\b.*\b(rm|del|delete)\b',  # Copy and delete
        r'\b(systemctl|service|init\.d)\s+(restart|reload|stop|start|enable|disable)',  # Service management
        r'\b(reboot|shutdown|halt|poweroff)\b',  # System restart
        r'\b(dd|mkfs|fdisk|parted)\b',  # Disk operations
        r'\b(>|>>)\s+',  # File redirection (overwrite)
        r'\b(sed|awk|grep)\s+.*\b(-i|--in-place)\b',  # In-place editing
        r'\b(find|locate)\s+.*\b(-delete|-exec\s+rm)\b',  # Find and delete
        r'\b(chmod|chown|chgrp)\b',  # Permission changes
        r'\b(umount|mount)\b',  # Mount operations
        r'\b(apt|yum|dnf|pacman|zypper)\s+(remove|purge|uninstall)',  # Package removal
        r'\b(pkill|killall|kill)\b',  # Process killing
        r'\b(truncate|>)\s+/dev/',  # Device operations
        r'\b(echo|printf)\s+.*\s+>\s+',  # File overwrite
        r'\b(tar|zip|gzip|bzip2)\s+.*\b(--remove-files|-d)\b',  # Archive with deletion
    ]
    
    is_destructive = any(re.search(pattern, command, re.IGNORECASE) for pattern in destructive_patterns)
    
    if is_destructive and not confirm:
        return f"⚠️  **DESTRUCTIVE OPERATION DETECTED**\n\n" \
               f"**Command:** `{command}`\n\n" \
               f"This command may modify files, delete data, restart services, or perform other destructive operations!\n\n" \
               f"**To proceed, call this function again with confirm=True**\n\n" \
               f"**Examples of destructive operations:**\n" \
               f"- File deletion: `rm`, `del`, `delete`\n" \
               f"- File modification: `>`, `>>`, `sed -i`\n" \
               f"- Service restart: `systemctl restart`, `service restart`\n" \
               f"- System operations: `reboot`, `shutdown`\n" \
               f"- Permission changes: `chmod`, `chown`\n" \
               f"- Package removal: `apt remove`, `yum remove`"
    
    try:
        user = DEFAULT_USER
        pwd = DEFAULT_PASSWORD
        key = DEFAULT_KEY_FILE
        port = DEFAULT_PORT
        
        if not user or (not pwd and not key):
            return "❌ Missing credentials. Please set SSH_USER and SSH_PASSWORD/SSH_KEY_FILE environment variables."
        
        with SSHClient(hostname, user, pwd, key, port).connection() as client:
            if use_sudo:
                exit_code, stdout, stderr = client.execute_sudo_command(command, sudo_password)
            else:
                exit_code, stdout, stderr = client.execute_command(command)
            
            result = f"🔧 **Command executed on {hostname}**\n\n"
            result += f"**Command:** `{command}`\n"
            result += f"**Exit Code:** {exit_code}\n"
            if is_destructive:
                result += f"**⚠️  DESTRUCTIVE OPERATION EXECUTED**\n"
            result += "\n"
            
            if stdout:
                result += f"**Output:**\n```\n{stdout}\n```\n"
            
            if stderr:
                result += f"**Error Output:**\n```\n{stderr}\n```\n"
            
            if exit_code == 0:
                result += "\n✅ Command completed successfully"
            else:
                result += f"\n❌ Command failed with exit code {exit_code}"
            
            return result
            
    except Exception as e:
        return _handle_error(e, f"executing command '{command}'")


def main():
    """Main function to run the SSH MCP server."""
    host = os.environ.get("SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("SERVER_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


# Export the Starlette/FastAPI app for testing and external use
protected_mcp_app = BearerAuthMiddleware(mcp.streamable_http_app(), AUTH_TOKEN)
app = Starlette(
    routes=[
        Route("/authorize", authorize, methods=["GET"]),
        Route("/oauth/token", oauth_token, methods=["POST"]),
        Mount("/", app=protected_mcp_app),
    ]
)


if __name__ == "__main__":
    main()
