#!/usr/bin/env python3
"""mcp-ssh-gateway server."""

import base64
from contextlib import asynccontextmanager
import hashlib
import json
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

from mcp.server.fastmcp import FastMCP
from .ssh_client import SSHClient

# Load environment variables
load_dotenv()

# Initialize MCP server
mcp = FastMCP("mcp-ssh-gateway")

# Default server configuration
DEFAULT_USER = os.environ.get('SSH_USER', 'root')
DEFAULT_PASSWORD = os.environ.get('SSH_PASSWORD')
DEFAULT_KEY_FILE = os.environ.get('SSH_KEY_FILE')
DEFAULT_PORT = int(os.environ.get('SSH_PORT', '22'))
AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
SERVER_URL = os.environ.get('SERVER_URL')
DEFAULT_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
REGISTERED_CLIENTS_FILE = "/app/ssh_keys/registered_clients.json"

# In-memory store for pending PKCE authorization codes: {code: {..., expires_at}}
_pending_codes: Dict[str, Dict[str, Any]] = {}

# In-memory store for RFC 7591 dynamic client registrations.
_registered_clients: Dict[str, Dict[str, Any]] = {}


def _is_protected_transport_path(path: str) -> bool:
    """Return True if request path targets protected MCP transports."""
    return path == "/mcp" or path.startswith("/mcp/") or path == "/sse" or path.startswith("/sse/")


def _is_public_oauth_path(path: str) -> bool:
    """Return True for OAuth and well-known endpoints that must stay public."""
    normalized = path.rstrip("/") or "/"
    return normalized in {
        "/authorize",
        "/oauth/token",
        "/register",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/sse",
        "/.well-known/oauth-protected-resource/mcp",
    }


def _issued_access_token() -> str:
    """Return the access token issued by /oauth/token."""
    return AUTH_TOKEN or ""


def _is_valid_bearer_header(auth_header: str) -> bool:
    """Validate Authorization header against the issued access token."""
    issued_token = _issued_access_token()
    if not issued_token:
        return False

    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2:
        return False

    scheme, token = parts
    if scheme.lower() != "bearer":
        return False

    return secrets.compare_digest(token, issued_token)


def _resolve_base_url(request: Request) -> str:
    """Resolve server base URL from SERVER_URL or request host with https scheme."""
    if SERVER_URL:
        return SERVER_URL.rstrip("/")

    host = request.headers.get("host")
    if host:
        return f"https://{host}".rstrip("/")

    return str(request.base_url).rstrip("/")


def _load_registered_clients() -> Dict[str, Dict[str, Any]]:
    """Load registered OAuth clients from disk if available."""
    if not os.path.exists(REGISTERED_CLIENTS_FILE):
        return {}

    try:
        with open(REGISTERED_CLIENTS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, dict):
            return data
    except Exception:
        # Fall back to empty registration set if file is unreadable/corrupt.
        pass

    return {}


def _save_registered_clients() -> None:
    """Persist registered OAuth clients to disk."""
    os.makedirs(os.path.dirname(REGISTERED_CLIENTS_FILE), exist_ok=True)
    temp_path = f"{REGISTERED_CLIENTS_FILE}.tmp"

    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(_registered_clients, file, ensure_ascii=True, indent=2, sort_keys=True)

    os.replace(temp_path, REGISTERED_CLIENTS_FILE)


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


def _get_client(client_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a client record from dynamic registrations or static env config."""
    if client_id in _registered_clients:
        return _registered_clients[client_id]

    if CLIENT_ID and client_id == CLIENT_ID:
        return {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uris": [DEFAULT_REDIRECT_URI],
            "client_name": "static-env-client",
            "client_id_issued_at": 0,
            "client_secret_expires_at": 0,
        }

    return None


def _validate_client_secret(client_id: str, client_secret: str) -> bool:
    """Validate client credentials against registered or static clients."""
    client = _get_client(client_id)
    if not client:
        return False

    expected_secret = client.get("client_secret")
    if not expected_secret:
        return False

    return secrets.compare_digest(client_secret or "", expected_secret)


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

    client = _get_client(client_id or "")
    if not client:
        return JSONResponse(
            {"error": "unauthorized_client"},
            status_code=401
        )

    if redirect_uri not in client.get("redirect_uris", []):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri not registered for client"},
            status_code=400,
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
        if not CLIENT_ID and not _registered_clients:
            return JSONResponse({"error": "server_misconfigured"}, status_code=503)

        client_id = payload.get("client_id")
        client_secret = payload.get("client_secret")

        if not _validate_client_secret(client_id or "", client_secret or ""):
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


async def register_client(request: Request) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration endpoint."""
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            payload = await request.json()
        else:
            form_data = await request.form()
            payload = dict(form_data)
    except Exception:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "Invalid registration payload"},
            status_code=400,
        )

    redirect_uris = payload.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(uri, str) for uri in redirect_uris):
        return JSONResponse(
            {"error": "invalid_redirect_uri", "error_description": "redirect_uris must be a non-empty array of strings"},
            status_code=400,
        )

    client_id = f"client_{secrets.token_urlsafe(24)}"
    client_secret = secrets.token_urlsafe(32)
    issued_at = int(time.time())

    client_record = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,
        "redirect_uris": redirect_uris,
        "client_name": payload.get("client_name"),
        "token_endpoint_auth_method": payload.get("token_endpoint_auth_method", "client_secret_post"),
        "grant_types": payload.get("grant_types", ["authorization_code"]),
        "response_types": payload.get("response_types", ["code"]),
    }

    _registered_clients[client_id] = client_record
    _save_registered_clients()

    return JSONResponse(client_record, status_code=201)


async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
    """Return OAuth 2.0 Authorization Server Metadata."""
    base_url = _resolve_base_url(request)
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }
    return JSONResponse(metadata)


async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
    """Return OAuth 2.0 Protected Resource Metadata (RFC 9728)."""
    base_url = _resolve_base_url(request)
    metadata = {
        "resource": base_url,
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
    }
    return JSONResponse(metadata)


async def oauth_transport_protected_resource_metadata(request: Request) -> JSONResponse:
    """Return RFC 9728 protected resource metadata for a transport-specific path."""
    base_url = _resolve_base_url(request)
    transport = request.path_params.get("transport")

    if not transport:
        normalized_path = request.url.path.rstrip("/")
        transport = normalized_path.rsplit("/", 1)[-1]

    metadata = {
        "resource": f"{base_url}/{transport}",
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
    }
    return JSONResponse(metadata)


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
                # Avoid double-sudo when clients send "sudo ..." with use_sudo=True.
                normalized_command = re.sub(r"^\s*sudo\s+", "", command, flags=re.IGNORECASE)
                exit_code, stdout, stderr = client.execute_sudo_command(normalized_command, sudo_password)
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
    """Main function to run mcp-ssh-gateway."""
    host = os.environ.get("SERVER_HOST", "0.0.0.0")
    port = int(os.environ.get("SERVER_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


@asynccontextmanager
async def lifespan(_app: Starlette):
    """Ensure FastMCP session manager is initialised for mounted transports."""
    global _registered_clients
    _registered_clients = _load_registered_clients()
    async with mcp.session_manager.run():
        yield


# Mount both transports explicitly at required paths.
mcp.settings.streamable_http_path = "/"
mcp.settings.sse_path = "/"


class _NormalizeEmptyPath:
    """ASGI wrapper: converts empty path '' to '/' after Mount prefix-stripping.

    Starlette's Mount strips the mount prefix, leaving '' when the client
    requests the bare mount path (e.g. GET /sse).  Most ASGI apps expect
    at least a '/', so this wrapper normalises the empty string before
    forwarding the scope to the inner app.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("path", "") == "":
            scope = {**scope, "path": "/"}
        await self.app(scope, receive, send)


app = Starlette(
    routes=[
        Route("/.well-known/oauth-authorization-server", oauth_authorization_server_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/sse", oauth_transport_protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", oauth_transport_protected_resource_metadata, methods=["GET"]),
        Route("/register", register_client, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/oauth/token", oauth_token, methods=["POST"]),
        Mount("/mcp", app=_NormalizeEmptyPath(mcp.streamable_http_app())),
        Mount("/sse", app=_NormalizeEmptyPath(mcp.sse_app())),
    ],
    lifespan=lifespan,
)
# Prevent 307 redirects that cause clients to drop Authorization headers.
app.router.redirect_slashes = False


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Protect /mcp and /sse with bearer auth when AUTH_TOKEN is configured."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Keep OAuth and discovery endpoints fully public.
        if _is_public_oauth_path(path):
            return await call_next(request)

        if AUTH_TOKEN and _is_protected_transport_path(path):
            auth_header = request.headers.get("authorization", "")
            if not _is_valid_bearer_header(auth_header):
                return JSONResponse(
                    {"detail": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return await call_next(request)


app.add_middleware(BearerAuthMiddleware)


if __name__ == "__main__":
    main()
