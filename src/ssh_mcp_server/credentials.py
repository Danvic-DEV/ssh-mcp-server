"""Credential management for SSH MCP server - Docker/Environment version."""

import os
from typing import Optional, NamedTuple


class SSHCredentials(NamedTuple):
    """Model for SSH server credentials."""
    hostname: str
    username: str
    password: str = None
    key_file: str = None
    port: int = 22


def get_ssh_credentials(hostname: str) -> Optional[SSHCredentials]:
    """
    Retrieve SSH credentials from environment variables.
    
    Args:
        hostname: Server hostname (used as fallback if not in env)
        
    Returns:
        SSHCredentials object or None if not found
    """
    # Read environment variables defined in the .env file
    host = os.environ.get('SSH_HOST', hostname)
    user = os.environ.get('SSH_USER')
    password = os.environ.get('SSH_PASSWORD')
    key_file = os.environ.get('SSH_KEY_FILE')
    port = int(os.environ.get('SSH_PORT', '22'))
    
    if host and user and (password or key_file):
        return SSHCredentials(
            hostname=host,
            username=user,
            password=password,
            key_file=key_file,
            port=port
        )
    return None


def get_credentials(hostname: str) -> Optional[SSHCredentials]:
    """
    Retrieve SSH credentials.
    Try to get credentials from environment variables first.
    Fallback: return None (for non-Docker environments)
    
    Args:
        hostname: Server hostname
        
    Returns:
        SSHCredentials object or None
    """
    return get_ssh_credentials(hostname)
