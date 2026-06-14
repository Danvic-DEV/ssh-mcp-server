# SSH MCP Server

A Model Context Protocol (MCP) server for managing Linux servers via SSH. This server provides tools for executing commands, managing files, monitoring services, and analyzing logs on remote Linux systems.

## Installation

### Docker (Recommended)

1. Build and run with Docker Compose:
```bash
docker compose up -d
```

No `.env` file is required. `SSH_HOST` and `SSH_USER` are defined in `docker-compose.yml` (with defaults), and `SSH_KEY_FILE` defaults to `/app/ssh_keys/id_ed25519`.

On first container start, the entrypoint checks for `/app/ssh_keys/id_ed25519`. If it does not exist, a new ed25519 key pair is generated automatically. The `/app/ssh_keys` folder is mounted as a Docker volume, so the key persists across restarts.

### Manual Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export SSH_HOST=your-server.example.com
export SSH_USER=root
export SSH_PASSWORD=your_password
# OR
export SSH_KEY_FILE=/path/to/private/key
```

3. Run the server:
```bash
python -m ssh_mcp_server.server
```
### AnythingLLM Integration

Add the following configuration to your `anythingllm_mcp_servers.json`:

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "name": "SSH MCP Server",
      "type": "streamable",
      "url": "http://ssh-mcp-server:8000/mcp",
      "auth_token": null,
      "enabled": true
    }
  }
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SSH_HOST` | Target server hostname or IP | `localhost` |
| `SSH_USER` | SSH username | `root` |
| `SSH_PASSWORD` | SSH password | - |
| `SSH_KEY_FILE` | Path to SSH private key | `/app/ssh_keys/id_ed25519` |
| `SSH_PORT` | SSH port | `22` |
| `AUTH_TOKEN` | Optional bearer token for MCP HTTP auth | - |
| `CLIENT_ID` | OAuth client ID for `/oauth/token` | - |
| `CLIENT_SECRET` | OAuth client secret for `/oauth/token` | - |
| `SERVER_HOST` | MCP server bind address | `0.0.0.0` |
| `SERVER_PORT` | MCP server port | `8000` |

### Authentication

The server supports two authentication methods:

1. **Password Authentication**: Set `SSH_PASSWORD` in your environment
2. **Key-based Authentication**: By default, Docker uses `/app/ssh_keys/id_ed25519` (auto-generated on first run). You can still override `SSH_KEY_FILE` if needed.

### MCP HTTP Authentication (Optional)

Set `AUTH_TOKEN` to require bearer authentication on all incoming MCP HTTP requests.

- Header required: `Authorization: Bearer <AUTH_TOKEN>`
- Missing or incorrect token: HTTP `401 Unauthorized`
- `AUTH_TOKEN` unset: authentication is disabled and requests are allowed through

### OAuth 2.0 Client Credentials

The server exposes `POST /oauth/token` for client credentials token exchange.

- Required env vars: `CLIENT_ID`, `CLIENT_SECRET`, and `AUTH_TOKEN`
- Request body (`application/json` or form-encoded):
  - `client_id`
  - `client_secret`
  - optional `grant_type=client_credentials`
- Success response: bearer token payload with `access_token` equal to `AUTH_TOKEN`
- Invalid credentials: HTTP `401` with `invalid_client`
- Missing server config (`CLIENT_ID`, `CLIENT_SECRET`, or `AUTH_TOKEN`): HTTP `503`

## Usage

### Basic Connection Test

```python
# Test SSH connection
test_ssh_connection(
    hostname="server.example.com",
    username="root",
    password="your_password"
)
```

### Execute Commands

```python
# Execute a simple command
execute_command("ls -la /var/log")

# Execute with sudo
execute_command("systemctl status nginx", use_sudo=True)
```

### File Operations

```python
# Read a file
read_file("/etc/nginx/nginx.conf")

# Write to a file
write_file("/tmp/test.txt", "Hello World!")

# List directory contents
list_directory("/var/log")
```

### Service Management

```python
# Check service status
get_service_status("nginx")

# Start a service
start_service("nginx")

# Stop a service
stop_service("nginx")

# Restart a service
restart_service("nginx")
```

### Process Management

```python
# List all processes
list_processes()

# List specific processes
list_processes(filter_by="nginx")

# Kill a process
kill_process("12345", signal="TERM")
```

### Network Tools

```python
# Check if port is open
check_port(80)

# Get network connections
get_network_connections()
```

### Log Analysis

```python
# Tail a log file
tail_log("/var/log/nginx/access.log", lines=100)

# Search in logs
search_log("/var/log/nginx/error.log", "error")
```

## Security Considerations

- Use SSH key-based authentication when possible
- Limit SSH access to specific users and IPs
- Regularly rotate SSH keys and passwords
- Monitor SSH access logs
- Use sudo judiciously and limit sudo privileges

## Troubleshooting

### Connection Issues

1. **Authentication Failed**: Check username, password, or key file
2. **Connection Refused**: Verify SSH service is running and port is correct
3. **Host Key Verification**: Ensure the server's host key is trusted

### Permission Issues

1. **File Access Denied**: Check file permissions and ownership
2. **Sudo Required**: Use `use_sudo=True` for privileged operations
3. **Service Management**: Ensure user has appropriate systemd permissions

### Performance Issues

1. **Slow Commands**: Increase timeout values for long-running commands
2. **Connection Timeouts**: Check network connectivity and server load
3. **Resource Usage**: Monitor server resources during operations

## API Reference

The server exposes the following MCP tools:

- `test_ssh_connection`: Test SSH connectivity
- `get_server_info`: Get system information
- `execute_command`: Execute commands
- `read_file`: Read file contents
- `write_file`: Write file contents
- `list_directory`: List directory contents
- `get_service_status`: Check service status
- `start_service`: Start a service
- `stop_service`: Stop a service
- `restart_service`: Restart a service
- `list_processes`: List running processes
- `kill_process`: Kill a process
- `check_port`: Check port status
- `get_network_connections`: Get network connections
- `tail_log`: Tail log files
- `search_log`: Search log files

## License

This project is licensed under the MIT License.
