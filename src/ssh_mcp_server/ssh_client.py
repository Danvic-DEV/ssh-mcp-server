"""SSH client for Linux server management."""

import paramiko
import os
from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager


class SSHClient:
    """SSH client for connecting to Linux servers."""
    
    def __init__(self, hostname: str, username: str, password: str = None, 
                 key_file: str = None, port: int = 22, timeout: int = 30):
        """Initialize SSH client.
        
        Args:
            hostname: Server hostname or IP
            username: SSH username
            password: SSH password (if not using key)
            key_file: Path to SSH private key file
            port: SSH port (default 22)
            timeout: Connection timeout in seconds
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self.client = None
        self.sftp = None
    
    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try key-based authentication first
            if self.key_file and os.path.exists(self.key_file):
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file,
                    timeout=self.timeout
                )
            elif self.password:
                self.client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout
                )
            else:
                raise ValueError("Either password or key_file must be provided")
            
            # Initialize SFTP for file operations
            self.sftp = self.client.open_sftp()
            return True
            
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.hostname}: {str(e)}")
    
    def disconnect(self):
        """Close SSH connection."""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()
    
    @contextmanager
    def connection(self):
        """Context manager for SSH connection."""
        try:
            self.connect()
            yield self
        finally:
            self.disconnect()
    
    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute a command on the remote server.
        
        Args:
            command: Command to execute
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self.client:
            raise ConnectionError("Not connected to server")
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
            
            # Wait for command to complete
            exit_code = stdout.channel.recv_exit_status()
            
            # Read output
            stdout_text = stdout.read().decode('utf-8')
            stderr_text = stderr.read().decode('utf-8')
            
            return exit_code, stdout_text, stderr_text
            
        except Exception as e:
            raise RuntimeError(f"Command execution failed: {str(e)}")
    
    def execute_sudo_command(self, command: str, password: str = None) -> Tuple[int, str, str]:
        """Execute a command with sudo privileges.
        
        Args:
            command: Command to execute with sudo
            password: Sudo password (if not provided, uses connection password)
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        sudo_password = password or self.password
        if not sudo_password:
            raise ValueError("Sudo password required")
        
        sudo_command = f"echo '{sudo_password}' | sudo -S {command}"
        return self.execute_command(sudo_command)
    
    def get_file_content(self, remote_path: str) -> str:
        """Read content of a remote file.
        
        Args:
            remote_path: Path to remote file
            
        Returns:
            File content as string
        """
        if not self.sftp:
            raise ConnectionError("SFTP not available")
        
        try:
            with self.sftp.open(remote_path, 'r') as f:
                return f.read().decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"Failed to read file {remote_path}: {str(e)}")
    
    def put_file_content(self, local_content: str, remote_path: str) -> bool:
        """Write content to a remote file.
        
        Args:
            local_content: Content to write
            remote_path: Path to remote file
            
        Returns:
            True if successful
        """
        if not self.sftp:
            raise ConnectionError("SFTP not available")
        
        try:
            with self.sftp.open(remote_path, 'w') as f:
                f.write(local_content.encode('utf-8'))
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to write file {remote_path}: {str(e)}")
    
    def list_directory(self, remote_path: str = ".") -> List[Dict[str, Any]]:
        """List contents of a remote directory.
        
        Args:
            remote_path: Path to remote directory
            
        Returns:
            List of file/directory info dictionaries
        """
        if not self.sftp:
            raise ConnectionError("SFTP not available")
        
        try:
            files = []
            for item in self.sftp.listdir_attr(remote_path):
                files.append({
                    'name': item.filename,
                    'size': item.st_size,
                    'permissions': oct(item.st_mode)[-3:],
                    'is_directory': item.st_mode & 0o040000 != 0,
                    'modified': item.st_mtime
                })
            return files
        except Exception as e:
            raise RuntimeError(f"Failed to list directory {remote_path}: {str(e)}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information.
        
        Returns:
            Dictionary with system information
        """
        info = {}
        
        try:
            # OS info
            exit_code, stdout, stderr = self.execute_command("uname -a")
            if exit_code == 0:
                info['uname'] = stdout.strip()
            
            # CPU info
            exit_code, stdout, stderr = self.execute_command("lscpu")
            if exit_code == 0:
                info['cpu_info'] = stdout.strip()
            
            # Memory info
            exit_code, stdout, stderr = self.execute_command("free -h")
            if exit_code == 0:
                info['memory_info'] = stdout.strip()
            
            # Disk info
            exit_code, stdout, stderr = self.execute_command("df -h")
            if exit_code == 0:
                info['disk_info'] = stdout.strip()
            
            # Load average
            exit_code, stdout, stderr = self.execute_command("uptime")
            if exit_code == 0:
                info['uptime'] = stdout.strip()
            
            # Network interfaces
            exit_code, stdout, stderr = self.execute_command("ip addr show")
            if exit_code == 0:
                info['network_info'] = stdout.strip()
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
