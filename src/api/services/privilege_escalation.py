"""
Privilege Escalation Service for Network Monitoring
Allows web-based elevation without restarting uvicorn
"""

import os
import sys
import json
import subprocess
import tempfile
import hashlib
import time
from pathlib import Path
from typing import Dict, Optional
import shlex

class PrivilegeManager:
    """Manage privilege elevation for network operations"""
    
    def __init__(self):
        self.privileged_pid = None
        self.privileged_process = None
        self.credential_file = None
        
    def check_privileges(self) -> Dict:
        """Check current privilege level"""
        is_root = os.geteuid() == 0
        is_admin = self._check_admin_group()
        
        return {
            "has_root": is_root,
            "has_admin": is_admin,
            "username": os.getenv("USER", "unknown"),
            "uid": os.geteuid(),
            "gid": os.getegid()
        }
    
    def _check_admin_group(self) -> bool:
        """Check if user is in admin/sudo group"""
        try:
            import grp
            admin_groups = ["sudo", "admin", "wheel", "root"]
            user_groups = [g.gr_name for g in grp.getgrall() 
                          if os.getlogin() in g.gr_mem]
            return any(group in admin_groups for group in user_groups)
        except:
            return False
    
    def start_privileged_service(self, password: Optional[str] = None) -> Dict:
        """
        Start network monitor with elevated privileges
        Returns a token for communication
        """
        # Create a temporary credential file
        token = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        
        # Create a temporary directory for IPC
        temp_dir = tempfile.mkdtemp(prefix="chronos_priv_")
        
        # Create a command to run with sudo
        monitor_script = """
#!/usr/bin/env python3
import socket
import json
import time
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.NTA.network_monitoring import NetworkMonitor

def main():
    # Create monitor instance
    monitor = NetworkMonitor(interface="lo", packet_limit=1000)
    
    # Start monitoring
    if monitor.start_monitoring():
        print(json.dumps({"status": "success", "pid": os.getpid()}))
        sys.stdout.flush()
        
        # Keep running
        try:
            while True:
                stats = monitor.get_statistics()
                print(json.dumps(stats))
                sys.stdout.flush()
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop_monitoring()
    else:
        print(json.dumps({"status": "failed", "error": "Failed to start monitor"}))
        sys.stdout.flush()

if __name__ == "__main__":
    main()
"""
        
        # Save the script
        script_path = os.path.join(temp_dir, "privileged_monitor.py")
        with open(script_path, "w") as f:
            f.write(monitor_script)
        
        # Make it executable
        os.chmod(script_path, 0o755)
        
        try:
            # Start the privileged process
            # Using pkexec for GUI prompt or sudo with password
            if password:
                # Use sudo with password (requires -S flag)
                cmd = f"echo {shlex.quote(password)} | sudo -S python3 {script_path}"
                self.privileged_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True
                )
            else:
                # Try pkexec for GUI prompt
                cmd = ["pkexec", "python3", script_path]
                self.privileged_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            # Read initial response
            line = self.privileged_process.stdout.readline()
            try:
                response = json.loads(line)
                if response.get("status") == "success":
                    self.privileged_pid = response.get("pid")
                    return {
                        "success": True,
                        "token": token,
                        "pid": self.privileged_pid,
                        "message": "Privileged service started"
                    }
            except:
                pass
            
            return {
                "success": False,
                "error": "Failed to start privileged service"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def stop_privileged_service(self) -> Dict:
        """Stop the privileged service"""
        if self.privileged_process:
            self.privileged_process.terminate()
            self.privileged_process.wait()
            self.privileged_process = None
            self.privileged_pid = None
            return {"success": True, "message": "Service stopped"}
        return {"success": False, "error": "No service running"}

# Global instance
privilege_manager = PrivilegeManager()
