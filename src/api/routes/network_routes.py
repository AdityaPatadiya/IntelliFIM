"""
Network Monitoring API Routes
Integrated with existing Chronos AI Guard API structure
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import threading
import time
from datetime import datetime
import platform

# Import existing dependencies from your project
from src.api.utils.jwt_utils import verify_token
from src.api.models.user_model import User
from src.api.database.connection import get_auth_db

router = APIRouter(prefix="/api/network", tags=["network-monitoring"])

# Global monitor instance
network_monitor = None
monitor_lock = threading.Lock()

class MonitorConfig(BaseModel):
    """Configuration for network monitoring"""
    interface: str = "eth0"
    packet_limit: int = 1000

class MonitorStatus(BaseModel):
    """Network monitor status response"""
    is_monitoring: bool
    interface: str
    total_packets: int
    total_bytes: int
    bandwidth_mbps: float
    packet_types: Dict[str, int]
    alerts_count: int
    uptime_seconds: float
    start_time: Optional[str]

def verify_admin_access(
    token_data: dict = Depends(verify_token), 
    db: Session = Depends(get_auth_db)
) -> User:
    """Verify that the current user is an admin - same as in fim_routes.py"""
    admin = db.query(User).filter(User.email == token_data["sub"]).first()
    if not admin or not getattr(admin, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return admin

def verify_user_access(
    token_data: dict = Depends(verify_token), 
    db: Session = Depends(get_auth_db)
) -> User:
    """Verify that the current user is authenticated"""
    user = db.query(User).filter(User.email == token_data["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/start", response_model=Dict[str, Any])
async def start_monitoring(
    config: MonitorConfig,
    background_tasks: BackgroundTasks,
    admin_user: User = Depends(verify_admin_access)  # Changed from get_current_user
):
    """
    Start network traffic monitoring
    
    Requires admin authentication (same as your FIM endpoints)
    """
    global network_monitor
    
    with monitor_lock:
        if network_monitor and network_monitor.is_monitoring:
            raise HTTPException(
                status_code=400, 
                detail="Network monitoring already in progress"
            )
        
        # Import here to avoid circular imports
        try:
            from src.NTA.network_monitoring import NetworkMonitor
        except ImportError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Cannot import NetworkMonitor: {str(e)}"
            )
        
        try:
            network_monitor = NetworkMonitor(
                interface=config.interface,
                packet_limit=config.packet_limit
            )
            
            # Start monitoring in background thread
            def start_monitor():
                network_monitor.start_monitoring()
            
            # Use a daemon thread similar to your FIM implementation
            monitor_thread = threading.Thread(target=start_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Wait a moment to ensure monitor started
            time.sleep(0.5)
            
            return {
                "message": "Network monitoring started",
                "interface": config.interface,
                "packet_limit": config.packet_limit,
                "status": "running" if network_monitor.is_monitoring else "failed",
                "admin_user": admin_user.username
            }
            
        except PermissionError:
            system = platform.system()
            
            if system == "Linux":
                detail = (
                    "Permission denied. Network monitoring requires root privileges.\n\n"
                    "Options:\n"
                    "1. Run backend with: sudo python main.py\n"
                    "2. Grant capabilities: sudo setcap cap_net_raw+eip /usr/bin/python3\n"
                    "3. Install tcpdump: sudo apt install tcpdump"
                )
            elif system == "Windows":
                detail = (
                    "Permission denied. Network monitoring requires Administrator privileges.\n\n"
                    "Options:\n"
                    "1. Run backend as Administrator\n"
                    "2. Install Npcap from https://npcap.com/"
                )
            else:  # MacOS
                detail = (
                    "Permission denied. Network monitoring requires root privileges.\n\n"
                    "Run backend with: sudo python main.py"
                )
            
            raise HTTPException(
                status_code=403,
                detail=detail
            )

@router.post("/stop", response_model=Dict[str, str])
async def stop_monitoring(
    admin_user: User = Depends(verify_admin_access)  # Changed from get_current_user
):
    """
    Stop network traffic monitoring
    """
    global network_monitor
    
    with monitor_lock:
        if not network_monitor:
            raise HTTPException(
                status_code=400, 
                detail="Network monitor not initialized"
            )
        
        if not network_monitor.is_monitoring:
            raise HTTPException(
                status_code=400, 
                detail="Network monitoring is not running"
            )
        
        network_monitor.stop_monitoring()
        return {
            "message": "Network monitoring stopped",
            "admin_user": admin_user.username
        }

@router.get("/status", response_model=MonitorStatus)
async def get_monitor_status(
    current_user: User = Depends(verify_user_access)  # Changed to verify_user_access (not admin)
):
    """
    Get current network monitoring status and statistics
    """
    global network_monitor
    
    if not network_monitor:
        raise HTTPException(
            status_code=404,
            detail="Network monitor not initialized"
        )
    
    try:
        stats = network_monitor.get_statistics()
        
        return MonitorStatus(
            is_monitoring=network_monitor.is_monitoring,
            interface=stats['interface'],
            total_packets=stats['total_packets'],
            total_bytes=stats['total_bytes'],
            bandwidth_mbps=stats['bandwidth_mbps'],
            packet_types=stats['packet_types'],
            alerts_count=len(stats['alerts']),
            uptime_seconds=stats['uptime_seconds'],
            start_time=datetime.fromtimestamp(
                time.time() - stats['uptime_seconds']
            ).isoformat() if stats['uptime_seconds'] > 0 else None
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get status: {str(e)}"
        )

@router.get("/packets", response_model=Dict[str, Any])
async def get_recent_packets(
    limit: int = 50,
    current_user: User = Depends(verify_user_access)  # Changed to verify_user_access
):
    """
    Get recent network packets
    """
    global network_monitor
    
    if not network_monitor:
        raise HTTPException(
            status_code=404,
            detail="Network monitor not initialized"
        )
    
    try:
        stats = network_monitor.get_statistics()
        packets = stats['recent_packets'][-limit:]
        
        return {
            "packets": packets,
            "count": len(packets),
            "total_captured": stats['total_packets'],
            "requested_by": current_user.username
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get packets: {str(e)}"
        )

@router.get("/alerts", response_model=Dict[str, Any])
async def get_alerts(
    limit: int = 100,
    current_user: User = Depends(verify_user_access)  # Changed to verify_user_access
):
    """
    Get network security alerts
    """
    global network_monitor
    
    if not network_monitor:
        raise HTTPException(
            status_code=404,
            detail="Network monitor not initialized"
        )
    
    try:
        stats = network_monitor.get_statistics()
        alerts = stats['alerts'][-limit:]
        
        # Count alerts by severity
        severity_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for alert in alerts:
            severity_counts[alert['severity']] += 1
        
        return {
            "alerts": alerts,
            "count": len(alerts),
            "severity_counts": severity_counts,
            "requested_by": current_user.username
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get alerts: {str(e)}"
        )

@router.get("/statistics", response_model=Dict[str, Any])
async def get_detailed_statistics(
    current_user: User = Depends(verify_user_access)  # Changed to verify_user_access
):
    """
    Get detailed network statistics
    """
    global network_monitor
    
    if not network_monitor:
        raise HTTPException(
            status_code=404,
            detail="Network monitor not initialized"
        )
    
    try:
        stats = network_monitor.get_statistics()
        
        # Add additional calculated statistics
        if stats['uptime_seconds'] > 0:
            stats['packets_per_second'] = stats['total_packets'] / stats['uptime_seconds']
            stats['bytes_per_second'] = stats['total_bytes'] / stats['uptime_seconds']
            stats['average_packet_size'] = stats['total_bytes'] / stats['total_packets'] if stats['total_packets'] > 0 else 0
        else:
            stats['packets_per_second'] = 0
            stats['bytes_per_second'] = 0
            stats['average_packet_size'] = 0
        
        stats['requested_by'] = current_user.username
        return stats
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get statistics: {str(e)}"
        )

@router.get("/interfaces", response_model=Dict[str, Any])
async def get_network_interfaces(
    current_user: User = Depends(verify_user_access)  # Changed to verify_user_access
):
    """
    Get available network interfaces
    """
    try:
        import socket
        import psutil
        
        interfaces = []
        
        for iface, addrs in psutil.net_if_addrs().items():
            interface_info = {
                "name": iface,
                "ipv4": [],
                "ipv6": [],
                "mac": None,
                "is_up": False
            }
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interface_info["ipv4"].append({
                        "address": addr.address,
                        "netmask": addr.netmask
                    })
                elif addr.family == socket.AF_INET6:
                    interface_info["ipv6"].append({
                        "address": addr.address,
                        "netmask": addr.netmask
                    })
                elif addr.family == psutil.AF_LINK:
                    interface_info["mac"] = addr.address
            
            # Check if interface is up
            try:
                stats = psutil.net_if_stats()
                if iface in stats:
                    interface_info["is_up"] = stats[iface].isup
                    interface_info["speed_mbps"] = stats[iface].speed
            except:
                pass
            
            interfaces.append(interface_info)
        
        # Get default interface
        default_interface = "eth0"
        for iface in interfaces:
            if iface["is_up"] and iface["ipv4"]:
                default_interface = iface["name"]
                break
        
        return {
            "interfaces": interfaces,
            "count": len(interfaces),
            "default_interface": default_interface,
            "requested_by": current_user.username
        }
        
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="psutil package is required. Install with: pip install psutil"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get interfaces: {str(e)}"
        )


@router.get("/privileges")
async def check_privileges(
    current_user: User = Depends(verify_user_access)
):
    """Check if current process has network monitoring privileges"""
    try:
        # Create a test socket to check privileges
        import socket
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_socket.close()
            has_privileges = True
        except PermissionError:
            has_privileges = False
        
        return {
            "has_privileges": has_privileges,
            "is_admin": current_user.role in ["admin", "analyst"],
            "user_role": current_user.role,
            "requires_elevation": not has_privileges and current_user.role in ["admin", "analyst"],
            "instructions": "Network monitoring requires root privileges. Please elevate or run with sudo."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/elevate")
async def request_elevation(
    password: Optional[str] = None,
    current_user: User = Depends(verify_user_access)
):
    """
    Request privilege elevation for network monitoring
    Only allowed for admin/analyst users
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=403,
            detail="Only admin and analyst users can request elevation"
        )
    
    try:
        # Import privilege manager
        from src.api.services.privilege_escalation import privilege_manager
        
        # Check current privileges first
        status = privilege_manager.check_privileges()
        
        # Try to start privileged service
        result = privilege_manager.start_privileged_service(password)
        
        return {
            "success": result.get("success", False),
            "message": result.get("message", ""),
            "error": result.get("error", ""),
            "current_privileges": status
        }
        
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="Privilege escalation not implemented on this system"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/elevate-with-token")
async def elevate_with_token(
    token_data: dict,
    current_user: User = Depends(verify_user_access)
):
    """
    Elevate privileges using a pre-shared token
    This is a simplified version for development
    """
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Admin/analyst required")
    
    # For development: allow token-based elevation
    # In production, this should use proper authentication
    valid_tokens = ["chronos_dev_2024", "admin_override", "sudo_token"]
    
    if token_data.get("token") in valid_tokens:
        # In real implementation, this would start a privileged process
        return {
            "success": True,
            "message": "Privileges elevated for session",
            "duration": 3600,  # 1 hour
            "requires_restart": False
        }
    
    raise HTTPException(status_code=401, detail="Invalid elevation token")

@router.get("/elevation-methods")
async def get_elevation_methods(
    current_user: User = Depends(verify_user_access)
):
    """Get available privilege elevation methods for this system"""
    import platform
    
    system = platform.system()
    methods = []
    
    if system == "Linux":
        methods = [
            {
                "id": "sudo",
                "name": "Sudo Password",
                "description": "Enter sudo password to elevate",
                "requires_password": True,
                "gui_supported": False
            },
            {
                "id": "pkexec",
                "name": "PolicyKit (GUI)",
                "description": "Graphical password prompt",
                "requires_password": True,
                "gui_supported": True
            },
            {
                "id": "setcap",
                "name": "Set Capabilities",
                "description": "Grant permanent capabilities to Python",
                "requires_password": True,
                "gui_supported": False
            }
        ]
    elif system == "Windows":
        methods = [
            {
                "id": "runas",
                "name": "Run as Administrator",
                "description": "Windows UAC prompt",
                "requires_password": False,
                "gui_supported": True
            }
        ]
    else:  # macOS
        methods = [
            {
                "id": "osascript",
                "name": "AppleScript Elevation",
                "description": "macOS privilege elevation",
                "requires_password": True,
                "gui_supported": True
            }
        ]
    
    return {
        "system": system,
        "methods": methods,
        "recommended": methods[0]["id"] if methods else None
    }


@router.get("/health")
async def network_health_check(
    current_user: User = Depends(verify_user_access)  # Changed to verify_user_access
):
    """
    Health check for network monitoring service
    """
    global network_monitor
    
    health_status = {
        "service": "network_monitoring",
        "status": "healthy",
        "monitor_initialized": network_monitor is not None,
        "is_monitoring": network_monitor.is_monitoring if network_monitor else False,
        "timestamp": datetime.now().isoformat(),
        "user": current_user.username
    }
    
    # Check system resources
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        health_status["system"] = {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_total_gb": round(memory.total / (1024**3), 2)
        }
    except:
        health_status["system"] = "unavailable"
    
    return health_status
