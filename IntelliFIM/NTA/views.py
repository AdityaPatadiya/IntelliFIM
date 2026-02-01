import threading
import time
from datetime import datetime
import platform
import socket

from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view

from accounts.permissions import IsAdminUser
from .serializers import (
    MonitorConfigSerializer, MonitorStatusSerializer,
    NetworkInterfaceSerializer, ElevationTokenSerializer,
    PrivilegeStatusSerializer, ElevationMethodSerializer
)
from .core.network_monitor import NetworkMonitor

# Global monitor instance (similar to your FastAPI implementation)
network_monitor = None
monitor_lock = threading.Lock()


class NetworkMonitoringView(APIView):
    """Base view for network monitoring"""
    permission_classes = [IsAuthenticated]
    
    def get_network_monitor(self):
        global network_monitor
        return network_monitor


class StartMonitoringView(NetworkMonitoringView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        global network_monitor
        
        serializer = MonitorConfigSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        config = serializer.validated_data
        
        with monitor_lock:
            if network_monitor and network_monitor.is_monitoring:
                return Response(
                    {"detail": "Network monitoring already in progress"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                network_monitor = NetworkMonitor(
                    interface=config['interface'],
                    packet_limit=config['packet_limit']
                )
                
                # Try to start monitoring
                success = network_monitor.start_monitoring()
                
                if success:
                    return Response({
                        "message": "Network monitoring started successfully",
                        "interface": config['interface'],
                        "packet_limit": config['packet_limit'],
                        "status": "running",
                        "admin_user": request.user.username,
                        "has_privileges": network_monitor.has_privileges
                    })
                else:
                    return Response({
                        "message": "Failed to start network monitoring",
                        "status": "failed"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
            except PermissionError:
                system = platform.system()
                
                if system == "Linux":
                    detail = (
                        "Permission denied. Network monitoring requires root privileges.\n\n"
                        "Options:\n"
                        "1. Run Django with sudo: sudo python manage.py runserver\n"
                        "2. Grant capabilities: sudo setcap cap_net_raw+eip $(which python3)\n"
                        "3. Install tcpdump: sudo apt install tcpdump"
                    )
                elif system == "Windows":
                    detail = (
                        "Permission denied. Network monitoring requires Administrator privileges.\n\n"
                        "Options:\n"
                        "1. Run Django as Administrator\n"
                        "2. Install Npcap from https://npcap.com/"
                    )
                else:  # MacOS
                    detail = (
                        "Permission denied. Network monitoring requires root privileges.\n\n"
                        "Run Django with sudo: sudo python manage.py runserver"
                    )
                
                return Response(
                    {"detail": detail},
                    status=status.HTTP_403_FORBIDDEN
                )
            except Exception as e:
                return Response(
                    {"detail": f"Failed to start monitoring: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )


class StopMonitoringView(NetworkMonitoringView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        global network_monitor
        
        with monitor_lock:
            if not network_monitor:
                return Response(
                    {"detail": "Network monitor not initialized"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not network_monitor.is_monitoring:
                return Response(
                    {"detail": "Network monitoring is not running"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            network_monitor.stop_monitoring()
            return Response({
                "message": "Network monitoring stopped",
                "admin_user": request.user.username
            })


class MonitorStatusView(NetworkMonitoringView):
    def get(self, request):
        monitor = self.get_network_monitor()
        
        if not monitor:
            return Response(
                {"detail": "Network monitor not initialized"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            stats = monitor.get_statistics()
            
            serializer = MonitorStatusSerializer({
                "is_monitoring": monitor.is_monitoring,
                "interface": stats.get('interface', ''),
                "total_packets": stats.get('total_packets', 0),
                "total_bytes": stats.get('total_bytes', 0),
                "bandwidth_mbps": stats.get('bandwidth_mbps', 0.0),
                "packet_types": stats.get('packet_types', {}),
                "alerts_count": len(stats.get('alerts', [])),
                "uptime_seconds": stats.get('uptime_seconds', 0),
                "start_time": datetime.fromtimestamp(
                    time.time() - stats.get('uptime_seconds', 0)
                ) if stats.get('uptime_seconds', 0) > 0 else None
            })
            
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get status: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RecentPacketsView(NetworkMonitoringView):
    def get(self, request):
        monitor = self.get_network_monitor()
        
        if not monitor:
            return Response(
                {"detail": "Network monitor not initialized"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        limit = int(request.query_params.get('limit', 50))
        
        try:
            stats = monitor.get_statistics()
            packets = stats.get('recent_packets', [])[-limit:]
            
            return Response({
                "packets": packets,
                "count": len(packets),
                "total_captured": stats.get('total_packets', 0),
                "requested_by": request.user.username
            })
        except Exception as e:
            return Response(
                {"detail": f"Failed to get packets: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkAlertsView(NetworkMonitoringView):
    def get(self, request):
        monitor = self.get_network_monitor()
        
        if not monitor:
            return Response(
                {"detail": "Network monitor not initialized"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        limit = int(request.query_params.get('limit', 100))
        
        try:
            stats = monitor.get_statistics()
            alerts = stats.get('alerts', [])[-limit:]
            
            severity_counts = {
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            }
            
            for alert in alerts:
                severity = alert.get('severity', 'LOW')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            return Response({
                "alerts": alerts,
                "count": len(alerts),
                "severity_counts": severity_counts,
                "requested_by": request.user.username
            })
        except Exception as e:
            return Response(
                {"detail": f"Failed to get alerts: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class DetailedStatisticsView(NetworkMonitoringView):
    def get(self, request):
        monitor = self.get_network_monitor()
        
        if not monitor:
            return Response(
                {"detail": "Network monitor not initialized"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            stats = monitor.get_statistics()
            
            # Add additional calculated statistics
            uptime = stats.get('uptime_seconds', 0)
            total_packets = stats.get('total_packets', 0)
            total_bytes = stats.get('total_bytes', 0)
            
            if uptime > 0:
                stats['packets_per_second'] = total_packets / uptime
                stats['bytes_per_second'] = total_bytes / uptime
                stats['average_packet_size'] = total_bytes / total_packets if total_packets > 0 else 0
            else:
                stats['packets_per_second'] = 0
                stats['bytes_per_second'] = 0
                stats['average_packet_size'] = 0
            
            stats['has_privileges'] = monitor.has_privileges
            stats['requested_by'] = request.user.username
            return Response(stats)
            
        except Exception as e:
            return Response(
                {"detail": f"Failed to get statistics: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NetworkInterfacesView(NetworkMonitoringView):
    def get(self, request):
        try:
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
            
            return Response({
                "interfaces": interfaces,
                "count": len(interfaces),
                "default_interface": default_interface,
                "requested_by": request.user.username
            })
            
        except ImportError:
            return Response(
                {"detail": "psutil package is required. Install with: pip install psutil"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {"detail": f"Failed to get interfaces: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PrivilegesView(NetworkMonitoringView):
    def get(self, request):
        try:
            monitor = self.get_network_monitor()
            has_privileges = monitor.has_privileges if monitor else False
            
            # Check if user is admin or analyst
            is_admin_or_analyst = request.user.role in ["admin", "analyst"] if hasattr(request.user, 'role') else False
            
            serializer = PrivilegeStatusSerializer({
                "has_privileges": has_privileges,
                "is_admin": is_admin_or_analyst,
                "user_role": getattr(request.user, 'role', 'user'),
                "requires_elevation": not has_privileges and is_admin_or_analyst,
                "instructions": "Network monitoring requires root privileges. Please elevate or run with sudo."
            })
            
            return Response(serializer.data)
        except Exception as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ElevationMethodsView(NetworkMonitoringView):
    def get(self, request):
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
        
        return Response({
            "system": system,
            "methods": methods,
            "recommended": methods[0]["id"] if methods else None
        })


class HealthCheckView(NetworkMonitoringView):
    def get(self, request):
        monitor = self.get_network_monitor()
        
        health_status = {
            "service": "network_monitoring",
            "status": "healthy",
            "monitor_initialized": monitor is not None,
            "is_monitoring": monitor.is_monitoring if monitor else False,
            "has_privileges": monitor.has_privileges if monitor else False,
            "timestamp": timezone.now().isoformat(),
            "user": request.user.username
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
        
        return Response(health_status)


@api_view(['POST'])
def test_raw_socket(request):
    """Test raw socket creation (requires admin)"""
    from django.contrib.auth.decorators import login_required
    from accounts.decorators import admin_required
    
    @login_required
    @admin_required
    def inner(request):
        try:
            # Try to create a raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.close()
            
            return Response({
                "success": True,
                "message": "Raw socket creation successful",
                "has_privileges": True
            })
        except PermissionError:
            return Response({
                "success": False,
                "message": "Permission denied. Requires root/Administrator privileges.",
                "has_privileges": False
            }, status=403)
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Error: {str(e)}",
                "has_privileges": False
            }, status=500)
    
    return inner(request)
