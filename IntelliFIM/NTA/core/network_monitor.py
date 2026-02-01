"""
Network Traffic Analysis and Monitoring Module for Django
Monitors network traffic and provides real-time analysis
Integrated with Chronos AI Guard
"""

import socket
import struct
import time
import json
import logging
import threading
import subprocess
import platform
import os
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
from django.utils import timezone

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Network Traffic Monitoring and Analysis Class"""
    
    def __init__(self, interface: str = "eth0", packet_limit: int = 1000):
        """
        Initialize network monitor
        
        Args:
            interface: Network interface to monitor
            packet_limit: Maximum packets to capture in one session
        """
        self.interface = interface
        self.packet_limit = packet_limit
        self.is_monitoring = False
        self.monitor_thread = None
        self.sock = None
        self.has_privileges = self._check_privileges()
        
        # Statistics storage
        self.packets = deque(maxlen=10000)
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'total_bytes': 0,
            'start_time': None,
            'connections': defaultdict(lambda: {'packets': 0, 'bytes': 0}),
            'top_talkers': defaultdict(lambda: {'sent': 0, 'received': 0}),
        }
        
        self.alerts = deque(maxlen=100)
        self.anomaly_thresholds = {
            'high_bandwidth': 10 * 1024 * 1024,  # 10 MB/s
            'port_scan_threshold': 50,  # 50 connections/min to same port
            'syn_flood_threshold': 100,  # 100 SYN packets/min
            'suspicious_ports': [21, 22, 23, 25, 53, 80, 443, 3389, 8080],
        }
        
    def _check_privileges(self):
        """Check if we have sufficient privileges for packet capture"""
        try:
            # Try to create a raw socket (will fail without privileges)
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_sock.close()
            return True
        except PermissionError:
            return False
        except:
            return False
    
    def _request_privileges(self):
        """Request elevated privileges from the user"""
        system = platform.system()
        
        if system == "Linux":
            message = (
                "Network monitoring requires root privileges.\n\n"
                "Please run one of these commands:\n"
                "1. Run Django with sudo: sudo python manage.py runserver\n"
                "2. Grant capabilities: sudo setcap cap_net_raw+eip $(which python3)\n"
                "3. Use tcpdump: sudo apt install tcpdump"
            )
            logger.error(message)
            return False
            
        elif system == "Windows":
            message = (
                "Network monitoring requires Administrator privileges.\n\n"
                "Please run the Django server as Administrator or install Npcap."
            )
            logger.error(message)
            return False
            
        else:  # MacOS
            message = (
                "Network monitoring requires root privileges.\n\n"
                "Please run Django with sudo: sudo python manage.py runserver"
            )
            logger.error(message)
            return False
    
    def _create_raw_socket(self):
        """Create a raw socket for packet capture"""
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try to create raw socket with elevated privileges
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                return sock
                
            elif system == "Darwin":  # MacOS
                # MacOS uses different constants
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                return sock
                
            elif system == "Windows":
                # Windows requires Npcap/WinPcap
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind(('0.0.0.0', 0))
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                return sock
            
        except PermissionError as e:
            logger.error(f"Permission denied: {e}")
            if not self._request_privileges():
                raise PermissionError(
                    "Insufficient privileges for network monitoring. "
                    "Please run with elevated privileges (sudo/Administrator)."
                )
            raise
        except Exception as e:
            logger.error(f"Error creating socket: {e}")
            raise
    
    def _parse_packet(self, packet):
        """Parse raw packet data"""
        try:
            # Ethernet header is 14 bytes
            eth_length = 14
            
            # Check if packet is long enough
            if len(packet) < eth_length:
                return None
                
            eth_header = packet[:eth_length]
            
            # Parse Ethernet header
            try:
                eth = struct.unpack('!6s6sH', eth_header)
                eth_protocol = socket.ntohs(eth[2])
            except:
                return None
            
            # Parse IP packets (IP protocol number = 8)
            if eth_protocol == 8:
                # Parse IP header (20 bytes minimum)
                if len(packet) < eth_length + 20:
                    return None
                    
                ip_header = packet[eth_length:eth_length + 20]
                try:
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                except:
                    return None
                
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                
                packet_size = len(packet)
                
                # TCP protocol
                if protocol == 6:
                    t = iph_length + eth_length
                    if len(packet) < t + 20:
                        return None
                        
                    tcp_header = packet[t:t + 20]
                    try:
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    except:
                        return None
                    
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    
                    flags = tcph[5]
                    urg_flag = (flags & 32) >> 5
                    ack_flag = (flags & 16) >> 4
                    psh_flag = (flags & 8) >> 3
                    rst_flag = (flags & 4) >> 2
                    syn_flag = (flags & 2) >> 1
                    fin_flag = flags & 1
                    
                    return {
                        'timestamp': timezone.now().isoformat(),
                        'src_ip': s_addr,
                        'dst_ip': d_addr,
                        'protocol': 'TCP',
                        'protocol_num': protocol,
                        'src_port': source_port,
                        'dst_port': dest_port,
                        'size': packet_size,
                        'flags': {
                            'urg': bool(urg_flag),
                            'ack': bool(ack_flag),
                            'psh': bool(psh_flag),
                            'rst': bool(rst_flag),
                            'syn': bool(syn_flag),
                            'fin': bool(fin_flag),
                        },
                    }
                
                # UDP protocol
                elif protocol == 17:
                    u = iph_length + eth_length
                    if len(packet) < u + 8:
                        return None
                        
                    udp_header = packet[u:u + 8]
                    try:
                        udph = struct.unpack('!HHHH', udp_header)
                    except:
                        return None
                    
                    source_port = udph[0]
                    dest_port = udph[1]
                    
                    return {
                        'timestamp': timezone.now().isoformat(),
                        'src_ip': s_addr,
                        'dst_ip': d_addr,
                        'protocol': 'UDP',
                        'protocol_num': protocol,
                        'src_port': source_port,
                        'dst_port': dest_port,
                        'size': packet_size,
                    }
                
                # ICMP protocol
                elif protocol == 1:
                    return {
                        'timestamp': timezone.now().isoformat(),
                        'src_ip': s_addr,
                        'dst_ip': d_addr,
                        'protocol': 'ICMP',
                        'protocol_num': protocol,
                        'size': packet_size,
                    }
                
                # Other protocols
                else:
                    return {
                        'timestamp': timezone.now().isoformat(),
                        'src_ip': s_addr,
                        'dst_ip': d_addr,
                        'protocol': f'OTHER_{protocol}',
                        'protocol_num': protocol,
                        'size': packet_size,
                    }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    def _process_packet_info(self, packet_info: Dict[str, Any]) -> None:
        """Process parsed packet information"""
        if not packet_info:
            return
        
        # Update statistics
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += packet_info['size']
        
        # Update protocol-specific counts
        protocol = packet_info['protocol']
        if protocol == 'TCP':
            self.stats['tcp_packets'] += 1
        elif protocol == 'UDP':
            self.stats['udp_packets'] += 1
        elif protocol == 'ICMP':
            self.stats['icmp_packets'] += 1
        else:
            self.stats['other_packets'] += 1
        
        # Update connection stats
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        protocol_num = packet_info['protocol_num']
        
        conn_key = f"{src_ip}:{dst_ip}:{protocol_num}"
        self.stats['connections'][conn_key]['packets'] += 1
        self.stats['connections'][conn_key]['bytes'] += packet_info['size']
        
        # Update top talkers
        self.stats['top_talkers'][src_ip]['sent'] += packet_info['size']
        self.stats['top_talkers'][dst_ip]['received'] += packet_info['size']
        
        # Store packet
        self.packets.append(packet_info)
        
        # Log packet for debugging
        self._log_packet(packet_info)
        
        # Check for anomalies
        self._check_anomalies(packet_info)
    
    def _log_packet(self, packet_info: Dict[str, Any]) -> None:
        """Log packet information (for debugging)"""
        timestamp = packet_info['timestamp'].split('T')[1].split('.')[0]
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        protocol = packet_info['protocol']
        size = packet_info['size']
        
        # Only log every 100th packet to avoid flooding logs
        if self.stats['total_packets'] % 100 == 0:
            log_msg = f"[{timestamp}] {src_ip} → {dst_ip} | {protocol} | {size} bytes"
            
            # Add port information if available
            if 'src_port' in packet_info and 'dst_port' in packet_info:
                log_msg += f" | {packet_info['src_port']} → {packet_info['dst_port']}"
            
            logger.debug(log_msg)
    
    def _check_anomalies(self, packet_info: Dict[str, Any]) -> None:
        """Check for network anomalies"""
        src_ip = packet_info['src_ip']
        dst_port = packet_info.get('dst_port')
        
        # Check for suspicious ports
        if dst_port and dst_port in self.anomaly_thresholds['suspicious_ports']:
            self._add_alert(
                'SUSPICIOUS_PORT', 
                f"Connection to suspicious port {dst_port} from {src_ip}"
            )
        
        # Check for SYN flood (TCP only)
        if packet_info['protocol'] == 'TCP' and packet_info.get('flags', {}).get('syn'):
            self._check_syn_flood(src_ip, packet_info['dst_ip'], dst_port)
    
    def _check_syn_flood(self, src_ip: str, dst_ip: str, dst_port: int) -> None:
        """Check for SYN flood attacks"""
        # Count SYN packets from this source in the last minute
        current_time = time.time()
        one_minute_ago = current_time - 60
        
        syn_count = 0
        for packet in self.packets:
            try:
                packet_time = datetime.fromisoformat(packet['timestamp']).timestamp()
                if (packet_time > one_minute_ago and 
                    packet['src_ip'] == src_ip and 
                    packet.get('flags', {}).get('syn')):
                    syn_count += 1
            except:
                continue
        
        if syn_count > self.anomaly_thresholds['syn_flood_threshold']:
            self._add_alert(
                'SYN_FLOOD',
                f"Possible SYN flood from {src_ip} ({syn_count} SYNs/min)"
            )
    
    def _add_alert(self, alert_type: str, message: str) -> None:
        """Add security alert"""
        alert = {
            'timestamp': timezone.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': self._get_severity(alert_type)
        }
        self.alerts.append(alert)
        
        # Log alert
        severity = alert['severity']
        if severity == 'HIGH':
            logger.error(f"ALERT [{alert_type}] {message}")
        elif severity == 'MEDIUM':
            logger.warning(f"ALERT [{alert_type}] {message}")
        else:
            logger.info(f"ALERT [{alert_type}] {message}")
    
    def _get_severity(self, alert_type: str) -> str:
        """Get severity level for alert type"""
        severity_map = {
            'SYN_FLOOD': 'HIGH',
            'PORT_SCAN': 'HIGH',
            'HIGH_BANDWIDTH': 'MEDIUM',
            'SUSPICIOUS_PORT': 'LOW',
        }
        return severity_map.get(alert_type, 'LOW')
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        logger.info(f"Starting network monitoring on interface: {self.interface}")
        self.stats['start_time'] = time.time()
        
        packet_count = 0
        
        try:
            self.sock = self._create_raw_socket()
            self.sock.settimeout(1)  # 1 second timeout
            
            while self.is_monitoring and (self.packet_limit == 0 or packet_count < self.packet_limit):
                try:
                    # Receive packet
                    packet = self.sock.recvfrom(65565)[0]
                    packet_count += 1
                    
                    # Parse and process packet
                    packet_info = self._parse_packet(packet)
                    if packet_info:
                        self._process_packet_info(packet_info)
                    
                    # Log statistics every 100 packets
                    if packet_count % 100 == 0:
                        self._log_stats()
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error receiving packet: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
            self.is_monitoring = False
    
    def _log_stats(self) -> None:
        """Log current statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        bandwidth = self.stats['total_bytes'] / elapsed if elapsed > 0 else 0
        
        stats_msg = (
            f"Packets: {self.stats['total_packets']:,} | "
            f"Data: {self.stats['total_bytes']/1024/1024:.2f} MB | "
            f"Bandwidth: {bandwidth/1024/1024:.2f} MB/s | "
            f"Uptime: {elapsed:.1f}s | "
            f"TCP: {self.stats['tcp_packets']:,} | "
            f"UDP: {self.stats['udp_packets']:,} | "
            f"ICMP: {self.stats['icmp_packets']:,} | "
            f"Alerts: {len(self.alerts)}"
        )
        logger.info(stats_msg)
    
    def start_monitoring(self) -> bool:
        """Start network traffic monitoring"""
        if self.is_monitoring:
            logger.warning("Monitoring already in progress")
            return False
        
        try:
            self.is_monitoring = True
            
            # Start monitoring in a separate thread
            self.monitor_thread = threading.Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            # Wait a bit to ensure thread started
            time.sleep(0.5)
            
            logger.info(f"Network monitoring started on {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.is_monitoring = False
            return False
    
    def stop_monitoring(self) -> None:
        """Stop network monitoring"""
        self.is_monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        
        # Log final statistics
        self._log_final_stats()
        logger.info("Network monitoring stopped")
    
    def _log_final_stats(self) -> None:
        """Log final statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        final_stats = (
            f"Monitoring stopped. Total time: {elapsed:.1f}s | "
            f"Packets: {self.stats['total_packets']:,} | "
            f"Data: {self.stats['total_bytes']/1024/1024:.2f} MB | "
            f"Alerts: {len(self.alerts)}"
        )
        logger.info(final_stats)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        current_time = time.time()
        elapsed = current_time - self.stats['start_time'] if self.stats['start_time'] else 0
        
        # Calculate bandwidth
        bandwidth = self.stats['total_bytes'] / elapsed if elapsed > 0 else 0
        
        # Get top connections
        top_connections = sorted(
            self.stats['connections'].items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )[:10]
        
        # Get top talkers
        top_talkers = sorted(
            self.stats['top_talkers'].items(),
            key=lambda x: x[1]['sent'] + x[1]['received'],
            reverse=True
        )[:10]
        
        return {
            'interface': self.interface,
            'is_monitoring': self.is_monitoring,
            'total_packets': self.stats['total_packets'],
            'total_bytes': self.stats['total_bytes'],
            'bandwidth_bps': bandwidth,
            'bandwidth_mbps': bandwidth / 1024 / 1024,
            'packet_types': {
                'tcp': self.stats['tcp_packets'],
                'udp': self.stats['udp_packets'],
                'icmp': self.stats['icmp_packets'],
                'other': self.stats['other_packets'],
            },
            'top_connections': [
                {'connection': k, 'packets': v['packets'], 'bytes': v['bytes']}
                for k, v in top_connections
            ],
            'top_talkers': [
                {'ip': k, 'sent': v['sent'], 'received': v['received']}
                for k, v in top_talkers
            ],
            'alerts': list(self.alerts),
            'recent_packets': list(self.packets)[-20:],  # Last 20 packets
            'uptime_seconds': elapsed,
        }
