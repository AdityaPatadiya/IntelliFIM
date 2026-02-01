import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { DashboardLayout } from '@/components/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import PrivilegeDialog from '@/components/PrivilegeDialog';
import {
  Play,
  Square,
  Shield,
  RefreshCw,
  Eye,
  AlertTriangle,
  Network,
  Activity,
  BarChart3,
  Filter,
  Search,
  Trash2,
  Clock,
  Server,
  Wifi,
  HardDrive,
  ChevronLeft,
  ChevronRight,
  Download,
  Upload,
  Globe
} from 'lucide-react';
import { toast } from 'sonner';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface NetworkPacket {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  protocol_num: number;
  src_port?: number;
  dst_port?: number;
  size: number;
  flags?: {
    urg: boolean;
    ack: boolean;
    psh: boolean;
    rst: boolean;
    syn: boolean;
    fin: boolean;
  };
  ttl?: number;
}

interface NetworkAlert {
  id: string;
  timestamp: string;
  type: string;
  message: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

interface NetworkInterface {
  name: string;
  ipv4: Array<{ address: string; netmask: string }>;
  ipv6: Array<{ address: string; netmask: string }>;
  mac: string | null;
  is_up: boolean;
  speed_mbps?: number;
}

interface MonitorStatus {
  is_monitoring: boolean;
  interface: string;
  total_packets: number;
  total_bytes: number;
  bandwidth_mbps: number;
  packet_types: {
    tcp: number;
    udp: number;
    icmp: number;
    other: number;
  };
  alerts_count: number;
  uptime_seconds: number;
  start_time: string | null;
}

interface DetailedStatistics {
  interface: string;
  is_monitoring: boolean;
  total_packets: number;
  total_bytes: number;
  bandwidth_bps: number;
  bandwidth_mbps: number;
  packet_types: {
    tcp: number;
    udp: number;
    icmp: number;
    other: number;
  };
  top_connections: Array<{
    connection: string;
    packets: number;
    bytes: number;
  }>;
  top_talkers: Array<{
    ip: string;
    sent: number;
    received: number;
  }>;
  alerts: NetworkAlert[];
  recent_packets: NetworkPacket[];
  uptime_seconds: number;
  packets_per_second: number;
  bytes_per_second: number;
  average_packet_size: number;
}

const NetworkMonitoring = () => {
  const { user } = useAuth();
  const [networkPackets, setNetworkPackets] = useState<NetworkPacket[]>([]);
  const [networkAlerts, setNetworkAlerts] = useState<NetworkAlert[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [monitorStatus, setMonitorStatus] = useState<MonitorStatus>({
    is_monitoring: false,
    interface: 'eth0',
    total_packets: 0,
    total_bytes: 0,
    bandwidth_mbps: 0,
    packet_types: { tcp: 0, udp: 0, icmp: 0, other: 0 },
    alerts_count: 0,
    uptime_seconds: 0,
    start_time: null
  });
  const [statistics, setStatistics] = useState<DetailedStatistics | null>(null);
  const [loading, setLoading] = useState(false);
  const [isStartDialogOpen, setIsStartDialogOpen] = useState(false);
  const [selectedInterface, setSelectedInterface] = useState('eth0');
  const [packetLimit, setPacketLimit] = useState(1000);
  const [selectedPacket, setSelectedPacket] = useState<NetworkPacket | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<NetworkAlert | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [packetLimitDisplay, setPacketLimitDisplay] = useState(100);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('packets');
  const [filterProtocol, setFilterProtocol] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 20;
  const eventsEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [privilegeDialogOpen, setPrivilegeDialogOpen] = useState(false);
  const [needsElevation, setNeedsElevation] = useState(false);
  const [elevationChecked, setElevationChecked] = useState(false);

  const eventCounterRef = useRef(0);
  const generateId = () => {
    eventCounterRef.current += 1;
    return `${Date.now()}_${eventCounterRef.current}`;
  };

  const getAuthHeaders = () => {
    const token = localStorage.getItem('access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
    };
  };

  // Fetch interfaces
  const fetchInterfaces = async () => {
    try {
      const response = await fetch(`${API_URL}/api/network/interfaces`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch interfaces');
      const data = await response.json();
      setInterfaces(data.interfaces);

      // Set default interface if available
      if (data.interfaces.length > 0) {
        const defaultIf = data.interfaces.find((iface: NetworkInterface) => iface.is_up) || data.interfaces[0];
        setSelectedInterface(defaultIf.name);
      }
    } catch (error) {
      console.error('Error fetching interfaces:', error);
      toast.error('Failed to fetch network interfaces');
    }
  };

  // Fetch monitor status
  const fetchStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/api/network/status`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch status');
      const data = await response.json();
      setMonitorStatus(data);

      // If monitoring is active, setup real-time updates
      if (data.is_monitoring && !eventSourceRef.current) {
        setupEventSource();
      } else if (!data.is_monitoring && eventSourceRef.current) {
        cleanupEventSource();
      }
    } catch (error) {
      console.error('Error fetching status:', error);
    }
  };

  // Fetch statistics
  const fetchStatistics = async () => {
    try {
      const response = await fetch(`${API_URL}/api/network/statistics`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch statistics');
      const data = await response.json();
      setStatistics(data);

      // Update packets list
      if (data.recent_packets) {
        const packetsWithIds = data.recent_packets.map((packet: any) => ({
          ...packet,
          id: generateId()
        }));
        setNetworkPackets(prev => {
          // Merge and deduplicate by timestamp + src_ip + dst_ip
          const newPackets = [...packetsWithIds];
          const existingIds = new Set(prev.map(p => p.id));
          const uniqueNewPackets = newPackets.filter(p => !existingIds.has(p.id));
          return [...uniqueNewPackets, ...prev].slice(0, packetLimitDisplay);
        });
      }

      // Update alerts
      if (data.alerts) {
        const alertsWithIds = data.alerts.map((alert: any) => ({
          ...alert,
          id: generateId()
        }));
        setNetworkAlerts(prev => {
          const newAlerts = [...alertsWithIds];
          const existingIds = new Set(prev.map(a => a.id));
          const uniqueNewAlerts = newAlerts.filter(a => !existingIds.has(a.id));
          return [...uniqueNewAlerts, ...prev].slice(0, packetLimitDisplay);
        });
      }
    } catch (error) {
      console.error('Error fetching statistics:', error);
    }
  };

  // Setup EventSource for real-time updates
  const setupEventSource = () => {
    if (eventSourceRef.current) {
      cleanupEventSource();
    }

    try {
      // For now, we'll use polling since SSE endpoint might not be implemented
      // Start polling for updates
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }

      refreshIntervalRef.current = setInterval(() => {
        if (monitorStatus.is_monitoring) {
          fetchStatistics();
        }
      }, 1000); // Poll every second for real-time updates

      toast.success('Real-time monitoring connected');
    } catch (error) {
      console.error('Failed to setup real-time updates:', error);
      toast.error('Failed to connect to real-time monitoring');
    }
  };

  const cleanupEventSource = () => {
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }

    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  // Start monitoring
  const handleStartMonitoring = async () => {
    try {
      const response = await fetch(`${API_URL}/api/network/start`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          interface: selectedInterface,
          packet_limit: packetLimit
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to start monitoring');
      }

      const data = await response.json();
      toast.success(data.message);
      setIsStartDialogOpen(false);

      // Clear existing data
      setNetworkPackets([]);
      setNetworkAlerts([]);
      eventCounterRef.current = 0;

      // Fetch updated status
      setTimeout(() => {
        fetchStatus();
        fetchStatistics();
      }, 1000);
    } catch (error: any) {
      toast.error(error.message || 'Failed to start monitoring');
    }
  };

  // Stop monitoring
  const handleStopMonitoring = async () => {
    try {
      const response = await fetch(`${API_URL}/api/network/stop`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to stop monitoring');
      }

      const data = await response.json();
      toast.success(data.message);

      // Cleanup real-time updates
      cleanupEventSource();

      // Fetch updated status
      fetchStatus();
    } catch (error: any) {
      toast.error(error.message || 'Failed to stop monitoring');
    }
  };

  // Clear events
  const clearEvents = () => {
    if (activeTab === 'packets') {
      setNetworkPackets([]);
      toast.success('Network packets cleared');
    } else {
      setNetworkAlerts([]);
      toast.success('Network alerts cleared');
    }
    eventCounterRef.current = 0;
  };

  // Format time
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  // Format duration
  const formatDuration = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  };

  // Format bytes
  const formatBytes = (bytes: number) => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unitIndex = 0;

    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }

    return `${value.toFixed(2)} ${units[unitIndex]}`;
  };

  // Get protocol color
  const getProtocolColor = (protocol: string) => {
    switch (protocol.toUpperCase()) {
      case 'TCP':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'UDP':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'ICMP':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return 'destructive';
      case 'MEDIUM':
        return 'secondary';
      case 'LOW':
        return 'default';
      default:
        return 'outline';
    }
  };

  // Get severity icon
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'MEDIUM':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'LOW':
        return <AlertTriangle className="h-4 w-4 text-blue-500" />;
      default:
        return <AlertTriangle className="h-4 w-4" />;
    }
  };

  // Filter packets
  const getFilteredPackets = () => {
    let filtered = networkPackets;

    // Apply search filter
    if (searchQuery.trim()) {
      filtered = filtered.filter(packet =>
        packet.src_ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        packet.dst_ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
        packet.protocol.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (packet.src_port && packet.src_port.toString().includes(searchQuery)) ||
        (packet.dst_port && packet.dst_port.toString().includes(searchQuery))
      );
    }

    // Apply protocol filter
    if (filterProtocol !== 'all') {
      filtered = filtered.filter(packet =>
        packet.protocol.toUpperCase() === filterProtocol.toUpperCase()
      );
    }

    return filtered;
  };

  // Filter alerts
  const getFilteredAlerts = () => {
    let filtered = networkAlerts;

    // Apply search filter
    if (searchQuery.trim()) {
      filtered = filtered.filter(alert =>
        alert.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
        alert.type.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Apply severity filter
    if (filterSeverity !== 'all') {
      filtered = filtered.filter(alert =>
        alert.severity === filterSeverity.toUpperCase()
      );
    }

    return filtered;
  };

  // Get paginated data
  const getPaginatedData = () => {
    const filteredData = activeTab === 'packets' ? getFilteredPackets() : getFilteredAlerts();
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return filteredData.slice(startIndex, endIndex);
  };

  const getTotalPages = () => {
    const filteredData = activeTab === 'packets' ? getFilteredPackets() : getFilteredAlerts();
    return Math.ceil(filteredData.length / itemsPerPage);
  };

  // Auto-scroll effect
  useEffect(() => {
    if (autoScroll && eventsEndRef.current) {
      eventsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [networkPackets, networkAlerts, activeTab, autoScroll]);

  // Initial fetch and setup
  useEffect(() => {
    fetchInterfaces();
    fetchStatus();
    fetchStatistics();

    // Set up polling for status
    const statusInterval = setInterval(fetchStatus, 10000); // Every 10 seconds

    return () => {
      clearInterval(statusInterval);
      cleanupEventSource();
    };
  }, []);

  // Reset page when tab changes
  useEffect(() => {
    setCurrentPage(1);
    setSearchQuery('');
  }, [activeTab]);

  useEffect(() => {
    const checkPrivileges = async () => {
      try {
        const response = await fetch(`${API_URL}/api/network/privileges`, {
          headers: getAuthHeaders(),
        });
        const data = await response.json();
        setNeedsElevation(data.requires_elevation || false);
        setElevationChecked(true);
      } catch (error) {
        console.error('Failed to check privileges:', error);
      }
    };

    if (user?.role && ['admin', 'analyst'].includes(user.role)) {
      checkPrivileges();
    }
  }, [user]);

  // Update the Start Monitoring button logic
  {
    monitorStatus.is_monitoring ? (
      user?.role === 'admin' && (
        <Button variant="destructive" size="sm" onClick={handleStopMonitoring}>
          <Square className="mr-2 h-4 w-4" />
          Stop Monitoring
        </Button>
      )
    ) : (
    user?.role === 'admin' && (
      <>
        <Button
          variant="default"
          size="sm"
          onClick={() => {
            if (needsElevation && !monitorStatus.is_monitoring) {
              setPrivilegeDialogOpen(true);
            } else {
              setIsStartDialogOpen(true);
            }
          }}
        >
          <Play className="mr-2 h-4 w-4" />
          Start Monitoring
          {needsElevation && (
            <Badge variant="outline" className="ml-2 bg-amber-100 text-amber-800 border-amber-300">
              <Lock className="h-3 w-3 mr-1" />
              Needs Elevation
            </Badge>
          )}
        </Button>
      </>
    )
  )
  }

  // Add the PrivilegeDialog component at the end (before the final closing div)
  <PrivilegeDialog
    open={privilegeDialogOpen}
    onOpenChange={setPrivilegeDialogOpen}
    onElevationSuccess={() => {
      // Refresh status after elevation
      setTimeout(() => {
        fetchStatus();
        fetchStatistics();
      }, 1000);
    }}
    userRole={user?.role || ''}
  />

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-2">
              <Network className="h-8 w-8" />
              Network Traffic Analysis
            </h1>
            <p className="text-muted-foreground">Real-time network monitoring and security alerts</p>
          </div>
          <div className="flex gap-2">
            {monitorStatus.is_monitoring ? (
              user?.role === 'admin' && (
                <Button variant="destructive" size="sm" onClick={handleStopMonitoring}>
                  <Square className="mr-2 h-4 w-4" />
                  Stop Monitoring
                </Button>
              )
            ) : (
              user?.role === 'admin' && (
                <Dialog open={isStartDialogOpen} onOpenChange={setIsStartDialogOpen}>
                  <DialogTrigger asChild>
                    <Button variant="default" size="sm">
                      <Play className="mr-2 h-4 w-4" />
                      Start Monitoring
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Start Network Monitoring</DialogTitle>
                      <DialogDescription>
                        Configure network interface and monitoring parameters
                      </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                      <div className="space-y-2">
                        <Label htmlFor="interface">Network Interface</Label>
                        <Select value={selectedInterface} onValueChange={setSelectedInterface}>
                          <SelectTrigger>
                            <SelectValue placeholder="Select interface" />
                          </SelectTrigger>
                          <SelectContent>
                            {interfaces.map((iface) => (
                              <SelectItem key={iface.name} value={iface.name}>
                                <div className="flex items-center gap-2">
                                  <Wifi className="h-4 w-4" />
                                  {iface.name}
                                  {!iface.is_up && (
                                    <Badge variant="outline" className="ml-2 text-xs">
                                      Down
                                    </Badge>
                                  )}
                                </div>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="packet-limit">Packet Limit (0 for unlimited)</Label>
                        <Input
                          id="packet-limit"
                          type="number"
                          min="0"
                          value={packetLimit}
                          onChange={(e) => setPacketLimit(parseInt(e.target.value) || 0)}
                          placeholder="1000"
                        />
                      </div>
                      {selectedInterface && (
                        <div className="text-sm text-muted-foreground">
                          <p>Interface: {selectedInterface}</p>
                          {interfaces.find(i => i.name === selectedInterface)?.ipv4[0] && (
                            <p>IP Address: {interfaces.find(i => i.name === selectedInterface)?.ipv4[0].address}</p>
                          )}
                          {interfaces.find(i => i.name === selectedInterface)?.speed_mbps && (
                            <p>Speed: {interfaces.find(i => i.name === selectedInterface)?.speed_mbps} Mbps</p>
                          )}
                        </div>
                      )}
                    </div>
                    <DialogFooter>
                      <Button onClick={handleStartMonitoring}>Start Monitoring</Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              )
            )}
            <Button variant="outline" size="sm" onClick={fetchStatistics}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
            {(networkPackets.length > 0 || networkAlerts.length > 0) && (
              <Button variant="outline" size="sm" onClick={clearEvents}>
                <Trash2 className="mr-2 h-4 w-4" />
                Clear {activeTab === 'packets' ? 'Packets' : 'Alerts'}
              </Button>
            )}
          </div>
        </div>

        {/* Status Alert */}
        <Alert>
          <Shield className="h-4 w-4" />
          <AlertDescription>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <span className="flex items-center gap-2">
                  <strong>Status:</strong>
                  <Badge
                    variant={monitorStatus.is_monitoring ? "default" : "secondary"}
                    className="ml-2"
                  >
                    {monitorStatus.is_monitoring ? (
                      <div className="flex items-center gap-1">
                        <Activity className="h-3 w-3 animate-pulse" />
                        Monitoring Active
                      </div>
                    ) : 'Monitoring Stopped'}
                  </Badge>
                </span>
                <span className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  <strong>Interface:</strong> {monitorStatus.interface}
                </span>
                <span className="flex items-center gap-2">
                  <Download className="h-4 w-4" />
                  <strong>Packets:</strong> {monitorStatus.total_packets.toLocaleString()}
                </span>
                <span className="flex items-center gap-2">
                  <HardDrive className="h-4 w-4" />
                  <strong>Data:</strong> {formatBytes(monitorStatus.total_bytes)}
                </span>
                <span className="flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  <strong>Bandwidth:</strong> {monitorStatus.bandwidth_mbps.toFixed(2)} Mbps
                </span>
                {monitorStatus.uptime_seconds > 0 && (
                  <span className="flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    <strong>Uptime:</strong> {formatDuration(monitorStatus.uptime_seconds)}
                  </span>
                )}
              </div>
            </div>
          </AlertDescription>
        </Alert>

        {/* Statistics Cards */}
        {statistics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  Traffic Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="flex items-center gap-1">
                      <div className="w-3 h-3 rounded-full bg-green-500"></div>
                      TCP
                    </span>
                    <span>{((statistics.packet_types.tcp / statistics.total_packets) * 100 || 0).toFixed(1)}%</span>
                  </div>
                  <Progress value={(statistics.packet_types.tcp / statistics.total_packets) * 100 || 0} className="h-2" />

                  <div className="flex justify-between text-sm">
                    <span className="flex items-center gap-1">
                      <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                      UDP
                    </span>
                    <span>{((statistics.packet_types.udp / statistics.total_packets) * 100 || 0).toFixed(1)}%</span>
                  </div>
                  <Progress value={(statistics.packet_types.udp / statistics.total_packets) * 100 || 0} className="h-2" />

                  <div className="flex justify-between text-sm">
                    <span className="flex items-center gap-1">
                      <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                      ICMP
                    </span>
                    <span>{((statistics.packet_types.icmp / statistics.total_packets) * 100 || 0).toFixed(1)}%</span>
                  </div>
                  <Progress value={(statistics.packet_types.icmp / statistics.total_packets) * 100 || 0} className="h-2" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Real-time Stats
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Packets/sec:</span>
                    <span className="font-mono">{statistics.packets_per_second.toFixed(1)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Data/sec:</span>
                    <span className="font-mono">{formatBytes(statistics.bytes_per_second)}/s</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Avg Packet Size:</span>
                    <span className="font-mono">{formatBytes(statistics.average_packet_size)}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Alerts:</span>
                    <Badge variant="outline">{statistics.alerts?.length || 0}</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Server className="h-4 w-4" />
                  Top Talkers
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {statistics.top_talkers?.slice(0, 5).map((talker, index) => (
                    <div key={index} className="flex justify-between text-sm">
                      <span className="font-mono truncate" title={talker.ip}>
                        {talker.ip}
                      </span>
                      <span className="font-mono">{formatBytes(talker.sent + talker.received)}</span>
                    </div>
                  ))}
                  {(!statistics.top_talkers || statistics.top_talkers.length === 0) && (
                    <div className="text-sm text-muted-foreground text-center py-2">
                      No traffic data yet
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  Security Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="flex items-center gap-1">
                      {getSeverityIcon('HIGH')}
                      High
                    </span>
                    <span>{statistics.alerts?.filter(a => a.severity === 'HIGH').length || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="flex items-center gap-1">
                      {getSeverityIcon('MEDIUM')}
                      Medium
                    </span>
                    <span>{statistics.alerts?.filter(a => a.severity === 'MEDIUM').length || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="flex items-center gap-1">
                      {getSeverityIcon('LOW')}
                      Low
                    </span>
                    <span>{statistics.alerts?.filter(a => a.severity === 'LOW').length || 0}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between text-sm font-medium">
                    <span>Total:</span>
                    <span>{statistics.alerts?.length || 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Main Content Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <div className="flex items-center justify-between">
            <TabsList>
              <TabsTrigger value="packets" className="flex items-center gap-2">
                <Network className="h-4 w-4" />
                Network Packets
                <Badge variant="outline" className="ml-2">
                  {getFilteredPackets().length}
                </Badge>
              </TabsTrigger>
              <TabsTrigger value="alerts" className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                Security Alerts
                <Badge variant="outline" className="ml-2">
                  {getFilteredAlerts().length}
                </Badge>
              </TabsTrigger>
            </TabsList>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Label htmlFor="auto-scroll" className="text-sm whitespace-nowrap">Auto-scroll</Label>
                <Switch
                  id="auto-scroll"
                  checked={autoScroll}
                  onCheckedChange={setAutoScroll}
                />
              </div>
              <div className="flex items-center gap-2">
                <Label htmlFor="limit" className="text-sm whitespace-nowrap">Show:</Label>
                <select
                  id="limit"
                  value={packetLimitDisplay}
                  onChange={(e) => setPacketLimitDisplay(Number(e.target.value))}
                  className="text-sm border rounded px-2 py-1 bg-background"
                >
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                  <option value={250}>250</option>
                  <option value={500}>500</option>
                </select>
              </div>
            </div>
          </div>

          {/* Search and Filters */}
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={`Search ${activeTab === 'packets' ? 'packets by IP, port, or protocol...' : 'alerts by type or message...'}`}
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                className="pl-8"
              />
            </div>
            {activeTab === 'packets' ? (
              <Select value={filterProtocol} onValueChange={setFilterProtocol}>
                <SelectTrigger className="w-[180px]">
                  <Filter className="mr-2 h-4 w-4" />
                  <SelectValue placeholder="Filter by protocol" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Protocols</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                  <SelectItem value="other">Other</SelectItem>
                </SelectContent>
              </Select>
            ) : (
              <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                <SelectTrigger className="w-[180px]">
                  <Filter className="mr-2 h-4 w-4" />
                  <SelectValue placeholder="Filter by severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            )}
          </div>

          {/* Packets Tab */}
          <TabsContent value="packets" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Real-time Network Packets</span>
                  <span className="text-sm font-normal text-muted-foreground">
                    Showing {getPaginatedData().length} of {getFilteredPackets().length} packets
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!monitorStatus.is_monitoring ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <Network className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Start network monitoring to see real-time packets</p>
                  </div>
                ) : getFilteredPackets().length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <p>No packets captured yet. Network traffic will appear here in real-time.</p>
                  </div>
                ) : (
                  <>
                    <ScrollArea className="h-[400px] w-full rounded-md border">
                      <Table>
                        <TableHeader className="sticky top-0 bg-background">
                          <TableRow>
                            <TableHead className="w-[120px]">Time</TableHead>
                            <TableHead className="w-[150px]">Source IP</TableHead>
                            <TableHead className="w-[150px]">Destination IP</TableHead>
                            <TableHead className="w-[100px]">Protocol</TableHead>
                            <TableHead className="w-[100px]">Source Port</TableHead>
                            <TableHead className="w-[100px]">Dest Port</TableHead>
                            <TableHead className="w-[80px]">Size</TableHead>
                            <TableHead className="w-[100px]">Flags</TableHead>
                            <TableHead className="w-[80px]">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {getPaginatedData().map((packet) => (
                            <TableRow
                              key={packet.id}
                              onClick={() => setSelectedPacket(packet)}
                              className="cursor-pointer hover:bg-muted/50"
                            >
                              <TableCell className="font-mono text-sm">
                                {formatTime(packet.timestamp)}
                              </TableCell>
                              <TableCell className="font-mono text-sm" title={packet.src_ip}>
                                {packet.src_ip}
                              </TableCell>
                              <TableCell className="font-mono text-sm" title={packet.dst_ip}>
                                {packet.dst_ip}
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className={getProtocolColor(packet.protocol)}>
                                  {packet.protocol}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-mono text-sm">
                                {packet.src_port || '-'}
                              </TableCell>
                              <TableCell className="font-mono text-sm">
                                {packet.dst_port || '-'}
                              </TableCell>
                              <TableCell className="font-mono text-sm">
                                {packet.size} B
                              </TableCell>
                              <TableCell>
                                {packet.flags && (
                                  <div className="flex gap-1">
                                    {packet.flags.syn && <Badge variant="outline" className="text-xs">SYN</Badge>}
                                    {packet.flags.ack && <Badge variant="outline" className="text-xs">ACK</Badge>}
                                    {packet.flags.fin && <Badge variant="outline" className="text-xs">FIN</Badge>}
                                    {packet.flags.rst && <Badge variant="outline" className="text-xs">RST</Badge>}
                                  </div>
                                )}
                              </TableCell>
                              <TableCell>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPacket(packet);
                                  }}
                                >
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                          <div ref={eventsEndRef} />
                        </TableBody>
                      </Table>
                    </ScrollArea>

                    {/* Pagination */}
                    {getTotalPages() > 1 && (
                      <div className="flex items-center justify-between mt-4">
                        <div className="text-sm text-muted-foreground">
                          Page {currentPage} of {getTotalPages()}
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                            disabled={currentPage === 1}
                          >
                            <ChevronLeft className="h-4 w-4" />
                            Previous
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setCurrentPage(prev => Math.min(getTotalPages(), prev + 1))}
                            disabled={currentPage === getTotalPages()}
                          >
                            Next
                            <ChevronRight className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Alerts Tab */}
          <TabsContent value="alerts" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Security Alerts</span>
                  <span className="text-sm font-normal text-muted-foreground">
                    {getFilteredAlerts().length} alerts detected
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!monitorStatus.is_monitoring ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Start network monitoring to see security alerts</p>
                  </div>
                ) : getFilteredAlerts().length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <div className="flex items-center justify-center gap-2 mb-2">
                      <Shield className="h-6 w-6 text-green-500" />
                      <p>No security alerts detected</p>
                    </div>
                    <p className="text-sm">Network traffic is currently secure</p>
                  </div>
                ) : (
                  <>
                    <ScrollArea className="h-[400px] w-full rounded-md border">
                      <Table>
                        <TableHeader className="sticky top-0 bg-background">
                          <TableRow>
                            <TableHead className="w-[120px]">Time</TableHead>
                            <TableHead className="w-[100px]">Severity</TableHead>
                            <TableHead className="w-[150px]">Type</TableHead>
                            <TableHead>Message</TableHead>
                            <TableHead className="w-[80px]">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {getPaginatedData().map((alert: any) => (
                            <TableRow
                              key={alert.id}
                              onClick={() => setSelectedAlert(alert)}
                              className={`cursor-pointer hover:bg-muted/50 ${alert.severity === 'HIGH' ? 'bg-red-50 hover:bg-red-100 dark:bg-red-950/20' :
                                  alert.severity === 'MEDIUM' ? 'bg-yellow-50 hover:bg-yellow-100 dark:bg-yellow-950/20' :
                                    'bg-blue-50 hover:bg-blue-100 dark:bg-blue-950/20'
                                }`}
                            >
                              <TableCell className="font-mono text-sm">
                                {formatTime(alert.timestamp)}
                              </TableCell>
                              <TableCell>
                                <Badge variant={getSeverityColor(alert.severity)} className="flex items-center gap-1">
                                  {getSeverityIcon(alert.severity)}
                                  {alert.severity}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-medium">
                                {alert.type}
                              </TableCell>
                              <TableCell className="max-w-md truncate" title={alert.message}>
                                {alert.message}
                              </TableCell>
                              <TableCell>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedAlert(alert);
                                  }}
                                >
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </TableCell>
                            </TableRow>
                          ))}
                          <div ref={eventsEndRef} />
                        </TableBody>
                      </Table>
                    </ScrollArea>

                    {/* Pagination */}
                    {getTotalPages() > 1 && (
                      <div className="flex items-center justify-between mt-4">
                        <div className="text-sm text-muted-foreground">
                          Page {currentPage} of {getTotalPages()}
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                            disabled={currentPage === 1}
                          >
                            <ChevronLeft className="h-4 w-4" />
                            Previous
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setCurrentPage(prev => Math.min(getTotalPages(), prev + 1))}
                            disabled={currentPage === getTotalPages()}
                          >
                            Next
                            <ChevronRight className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Packet Details Dialog */}
        <Dialog open={!!selectedPacket} onOpenChange={() => setSelectedPacket(null)}>
          <DialogContent className="max-w-3xl">
            <DialogHeader>
              <DialogTitle>Packet Details</DialogTitle>
              <DialogDescription>
                Complete information about the network packet
              </DialogDescription>
            </DialogHeader>
            {selectedPacket && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Timestamp</Label>
                    <div className="mt-1 p-2 bg-muted rounded text-sm">
                      {new Date(selectedPacket.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">Protocol</Label>
                    <div className="mt-1">
                      <Badge variant="outline" className={getProtocolColor(selectedPacket.protocol)}>
                        {selectedPacket.protocol} (ID: {selectedPacket.protocol_num})
                      </Badge>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Source IP</Label>
                    <div className="mt-1 p-2 bg-muted rounded font-mono text-sm">
                      {selectedPacket.src_ip}
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">Destination IP</Label>
                    <div className="mt-1 p-2 bg-muted rounded font-mono text-sm">
                      {selectedPacket.dst_ip}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Source Port</Label>
                    <div className="mt-1 p-2 bg-muted rounded font-mono text-sm">
                      {selectedPacket.src_port || 'N/A'}
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">Destination Port</Label>
                    <div className="mt-1 p-2 bg-muted rounded font-mono text-sm">
                      {selectedPacket.dst_port || 'N/A'}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Packet Size</Label>
                    <div className="mt-1 p-2 bg-muted rounded text-sm">
                      {selectedPacket.size} bytes ({formatBytes(selectedPacket.size)})
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">TTL</Label>
                    <div className="mt-1 p-2 bg-muted rounded text-sm">
                      {selectedPacket.ttl || 'N/A'}
                    </div>
                  </div>
                </div>

                {selectedPacket.flags && (
                  <div>
                    <Label className="text-sm font-semibold">TCP Flags</Label>
                    <div className="mt-1 p-2 bg-muted rounded">
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(selectedPacket.flags).map(([flag, value]) => (
                          value && (
                            <Badge key={flag} variant="outline" className="capitalize">
                              {flag.toUpperCase()}
                            </Badge>
                          )
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <Label className="text-sm font-semibold">Raw Packet Data</Label>
                  <pre className="mt-1 p-2 bg-muted rounded text-xs overflow-auto max-h-32">
                    {JSON.stringify(selectedPacket, null, 2)}
                  </pre>
                </div>
              </div>
            )}
            <DialogFooter>
              <Button variant="outline" onClick={() => setSelectedPacket(null)}>
                Close
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Alert Details Dialog */}
        <Dialog open={!!selectedAlert} onOpenChange={() => setSelectedAlert(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Security Alert Details</DialogTitle>
              <DialogDescription>
                Complete information about the security alert
              </DialogDescription>
            </DialogHeader>
            {selectedAlert && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Timestamp</Label>
                    <div className="mt-1 p-2 bg-muted rounded text-sm">
                      {new Date(selectedAlert.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">Severity</Label>
                    <div className="mt-1">
                      <Badge variant={getSeverityColor(selectedAlert.severity)} className="flex items-center gap-1 w-fit">
                        {getSeverityIcon(selectedAlert.severity)}
                        {selectedAlert.severity}
                      </Badge>
                    </div>
                  </div>
                </div>

                <div>
                  <Label className="text-sm font-semibold">Alert Type</Label>
                  <div className="mt-1 p-2 bg-muted rounded font-mono text-sm">
                    {selectedAlert.type}
                  </div>
                </div>

                <div>
                  <Label className="text-sm font-semibold">Message</Label>
                  <div className="mt-1 p-2 bg-muted rounded">
                    {selectedAlert.message}
                  </div>
                </div>

                <div>
                  <Label className="text-sm font-semibold">Alert ID</Label>
                  <div className="mt-1 p-2 bg-muted rounded font-mono text-xs break-all">
                    {selectedAlert.id}
                  </div>
                </div>
              </div>
            )}
            <DialogFooter>
              <Button variant="outline" onClick={() => setSelectedAlert(null)}>
                Close
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
};

export default NetworkMonitoring;
