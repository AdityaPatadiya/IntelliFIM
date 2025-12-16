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
import { Plus, RefreshCw, Undo2, Eye, Play, Square, Shield, ArrowUpDown, Search, ChevronLeft, ChevronRight, Trash2, Clock, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { ScrollArea } from '@/components/ui/scroll-area';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface FileChange {
  path: string;
  hash: string;
  last_modified: string | null;
  type: string;
  detected_at: string | null;
  status: 'added' | 'modified' | 'deleted';
}

interface RealTimeEvent {
  type: 'added' | 'modified' | 'deleted';
  path: string;
  details: {
    hash?: string;
    timestamp: string;
  };
  receivedAt: string;
  id: string;
}

interface FIMStatus {
  is_monitoring: boolean;
  watched_directories: string[];
  total_watched: number;
}

interface BaselineFile {
  path: string;
  type: string;
  hash: string;
  last_modified: string | null;
  detected_at: string | null;
}

const FileIntegrity = () => {
  const { user } = useAuth();
  const [fileChanges, setFileChanges] = useState<FileChange[]>([]);
  const [realTimeEvents, setRealTimeEvents] = useState<RealTimeEvent[]>([]);
  const [fimStatus, setFimStatus] = useState<FIMStatus>({ is_monitoring: false, watched_directories: [], total_watched: 0 });
  const [loading, setLoading] = useState(false);
  const [newDirectory, setNewDirectory] = useState('');
  const [startDirectories, setStartDirectories] = useState('');
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [isStartDialogOpen, setIsStartDialogOpen] = useState(false);
  const [baselineFiles, setBaselineFiles] = useState<BaselineFile[]>([]);
  const [loadingBaseline, setLoadingBaseline] = useState(false);
  const [sortField, setSortField] = useState<'type' | 'detected_at' | 'last_modified' | null>(null);
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedFile, setSelectedFile] = useState<BaselineFile | null>(null);
  const [autoScrollRealTime, setAutoScrollRealTime] = useState(true);
  const [realTimeLimit, setRealTimeLimit] = useState(50);
  const itemsPerPage = 10;
  const eventsEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
    };
  };

  const eventCounterRef = useRef(0);
  // Generate unique ID for real-time events
  const generateEventId = () => {
    eventCounterRef.current += 1;
    return `${Date.now()}_${eventCounterRef.current}`;
  };

  // Fetch status
  const fetchStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/api/fim/status`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch status');
      const data = await response.json();
      setFimStatus(data);
    } catch (error) {
      console.error('Error fetching FIM status:', error);
    }
  };

  // Fetch changes from database
  const fetchChanges = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_URL}/api/fim/changes`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch changes');
      const data = await response.json();

      // Convert changes object to array
      const changes: FileChange[] = [];

      Object.entries(data.added).forEach(([path, info]: [string, any]) => {
        changes.push({ path, ...info, status: 'added' });
      });

      Object.entries(data.modified).forEach(([path, info]: [string, any]) => {
        changes.push({ path, ...info, status: 'modified' });
      });

      Object.entries(data.deleted).forEach(([path, info]: [string, any]) => {
        changes.push({ path, ...info, status: 'deleted' });
      });

      setFileChanges(changes);
    } catch (error) {
      console.error('Error fetching changes:', error);
      toast.error('Failed to fetch file changes');
    } finally {
      setLoading(false);
    }
  };

  // Fetch baseline
  const fetchBaseline = async () => {
    try {
      setLoadingBaseline(true);
      const response = await fetch(`${API_URL}/api/fim/baseline`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) throw new Error('Failed to fetch baseline');
      const data = await response.json();

      // Convert baseline object to array
      const files: BaselineFile[] = [];

      Object.entries(data.baseline).forEach(([directory, items]: [string, any]) => {
        Object.entries(items).forEach(([path, info]: [string, any]) => {
          files.push({
            path,
            type: info.type || 'unknown',
            hash: info.hash || '',
            last_modified: info.last_modified || null,
            detected_at: info.detected_at || null
          });
        });
      });

      setBaselineFiles(files);
    } catch (error) {
      console.error('Error fetching baseline:', error);
      toast.error('Failed to fetch monitored files');
    } finally {
      setLoadingBaseline(false);
    }
  };

  // Setup EventSource for real-time events
  const setupEventSource = () => {
    // Close existing connection if any
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }

    try {
      const eventSource = new EventSource(`${API_URL}/api/fim/stream`, {
        withCredentials: true,
      });

      eventSource.onopen = () => {
        console.log('FIM EventSource connection opened');
        toast.success('Real-time monitoring connected');
      };

      eventSource.onmessage = (event) => {
        try {
          console.log('Raw SSE event data:', event.data);

          // Handle the SSE format: "data: {json}\n\n"
          let dataString = event.data;

          if (dataString.startsWith('data: ')) {
            dataString = dataString.substring(6);
            dataString = dataString.trim();

            const data = JSON.parse(dataString);
            console.log('Parsed SSE event:', data);

            const newEvent: RealTimeEvent = {
              type: data.type,
              path: data.path,
              details: data.details || {},
              receivedAt: new Date().toISOString(),
              id: generateEventId()
            };

            setRealTimeEvents(prev => {
              const updated = [newEvent, ...prev];
              return updated.slice(0, realTimeLimit);
            });

            const eventType = data.type.charAt(0).toUpperCase() + data.type.slice(1);
            toast.info(`${eventType}: ${data.path}`, {
              duration: 3000,
              icon: <AlertCircle className="h-4 w-4" />,
            });

          } else {
            console.warn('Unexpected SSE format:', dataString);
          }

        } catch (error) {
          console.error('Error parsing SSE event:', error, 'Raw data:', event.data);
          try {
            const data = JSON.parse(event.data.trim());
            console.log('Parsed as raw JSON:', data);

            const newEvent: RealTimeEvent = {
              type: data.type,
              path: data.path,
              details: data.details || {},
              receivedAt: new Date().toISOString(),
              id: generateEventId()
            };

            setRealTimeEvents(prev => [newEvent, ...prev.slice(0, realTimeLimit - 1)]);
          } catch (e) {
            console.error('Failed to parse as raw JSON:', e);
          }
        }
      };

      eventSource.onerror = (error) => {
        console.error('EventSource error:', error);

        if (eventSource.readyState === EventSource.CLOSED) {
          toast.error('Real-time connection closed');
        } else if (eventSource.readyState === EventSource.CONNECTING) {
          console.log('EventSource reconnecting...');
        }

        // Attempt reconnect after 3 seconds if monitoring is active
        if (fimStatus.is_monitoring) {
          setTimeout(() => {
            if (fimStatus.is_monitoring && (!eventSourceRef.current || eventSourceRef.current.readyState === EventSource.CLOSED)) {
              console.log('Attempting to reconnect EventSource...');
              setupEventSource();
            }
          }, 3000);
        }
      };

      eventSourceRef.current = eventSource;

    } catch (error) {
      console.error('Failed to create EventSource:', error);
    }
  };

  // Clear real-time events
  const clearRealTimeEvents = () => {
    setRealTimeEvents([]);
    eventCounterRef.current = 0;
    toast.success('Real-time events cleared');
  };

  // Handle start monitoring
  const handleStartMonitoring = async () => {
    if (!startDirectories.trim()) {
      toast.error('Please enter at least one directory');
      return;
    }

    try {
      const directories = startDirectories.split(',').map(d => d.trim()).filter(d => d);

      const response = await fetch(`${API_URL}/api/fim/start`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ directories, excluded_files: [] }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to start monitoring');
      }

      const data = await response.json();
      toast.success(data.message);
      setIsStartDialogOpen(false);
      setStartDirectories('');

      // Clear previous real-time events
      clearRealTimeEvents();

      // Fetch status and setup event source
      await fetchStatus();
      if (fimStatus.is_monitoring) {
        setupEventSource();
      }
    } catch (error: any) {
      toast.error(error.message || 'Failed to start monitoring');
    }
  };

  const testSSEConnection = async () => {
    try {
      console.log('Testing SSE connection...');
      const response = await fetch(`${API_URL}/api/fim/stream`, {
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        console.error('SSE test failed with status:', response.status);
        return;
      }

      const reader = response.body?.getReader();
      if (!reader) {
        console.error('No reader available');
        return;
      }

      const decoder = new TextDecoder();
      console.log('SSE test connected, waiting for events...');

      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          console.log('SSE test stream ended');
          break;
        }

        const chunk = decoder.decode(value);
        console.log('SSE raw chunk:', chunk);

        // Parse each line
        const lines = chunk.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data: ')) {
            const jsonStr = trimmed.substring(6);
            console.log('SSE data line:', jsonStr);
            try {
              const data = JSON.parse(jsonStr);
              console.log('Parsed SSE data:', data);
            } catch (e) {
              console.error('Failed to parse JSON:', e, 'String:', jsonStr);
            }
          }
        }
      }
    } catch (error) {
      console.error('SSE test error:', error);
    }
  };

  // Handle stop monitoring
  const handleStopMonitoring = async () => {
    try {
      const response = await fetch(`${API_URL}/api/fim/stop`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ directories: fimStatus.watched_directories }),
      });

      if (!response.ok) throw new Error('Failed to stop monitoring');

      const data = await response.json();
      toast.success(data.message);

      // Close EventSource connection
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }

      fetchStatus();
    } catch (error) {
      toast.error('Failed to stop monitoring');
    }
  };

  // Handle add directory
  const handleAddDirectory = async () => {
    if (!newDirectory.trim()) {
      toast.error('Please enter a directory path');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/fim/add-path`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ directory: newDirectory }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to add directory');
      }

      const data = await response.json();
      toast.success(data.message);
      setIsAddDialogOpen(false);
      setNewDirectory('');
      fetchStatus();
    } catch (error: any) {
      toast.error(error.message || 'Failed to add directory');
    }
  };

  // Handle rebuild baseline
  const handleRebuildBaseline = async () => {
    if (fimStatus.watched_directories.length === 0) {
      toast.error('No directories are being monitored');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/fim/reset-baseline`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          directories: fimStatus.watched_directories,
          excluded_files: []
        }),
      });

      if (!response.ok) throw new Error('Failed to rebuild baseline');

      const data = await response.json();
      toast.success(data.message);
      fetchChanges();
    } catch (error) {
      toast.error('Failed to rebuild baseline');
    }
  };

  // Handle restore
  const handleRestore = async (path: string) => {
    try {
      const response = await fetch(`${API_URL}/api/fim/restore`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ path_to_restore: path }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to restore file');
      }

      const data = await response.json();
      toast.success(data.message);
      fetchChanges();
    } catch (error: any) {
      toast.error(error.message || 'Failed to restore file');
    }
  };

  // Format timestamp
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      // hour12: true
    });
  };

  // Get status color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'added': return 'default';
      case 'modified': return 'secondary';
      case 'deleted': return 'destructive';
      default: return 'default';
    }
  };

  // Auto-scroll to bottom of real-time events
  useEffect(() => {
    if (autoScrollRealTime && eventsEndRef.current) {
      eventsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [realTimeEvents, autoScrollRealTime]);

  // Setup and cleanup
  useEffect(() => {
    // Initial fetch
    fetchStatus();
    fetchChanges();
    fetchBaseline();

    // Set up polling intervals
    const statusInterval = setInterval(() => {
      fetchStatus();
      fetchBaseline();
    }, 60000);

    const changesInterval = setInterval(() => {
      if (fimStatus.is_monitoring) {
        fetchChanges();
      }
    }, 30000);

    // Cleanup function
    return () => {
      console.log('Cleaning up FIM intervals and EventSource');
      clearInterval(statusInterval);
      clearInterval(changesInterval);

      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, []);

  // Handle monitoring status changes
  useEffect(() => {
    if (fimStatus.is_monitoring) {
      setupEventSource();
      // testSSEConnection();
    } else {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    }
  }, [fimStatus.is_monitoring]);

  const handleSort = (field: 'type' | 'detected_at' | 'last_modified') => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const getFilteredAndSortedFiles = () => {
    let filtered = baselineFiles;

    // Apply search filter
    if (searchQuery.trim()) {
      filtered = filtered.filter(file =>
        file.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
        file.hash.toLowerCase().includes(searchQuery.toLowerCase()) ||
        file.type.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Apply sorting
    if (sortField) {
      filtered = [...filtered].sort((a, b) => {
        let aValue = a[sortField];
        let bValue = b[sortField];

        if (aValue === null) return sortOrder === 'asc' ? 1 : -1;
        if (bValue === null) return sortOrder === 'asc' ? -1 : 1;

        if (sortField === 'type') {
          return sortOrder === 'asc'
            ? aValue.localeCompare(bValue)
            : bValue.localeCompare(aValue);
        } else {
          return sortOrder === 'asc'
            ? new Date(aValue).getTime() - new Date(bValue).getTime()
            : new Date(bValue).getTime() - new Date(aValue).getTime();
        }
      });
    }

    return filtered;
  };

  const getPaginatedFiles = () => {
    const filtered = getFilteredAndSortedFiles();
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return filtered.slice(startIndex, endIndex);
  };

  const getTotalPages = () => {
    return Math.ceil(getFilteredAndSortedFiles().length / itemsPerPage);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">File Integrity Monitoring</h1>
            <p className="text-muted-foreground">Monitor and track file system changes in real-time</p>
          </div>
          <div className="flex gap-2">
            {fimStatus.is_monitoring ? (
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
                      <DialogTitle>Start FIM Monitoring</DialogTitle>
                      <DialogDescription>
                        Enter directories to monitor (comma-separated paths)
                      </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="directories">Directories</Label>
                        <Input
                          id="directories"
                          placeholder="/path/to/dir1, /path/to/dir2"
                          value={startDirectories}
                          onChange={(e) => setStartDirectories(e.target.value)}
                        />
                      </div>
                    </div>
                    <DialogFooter>
                      <Button onClick={handleStartMonitoring}>Start Monitoring</Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              )
            )}
            {user?.role === 'admin' && (
              <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Plus className="mr-2 h-4 w-4" />
                    Add Directory
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Directory to Monitor</DialogTitle>
                    <DialogDescription>
                      Enter the path of the directory you want to monitor
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="directory">Directory Path</Label>
                      <Input
                        id="directory"
                        placeholder="/path/to/directory"
                        value={newDirectory}
                        onChange={(e) => setNewDirectory(e.target.value)}
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button onClick={handleAddDirectory}>Add Directory</Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            )}

            {user?.role === 'admin' && (
              <Button variant="outline" size="sm" onClick={handleRebuildBaseline}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Rebuild Baseline
              </Button>
            )}
          </div>
        </div>

        {/* Status Alert */}
        <Alert>
          <Shield className="h-4 w-4" />
          <AlertDescription>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1">
                  <strong>Status:</strong>
                  <Badge
                    variant={fimStatus.is_monitoring ? "default" : "secondary"}
                    className="ml-2"
                  >
                    {fimStatus.is_monitoring ? 'Monitoring Active' : 'Monitoring Stopped'}
                  </Badge>
                </span>
                <span>
                  <strong>Watched Directories:</strong> {fimStatus.total_watched}
                </span>
                <span>
                  <strong>Monitored Files:</strong> {baselineFiles.length}
                </span>
                <span>
                  <strong>Real-time Events:</strong> {realTimeEvents.length}
                </span>
              </div>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={fetchChanges}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
                {realTimeEvents.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={clearRealTimeEvents}>
                    <Trash2 className="h-4 w-4 mr-2" />
                    Clear Events
                  </Button>
                )}
              </div>
            </div>
          </AlertDescription>
        </Alert>

        {/* Real-time Events Section */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Real-time Events ({realTimeEvents.length})
              </CardTitle>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Label htmlFor="auto-scroll" className="text-sm">Auto-scroll</Label>
                  <Switch
                    id="auto-scroll"
                    checked={autoScrollRealTime}
                    onCheckedChange={setAutoScrollRealTime}
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Label htmlFor="event-limit" className="text-sm">Max Events:</Label>
                  <select
                    id="event-limit"
                    value={realTimeLimit}
                    onChange={(e) => setRealTimeLimit(Number(e.target.value))}
                    className="text-sm border rounded px-2 py-1 bg-background"
                  >
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={250}>250</option>
                  </select>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {!fimStatus.is_monitoring ? (
              <div className="text-center py-8 text-muted-foreground">
                Start monitoring to see real-time events
              </div>
            ) : realTimeEvents.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                Waiting for file system events... Make changes to monitored directories to see them here.
              </div>
            ) : (
              <div className="relative">
                <ScrollArea className="h-[300px] w-full rounded-md border">
                  <Table>
                    <TableHeader className="sticky top-0 bg-background">
                      <TableRow>
                        <TableHead className="w-[120px] font-semibold">Time</TableHead>
                        <TableHead className="w-[100px] font-semibold">Type</TableHead>
                        <TableHead className="min-w-[300px] font-semibold">Path</TableHead>
                        <TableHead className="w-[150px] font-semibold">Hash</TableHead>
                        <TableHead className="w-[180px] font-semibold">Changed At</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {realTimeEvents.map((event) => (
                        <TableRow
                          key={event.id}
                          className={
                            event.type === 'added' ? 'bg-green-50 hover:bg-green-100 dark:bg-green-950/20 dark:hover:bg-green-900/30' :
                              event.type === 'modified' ? 'bg-amber-50 hover:bg-amber-100 dark:bg-amber-950/20 dark:hover:bg-amber-900/30' :
                                'bg-red-50 hover:bg-red-100 dark:bg-red-950/20 dark:hover:bg-red-900/30'
                          }
                        >
                          <TableCell className="py-3">
                            <div className="text-sm font-medium text-gray-900 dark:text-gray-100">
                              {formatTime(event.receivedAt)}
                            </div>
                          </TableCell>
                          <TableCell className="py-3">
                            <Badge
                              variant={
                                event.type === 'added' ? 'default' :
                                  event.type === 'modified' ? 'secondary' :
                                    'destructive'
                              }
                              className="capitalize font-medium"
                            >
                              {event.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="py-3">
                            <div className="font-mono text-sm truncate max-w-[300px]" title={event.path}>
                              {event.path}
                            </div>
                          </TableCell>
                          <TableCell className="py-3">
                            <div className="font-mono text-xs text-gray-600 dark:text-gray-400 truncate" title={event.details.hash}>
                              {event.details.hash ? `${event.details.hash.substring(0, 10)}...` : 'N/A'}
                            </div>
                          </TableCell>
                          <TableCell className="py-3">
                            <div className="text-sm text-gray-600 dark:text-gray-400">
                              {event.details.timestamp ?
                                new Date(event.details.timestamp).toLocaleTimeString('en-US', {
                                  hour: '2-digit',
                                  minute: '2-digit',
                                  second: '2-digit',
                                  hour12: true
                                }) :
                                'N/A'
                              }
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                      <div ref={eventsEndRef} />
                    </TableBody>
                  </Table>
                </ScrollArea>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Separator */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <Separator className="w-full" />
          </div>
          <div className="relative flex justify-center">
            <span className="bg-background px-4 text-sm text-muted-foreground">
              Historical Data
            </span>
          </div>
        </div>

        {/* Detected Changes Table (Historical) */}
        <Card>
          <CardHeader>
            <CardTitle>Detected Changes ({fileChanges.length})</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8">Loading changes...</div>
            ) : fileChanges.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No historical changes detected.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>File Path</TableHead>
                    <TableHead>Hash</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Modified</TableHead>
                    <TableHead>Detected At</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {fileChanges.map((file, index) => (
                    <TableRow key={index}>
                      <TableCell className="font-mono text-sm max-w-md truncate" title={file.path}>
                        {file.path}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {file.hash ? file.hash.substring(0, 12) + '...' : 'N/A'}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getStatusColor(file.status)}>
                          {file.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">{file.last_modified || 'N/A'}</TableCell>
                      <TableCell className="text-sm">{file.detected_at || 'N/A'}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toast.info(`File: ${file.path}\nHash: ${file.hash}\nType: ${file.type}`)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {file.status !== 'added' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleRestore(file.path)}
                            >
                              <Undo2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Watched Directories */}
        {fimStatus.watched_directories.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Monitored Directories</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {fimStatus.watched_directories.map((dir, index) => (
                  <div key={index} className="flex items-center justify-between p-2 bg-muted rounded">
                    <span className="font-mono text-sm">{dir}</span>
                    <Badge variant="outline">
                      {fimStatus.watched_directories?.includes(dir) ? 'Active' : 'Configured'}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Monitored Files (Baseline) */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Monitored Files ({getFilteredAndSortedFiles().length})</CardTitle>
              <div className="relative w-72">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by path, hash, or type..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="pl-8"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {loadingBaseline ? (
              <div className="text-center py-8">Loading monitored files...</div>
            ) : baselineFiles.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No files are being monitored. Start monitoring to see files here.
              </div>
            ) : getFilteredAndSortedFiles().length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No files match your search criteria.
              </div>
            ) : (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>File Path</TableHead>
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleSort('type')}
                          className="h-8 px-2"
                        >
                          Type
                          <ArrowUpDown className="ml-2 h-3 w-3" />
                        </Button>
                      </TableHead>
                      <TableHead>Hash</TableHead>
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleSort('last_modified')}
                          className="h-8 px-2"
                        >
                          Last Modified
                          <ArrowUpDown className="ml-2 h-3 w-3" />
                        </Button>
                      </TableHead>
                      <TableHead>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleSort('detected_at')}
                          className="h-8 px-2"
                        >
                          Detected At
                          <ArrowUpDown className="ml-2 h-3 w-3" />
                        </Button>
                      </TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {getPaginatedFiles().map((file, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono text-sm max-w-md truncate" title={file.path}>
                          {file.path}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{file.type}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {file.hash ? file.hash.substring(0, 16) + '...' : 'N/A'}
                        </TableCell>
                        <TableCell className="text-sm">{file.last_modified || 'N/A'}</TableCell>
                        <TableCell className="text-sm">{file.detected_at || 'N/A'}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedFile(file)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {/* Pagination */}
                {getTotalPages() > 1 && (
                  <div className="flex items-center justify-between mt-4">
                    <div className="text-sm text-muted-foreground">
                      Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, getFilteredAndSortedFiles().length)} of {getFilteredAndSortedFiles().length} files
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
                      <div className="text-sm">
                        Page {currentPage} of {getTotalPages()}
                      </div>
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

        {/* File Details Modal */}
        <Dialog open={!!selectedFile} onOpenChange={() => setSelectedFile(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>File Details</DialogTitle>
              <DialogDescription>
                Complete information about the monitored file
              </DialogDescription>
            </DialogHeader>
            {selectedFile && (
              <div className="space-y-4">
                <div>
                  <Label className="text-sm font-semibold">File Path</Label>
                  <div className="mt-1 p-2 bg-muted rounded font-mono text-sm break-all">
                    {selectedFile.path}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Type</Label>
                    <div className="mt-1">
                      <Badge variant="outline">{selectedFile.type}</Badge>
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">Status</Label>
                    <div className="mt-1">
                      <Badge>Monitored</Badge>
                    </div>
                  </div>
                </div>
                <div>
                  <Label className="text-sm font-semibold">Hash (SHA-256)</Label>
                  <div className="mt-1 p-2 bg-muted rounded font-mono text-xs break-all">
                    {selectedFile.hash || 'N/A'}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-semibold">Last Modified</Label>
                    <div className="mt-1 p-2 bg-muted rounded text-sm">
                      {selectedFile.last_modified || 'N/A'}
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-semibold">Detected At</Label>
                    <div className="mt-1 p-2 bg-muted rounded text-sm">
                      {selectedFile.detected_at || 'N/A'}
                    </div>
                  </div>
                </div>
              </div>
            )}
            <DialogFooter>
              <Button variant="outline" onClick={() => setSelectedFile(null)}>
                Close
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
};

export default FileIntegrity;
