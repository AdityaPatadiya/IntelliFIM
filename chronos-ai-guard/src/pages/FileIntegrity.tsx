import { useState, useEffect } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { DashboardLayout } from '@/components/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Plus, RefreshCw, Undo2, Eye, Play, Square, Shield, ArrowUpDown, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription } from '@/components/ui/alert';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface FileChange {
  path: string;
  hash: string;
  last_modified: string | null;
  type: string;
  detected_at: string | null;
  status: 'added' | 'modified' | 'deleted';
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
  const itemsPerPage = 10;

  const getAuthHeaders = () => {  // used for authenticated API requests
    const token = localStorage.getItem('access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
    };
  };

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
      fetchStatus();
    } catch (error: any) {
      toast.error(error.message || 'Failed to start monitoring');
    }
  };

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
      fetchStatus();
    } catch (error) {
      toast.error('Failed to stop monitoring');
    }
  };

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

  useEffect(() => {
    fetchStatus();
    fetchChanges();
    fetchBaseline();

    // Poll for changes every 30 seconds
    const interval = setInterval(() => {
      if (fimStatus.is_monitoring) {
        fetchChanges();
        fetchBaseline();
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [fimStatus.is_monitoring]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'added': return 'default';
      case 'modified': return 'secondary';
      case 'deleted': return 'destructive';
      default: return 'default';
    }
  };

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
            <p className="text-muted-foreground">Monitor and track file system changes</p>
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
              <span>
                <strong>Status:</strong> {fimStatus.is_monitoring ? 'Monitoring Active' : 'Monitoring Stopped'} |
                <strong> Watched Directories:</strong> {fimStatus.total_watched} |
                <strong> Monitored Files:</strong> {baselineFiles.length}
              </span>
              <Button variant="ghost" size="sm" onClick={fetchChanges}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </AlertDescription>
        </Alert>

        {/* File Changes Table */}
        <Card>
          <CardHeader>
            <CardTitle>Detected Changes ({fileChanges.length})</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8">Loading changes...</div>
            ) : fileChanges.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No changes detected. Start monitoring to track file integrity.
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
                      <TableCell className="font-mono text-sm">{file.path}</TableCell>
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
