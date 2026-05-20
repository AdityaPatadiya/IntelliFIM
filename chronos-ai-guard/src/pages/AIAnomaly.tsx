import { DashboardLayout } from '@/components/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { mockAnomalies } from '@/lib/mockData';
import { Brain, RefreshCw, Download, Settings } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';

const AIAnomaly = () => {
  const { user } = useAuth();
  const { toast } = useToast();

  const handleRetrainModel = () => {
    if (user?.role !== 'admin') {
      toast({ 
        title: 'Access Denied', 
        description: 'Only administrators can retrain the AI model',
        variant: 'destructive'
      });
      return;
    }
    toast({ title: 'Model retraining initiated' });
  };

  const handleAdjustSensitivity = () => {
    if (user?.role !== 'admin') {
      toast({ 
        title: 'Access Denied', 
        description: 'Only administrators can adjust sensitivity',
        variant: 'destructive'
      });
      return;
    }
    toast({ title: 'Sensitivity adjustment panel opened' });
  };

  const handleExportResults = () => {
    const csvContent = [
      ['Type', 'Severity', 'Confidence', 'Feature', 'Timestamp'].join(','),
      ...mockAnomalies.map(a => 
        [a.type, a.severity, (a.confidence * 100).toFixed(1) + '%', a.feature, a.timestamp].join(',')
      )
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai_anomalies_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    toast({ title: 'Results exported successfully' });
  };
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'secondary';
      case 'medium': return 'default';
      default: return 'outline';
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold">AI Anomaly Detection (Row Data Displayed) Dynamic feature comming soon...</h1>
              <Badge variant="outline">Mock data — v2</Badge>
            </div>
            <p className="text-muted-foreground">Machine learning-powered threat detection</p>
          </div>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              size="sm"
              onClick={handleRetrainModel}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Retrain Model
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={handleAdjustSensitivity}
            >
              <Settings className="mr-2 h-4 w-4" />
              Adjust Sensitivity
            </Button>
            <Button size="sm" onClick={handleExportResults}>
              <Download className="mr-2 h-4 w-4" />
              Export Results
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Model Version</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">v2.4.1</div>
              <p className="text-xs text-muted-foreground">Latest stable</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Accuracy</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-success">96.8%</div>
              <p className="text-xs text-muted-foreground">Validation set</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Threshold</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">0.75</div>
              <p className="text-xs text-muted-foreground">Detection sensitivity</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Last Retrained</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">2h ago</div>
              <p className="text-xs text-muted-foreground">2025-10-19 10:30</p>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5" />
              Top Anomalies Detected
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Feature</TableHead>
                  <TableHead>Timestamp</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mockAnomalies.map((anomaly) => (
                  <TableRow key={anomaly.id}>
                    <TableCell className="font-medium">{anomaly.type}</TableCell>
                    <TableCell>
                      <Badge variant={getSeverityColor(anomaly.severity)}>
                        {anomaly.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-sm">{(anomaly.confidence * 100).toFixed(1)}%</span>
                    </TableCell>
                    <TableCell className="max-w-xs truncate">{anomaly.feature}</TableCell>
                    <TableCell className="text-sm">{anomaly.timestamp}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm">
                        View Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default AIAnomaly;
