import { DashboardLayout } from '@/components/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { mockDashboardStats, mockChartData } from '@/lib/mockData';
import { Activity, FileWarning, AlertTriangle, Shield, ShieldCheck, Zap, Database, TrendingUp, TrendingDown } from 'lucide-react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const COLORS = ['hsl(var(--destructive))', 'hsl(var(--warning))', 'hsl(var(--chart-3))', 'hsl(var(--success))'];

const mockThreatTrends = [
  { time: '00:00', threats: 2 },
  { time: '04:00', threats: 4 },
  { time: '08:00', threats: 3 },
  { time: '12:00', threats: 5 },
  { time: '16:00', threats: 8 },
  { time: '20:00', threats: 6 },
  { time: '24:00', threats: 12 },
];

const mockFileChanges = [
  { day: 'Mon', created: 12, deleted: 3, modified: 6 },
  { day: 'Tue', created: 15, deleted: 4, modified: 8 },
  { day: 'Wed', created: 10, deleted: 2, modified: 12 },
  { day: 'Thu', created: 18, deleted: 1, modified: 4 },
  { day: 'Fri', created: 24, deleted: 5, modified: 18 },
  { day: 'Sat', created: 8, deleted: 2, modified: 6 },
  { day: 'Sun', created: 4, deleted: 1, modified: 3 },
];

const mockRecentAlerts = [
  {
    type: 'critical',
    title: 'Suspicious File Modification',
    description: 'Multiple attempts to modify system files detected',
    severity: 'Critical',
    agent: 'AGENT-001',
    time: '2024-11-13 14:32:15'
  },
  {
    type: 'high',
    title: 'Unusual Network Activity',
    description: 'Outbound connection to unknown IP detected',
    severity: 'High',
    agent: 'AGENT-003',
    time: '2024-11-13 13:28:42'
  },
  {
    type: 'medium',
    title: 'Failed Login Attempt',
    description: 'Multiple failed authentication attempts',
    severity: 'Medium',
    agent: 'AGENT-002',
    time: '2024-11-13 12:15:30'
  },
];

const Dashboard = () => {
  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold">Dashboard</h1>
              <Badge variant="outline">Mock data — v2</Badge>
            </div>
            <p className="text-muted-foreground">System overview and security metrics</p>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className="bg-card border-border">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Active Agents</p>
                  <p className="text-4xl font-bold mb-2">24</p>
                  <div className="flex items-center text-xs">
                    <TrendingUp className="h-3 w-3 text-destructive mr-1" />
                    <span className="text-destructive">+2 from last week</span>
                  </div>
                </div>
                <div className="p-3 bg-primary/20 rounded-lg">
                  <ShieldCheck className="h-6 w-6 text-primary" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Threats Detected</p>
                  <p className="text-4xl font-bold mb-2">12</p>
                  <div className="flex items-center text-xs">
                    <TrendingDown className="h-3 w-3 text-success mr-1" />
                    <span className="text-success">+3 from last week</span>
                  </div>
                </div>
                <div className="p-3 bg-primary/20 rounded-lg">
                  <AlertTriangle className="h-6 w-6 text-primary" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Files Monitored</p>
                  <p className="text-4xl font-bold mb-2">4,231</p>
                  <div className="flex items-center text-xs">
                    <TrendingUp className="h-3 w-3 text-destructive mr-1" />
                    <span className="text-destructive">+156 from last week</span>
                  </div>
                </div>
                <div className="p-3 bg-primary/20 rounded-lg">
                  <Database className="h-6 w-6 text-primary" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Prevention Actions</p>
                  <p className="text-4xl font-bold mb-2">8</p>
                  <div className="flex items-center text-xs">
                    <TrendingDown className="h-3 w-3 text-success mr-1" />
                    <span className="text-success">-2 from last week</span>
                  </div>
                </div>
                <div className="p-3 bg-primary/20 rounded-lg">
                  <Zap className="h-6 w-6 text-primary" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Charts */}
        <div className="grid gap-4 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>File Changes Over Time</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={mockChartData.fileChanges}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" />
                  <YAxis stroke="hsl(var(--muted-foreground))" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      border: '1px solid hsl(var(--border))',
                      color: 'hsl(var(--foreground))'
                    }} 
                  />
                  <Legend />
                  <Line type="monotone" dataKey="changes" stroke="hsl(var(--primary))" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Network Traffic Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={mockChartData.networkTraffic}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" />
                  <YAxis stroke="hsl(var(--muted-foreground))" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      border: '1px solid hsl(var(--border))',
                      color: 'hsl(var(--foreground))'
                    }} 
                  />
                  <Legend />
                  <Bar dataKey="normal" fill="hsl(var(--success))" />
                  <Bar dataKey="suspicious" fill="hsl(var(--destructive))" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Anomaly Severity Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={mockChartData.severityDistribution}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }: any) => `${name}: ${((percent || 0) * 100).toFixed(0)}%`}
                    outerRadius={100}
                    fill="hsl(var(--primary))"
                    dataKey="value"
                  >
                    {mockChartData.severityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'hsl(var(--card))', 
                      border: '1px solid hsl(var(--border))',
                      color: 'hsl(var(--foreground))'
                    }} 
                  />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
