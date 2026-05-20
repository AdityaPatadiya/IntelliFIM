import { DashboardLayout } from '@/components/DashboardLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { Save, Database } from 'lucide-react';

const SystemConfig = () => {
  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold">System Configuration</h1>
              <Badge variant="outline">Mock data — v2</Badge>
            </div>
            <p className="text-muted-foreground">Configure system settings and integrations</p>
          </div>
          <Button>
            <Save className="mr-2 h-4 w-4" />
            Save Changes
          </Button>
        </div>

        <div className="grid gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Monitoring Settings</CardTitle>
              <CardDescription>Configure file integrity and network monitoring intervals</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="fim-interval">FIM Scan Interval (seconds)</Label>
                <Input id="fim-interval" type="number" defaultValue="300" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="network-interval">Network Monitoring Interval (seconds)</Label>
                <Input id="network-interval" type="number" defaultValue="60" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="network-interface">Network Interface</Label>
                <Select defaultValue="eth0">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="eth0">eth0</SelectItem>
                    <SelectItem value="eth1">eth1</SelectItem>
                    <SelectItem value="wlan0">wlan0</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Isolation Method</CardTitle>
              <CardDescription>Configure how hosts are isolated when threats are detected</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="isolation-method">Isolation Method</Label>
                <Select defaultValue="firewall">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="firewall">Firewall Rules</SelectItem>
                    <SelectItem value="vlan">VLAN Isolation</SelectItem>
                    <SelectItem value="shutdown">System Shutdown</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="auto-isolate">Auto-Isolate Critical Threats</Label>
                <Switch id="auto-isolate" defaultChecked />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Alert Channels</CardTitle>
              <CardDescription>Configure notification channels for security alerts</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <Label htmlFor="email-alerts">Email Alerts</Label>
                <Switch id="email-alerts" defaultChecked />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <Label htmlFor="slack-alerts">Slack Notifications</Label>
                <Switch id="slack-alerts" />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <Label htmlFor="telegram-alerts">Telegram Notifications</Label>
                <Switch id="telegram-alerts" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Backup & Recovery</CardTitle>
              <CardDescription>Configure system backup settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <Label htmlFor="auto-backup">Automatic Backups</Label>
                <Switch id="auto-backup" defaultChecked />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="backup-interval">Backup Interval (hours)</Label>
                <Input id="backup-interval" type="number" defaultValue="24" />
              </div>
              <Button variant="outline" className="w-full">
                <Database className="mr-2 h-4 w-4" />
                Backup Now
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default SystemConfig;
