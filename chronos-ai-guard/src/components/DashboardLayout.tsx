import { ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth, UserRole } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { ThemeToggle } from '@/components/ThemeToggle';
import {
  LayoutDashboard,
  FileSearch,
  Network,
  Brain,
  AlertTriangle,
  Users,
  Settings,
  FileText,
  ScrollText,
  LogOut,
  Shield,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavItem {
  title: string;
  href: string;
  icon: React.ElementType;
  roles: UserRole[];
}

const navItems: NavItem[] = [
  { title: 'Dashboard', href: '/dashboard', icon: LayoutDashboard, roles: ['admin', 'analyst', 'viewer'] },
  { title: 'File Monitoring', href: '/file-integrity', icon: FileSearch, roles: ['admin', 'analyst', 'viewer'] },
  { title: 'Network Monitoring', href: '/network-monitoring', icon: Network, roles: ['admin', 'analyst', 'viewer'] },
  // { title: 'AI Anomaly Detection', href: '/ai-anomaly', icon: Brain, roles: ['admin', 'analyst', 'viewer'] },
  // { title: 'Incident Management', href: '/incidents', icon: AlertTriangle, roles: ['admin', 'analyst'] },
  
  { title: 'Employee Management', href: '/employees', icon: Users, roles: ['admin'] },
  { title: 'System Configuration', href: '/config', icon: Settings, roles: ['admin'] },
  { title: 'Reports & Analytics', href: '/reports', icon: FileText, roles: ['admin', 'analyst', 'viewer'] },
  { title: 'Logs & Audit', href: '/logs', icon: ScrollText, roles: ['admin', 'analyst', 'viewer'] },
];

export const DashboardLayout = ({ children }: { children: ReactNode }) => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const filteredNavItems = navItems.filter(item => 
    user && item.roles.includes(user.role)
  );

  return (
    <div className="flex h-screen w-full bg-background">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card">
        <div className="flex h-16 items-center gap-2 border-b border-border px-6">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-bold text-lg">IntelliFIM</span>
        </div>
        
        <ScrollArea className="flex-1 px-3 py-4">
          <nav className="space-y-1">
            {filteredNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.href;
              
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground font-medium'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {item.title}
                </Link>
              );
            })}
          </nav>
        </ScrollArea>

        <Separator />
        
        <div className="p-4">
          <div className="mb-3 rounded-lg bg-muted p-3">
            <p className="text-xs text-muted-foreground mb-1">Logged in as</p>
            <p className="font-medium text-sm">{user?.username}</p>
            <p className="text-xs text-primary capitalize">{user?.role}</p>
          </div>
          <Button
            variant="outline"
            className="w-full justify-start"
            onClick={handleLogout}
          >
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="flex justify-end p-4 border-b border-border">
          <ThemeToggle />
        </div>
        <div className="container mx-auto p-6">
          {children}
        </div>
      </main>
    </div>
  );
};
