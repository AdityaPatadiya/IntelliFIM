import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Lock, Terminal, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { toast } from 'sonner';

interface PrivilegeDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onElevationSuccess: () => void;
  userRole: string;
}

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const PrivilegeDialog: React.FC<PrivilegeDialogProps> = ({
  open,
  onOpenChange,
  onElevationSuccess,
  userRole
}) => {
  const [password, setPassword] = useState('');
  const [method, setMethod] = useState('sudo');
  const [loading, setLoading] = useState(false);
  const [availableMethods, setAvailableMethods] = useState<any[]>([]);
  const [step, setStep] = useState<'method' | 'password' | 'success' | 'error'>('method');

  const getAuthHeaders = () => {
    const token = localStorage.getItem('access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
    };
  };

  const fetchElevationMethods = async () => {
    try {
      const response = await fetch(`${API_URL}/api/network/elevation-methods`, {
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      setAvailableMethods(data.methods || []);
      setMethod(data.recommended || 'sudo');
    } catch (error) {
      console.error('Failed to fetch elevation methods:', error);
    }
  };

  const handleElevate = async () => {
    if (!userRole || !['admin', 'analyst'].includes(userRole)) {
      toast.error('Only admin and analyst users can elevate privileges');
      return;
    }

    setLoading(true);
    try {
      if (method === 'sudo' && password) {
        // Use password-based elevation
        const response = await fetch(`${API_URL}/api/network/elevate`, {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify({ password }),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.detail || 'Elevation failed');
        }

        const data = await response.json();
        if (data.success) {
          setStep('success');
          toast.success('Privileges elevated successfully');
          setTimeout(() => {
            onElevationSuccess();
            onOpenChange(false);
          }, 1500);
        } else {
          setStep('error');
          toast.error(data.error || 'Elevation failed');
        }
      } else if (method === 'pkexec') {
        // For GUI-based elevation, we need to trigger external process
        toast.info('A system dialog will appear for password entry');
        // You would implement actual pkexec call here
      }
    } catch (error: any) {
      setStep('error');
      toast.error(error.message || 'Failed to elevate privileges');
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    if (open && userRole) {
      fetchElevationMethods();
      setStep('method');
      setPassword('');
    }
  }, [open, userRole]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Elevate Privileges
          </DialogTitle>
          <DialogDescription>
            Network monitoring requires root/administrator privileges
          </DialogDescription>
        </DialogHeader>

        {step === 'method' && (
          <div className="space-y-4 py-4">
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription className="text-sm">
                You are logged in as <strong>{userRole}</strong>. Only admin and analyst roles can elevate privileges.
              </AlertDescription>
            </Alert>

            <div className="space-y-3">
              <Label>Elevation Method</Label>
              {availableMethods.length > 0 ? (
                <div className="space-y-2">
                  {availableMethods.map((m) => (
                    <div
                      key={m.id}
                      className={`flex items-center gap-3 p-3 border rounded cursor-pointer hover:bg-muted ${
                        method === m.id ? 'border-primary bg-primary/5' : ''
                      }`}
                      onClick={() => setMethod(m.id)}
                    >
                      <div className="p-2 rounded-full bg-muted">
                        {m.gui_supported ? <Terminal className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                      </div>
                      <div className="flex-1">
                        <div className="font-medium">{m.name}</div>
                        <div className="text-sm text-muted-foreground">{m.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6 text-muted-foreground">
                  No elevation methods available
                </div>
              )}
            </div>

            <div className="pt-2">
              <Button
                onClick={() => setStep('password')}
                disabled={!method}
                className="w-full"
              >
                Continue
              </Button>
            </div>
          </div>
        )}

        {step === 'password' && (
          <div className="space-y-4 py-4">
            <div className="space-y-3">
              <Label htmlFor="password">Enter Sudo Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                autoComplete="current-password"
              />
              <p className="text-xs text-muted-foreground">
                Your password is sent securely to the backend and only used for this session.
              </p>
            </div>

            <div className="flex gap-2 pt-2">
              <Button
                variant="outline"
                onClick={() => setStep('method')}
                className="flex-1"
              >
                Back
              </Button>
              <Button
                onClick={handleElevate}
                disabled={!password || loading}
                className="flex-1"
              >
                {loading ? 'Elevating...' : 'Elevate Privileges'}
              </Button>
            </div>
          </div>
        )}

        {step === 'success' && (
          <div className="space-y-4 py-4 text-center">
            <div className="mx-auto w-16 h-16 rounded-full bg-green-100 flex items-center justify-center">
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
            <div>
              <h3 className="font-semibold text-lg">Privileges Elevated!</h3>
              <p className="text-muted-foreground mt-1">
                You can now start network monitoring.
              </p>
            </div>
          </div>
        )}

        {step === 'error' && (
          <div className="space-y-4 py-4 text-center">
            <div className="mx-auto w-16 h-16 rounded-full bg-red-100 flex items-center justify-center">
              <XCircle className="h-8 w-8 text-red-600" />
            </div>
            <div>
              <h3 className="font-semibold text-lg">Elevation Failed</h3>
              <p className="text-muted-foreground mt-1">
                Please try another method or run backend manually.
              </p>
            </div>
            <Button
              variant="outline"
              onClick={() => setStep('method')}
              className="w-full"
            >
              Try Again
            </Button>
          </div>
        )}

        <DialogFooter className="sm:justify-start">
          <div className="text-xs text-muted-foreground">
            Need help? Run backend manually: <code className="ml-1">sudo python main.py</code>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default PrivilegeDialog;
