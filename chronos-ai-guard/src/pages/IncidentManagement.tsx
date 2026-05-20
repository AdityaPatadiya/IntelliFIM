// chronos-ai-guard/src/pages/IncidentManagement.tsx
import { DashboardLayout } from "@/components/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CheckCircle, XCircle, Clock, ShieldAlert } from "lucide-react";
import { apiFetch, ORCH_API_URL } from "@/lib/apiClient";
import { useAuth } from "@/contexts/AuthContext";

interface ApprovalRow {
  id: string;
  host_id: string;
  priority: "low" | "high";
  score: number;
  last_reason: string;
  state: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED" | "FAILED";
  created_at: string;
  decided_at: string | null;
  executed_at: string | null;
  decided_by: string | null;
  error_message: string | null;
}

const priorityVariant: Record<ApprovalRow["priority"], "destructive" | "default"> = {
  high: "destructive",
  low: "default",
};

const stateVariant: Record<ApprovalRow["state"], "secondary" | "default" | "destructive" | "outline"> = {
  PENDING: "secondary",
  APPROVED: "default",
  EXECUTED: "default",
  FAILED: "destructive",
  REJECTED: "outline",
};

const ResponseApprovals = () => {
  const { user } = useAuth();
  const canDecide = user?.role === "admin" || user?.role === "analyst";
  const qc = useQueryClient();

  const approvalsQuery = useQuery({
    queryKey: ["approvals", "PENDING"],
    queryFn: async (): Promise<ApprovalRow[]> => {
      const resp = await apiFetch(`${ORCH_API_URL}/approvals?state=PENDING`);
      if (!resp.ok) throw new Error(`status ${resp.status}`);
      const body = (await resp.json()) as { approvals: ApprovalRow[] };
      return body.approvals;
    },
    refetchInterval: 3000,
  });

  const decide = useMutation({
    mutationFn: async ({ id, action }: { id: string; action: "approve" | "reject" }) => {
      const resp = await apiFetch(`${ORCH_API_URL}/approvals/${id}/${action}`, { method: "POST" });
      if (!resp.ok) throw new Error(await resp.text());
      return resp.json();
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });

  const rows = approvalsQuery.data ?? [];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Response Approvals</h1>
            <p className="text-muted-foreground">
              Review threat-score updates and approve enforcement actions.
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Pending Approvals
              <Badge variant="outline" className="ml-2">
                Polling every 3s
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {approvalsQuery.isLoading && <p className="text-muted-foreground">Loading…</p>}
            {approvalsQuery.isError && (
              <p className="text-destructive">
                Failed to load approvals: {(approvalsQuery.error as Error).message}
              </p>
            )}
            {!approvalsQuery.isLoading && !approvalsQuery.isError && rows.length === 0 && (
              <p className="text-muted-foreground flex items-center gap-2">
                <Clock className="h-4 w-4" />
                No pending approvals.
              </p>
            )}
            {rows.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Created</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Reason</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(row.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.host_id}</TableCell>
                      <TableCell>
                        <Badge variant={priorityVariant[row.priority]}>{row.priority}</Badge>
                      </TableCell>
                      <TableCell>{row.score.toFixed(1)}</TableCell>
                      <TableCell className="max-w-xs truncate" title={row.last_reason}>
                        {row.last_reason}
                      </TableCell>
                      <TableCell>
                        <Badge variant={stateVariant[row.state]}>{row.state}</Badge>
                      </TableCell>
                      <TableCell className="text-right space-x-2">
                        {canDecide ? (
                          <>
                            <Button
                              size="sm"
                              onClick={() => decide.mutate({ id: row.id, action: "approve" })}
                              disabled={decide.isPending}
                            >
                              <CheckCircle className="h-4 w-4 mr-1" />
                              Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => decide.mutate({ id: row.id, action: "reject" })}
                              disabled={decide.isPending}
                            >
                              <XCircle className="h-4 w-4 mr-1" />
                              Reject
                            </Button>
                          </>
                        ) : (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span>
                                <Button size="sm" disabled>
                                  <CheckCircle className="h-4 w-4 mr-1" />
                                  Approve
                                </Button>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Requires analyst or admin role
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default ResponseApprovals;
