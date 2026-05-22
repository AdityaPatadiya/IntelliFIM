import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { DashboardLayout } from "@/components/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FileText, Download, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { apiFetch, REPORTING_API_URL } from "@/lib/apiClient";


type ReportMetadata = {
  id: string;
  name: string;
  range_start: string;
  range_end: string;
  generated_at: string;
  generated_by: string;
  size_bytes: number;
  approvals_count: number;
  scores_count: number;
};

type ReportListResponse = {
  reports: ReportMetadata[];
  total: number;
};


function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}


export default function Reports() {
  const { toast } = useToast();
  const { user } = useAuth();
  const qc = useQueryClient();

  const canGenerate = user?.role === "admin" || user?.role === "analyst";

  const today = new Date();
  const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
  const [name, setName] = useState("Daily Security Summary");
  const [rangeStart, setRangeStart] = useState(yesterday.toISOString().slice(0, 16));
  const [rangeEnd, setRangeEnd] = useState(today.toISOString().slice(0, 16));

  const list = useQuery<ReportListResponse, Error>({
    queryKey: ["reports"],
    queryFn: async () => {
      const r = await apiFetch(`${REPORTING_API_URL}/reports?limit=50`);
      if (!r.ok) throw new Error((await r.json()).error ?? `HTTP ${r.status}`);
      return r.json();
    },
  });

  const generate = useMutation({
    mutationFn: async () => {
      const body = {
        name,
        range_start: new Date(rangeStart).toISOString(),
        range_end: new Date(rangeEnd).toISOString(),
      };
      const r = await apiFetch(`${REPORTING_API_URL}/reports/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error((await r.json()).error ?? `HTTP ${r.status}`);
      return (await r.json()) as ReportMetadata;
    },
    onSuccess: (created) => {
      toast({ title: "Report generated", description: created.name });
      qc.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (e: Error) => {
      toast({ title: "Generate failed", description: e.message, variant: "destructive" });
    },
  });

  async function downloadReport(id: string, name: string, generatedAt: string) {
    const r = await apiFetch(`${REPORTING_API_URL}/reports/${id}/download`);
    if (!r.ok) {
      const msg = (await r.json()).error ?? `HTTP ${r.status}`;
      toast({ title: "Download failed", description: msg, variant: "destructive" });
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name.replace(/\s+/g, "_")}-${generatedAt.slice(0, 10)}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Reports</h1>
            <p className="text-muted-foreground">Generate and download Security Summary PDFs</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled title="CSV export — v2">
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>
          </div>
        </div>

        {canGenerate && (
          <Card>
            <CardHeader>
              <CardTitle>Generate report</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
                onSubmit={(e) => { e.preventDefault(); generate.mutate(); }}
              >
                <div className="md:col-span-2">
                  <Label htmlFor="r-name">Name</Label>
                  <Input id="r-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} />
                </div>
                <div>
                  <Label htmlFor="r-start">Range start (UTC)</Label>
                  <Input id="r-start" type="datetime-local" value={rangeStart} onChange={(e) => setRangeStart(e.target.value)} required />
                </div>
                <div>
                  <Label htmlFor="r-end">Range end (UTC)</Label>
                  <Input id="r-end" type="datetime-local" value={rangeEnd} onChange={(e) => setRangeEnd(e.target.value)} required />
                </div>
                <div className="md:col-span-4">
                  <Button type="submit" disabled={generate.isPending}>
                    {generate.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileText className="mr-2 h-4 w-4" />}
                    Generate PDF
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Past reports {list.data ? `(${list.data.total})` : ""}</CardTitle>
          </CardHeader>
          <CardContent>
            {list.isLoading ? (
              <div className="flex items-center text-muted-foreground"><Loader2 className="mr-2 h-4 w-4 animate-spin" />Loading…</div>
            ) : list.error ? (
              <div className="text-destructive">Error: {list.error.message}</div>
            ) : list.data && list.data.reports.length === 0 ? (
              <div className="text-muted-foreground">No reports yet.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Range</TableHead>
                    <TableHead>Generated by</TableHead>
                    <TableHead>Generated at</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Download</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.data?.reports.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-medium">{r.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {r.range_start.slice(0, 16)} → {r.range_end.slice(0, 16)}
                      </TableCell>
                      <TableCell>{r.generated_by}</TableCell>
                      <TableCell className="text-sm">{r.generated_at.slice(0, 19)}</TableCell>
                      <TableCell className="text-sm">{fmtBytes(r.size_bytes)}</TableCell>
                      <TableCell>
                        <Button size="sm" variant="outline" onClick={() => downloadReport(r.id, r.name, r.generated_at)}>
                          <Download className="mr-2 h-4 w-4" />
                          Download
                        </Button>
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
}
