// chronos-ai-guard/src/lib/apiClient.ts
// Small fetch wrapper that injects the JWT Bearer token from localStorage
// and handles 401 by clearing the session + redirecting to /auth.

export const AUTH_API_URL =
  (import.meta.env.VITE_AUTH_API_URL as string | undefined) ?? "http://localhost:8000";
export const ORCH_API_URL =
  (import.meta.env.VITE_ORCHESTRATOR_API_URL as string | undefined) ?? "http://localhost:8200";
export const REPORTING_API_URL =
  (import.meta.env.VITE_REPORTING_API_URL as string | undefined) ?? "http://localhost:8300";

export function getToken(): string | null {
  return localStorage.getItem("access_token");
}

export function clearSession(): void {
  localStorage.removeItem("access_token");
  localStorage.removeItem("aifim_user");
}

export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(url, { ...init, headers });
  if (response.status === 401) {
    clearSession();
    // Avoid redirect loop if we're already on /auth
    if (typeof window !== "undefined" && window.location.pathname !== "/auth") {
      window.location.href = "/auth";
    }
  }
  return response;
}
