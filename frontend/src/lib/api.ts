/**
 * CyberSentinel API client.
 *
 * All backend calls go through this module so base URL and headers
 * are configured in one place. Uses the Fetch API (no extra deps)
 * with typed response helpers.
 *
 * In development, Next.js rewrites /api/* → FastAPI (see next.config.ts).
 * In production, point NEXT_PUBLIC_API_URL at your backend domain.
 */

import type {
  HealthResponse,
  ScanCreateResponse,
  ScanDetail,
  ScanListResponse,
  ScanRequest,
  SortField,
  SortOrder,
} from "@/types";

// Base URL for all API calls.
// The rewrite in next.config.ts means we can always use /api/v1/* in the browser
// and it will be proxied to FastAPI automatically during dev.
const API_BASE = "/api/v1";

// ── Error handling ────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.ok) {
    return res.json() as Promise<T>;
  }

  let detail = `HTTP ${res.status}`;
  try {
    const body = await res.json();
    detail = body?.detail ?? detail;
  } catch {
    // ignore JSON parse errors on error responses
  }

  throw new ApiError(res.status, detail);
}

// ── Request helpers ───────────────────────────────────────────────────────────

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" },
    // Next.js fetch cache: don't cache scan results — always fresh
    cache: "no-store",
  });
  return handleResponse<T>(res);
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  return handleResponse<T>(res);
}

// ── API methods ───────────────────────────────────────────────────────────────

/** Submit a new scan. Returns 202 with scan_id immediately. */
export async function createScan(request: ScanRequest): Promise<ScanCreateResponse> {
  return post<ScanCreateResponse>("/scans", request);
}

/**
 * Fetch the full results of a scan by its ID.
 * Poll this until status === "completed" or "failed".
 */
export async function getScan(scanId: string): Promise<ScanDetail> {
  return get<ScanDetail>(`/scans/${scanId}`);
}

/**
 * Fetch paginated scan history.
 */
export async function listScans(params?: {
  page?: number;
  limit?: number;
  sort?: SortField;
  order?: SortOrder;
}): Promise<ScanListResponse> {
  const qs = new URLSearchParams();
  if (params?.page)  qs.set("page",  String(params.page));
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.sort)  qs.set("sort",  params.sort);
  if (params?.order) qs.set("order", params.order);

  const query = qs.toString() ? `?${qs.toString()}` : "";
  return get<ScanListResponse>(`/scans${query}`);
}

/** Health check — useful for connection status indicator. */
export async function getHealth(): Promise<HealthResponse> {
  return get<HealthResponse>("/health");
}
