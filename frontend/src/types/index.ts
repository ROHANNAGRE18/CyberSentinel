/**
 * CyberSentinel – shared TypeScript interfaces.
 *
 * These mirror the Pydantic schemas defined in backend/app/schemas/scan.py.
 * Keep both files in sync when adding new fields.
 */

// ── Enums ─────────────────────────────────────────────────────────────────────

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type CheckStatus = "pass" | "warn" | "fail" | "info";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Priority = "critical" | "high" | "medium" | "low";

export type SortField = "created_at" | "score";

export type SortOrder = "asc" | "desc";

// ── API request ───────────────────────────────────────────────────────────────

export interface ScanRequest {
  url: string;
}

// ── API responses ─────────────────────────────────────────────────────────────

/** Returned immediately after POST /api/v1/scans (202 Accepted) */
export interface ScanCreateResponse {
  scan_id: string;
  status: ScanStatus;
  message: string;
}

/** One security check result within a full scan report */
export interface CheckResult {
  check_name: string;
  status: CheckStatus;
  title: string;
  detail: string | null;
  severity: Severity;
}

/** One remediation recommendation within a full scan report */
export interface Recommendation {
  check_name: string;
  priority: Priority;
  title: string;
  description: string;
  reference_url: string | null;
}

/** Full scan report returned by GET /api/v1/scans/{scan_id} */
export interface ScanDetail {
  scan_id: string;
  url: string;
  status: ScanStatus;
  score: number | null;
  created_at: string;           // ISO 8601 datetime string
  scan_duration: number | null; // seconds
  error_message: string | null;
  checks: CheckResult[];
  recommendations: Recommendation[];
}

/** Lightweight scan row used in the history list */
export interface ScanSummary {
  scan_id: string;
  url: string;
  status: ScanStatus;
  score: number | null;
  created_at: string;           // ISO 8601 datetime string
}

/** Paginated scan history response from GET /api/v1/scans */
export interface ScanListResponse {
  total: number;
  page: number;
  limit: number;
  scans: ScanSummary[];
}

/** Health check response from GET /api/v1/health */
export interface HealthResponse {
  status: string;
  version: string;
  database: string;
}

// ── UI-only helpers ───────────────────────────────────────────────────────────

/** Used to display a score with an associated label and colour class */
export interface ScoreDisplay {
  score: number;
  label: "Poor" | "Fair" | "Good" | "Excellent";
  colorClass: string;
  bgClass: string;
}

/** Groups check results by their status for the summary chips */
export interface CheckSummary {
  pass: number;
  warn: number;
  fail: number;
  info: number;
  total: number;
}
