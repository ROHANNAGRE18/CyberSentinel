/**
 * Shared utility functions for CyberSentinel frontend.
 */

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type {
  CheckResult,
  CheckStatus,
  CheckSummary,
  Priority,
  ScoreDisplay,
  Severity,
  ScanStatus,
} from "@/types";

// ── Tailwind class helper ─────────────────────────────────────────────────────

/** Merge Tailwind classes safely, resolving conflicts. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// ── Score helpers ─────────────────────────────────────────────────────────────

/**
 * Map a numeric score (0–100) to a human-readable label and colour classes.
 *
 *  0–39   → Poor     (red)
 * 40–69   → Fair     (amber)
 * 70–89   → Good     (green)
 * 90–100  → Excellent (cyan)
 */
export function getScoreDisplay(score: number): ScoreDisplay {
  if (score >= 90) {
    return {
      score,
      label: "Excellent",
      colorClass: "text-cyan-500",
      bgClass: "bg-cyan-500",
    };
  }
  if (score >= 70) {
    return {
      score,
      label: "Good",
      colorClass: "text-green-500",
      bgClass: "bg-green-500",
    };
  }
  if (score >= 40) {
    return {
      score,
      label: "Fair",
      colorClass: "text-amber-500",
      bgClass: "bg-amber-500",
    };
  }
  return {
    score,
    label: "Poor",
    colorClass: "text-red-500",
    bgClass: "bg-red-500",
  };
}

// ── Severity / Status colour maps ─────────────────────────────────────────────

/** Returns Tailwind badge colour classes for a finding severity. */
export function getSeverityClasses(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: "bg-red-100 text-red-700 border-red-200",
    high:     "bg-orange-100 text-orange-700 border-orange-200",
    medium:   "bg-amber-100 text-amber-700 border-amber-200",
    low:      "bg-lime-100 text-lime-700 border-lime-200",
    info:     "bg-cyan-100 text-cyan-700 border-cyan-200",
  };
  return map[severity] ?? map.info;
}

/** Returns Tailwind colour classes for a check status indicator. */
export function getCheckStatusClasses(status: CheckStatus): string {
  const map: Record<CheckStatus, string> = {
    pass: "bg-green-100 text-green-700 border-green-200",
    warn: "bg-amber-100 text-amber-700 border-amber-200",
    fail: "bg-red-100 text-red-700 border-red-200",
    info: "bg-blue-100 text-blue-700 border-blue-200",
  };
  return map[status] ?? map.info;
}

/** Returns Tailwind colour classes for a scan status pill. */
export function getScanStatusClasses(status: ScanStatus): string {
  const map: Record<ScanStatus, string> = {
    pending:   "bg-slate-100 text-slate-600",
    running:   "bg-blue-100 text-blue-700 animate-pulse",
    completed: "bg-green-100 text-green-700",
    failed:    "bg-red-100 text-red-700",
  };
  return map[status] ?? "bg-slate-100 text-slate-600";
}

/** Returns a priority badge colour class. */
export function getPriorityClasses(priority: Priority): string {
  const map: Record<Priority, string> = {
    critical: "bg-red-100 text-red-700 border-red-200",
    high:     "bg-orange-100 text-orange-700 border-orange-200",
    medium:   "bg-amber-100 text-amber-700 border-amber-200",
    low:      "bg-lime-100 text-lime-700 border-lime-200",
  };
  return map[priority] ?? map.low;
}

// ── Check summary ─────────────────────────────────────────────────────────────

/** Count check results by status for the summary chip row. */
export function summariseChecks(checks: CheckResult[]): CheckSummary {
  const summary: CheckSummary = { pass: 0, warn: 0, fail: 0, info: 0, total: checks.length };
  for (const c of checks) {
    if (c.status in summary) {
      (summary as unknown as Record<string, number>)[c.status]++;
    }
  }
  return summary;
}

// ── Date formatting ───────────────────────────────────────────────────────────

/** Format an ISO datetime string for display, e.g. "10 Sep 2026, 14:32". */
export function formatDate(isoString: string): string {
  try {
    return new Intl.DateTimeFormat("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(isoString));
  } catch {
    return isoString;
  }
}

/** Format a duration in seconds to a human-readable string, e.g. "4.2s". */
export function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  return `${seconds.toFixed(1)}s`;
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/** Strip protocol and trailing slash for compact display. */
export function displayUrl(url: string): string {
  return url.replace(/^https?:\/\//, "").replace(/\/$/, "");
}

/** Basic client-side URL format check before submitting to the API. */
export function isValidUrl(value: string): boolean {
  try {
    const parsed = new URL(value.trim());
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}
