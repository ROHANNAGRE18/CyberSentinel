/**
 * History page — /history
 *
 * Displays a paginated, sortable table of all past scans.
 * Phase 1: Functional with real API data.
 * Phase 2: Will add filtering and richer status indicators.
 */

"use client";

import Link from "next/link";
import { useScanHistory } from "@/hooks/useScanHistory";
import {
  cn,
  formatDate,
  displayUrl,
  getScoreDisplay,
  getScanStatusClasses,
} from "@/lib/utils";
import type { ScanSummary } from "@/types";

export default function HistoryPage() {
  const {
    scans,
    total,
    page,
    limit,
    totalPages,
    isLoading,
    error,
    setPage,
    refetch,
  } = useScanHistory({ limit: 20 });

  return (
    <div className="animate-fade-in space-y-6">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scan History</h1>
          <p className="text-sm text-slate-500 mt-1">
            {isLoading ? "Loading…" : `${total} scan${total !== 1 ? "s" : ""} total`}
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={refetch}
            className="btn-secondary"
            disabled={isLoading}
            aria-label="Refresh scan history"
          >
            <RefreshIcon />
            Refresh
          </button>
          <Link href="/" className="btn-primary">
            + New Scan
          </Link>
        </div>
      </div>

      {/* ── Error ───────────────────────────────────────────────────────── */}
      {error && (
        <div
          role="alert"
          className="card border-red-500/20 bg-red-500/5 text-red-400 text-sm"
        >
          {error}
        </div>
      )}

      {/* ── Table ───────────────────────────────────────────────────────── */}
      <div className="card p-0 overflow-hidden">
        {isLoading && scans.length === 0 ? (
          <LoadingSkeleton />
        ) : scans.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm" aria-label="Scan history">
              <thead>
                <tr className="border-b border-slate-800 text-left">
                  <th className="px-6 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    URL
                  </th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider text-center">
                    Score
                  </th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider text-center">
                    Status
                  </th>
                  <th className="px-6 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-4 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wider text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {scans.map((scan) => (
                  <ScanRow key={scan.scan_id} scan={scan} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Pagination ──────────────────────────────────────────────────── */}
      {totalPages > 1 && (
        <nav
          className="flex items-center justify-between"
          aria-label="Scan history pagination"
        >
          <p className="text-xs text-slate-500">
            Page {page} of {totalPages} · {total} total
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page <= 1 || isLoading}
              className="btn-secondary px-3 py-1.5 text-xs"
            >
              ← Prev
            </button>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= totalPages || isLoading}
              className="btn-secondary px-3 py-1.5 text-xs"
            >
              Next →
            </button>
          </div>
        </nav>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ScanRow({ scan }: { scan: ScanSummary }) {
  const scoreDisplay = scan.score !== null ? getScoreDisplay(scan.score) : null;

  return (
    <tr className="hover:bg-slate-800/30 transition-colors group">
      {/* URL */}
      <td className="px-6 py-4 max-w-xs">
        <p className="text-slate-200 font-medium truncate">
          {displayUrl(scan.url)}
        </p>
        <p className="text-xs text-slate-600 truncate font-mono mt-0.5">
          {scan.scan_id}
        </p>
      </td>

      {/* Score */}
      <td className="px-4 py-4 text-center">
        {scoreDisplay ? (
          <span
            className={cn("text-lg font-bold tabular-nums", scoreDisplay.colorClass)}
            aria-label={`Score: ${scoreDisplay.score}`}
          >
            {scoreDisplay.score}
          </span>
        ) : (
          <span className="text-slate-600 text-sm">—</span>
        )}
      </td>

      {/* Status */}
      <td className="px-4 py-4 text-center">
        <span className={cn("badge", getScanStatusClasses(scan.status))}>
          {scan.status}
        </span>
      </td>

      {/* Date */}
      <td className="px-6 py-4 text-slate-500 whitespace-nowrap text-xs">
        {formatDate(scan.created_at)}
      </td>

      {/* Actions */}
      <td className="px-4 py-4 text-right">
        <Link
          href={`/results/${scan.scan_id}`}
          className="text-brand-400 hover:text-brand-300 text-xs font-medium transition-colors"
          aria-label={`View results for ${displayUrl(scan.url)}`}
        >
          View →
        </Link>
      </td>
    </tr>
  );
}

function EmptyState() {
  return (
    <div className="text-center py-16 px-6">
      <p className="text-4xl mb-4" aria-hidden="true">🔍</p>
      <p className="text-slate-300 font-medium mb-2">No scans yet</p>
      <p className="text-slate-500 text-sm mb-6">
        Run your first scan to see results here.
      </p>
      <Link href="/" className="btn-primary">
        Start a Scan
      </Link>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="divide-y divide-slate-800/50" aria-busy="true" aria-label="Loading scan history">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-6 py-4">
          <div className="flex-1 space-y-2">
            <div className="h-4 bg-slate-800 rounded w-48 animate-pulse" />
            <div className="h-3 bg-slate-800/60 rounded w-32 animate-pulse" />
          </div>
          <div className="h-6 bg-slate-800 rounded w-10 animate-pulse" />
          <div className="h-5 bg-slate-800 rounded w-20 animate-pulse" />
          <div className="h-3 bg-slate-800 rounded w-32 animate-pulse" />
          <div className="h-4 bg-slate-800 rounded w-12 animate-pulse" />
        </div>
      ))}
    </div>
  );
}

function RefreshIcon() {
  return (
    <svg
      className="w-4 h-4"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      strokeWidth={1.5}
      stroke="currentColor"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99"
      />
    </svg>
  );
}
