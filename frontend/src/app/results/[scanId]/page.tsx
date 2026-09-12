"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getScan, ApiError } from "@/lib/api";
import {
  cn,
  formatDate,
  formatDuration,
  displayUrl,
  getScoreDisplay,
  getScanStatusClasses,
  getCheckStatusClasses,
  getSeverityClasses,
  getPriorityClasses,
  summariseChecks,
} from "@/lib/utils";
import type {
  CheckResult,
  Recommendation,
  ScanDetail,
  ScanStatus,
  CheckStatus,
} from "@/types";

const TERMINAL: ScanStatus[] = ["completed", "failed"];
const POLL_MS = 2000;

// Human-readable labels for each check_name
const CHECK_LABELS: Record<string, string> = {
  https_available:          "HTTPS Available",
  http_redirects_to_https:  "HTTP→HTTPS Redirect",
  ssl_certificate_valid:    "Certificate Valid",
  ssl_certificate_expiry:   "Certificate Expiry",
  ssl_certificate_issuer:   "Certificate Issuer",
  ssl_certificate_subject:  "Certificate Subject / Domains",
  csp_header:               "Content-Security-Policy",
  hsts_header:              "Strict-Transport-Security",
  x_frame_options:          "X-Frame-Options",
  x_content_type_options:   "X-Content-Type-Options",
  referrer_policy:          "Referrer-Policy",
  permissions_policy:       "Permissions-Policy",
  cookie_overview:          "Cookie Overview",
  cookie_secure_flag:       "Secure Flag",
  cookie_httponly_flag:     "HttpOnly Flag",
  cookie_samesite_attr:     "SameSite Attribute",
};

// Group check_names into logical sections
const SECTIONS: { label: string; keys: string[] }[] = [
  {
    label: "HTTPS",
    keys: ["https_available", "http_redirects_to_https"],
  },
  {
    label: "SSL / TLS Certificate",
    keys: [
      "ssl_certificate_valid",
      "ssl_certificate_expiry",
      "ssl_certificate_issuer",
      "ssl_certificate_subject",
    ],
  },
  {
    label: "Security Headers",
    keys: [
      "csp_header",
      "hsts_header",
      "x_frame_options",
      "x_content_type_options",
      "referrer_policy",
      "permissions_policy",
    ],
  },
  {
    label: "Cookie Security",
    keys: [
      "cookie_overview",
      "cookie_secure_flag",
      "cookie_httponly_flag",
      "cookie_samesite_attr",
    ],
  },
];

export default function ResultsPage() {
  const params = useParams();
  const scanId = params?.scanId as string;

  const [scan, setScan]       = useState<ScanDetail | null>(null);
  const [error, setError]     = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    async function fetchAndMaybePoll() {
      try {
        const data = await getScan(scanId);
        if (cancelled) return;
        setScan(data);
        setLoading(false);
        if (!TERMINAL.includes(data.status)) {
          timer = setTimeout(fetchAndMaybePoll, POLL_MS);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.detail : "Failed to load scan results.");
        setLoading(false);
      }
    }

    fetchAndMaybePoll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [scanId]);

  // ── Loading ───────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-4 animate-fade-in">
        <Spinner />
        <p className="text-slate-400 text-sm">Loading scan results…</p>
      </div>
    );
  }

  // ── Error ─────────────────────────────────────────────────────────────────
  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-4 animate-fade-in">
        <div className="card max-w-md w-full text-center">
          <p className="text-red-400 font-medium mb-2">Failed to load scan</p>
          <p className="text-slate-500 text-sm mb-6">{error ?? "Scan not found."}</p>
          <Link href="/" className="btn-primary">← Back to Scanner</Link>
        </div>
      </div>
    );
  }

  const isRunning    = !TERMINAL.includes(scan.status);
  const scoreDisplay = scan.score !== null ? getScoreDisplay(scan.score) : null;
  const summary      = summariseChecks(scan.checks);

  return (
    <div className="animate-slide-up space-y-6">

      {/* ── Breadcrumb ──────────────────────────────────────────────────── */}
      <nav className="text-sm text-slate-500" aria-label="Breadcrumb">
        <Link href="/" className="hover:text-slate-300 transition-colors">Scanner</Link>
        <span className="mx-2">›</span>
        <span className="text-slate-300">Results</span>
      </nav>

      {/* ── Header card ─────────────────────────────────────────────────── */}
      <div className="card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="text-xs text-slate-500 mb-1">Scanned URL</p>
          <p className="text-lg font-semibold text-slate-100 truncate">{displayUrl(scan.url)}</p>
          <p className="text-xs text-slate-600 mt-1">
            {formatDate(scan.created_at)}
            {scan.scan_duration !== null && <> · {formatDuration(scan.scan_duration)}</>}
          </p>
        </div>

        <div className="flex items-center gap-5 flex-shrink-0">
          {/* Status pill */}
          <span
            className={cn("badge", getScanStatusClasses(scan.status))}
            aria-label={`Scan status: ${scan.status}`}
          >
            {isRunning && (
              <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" aria-hidden="true" />
            )}
            {scan.status}
          </span>

          {/* Score */}
          {scoreDisplay && (
            <div className="text-center" aria-label={`Security score: ${scoreDisplay.score} out of 100`}>
              <p className={cn("text-4xl font-bold tabular-nums", scoreDisplay.colorClass)}>
                {scoreDisplay.score}
              </p>
              <p className={cn("text-xs font-medium", scoreDisplay.colorClass)}>
                {scoreDisplay.label}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Running indicator ────────────────────────────────────────────── */}
      {isRunning && (
        <div className="card flex items-center gap-3 border-brand-500/20 bg-brand-500/5">
          <Spinner className="text-brand-400" />
          <div>
            <p className="text-sm font-medium text-slate-200">Scan in progress</p>
            <p className="text-xs text-slate-500">Checking HTTPS, headers, and more…</p>
          </div>
        </div>
      )}

      {/* ── Failed banner ────────────────────────────────────────────────── */}
      {scan.status === "failed" && (
        <div className="card border-red-500/20 bg-red-500/5">
          <p className="text-sm font-medium text-red-400 mb-1">Scan failed</p>
          <p className="text-xs text-slate-500">
            {scan.error_message ?? "An unexpected error occurred during the scan."}
          </p>
        </div>
      )}

      {/* ── Results ──────────────────────────────────────────────────────── */}
      {scan.checks.length > 0 && (
        <>
          {/* Summary chips */}
          <SummaryChips summary={summary} />

          {/* Check sections */}
          {SECTIONS.map((section) => {
            const sectionChecks = section.keys
              .map((key) => scan.checks.find((c) => c.check_name === key))
              .filter(Boolean) as CheckResult[];

            if (sectionChecks.length === 0) return null;

            return (
              <section key={section.label} aria-labelledby={`section-${section.label}`}>
                <h2
                  id={`section-${section.label}`}
                  className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3"
                >
                  {section.label}
                </h2>
                <div className="space-y-2">
                  {sectionChecks.map((check) => (
                    <CheckCard key={check.check_name} check={check} />
                  ))}
                </div>
              </section>
            );
          })}

          {/* Any checks not covered by SECTIONS (future phases) */}
          {(() => {
            const knownKeys = SECTIONS.flatMap((s) => s.keys);
            const extra = scan.checks.filter((c) => !knownKeys.includes(c.check_name));
            if (extra.length === 0) return null;
            return (
              <section aria-labelledby="section-other">
                <h2
                  id="section-other"
                  className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3"
                >
                  Other Checks
                </h2>
                <div className="space-y-2">
                  {extra.map((check) => (
                    <CheckCard key={check.check_name} check={check} />
                  ))}
                </div>
              </section>
            );
          })()}

          {/* Recommendations */}
          {scan.recommendations.length > 0 && (
            <RecommendationPanel recommendations={scan.recommendations} />
          )}
        </>
      )}

      {/* ── Empty state (scan completed but no checks yet) ───────────────── */}
      {scan.status === "completed" && scan.checks.length === 0 && (
        <div className="card text-center py-10">
          <p className="text-slate-400 text-sm">No check results available for this scan.</p>
        </div>
      )}

      {/* ── Actions ──────────────────────────────────────────────────────── */}
      <div className="flex gap-3 pt-2">
        <Link href="/" className="btn-secondary">← New Scan</Link>
        <Link href="/history" className="btn-secondary">View History</Link>
      </div>

    </div>
  );
}


// ── CheckCard ─────────────────────────────────────────────────────────────────

function CheckCard({ check }: { check: CheckResult }) {
  const [expanded, setExpanded] = useState(false);
  const label = CHECK_LABELS[check.check_name] ?? check.check_name;

  const statusIcon: Record<CheckStatus, string> = {
    pass: "✓",
    warn: "⚠",
    fail: "✗",
    info: "ℹ",
  };

  return (
    <div className="card py-3 px-4">
      <button
        className="w-full flex items-center justify-between gap-3 text-left"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={`check-detail-${check.check_name}`}
      >
        <div className="flex items-center gap-3 min-w-0">
          {/* Status indicator */}
          <span
            className={cn(
              "flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold",
              getCheckStatusClasses(check.status as CheckStatus),
            )}
            aria-label={`Status: ${check.status}`}
          >
            {statusIcon[check.status as CheckStatus]}
          </span>

          {/* Title */}
          <span className="text-sm font-medium text-slate-200 truncate">{check.title}</span>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Severity badge — only show for non-info */}
          {check.severity !== "info" && (
            <span className={cn("badge text-xs", getSeverityClasses(check.severity))}>
              {check.severity}
            </span>
          )}
          {/* Expand chevron */}
          {check.detail && (
            <svg
              className={cn("w-4 h-4 text-slate-500 transition-transform", expanded && "rotate-180")}
              xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"
              aria-hidden="true"
            >
              <path fillRule="evenodd" clipRule="evenodd"
                d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" />
            </svg>
          )}
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && check.detail && (
        <div
          id={`check-detail-${check.check_name}`}
          className="mt-3 pt-3 border-t border-slate-800 text-xs text-slate-400 leading-relaxed"
        >
          {check.detail}
        </div>
      )}
    </div>
  );
}


// ── SummaryChips ──────────────────────────────────────────────────────────────

function SummaryChips({ summary }: { summary: ReturnType<typeof summariseChecks> }) {
  const chips = [
    { label: "Passed",   count: summary.pass, cls: "bg-green-500/10 text-green-400 border-green-500/20" },
    { label: "Warnings", count: summary.warn, cls: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
    { label: "Failed",   count: summary.fail, cls: "bg-red-500/10 text-red-400 border-red-500/20" },
    { label: "Info",     count: summary.info, cls: "bg-slate-500/10 text-slate-400 border-slate-500/20" },
  ].filter((c) => c.count > 0);

  return (
    <div className="flex flex-wrap gap-2" role="list" aria-label="Check summary">
      {chips.map((chip) => (
        <span
          key={chip.label}
          role="listitem"
          className={cn("badge border font-semibold", chip.cls)}
        >
          {chip.count} {chip.label}
        </span>
      ))}
      <span className="badge border border-slate-700 text-slate-500">
        {summary.total} total checks
      </span>
    </div>
  );
}


// ── RecommendationPanel ───────────────────────────────────────────────────────

function RecommendationPanel({ recommendations }: { recommendations: Recommendation[] }) {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...recommendations].sort(
    (a, b) => (order[a.priority] ?? 9) - (order[b.priority] ?? 9)
  );

  return (
    <section aria-labelledby="recommendations-heading">
      <h2
        id="recommendations-heading"
        className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-3"
      >
        Recommendations
      </h2>
      <div className="space-y-3">
        {sorted.map((rec, i) => (
          <div key={`${rec.check_name}-${i}`} className="card py-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="text-sm font-semibold text-slate-100 mb-1">{rec.title}</p>
                <p className="text-xs text-slate-400 leading-relaxed mb-3">{rec.description}</p>
                {rec.reference_url && (
                  <a
                    href={rec.reference_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                  >
                    Learn more →
                  </a>
                )}
              </div>
              <span
                className={cn(
                  "badge flex-shrink-0 border font-semibold",
                  getPriorityClasses(rec.priority as "critical" | "high" | "medium" | "low"),
                )}
              >
                {rec.priority}
              </span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}


// ── Spinner ───────────────────────────────────────────────────────────────────

function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={cn("w-5 h-5 animate-spin text-brand-500", className)}
      xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10"
        stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}
