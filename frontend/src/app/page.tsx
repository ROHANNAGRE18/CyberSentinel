"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useScan } from "@/hooks/useScan";
import { isValidUrl, cn } from "@/lib/utils";

export default function HomePage() {
  const router = useRouter();
  const { submit, isLoading, isPolling, scanId, error } = useScan();
  const [url, setUrl] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const isWorking = isLoading || isPolling;

  // When a scan_id arrives, navigate to the results page
  if (scanId && !isLoading) {
    router.push(`/results/${scanId}`);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setValidationError(null);

    const trimmed = url.trim();
    if (!trimmed) {
      setValidationError("Please enter a URL.");
      return;
    }
    if (!isValidUrl(trimmed)) {
      setValidationError(
        "Enter a valid URL starting with http:// or https://"
      );
      return;
    }

    submit(trimmed);
  }

  return (
    <div className="animate-fade-in">
      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section className="text-center py-12 sm:py-16">
        <div className="inline-flex items-center gap-2 bg-brand-500/10 border border-brand-500/20 text-brand-400 text-xs font-medium px-3 py-1.5 rounded-full mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse-slow" aria-hidden="true" />
          Passive &amp; Non-Intrusive Analysis
        </div>

        <h1 className="text-4xl sm:text-5xl font-bold text-slate-100 tracking-tight mb-4">
          Website Security{" "}
          <span className="text-brand-400">Analyzer</span>
        </h1>
        <p className="text-slate-400 text-lg max-w-xl mx-auto mb-10">
          Check HTTPS, SSL/TLS certificates, security headers, cookie flags,
          and DNS configuration — instantly.
        </p>

        {/* ── Scanner form ─────────────────────────────────────────────── */}
        <form
          onSubmit={handleSubmit}
          className="max-w-2xl mx-auto"
          aria-label="Website security scanner"
        >
          <div className="flex flex-col sm:flex-row gap-3">
            <label htmlFor="url-input" className="sr-only">
              Website URL
            </label>
            <input
              id="url-input"
              type="url"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setValidationError(null);
              }}
              placeholder="https://example.com"
              className={cn(
                "input flex-1 text-base py-3",
                (validationError || error) && "border-red-500 focus:border-red-500"
              )}
              disabled={isWorking}
              autoComplete="url"
              spellCheck={false}
              aria-describedby={
                validationError || error ? "url-error" : undefined
              }
            />
            <button
              type="submit"
              className="btn-primary px-8 py-3 text-base"
              disabled={isWorking}
            >
              {isWorking ? (
                <>
                  <Spinner />
                  {isLoading ? "Starting…" : "Scanning…"}
                </>
              ) : (
                "Analyze"
              )}
            </button>
          </div>

          {/* Error message */}
          {(validationError || error) && (
            <p
              id="url-error"
              role="alert"
              className="mt-2 text-sm text-red-400 text-left"
            >
              {validationError ?? error}
            </p>
          )}
        </form>

        {/* ── Disclaimer ───────────────────────────────────────────────── */}
        <p className="mt-4 text-xs text-slate-500 max-w-lg mx-auto">
          <span className="font-semibold text-slate-400">Authorisation required.</span>{" "}
          Only scan websites you own or have explicit written permission to test.
          All checks are read-only and passive.
        </p>
      </section>

      {/* ── Feature grid ─────────────────────────────────────────────────── */}
      <section aria-labelledby="checks-heading" className="py-8">
        <h2
          id="checks-heading"
          className="text-center text-sm font-semibold text-slate-500 uppercase tracking-widest mb-8"
        >
          What we check
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          {CHECKS.map((check) => (
            <div
              key={check.label}
              className="card text-center py-5 hover:border-slate-700 transition-colors"
            >
              <div
                className="text-2xl mb-2"
                aria-hidden="true"
                role="img"
              >
                {check.icon}
              </div>
              <p className="text-xs font-medium text-slate-300">{check.label}</p>
              <p className="text-xs text-slate-500 mt-0.5">{check.sub}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Quick link to history ─────────────────────────────────────────── */}
      <section className="text-center py-6">
        <Link
          href="/history"
          className="text-sm text-slate-500 hover:text-brand-400 transition-colors"
        >
          View scan history →
        </Link>
      </section>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Spinner() {
  return (
    <svg
      className="w-4 h-4 animate-spin"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

// ── Static data ───────────────────────────────────────────────────────────────

const CHECKS = [
  { icon: "🔒", label: "HTTPS",        sub: "Availability & redirect" },
  { icon: "📜", label: "SSL/TLS",      sub: "Cert validity & expiry" },
  { icon: "🛡️", label: "Headers",     sub: "CSP, HSTS, X-Frame…" },
  { icon: "🍪", label: "Cookies",      sub: "Secure, HttpOnly, SameSite" },
  { icon: "🌐", label: "DNS",          sub: "A, MX, SPF, DMARC" },
  { icon: "📊", label: "Score",        sub: "0–100 weighted" },
];
