import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "CyberSentinel – Website Security Analyzer",
    template: "%s | CyberSentinel",
  },
  description:
    "Passive, non-intrusive security analysis for websites you own or are authorised to test. Check HTTPS, SSL/TLS, security headers, cookies, and DNS configuration.",
  keywords: ["security", "website", "SSL", "headers", "HTTPS", "scanner"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full flex flex-col">
        {/* ── Navigation ──────────────────────────────────────────────────── */}
        <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-50">
          <nav
            className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between"
            aria-label="Main navigation"
          >
            {/* Brand */}
            <Link
              href="/"
              className="flex items-center gap-2.5 text-slate-100 hover:text-brand-400 transition-colors"
              aria-label="CyberSentinel home"
            >
              {/* Shield icon */}
              <svg
                className="w-7 h-7 text-brand-500"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <path
                  fillRule="evenodd"
                  d="M12 1.5a.75.75 0 0 1 .439.143l9 6A.75.75 0 0 1 21.75 8.25v7.5a.75.75 0 0 1-.311.607l-9 6a.75.75 0 0 1-.878 0l-9-6A.75.75 0 0 1 2.25 15.75v-7.5a.75.75 0 0 1 .311-.607l9-6A.75.75 0 0 1 12 1.5Z"
                  clipRule="evenodd"
                />
              </svg>
              <span className="font-bold text-lg tracking-tight">
                CyberSentinel
              </span>
            </Link>

            {/* Nav links */}
            <div className="flex items-center gap-1">
              <Link
                href="/"
                className="text-sm text-slate-400 hover:text-slate-100 px-3 py-2 rounded-md transition-colors"
              >
                Scanner
              </Link>
              <Link
                href="/history"
                className="text-sm text-slate-400 hover:text-slate-100 px-3 py-2 rounded-md transition-colors"
              >
                History
              </Link>
            </div>
          </nav>
        </header>

        {/* ── Main content ─────────────────────────────────────────────────── */}
        <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>

        {/* ── Footer ───────────────────────────────────────────────────────── */}
        <footer className="border-t border-slate-800 mt-auto">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex flex-col sm:flex-row items-center justify-between gap-3">
            <p className="text-xs text-slate-500">
              © {new Date().getFullYear()} CyberSentinel. All scans are passive
              and non-intrusive.
            </p>
            <p className="text-xs text-slate-600">
              Only scan websites you own or have explicit authorisation to test.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
