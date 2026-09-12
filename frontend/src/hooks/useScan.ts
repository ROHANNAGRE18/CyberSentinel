/**
 * useScan hook
 *
 * Handles the full scan lifecycle:
 *   1. POST /api/v1/scans to start a scan
 *   2. Poll GET /api/v1/scans/{scan_id} every 2s until status is terminal
 *   3. Expose loading, error, and result state to the caller
 *
 * Usage:
 *   const { submit, scanDetail, isLoading, error } = useScan();
 *   await submit("https://example.com");
 */

"use client";

import { useState, useCallback, useRef } from "react";
import { createScan, getScan, ApiError } from "@/lib/api";
import type { ScanDetail, ScanStatus } from "@/types";

const TERMINAL_STATUSES: ScanStatus[] = ["completed", "failed"];
const POLL_INTERVAL_MS = 2000;
const MAX_POLLS = 60; // 2 min max (60 × 2s)

interface UseScanState {
  scanId: string | null;
  scanDetail: ScanDetail | null;
  isLoading: boolean;
  isPolling: boolean;
  error: string | null;
}

interface UseScanReturn extends UseScanState {
  submit: (url: string) => Promise<void>;
  reset: () => void;
}

export function useScan(): UseScanReturn {
  const [state, setState] = useState<UseScanState>({
    scanId: null,
    scanDetail: null,
    isLoading: false,
    isPolling: false,
    error: null,
  });

  // Track poll timer so we can cancel it on unmount or reset
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollCountRef = useRef(0);

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const reset = useCallback(() => {
    stopPolling();
    pollCountRef.current = 0;
    setState({
      scanId: null,
      scanDetail: null,
      isLoading: false,
      isPolling: false,
      error: null,
    });
  }, [stopPolling]);

  const poll = useCallback(
    (scanId: string) => {
      stopPolling();

      const tick = async () => {
        pollCountRef.current += 1;

        if (pollCountRef.current > MAX_POLLS) {
          setState((prev) => ({
            ...prev,
            isPolling: false,
            error: "Scan is taking longer than expected. Please check back later.",
          }));
          return;
        }

        try {
          const detail = await getScan(scanId);
          setState((prev) => ({ ...prev, scanDetail: detail }));

          if (TERMINAL_STATUSES.includes(detail.status)) {
            setState((prev) => ({ ...prev, isPolling: false }));
          } else {
            // Schedule next poll
            pollTimerRef.current = setTimeout(tick, POLL_INTERVAL_MS);
          }
        } catch (err) {
          const message =
            err instanceof ApiError
              ? err.detail
              : "Failed to retrieve scan results.";
          setState((prev) => ({ ...prev, isPolling: false, error: message }));
        }
      };

      // First poll immediately
      tick();
    },
    [stopPolling]
  );

  const submit = useCallback(
    async (url: string) => {
      reset();
      setState((prev) => ({ ...prev, isLoading: true, error: null }));

      try {
        const response = await createScan({ url });
        pollCountRef.current = 0;
        setState((prev) => ({
          ...prev,
          scanId: response.scan_id,
          isLoading: false,
          isPolling: true,
        }));
        poll(response.scan_id);
      } catch (err) {
        const message =
          err instanceof ApiError ? err.detail : "Failed to start scan.";
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isPolling: false,
          error: message,
        }));
      }
    },
    [reset, poll]
  );

  return { ...state, submit, reset };
}
