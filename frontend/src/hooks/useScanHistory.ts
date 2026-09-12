/**
 * useScanHistory hook
 *
 * Fetches a paginated list of past scans from GET /api/v1/scans.
 * Supports client-side page navigation and re-fetching.
 *
 * Usage:
 *   const { scans, total, page, setPage, isLoading, error, refetch } = useScanHistory();
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { listScans, ApiError } from "@/lib/api";
import type { ScanSummary, SortField, SortOrder } from "@/types";

interface UseScanHistoryOptions {
  initialPage?: number;
  limit?: number;
  sort?: SortField;
  order?: SortOrder;
}

interface UseScanHistoryReturn {
  scans: ScanSummary[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  isLoading: boolean;
  error: string | null;
  setPage: (page: number) => void;
  refetch: () => void;
}

export function useScanHistory(
  options: UseScanHistoryOptions = {}
): UseScanHistoryReturn {
  const {
    initialPage = 1,
    limit = 20,
    sort = "created_at",
    order = "desc",
  } = options;

  const [page, setPageState] = useState(initialPage);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);

  const fetchHistory = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await listScans({ page, limit, sort, order });
      setScans(data.scans);
      setTotal(data.total);
    } catch (err) {
      const message =
        err instanceof ApiError ? err.detail : "Failed to load scan history.";
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [page, limit, sort, order, refreshTick]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const setPage = useCallback((newPage: number) => {
    setPageState(newPage);
  }, []);

  const refetch = useCallback(() => {
    setRefreshTick((t) => t + 1);
  }, []);

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return {
    scans,
    total,
    page,
    limit,
    totalPages,
    isLoading,
    error,
    setPage,
    refetch,
  };
}
