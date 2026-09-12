/**
 * History detail page — /history/[scanId]
 *
 * Reuses the Results page at a different URL, accessed from the history list.
 * Simply redirects to /results/[scanId] — avoids duplicating result rendering logic.
 */

import { redirect } from "next/navigation";

interface Props {
  params: { scanId: string };
}

export default function HistoryDetailPage({ params }: Props) {
  // Permanently redirect to the canonical results URL
  redirect(`/results/${params.scanId}`);
}
