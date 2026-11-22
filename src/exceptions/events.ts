import { request } from '@kinvolk/headlamp-plugin/lib/ApiProxy';

/** A Kubernetes Event, with the fields used here. */
export interface ExceptionEvent {
  reason?: string;
  message?: string;
  count?: number;
  eventTime?: string;
  lastTimestamp?: string;
  firstTimestamp?: string;
}

export function eventTime(event: ExceptionEvent): string | undefined {
  return event.lastTimestamp ?? event.eventTime ?? event.firstTimestamp;
}

// The reasons of the events the scanners record when they apply an exception: Kubescape for a
// control (ExceptionMatched), kubevuln for a CVE (VulnerabilitySuppressed)
const appliedReasons = new Set(['ExceptionMatched', 'VulnerabilitySuppressed']);

/**
 * The events the Kubescape scanners recorded when they suppressed a finding with the exception,
 * newest first. A field selector takes one reason, so the reasons are picked from the events of
 * the exception. Events of a ClusterSecurityException are looked up in all namespaces, as their
 * namespace depends on the recorder.
 */
export async function fetchExceptionEvents(
  kind: 'SecurityException' | 'ClusterSecurityException',
  name: string,
  namespace?: string
): Promise<ExceptionEvent[]> {
  const fieldSelector = new URLSearchParams({
    fieldSelector: `involvedObject.kind=${kind},involvedObject.name=${name}`,
  });
  const path = namespace ? `/api/v1/namespaces/${namespace}/events` : '/api/v1/events';
  const list = await request(`${path}?${fieldSelector.toString()}`);
  return ((list.items ?? []) as ExceptionEvent[])
    .filter(event => appliedReasons.has(event.reason ?? ''))
    .sort((a, b) => new Date(eventTime(b) ?? 0).getTime() - new Date(eventTime(a) ?? 0).getTime());
}
