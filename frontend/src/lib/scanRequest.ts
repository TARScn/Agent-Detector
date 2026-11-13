/**
 * A scan is one process-wide operation, but its mutation instance lives in the
 * page that triggered it. Navigating away unmounts that page, so a per-page
 * `isPending` would flip back to "立即扫描" while the scan still runs. This
 * module-level flag is shared by every page and is cleared when the mutation
 * settles; the server status query remains the source of truth after reloads.
 */
let requested = false;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((listener) => listener());
}

export function beginScanRequest() {
  if (requested) return;
  requested = true;
  emit();
}

export function endScanRequest() {
  if (!requested) return;
  requested = false;
  emit();
}

export function subscribeScanRequest(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function isScanRequested() {
  return requested;
}