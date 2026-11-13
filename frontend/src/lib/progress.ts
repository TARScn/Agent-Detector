let active = 0;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((listener) => listener());
}

/** 全局进行中的长任务计数：扫描这类整页级操作在任意页面触发都在顶部显示进度条。 */
export function beginGlobalProgress() {
  active += 1;
  emit();
}

export function endGlobalProgress() {
  active = Math.max(0, active - 1);
  emit();
}

export function subscribeGlobalProgress(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function isGlobalProgressActive() {
  return active > 0;
}