import { nextBackupReadDelay } from './backupLiveSource.ts';
import type { BackupLiveState } from './backupLiveSource.ts';

export interface BackupPollScheduler {
  set(callback: () => void, delay: number): unknown;
  clear(handle: unknown): void;
}

const browserScheduler: BackupPollScheduler = {
  set: (callback, delay) => setTimeout(callback, delay),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

// The same abort signal covers all reads in this mounted view. A manual
// refresh starts a new view and cancels every request from the previous one.
export function startBackupLivePolling(
  source: { read(signal: AbortSignal): Promise<BackupLiveState> },
  onResult: (state: BackupLiveState) => void,
  beforeRead: () => void,
  isVisible: () => boolean,
  scheduler: BackupPollScheduler = browserScheduler,
) {
  const controller = new AbortController();
  let timer: unknown;
  let pending = false;
  let stopped = false;
  let failures = 0;

  const schedule = (delay: number) => {
    if (stopped) return;
    timer = scheduler.set(() => { timer = undefined; void read(); }, delay);
  };
  const read = async () => {
    if (stopped || pending) return;
    if (!isVisible()) { schedule(30_000); return; }
    pending = true;
    beforeRead();
    let result: BackupLiveState;
    try {
      result = await source.read(controller.signal);
    } catch {
      if (controller.signal.aborted) { pending = false; return; }
      result = { kind: 'error' };
    }
    pending = false;
    if (stopped || controller.signal.aborted) return;
    failures = result.kind === 'error' ? failures + 1 : 0;
    onResult(result);
    schedule(nextBackupReadDelay(result, failures));
  };

  void read();
  return {
    wake() {
      if (stopped || pending || !isVisible()) return;
      if (timer !== undefined) scheduler.clear(timer);
      schedule(0);
    },
    stop() {
      if (stopped) return;
      stopped = true;
      controller.abort();
      if (timer !== undefined) scheduler.clear(timer);
      timer = undefined;
    },
  };
}
