// Shared state of the control panel: what the supervisor last said, the
// open confirmation, and the toasts. There is no push channel from the
// supervisor (ADR-0009): the status is polled every 3 seconds while the
// window is visible, the settings every 10.

import { api, type config, type gui, type ipc } from "./api";
import { needsConfirmation, toApiError, type ApiError } from "./errors";

export const app = $state({
  status: undefined as ipc.StatusResult | undefined,
  config: undefined as config.Config | undefined,
  revision: 0,
  warnings: [] as string[],
  failed: false,
  version: "",
  ports: undefined as gui.Port[] | undefined,
});

export async function refreshStatus(): Promise<void> {
  try {
    app.status = await api().status();
    app.failed = false;
  } catch {
    app.failed = true;
  }
}

export async function refreshConfig(): Promise<void> {
  try {
    applyConfig(await api().config());
  } catch {
    app.failed = true;
  }
}

export async function refreshPorts(): Promise<void> {
  try {
    app.ports = await api().listeningPorts();
  } catch {
    app.ports = undefined;
  }
}

/** Takes the settings a change answered with. */
export function applyConfig(res: ipc.ConfigResult): void {
  app.config = res.config;
  app.revision = res.revision;
  app.warnings = res.warnings ?? [];
}

/** Starts polling; returns the function that stops it. */
export function startPolling(): () => void {
  let n = 0;
  const tick = () => {
    if (document.visibilityState === "hidden") return;
    void refreshStatus();
    if (n++ % 3 === 0) {
      void refreshConfig();
      void refreshPorts();
    }
  };
  tick();
  const timer = setInterval(tick, 3000);
  const onVisible = () => {
    if (document.visibilityState === "visible") tick();
  };
  document.addEventListener("visibilitychange", onVisible);
  return () => {
    clearInterval(timer);
    document.removeEventListener("visibilitychange", onVisible);
  };
}

// ---- Confirmation of weakening changes (S-32, SE-27) ----

export const confirmation = $state({
  open: false,
  sentences: [] as string[],
  resolve: undefined as ((ok: boolean) => void) | undefined,
});

function ask(sentences: string[]): Promise<boolean> {
  return new Promise((resolve) => {
    confirmation.sentences = sentences;
    confirmation.resolve = resolve;
    confirmation.open = true;
  });
}

export function answerConfirmation(ok: boolean): void {
  const r = confirmation.resolve;
  confirmation.open = false;
  confirmation.resolve = undefined;
  r?.(ok);
}

/** Thrown when the user declines a confirmation; nothing changed. */
export class Declined extends Error {}

/**
 * Runs a change. If the supervisor answers that it weakens protection, the
 * user sees its sentences, exactly as sent, and only on "Make the change" is
 * the call sent again with the supervisor's single-use token. The control
 * panel never decides on its own that a change is confirmed.
 */
export async function withConfirmation<T>(run: (token: string) => Promise<T>): Promise<T> {
  try {
    return await run("");
  } catch (e) {
    const err = toApiError(e);
    if (!needsConfirmation(err)) throw err;
    const ok = await ask(err.confirmation.sentences.length ? err.confirmation.sentences : [err.message]);
    if (!ok) throw new Declined();
    try {
      return await run(err.confirmation.token);
    } catch (e2) {
      throw toApiError(e2);
    }
  }
}

// ---- Toasts ----

export interface Toast {
  id: number;
  kind: "done" | "error";
  text: string;
  detail?: string;
}

export const toasts = $state<Toast[]>([]);
let nextToast = 1;

export function toastDone(text: string): void {
  const id = nextToast++;
  toasts.push({ id, kind: "done", text });
  setTimeout(() => dismissToast(id), 4000);
}

export function toastError(e: unknown, fallback: string): void {
  if (e instanceof Declined) return;
  const err: ApiError = toApiError(e);
  toasts.push({ id: nextToast++, kind: "error", text: err.message || fallback, detail: err.workerDetail });
}

export function dismissToast(id: number): void {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}
