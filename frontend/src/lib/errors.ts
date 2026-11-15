// The supervisor's errors reach the UI as the cause of a rejected binding
// call (internal/gui marshalError). Every field is plain text to show as
// text (S-34); workerDetail is the web server's own words and is always
// shown apart, labelled as coming from it (DR-6).

export interface Confirmation {
  token: string;
  sentences: string[];
  expires: string;
}

export interface ApiError {
  code: string;
  message: string;
  confirmation?: Confirmation;
  workerDetail?: string;
}

const codes = new Set(["invalid", "not_found", "confirmation_required", "forbidden", "unavailable", "internal"]);

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function fromObject(o: Record<string, unknown>): ApiError | undefined {
  const code = str(o.code);
  if (!codes.has(code)) return undefined;
  const out: ApiError = { code, message: str(o.message) };
  const wd = str(o.worker_detail);
  if (wd) out.workerDetail = wd;
  const c = o.confirmation;
  if (c && typeof c === "object") {
    const co = c as Record<string, unknown>;
    const sentences = Array.isArray(co.sentences) ? co.sentences.filter((s): s is string => typeof s === "string") : [];
    if (str(co.token)) out.confirmation = { token: str(co.token), sentences, expires: str(co.expires) };
  }
  return out;
}

/** Reads an ApiError out of whatever a failed call rejected with. */
export function toApiError(e: unknown): ApiError {
  const cause = (e as { cause?: unknown } | null)?.cause;
  let parsed: unknown = cause;
  if (typeof cause === "string") {
    try {
      parsed = JSON.parse(cause);
    } catch {
      parsed = undefined;
    }
  }
  if (parsed && typeof parsed === "object") {
    const got = fromObject(parsed as Record<string, unknown>);
    if (got) return got;
  }
  if (e && typeof e === "object" && "code" in e) {
    const got = fromObject(e as Record<string, unknown>);
    if (got) return got;
  }
  return { code: "unavailable", message: "" };
}

/** Whether the error offers a confirmation for a weakening change (S-32). */
export function needsConfirmation(e: ApiError): e is ApiError & { confirmation: Confirmation } {
  return e.code === "confirmation_required" && !!e.confirmation;
}
