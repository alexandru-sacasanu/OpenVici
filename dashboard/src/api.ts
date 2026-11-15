// Every API call carries the token from the link `openvici dashboard` printed.
// It arrives in the URL fragment, is kept for this tab only, and is removed
// from the address bar so it does not end up in history or a screenshot.

const KEY = "openvici-token";

function takeToken(): string {
  const match = /(?:^#|&)token=([^&]+)/.exec(window.location.hash);
  if (match?.[1]) {
    sessionStorage.setItem(KEY, match[1]);
    history.replaceState(null, "", window.location.pathname);
  }
  return sessionStorage.getItem(KEY) ?? "";
}

const token = takeToken();

export const hasToken = (): boolean => token !== "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function headers(json: boolean): HeadersInit {
  const h: Record<string, string> = { Authorization: `Bearer ${token}` };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

async function fail(response: Response): Promise<never> {
  let message = `Request failed (${response.status})`;
  try {
    const body = (await response.json()) as { error?: string };
    if (body.error) message = body.error;
  } catch {
    /* keep the generic message */
  }
  throw new ApiError(response.status, message);
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: headers(body !== undefined),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) return fail(response);
  return (await response.json()) as T;
}

/** POST text as the raw request body (the browser encodes it as UTF-8). */
export async function sendText(path: string, data: string): Promise<void> {
  const response = await fetch(path, { method: "POST", headers: headers(false), body: data });
  if (!response.ok) return fail(response);
}

export interface StreamEvent {
  d?: string;
  o?: number;
  k?: number;
  exit?: number;
}

/** Newline-delimited JSON events from a long-lived response. */
export async function* stream(path: string, signal: AbortSignal): AsyncGenerator<StreamEvent> {
  const response = await fetch(path, { headers: headers(false), signal });
  if (!response.ok || !response.body) return fail(response);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    pending += decoder.decode(value, { stream: true });
    let newline = pending.indexOf("\n");
    while (newline >= 0) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      if (line) yield JSON.parse(line) as StreamEvent;
      newline = pending.indexOf("\n");
    }
  }
}
