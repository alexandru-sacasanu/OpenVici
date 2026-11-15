// The chat tab is a terminal attached to the real `openvici chat` process.
// Nothing about the conversation is reimplemented here: approval prompts and
// tool output are whatever the agent prints.

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { api, sendText, stream } from "./api";
import { el } from "./dom";

function decodeBase64(text: string): Uint8Array {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

export function mountChat(root: HTMLElement): { focus: () => void } {
  const state = el("span", { class: "muted" }, "Starting…");
  const restart = el("button", { type: "button" }, "New session");
  // xterm puts its own "terminal" class on the element it opens in, so the
  // framed box and the element xterm measures are kept separate.
  const host = el("div", { class: "term-host" });
  root.append(el("div", { class: "toolbar" }, state, restart), el("div", { class: "term-box" }, host));

  const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 14,
    scrollback: 5000,
    theme: dark
      ? { background: "#16181b", foreground: "#e3e5e8", cursor: "#e3e5e8" }
      : { background: "#ffffff", foreground: "#1d2126", cursor: "#1d2126", selectionBackground: "#c9d7ef" },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(host);

  let id: string | null = null;
  let abort: AbortController | null = null;
  let outbox = "";
  let sending = false;

  // Keystrokes are sent one request at a time so they cannot overtake each other.
  async function flush(): Promise<void> {
    if (sending || !id || !outbox) return;
    sending = true;
    const batch = outbox;
    outbox = "";
    try {
      await sendText(`/api/terminals/${id}/input`, batch);
    } catch {
      state.textContent = "Session ended.";
    } finally {
      sending = false;
      void flush();
    }
  }

  term.onData((data) => {
    outbox += data;
    void flush();
  });

  async function resize(): Promise<void> {
    if (root.hidden) return;
    fit.fit();
    if (id) {
      await api("POST", `/api/terminals/${id}/resize`, { cols: term.cols, rows: term.rows }).catch(() => undefined);
    }
  }

  async function follow(current: string, signal: AbortSignal): Promise<void> {
    let offset = 0;
    for (;;) {
      try {
        for await (const event of stream(`/api/terminals/${current}/stream?offset=${offset}`, signal)) {
          if (event.d) term.write(decodeBase64(event.d));
          if (event.o !== undefined) offset = event.o;
          if (event.exit !== undefined) {
            state.textContent = "Session ended.";
            return;
          }
        }
      } catch {
        if (signal.aborted) return;
      }
      if (signal.aborted) return;
      state.textContent = "Reconnecting…";
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
  }

  async function start(): Promise<void> {
    abort?.abort();
    if (id) await api("DELETE", `/api/terminals/${id}`).catch(() => undefined);
    id = null;
    term.reset();
    fit.fit();
    state.textContent = "Starting…";
    try {
      const opened = await api<{ id: string }>("POST", "/api/terminals", { cols: term.cols, rows: term.rows });
      id = opened.id;
      state.textContent = "Connected to openvici chat.";
      abort = new AbortController();
      void follow(opened.id, abort.signal);
      term.focus();
    } catch (error) {
      state.textContent = error instanceof Error ? error.message : "Could not start a session.";
    }
  }

  restart.addEventListener("click", () => void start());
  window.addEventListener("resize", () => void resize());
  void start();

  return {
    focus: () => {
      void resize();
      term.focus();
    },
  };
}
