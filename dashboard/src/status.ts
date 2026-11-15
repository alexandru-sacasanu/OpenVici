import { api } from "./api";
import { clear, el } from "./dom";

interface Alert {
  level: "critical" | "warning";
  kind: string;
  message: string;
}

interface Status {
  alerts: Alert[];
  memory: { total: number; available: number } | null;
  disks: { label: string; path: string; free: number; total: number }[];
  sandbox: { mode: string; docker_found: boolean; workspace: string; network: string };
  audit: { ok: boolean; entries: number; error: string | null };
  notes: Record<string, { used: number; limit: number }>;
  model: { provider: string; name: string };
}

const gb = (bytes: number): string => `${(bytes / 2 ** 30).toFixed(1)} GB`;

function meter(used: number, total: number): HTMLElement {
  const share = total > 0 ? Math.min(1, used / total) : 0;
  const bar = el("div", { class: "meter" }, el("div", { class: share > 0.9 ? "fill high" : "fill" }));
  (bar.firstElementChild as HTMLElement).style.width = `${(share * 100).toFixed(1)}%`;
  bar.setAttribute("role", "meter");
  bar.setAttribute("aria-valuenow", String(Math.round(share * 100)));
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", "100");
  return bar;
}

function item(name: string, value: string, extra?: HTMLElement): HTMLElement {
  return el("div", { class: "stat" }, el("dt", {}, name), el("dd", {}, value, extra));
}

function renderBanner(banner: HTMLElement, alerts: Alert[], dismissed: Set<string>): void {
  const open = alerts.filter((alert) => !dismissed.has(alert.message));
  const first = open[0];
  if (!first) {
    banner.hidden = true;
    return;
  }
  clear(banner);
  banner.hidden = false;
  banner.className = first.level;
  const more = open.length > 1 ? ` (+${open.length - 1} more on the Status tab)` : "";
  const close = el("button", { type: "button", ariaLabel: "Dismiss" }, "Dismiss");
  close.addEventListener("click", () => {
    dismissed.add(first.message);
    renderBanner(banner, alerts, dismissed);
  });
  banner.append(el("span", {}, first.message + more), close);
}

function renderPanel(root: HTMLElement, status: Status): void {
  clear(root);
  if (status.alerts.length > 0) {
    const list = el("ul", { class: "alerts" });
    for (const alert of status.alerts) list.append(el("li", { class: alert.level }, alert.message));
    root.append(list);
  }
  const stats = el("dl", { class: "stats" });
  stats.append(item("Model", status.model.name ? `${status.model.name} (${status.model.provider})` : "not configured"));
  stats.append(item("Sandbox", status.sandbox.mode === "docker"
    ? `Docker, network: ${status.sandbox.network}${status.sandbox.docker_found ? "" : " (Docker not found)"}`
    : "none (host-unsafe)"));
  stats.append(item("Project folder", status.sandbox.workspace));
  stats.append(item("Audit log", status.audit.ok
    ? `verified, ${status.audit.entries} entries`
    : `FAILED verification: ${status.audit.error ?? "unknown"}`));
  if (status.memory) {
    const used = status.memory.total - status.memory.available;
    stats.append(item("Memory", `${gb(status.memory.available)} available of ${gb(status.memory.total)}`,
      meter(used, status.memory.total)));
  }
  for (const disk of status.disks) {
    stats.append(item(`Disk (${disk.label})`, `${gb(disk.free)} free of ${gb(disk.total)}`,
      meter(disk.total - disk.free, disk.total)));
  }
  for (const [file, usage] of Object.entries(status.notes)) {
    stats.append(item(file, `${usage.used} of ${usage.limit} characters`, meter(usage.used, usage.limit)));
  }
  root.append(stats);
}

export function mountStatus(root: HTMLElement, banner: HTMLElement): { refresh: () => void } {
  const dismissed = new Set<string>(); // lasts until the page is reloaded
  async function refresh(): Promise<void> {
    try {
      const status = await api<Status>("GET", "/api/status");
      renderBanner(banner, status.alerts, dismissed);
      renderPanel(root, status);
    } catch (error) {
      clear(root);
      root.append(el("p", { class: "error" }, error instanceof Error ? error.message : "Could not load status."));
    }
  }
  void refresh();
  window.setInterval(() => void refresh(), 15000);
  return { refresh: () => void refresh() };
}
