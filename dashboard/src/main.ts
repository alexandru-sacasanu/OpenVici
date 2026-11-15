import { hasToken } from "./api";
import { mountChat } from "./chat";
import { mountConfig } from "./config";
import { el } from "./dom";
import { mountStatus } from "./status";
import "./style.css";

function must(id: string): HTMLElement {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing #${id}`);
  return node;
}

const panels = { chat: must("tab-chat"), config: must("tab-config"), status: must("tab-status") };
type Tab = keyof typeof panels;

if (!hasToken()) {
  must("tabs").hidden = true;
  panels.chat.append(
    el("div", { class: "notice" },
      el("h1", {}, "This page needs its access link"),
      el("p", {}, "Run "), el("code", {}, "openvici dashboard"),
      el("p", {}, "in a terminal and open the link it prints. The link carries a one-time key for this " +
        "session, so that other pages in your browser cannot control the agent.")));
} else {
  const chat = mountChat(panels.chat);
  const status = mountStatus(panels.status, must("banner"));
  let configLoaded = false;

  const show = (tab: Tab): void => {
    for (const [name, panel] of Object.entries(panels)) panel.hidden = name !== tab;
    for (const button of document.querySelectorAll<HTMLButtonElement>("#tabs button")) {
      button.setAttribute("aria-selected", String(button.dataset.tab === tab));
    }
    if (tab === "chat") chat.focus();
    if (tab === "status") status.refresh();
    if (tab === "config" && !configLoaded) {
      configLoaded = true;
      void mountConfig(panels.config);
    }
  };

  for (const button of document.querySelectorAll<HTMLButtonElement>("#tabs button")) {
    button.addEventListener("click", () => show(button.dataset.tab as Tab));
  }
}
