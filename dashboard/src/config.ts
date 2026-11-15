// The settings form is drawn from the schema the server sends, which is the
// same schema the config loader validates against. There is no list of
// settings in this file to keep in step with the backend.

import { api } from "./api";
import { clear, el } from "./dom";

interface Field {
  key: string;
  type: "string" | "integer" | "boolean" | "string_list" | "integer_list" | "choice" | "grants";
  default: unknown;
  help: string;
  choices: string[];
  caution: string;
}

interface Section {
  name: string;
  title: string;
  help: string;
  fields: Field[];
}

type Values = Record<string, Record<string, unknown>>;
type Reader = () => unknown;

const lines = (text: string): string[] =>
  text.split("\n").map((line) => line.trim()).filter((line) => line !== "");

function grantsToText(value: unknown): string {
  return Object.entries((value ?? {}) as Record<string, string[]>)
    .map(([tool, names]) => `${tool} = ${names.join(", ")}`)
    .join("\n");
}

function textToGrants(text: string): Record<string, string[]> {
  const grants: Record<string, string[]> = {};
  for (const line of lines(text)) {
    const [tool, names = ""] = line.split("=", 2);
    if (tool?.trim()) {
      grants[tool.trim()] = names.split(",").map((name) => name.trim()).filter((name) => name !== "");
    }
  }
  return grants;
}

function control(field: Field, value: unknown, id: string): { node: HTMLElement; read: Reader } {
  switch (field.type) {
    case "boolean": {
      const input = el("input", { type: "checkbox", id, checked: value === true });
      return { node: input, read: () => input.checked };
    }
    case "integer": {
      const input = el("input", { type: "number", id, min: "0", step: "1", value: String(value ?? 0) });
      return { node: input, read: () => (Number.isFinite(input.valueAsNumber) ? Math.trunc(input.valueAsNumber) : NaN) };
    }
    case "choice": {
      const select = el("select", { id });
      for (const choice of field.choices) {
        select.append(el("option", { value: choice, selected: choice === value }, choice === "" ? "(same as main model)" : choice));
      }
      return { node: select, read: () => select.value };
    }
    case "string_list": {
      const area = el("textarea", { id, rows: 3, value: ((value ?? []) as string[]).join("\n"), placeholder: "one per line" });
      return { node: area, read: () => lines(area.value) };
    }
    case "integer_list": {
      const area = el("textarea", { id, rows: 2, value: ((value ?? []) as number[]).join("\n"), placeholder: "one per line" });
      return { node: area, read: () => lines(area.value).map((line) => (/^\d+$/.test(line) ? Number(line) : NaN)) };
    }
    case "grants": {
      const area = el("textarea", { id, rows: 4, value: grantsToText(value), placeholder: "model = ANTHROPIC_API_KEY" });
      return { node: area, read: () => textToGrants(area.value) };
    }
    default: {
      const input = el("input", { type: "text", id, value: String(value ?? ""), spellcheck: false });
      return { node: input, read: () => input.value.trim() };
    }
  }
}

export async function mountConfig(root: HTMLElement): Promise<void> {
  clear(root);
  let schema: Section[];
  let values: Values;
  try {
    [schema, values] = await Promise.all([api<Section[]>("GET", "/api/schema"), api<Values>("GET", "/api/config")]);
  } catch (error) {
    root.append(el("p", { class: "error" }, error instanceof Error ? error.message : "Could not load settings."));
    return;
  }

  const readers: Record<string, Record<string, Reader>> = {};
  const form = el("form", { class: "settings" });

  for (const section of schema) {
    const sectionReaders: Record<string, Reader> = {};
    readers[section.name] = sectionReaders;
    const box = el("fieldset", {}, el("legend", {}, section.title), el("p", { class: "muted" }, section.help));
    for (const field of section.fields) {
      const id = `f-${section.name}-${field.key}`;
      const { node, read } = control(field, values[section.name]?.[field.key], id);
      sectionReaders[field.key] = read;
      const label = el("label", { htmlFor: id }, field.key.replaceAll("_", " "));
      const row = el("div", { class: field.type === "boolean" ? "row check" : "row" }, label, node,
        el("p", { class: "help" }, field.help),
        field.caution ? el("p", { class: "caution" }, field.caution) : null);
      box.append(row);
    }
    form.append(box);
  }

  const result = el("span", { class: "muted" });
  result.setAttribute("role", "status");
  const save = el("button", { type: "submit", class: "primary" }, "Save settings");
  form.append(el("div", { class: "savebar" }, save, result));

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const next: Values = {};
    for (const [section, fields] of Object.entries(readers)) {
      const body: Record<string, unknown> = {};
      for (const [key, read] of Object.entries(fields)) body[key] = read();
      next[section] = body;
    }
    save.disabled = true;
    result.className = "muted";
    result.textContent = "Saving…";
    api<{ changed: string[] }>("PUT", "/api/config", next)
      .then(({ changed }) => {
        result.textContent = changed.length === 0
          ? "Nothing changed."
          : `Saved ${changed.length} change${changed.length === 1 ? "" : "s"} (${changed.join(", ")}). ` +
            "They apply to the next chat session.";
      })
      .catch((error: unknown) => {
        result.className = "error";
        result.textContent = `Not saved: ${error instanceof Error ? error.message : "unknown error"}`;
      })
      .finally(() => {
        save.disabled = false;
      });
  });

  root.append(form);
}
