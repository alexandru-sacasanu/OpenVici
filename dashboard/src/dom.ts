type Child = Node | string | null | undefined | false;

/** Build an element. Text always goes in as text, never as HTML. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { class: className, ...rest } = props;
  if (className) node.className = className;
  Object.assign(node, rest);
  for (const child of children) {
    if (child) node.append(child);
  }
  return node;
}

export function clear(node: Element): void {
  node.replaceChildren();
}
