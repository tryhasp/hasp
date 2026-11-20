const MAX_DEPTH = 5;

const escape = (value: string): string => CSS.escape(value);

const isUnique = (root: ParentNode, selector: string): boolean => {
  try {
    return root.querySelectorAll(selector).length === 1;
  } catch {
    return false;
  }
};

export const selectorFor = (el: Element): string | undefined => {
  const root = el.getRootNode();
  if (!(root instanceof Document)) return undefined;
  const id = el.id;
  if (id !== '' && isUnique(root, `#${escape(id)}`)) return `#${escape(id)}`;
  const tag = el.localName;
  const name = el.getAttribute('name');
  if (name !== null && name !== '') {
    const byName = `${tag}[name="${escape(name)}"]`;
    if (isUnique(root, byName)) return byName;
  }
  const parts: string[] = [];
  let node: Element | null = el;
  while (node !== null && parts.length < MAX_DEPTH && node !== root.documentElement) {
    const current: Element = node;
    const parent: Element | null = current.parentElement;
    const siblings: Element[] =
      parent === null
        ? []
        : Array.from(parent.children).filter((c) => c.localName === current.localName);
    const position = siblings.indexOf(current) + 1;
    parts.unshift(
      siblings.length > 1 ? `${current.localName}:nth-of-type(${position})` : current.localName,
    );
    const candidate = parts.join(' > ');
    if (isUnique(root, candidate)) return candidate;
    node = parent;
  }
  return undefined;
};
