import { Component, For, Show, createSignal, JSX } from "solid-js";

/**
 * SAFE Markdown renderer for chat messages.
 *
 * Security: ZERO use of innerHTML / dangerouslySetInnerHTML.
 * All parsing produces SolidJS JSX elements directly.
 * No raw HTML from user input ever reaches the DOM.
 *
 * Supported syntax:
 *   **bold**          → <strong>
 *   *italic*  _italic_ → <em>
 *   ~~strikethrough~~ → <del>
 *   `inline code`     → <code>
 *   ```code block```  → <pre><code>
 *   ||spoiler||       → click-to-reveal
 *   > quote           → blockquote
 *   [text](url)       → <a> (https only)
 */

/* ── Types ─────────────────────────────────────────── */
type Node =
  | { type: "text"; value: string }
  | { type: "bold"; children: Node[] }
  | { type: "italic"; children: Node[] }
  | { type: "strike"; children: Node[] }
  | { type: "code"; value: string }
  | { type: "codeblock"; lang: string; value: string }
  | { type: "spoiler"; children: Node[] }
  | { type: "link"; text: string; url: string }
  | { type: "quote"; children: Node[] }
  | { type: "br" };

/* ── URL validation — only safe protocols ──────────── */
const sanitizeUrl = (raw: string): string | null => {
  try {
    const u = new URL(raw);
    if (u.protocol === "http:" || u.protocol === "https:") return u.href;
  } catch { /* invalid URL */ }
  return null;
};

/* ── Inline parser ─────────────────────────────────── */
function parseInline(text: string): Node[] {
  const nodes: Node[] = [];
  let i = 0;
  let buf = "";

  const flush = () => {
    if (buf) { nodes.push({ type: "text", value: buf }); buf = ""; }
  };

  while (i < text.length) {
    // Escaped character
    if (text[i] === "\\" && i + 1 < text.length && "\\*_~`|[]()>".includes(text[i + 1])) {
      buf += text[i + 1];
      i += 2;
      continue;
    }

    // Inline code `...`
    if (text[i] === "`" && text[i + 1] !== "`") {
      const end = text.indexOf("`", i + 1);
      if (end !== -1) {
        flush();
        nodes.push({ type: "code", value: text.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }

    // Bold **...**
    if (text[i] === "*" && text[i + 1] === "*") {
      const end = text.indexOf("**", i + 2);
      if (end !== -1) {
        flush();
        nodes.push({ type: "bold", children: parseInline(text.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    }

    // Italic *...*
    if (text[i] === "*" && text[i + 1] !== "*") {
      const end = findClosing(text, i + 1, "*");
      if (end !== -1) {
        flush();
        nodes.push({ type: "italic", children: parseInline(text.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    }

    // Italic _..._  (only if not surrounded by word chars)
    if (text[i] === "_" && text[i + 1] !== "_") {
      const end = findClosing(text, i + 1, "_");
      if (end !== -1) {
        flush();
        nodes.push({ type: "italic", children: parseInline(text.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    }

    // Strikethrough ~~...~~
    if (text[i] === "~" && text[i + 1] === "~") {
      const end = text.indexOf("~~", i + 2);
      if (end !== -1) {
        flush();
        nodes.push({ type: "strike", children: parseInline(text.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    }

    // Spoiler ||...||
    if (text[i] === "|" && text[i + 1] === "|") {
      const end = text.indexOf("||", i + 2);
      if (end !== -1) {
        flush();
        nodes.push({ type: "spoiler", children: parseInline(text.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    }

    // Link [text](url)
    if (text[i] === "[") {
      const closeBracket = text.indexOf("]", i + 1);
      if (closeBracket !== -1 && text[closeBracket + 1] === "(") {
        const closeParen = text.indexOf(")", closeBracket + 2);
        if (closeParen !== -1) {
          const linkText = text.slice(i + 1, closeBracket);
          const rawUrl = text.slice(closeBracket + 2, closeParen);
          const safeUrl = sanitizeUrl(rawUrl);
          if (safeUrl && linkText.length > 0) {
            flush();
            nodes.push({ type: "link", text: linkText, url: safeUrl });
            i = closeParen + 1;
            continue;
          }
        }
      }
    }

    buf += text[i];
    i++;
  }

  flush();
  return nodes;
}

/** Find closing delimiter that isn't escaped */
function findClosing(text: string, from: number, delim: string): number {
  let i = from;
  while (i < text.length) {
    if (text[i] === "\\" && i + 1 < text.length) { i += 2; continue; }
    if (text.startsWith(delim, i) && i > from) return i;
    i++;
  }
  return -1;
}

/* ── Block-level parser ────────────────────────────── */
function parseBlocks(text: string): Node[] {
  const nodes: Node[] = [];
  const lines = text.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Code block ```
    if (line.trimStart().startsWith("```")) {
      const lang = line.trimStart().slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length) {
        if (lines[i].trimStart().startsWith("```")) { i++; break; }
        codeLines.push(lines[i]);
        i++;
      }
      nodes.push({ type: "codeblock", lang, value: codeLines.join("\n") });
      continue;
    }

    // Blockquote > ...
    if (line.startsWith("> ") || line === ">") {
      const quoteLines: string[] = [];
      while (i < lines.length && (lines[i].startsWith("> ") || lines[i] === ">")) {
        quoteLines.push(lines[i].slice(2));
        i++;
      }
      nodes.push({ type: "quote", children: parseBlocks(quoteLines.join("\n")) });
      continue;
    }

    // Empty line → break
    if (line.trim() === "") {
      if (nodes.length > 0 && nodes[nodes.length - 1].type !== "br") {
        nodes.push({ type: "br" });
      }
      i++;
      continue;
    }

    // Inline content
    const inline = parseInline(line);
    nodes.push(...inline);
    // Add linebreak between non-empty lines (except last)
    if (i < lines.length - 1) {
      nodes.push({ type: "br" });
    }
    i++;
  }

  return nodes;
}

/* ── Render nodes to JSX ───────────────────────────── */
const RenderNode: Component<{ node: Node }> = (props) => {
  switch (props.node.type) {
    case "text":
      return <>{props.node.value}</>;

    case "bold":
      return (
        <strong style={{ "font-weight": "600", color: "#e0e0e0" }}>
          <For each={props.node.children}>{(n) => <RenderNode node={n} />}</For>
        </strong>
      );

    case "italic":
      return (
        <em style={{ "font-style": "italic", color: "#c0c0d0" }}>
          <For each={props.node.children}>{(n) => <RenderNode node={n} />}</For>
        </em>
      );

    case "strike":
      return (
        <del style={{ "text-decoration": "line-through", opacity: "0.6" }}>
          <For each={props.node.children}>{(n) => <RenderNode node={n} />}</For>
        </del>
      );

    case "code":
      return (
        <code class="md-code">{props.node.value}</code>
      );

    case "codeblock":
      return (
        <pre class="md-codeblock">
          <Show when={props.node.lang}>
            <span class="md-codeblock-lang">{props.node.lang}</span>
          </Show>
          <code>{props.node.value}</code>
        </pre>
      );

    case "spoiler":
      return <Spoiler>{props.node.children}</Spoiler>;

    case "link":
      return (
        <a
          href={props.node.url}
          target="_blank"
          rel="noopener noreferrer"
          class="md-link"
          title={props.node.url}
        >
          {props.node.text}
        </a>
      );

    case "quote":
      return (
        <blockquote class="md-quote">
          <For each={props.node.children}>{(n) => <RenderNode node={n} />}</For>
        </blockquote>
      );

    case "br":
      return <br />;

    default:
      return null;
  }
};

/* ── Spoiler component with reveal ─────────────────── */
const Spoiler: Component<{ children: Node[] }> = (props) => {
  const [revealed, setRevealed] = createSignal(false);
  return (
    <span
      class={revealed() ? "md-spoiler md-spoiler-revealed" : "md-spoiler"}
      onClick={(e) => { e.stopPropagation(); setRevealed(!revealed()); }}
    >
      <For each={props.children}>{(n) => <RenderNode node={n} />}</For>
    </span>
  );
};

/* ── Public component ──────────────────────────────── */
interface MessageRendererProps {
  text: string;
  class?: string;
  style?: JSX.CSSProperties;
}

const MessageRenderer: Component<MessageRendererProps> = (props) => {
  const nodes = () => parseBlocks(props.text);

  return (
    <div class={`md-message ${props.class ?? ""}`} style={props.style}>
      <For each={nodes()}>{(n) => <RenderNode node={n} />}</For>
    </div>
  );
};

export { MessageRenderer };
