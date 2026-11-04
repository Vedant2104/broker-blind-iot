// Read-only xterm.js panel: shows log lines, colour-coded. No keyboard input — the
// dashboard never runs free-text commands.
import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

const ESC = "\x1b[";
const color = (code: string, s: string) => `${ESC}${code}m${s}${ESC}0m`;

/** Colour a log line the way a terminal user would expect. */
export function paint(line: string): string {
  if (line.startsWith("$ ")) return color("1;36", "$ ") + color("1", line.slice(2));
  if (/✗|REJECTED|SUCCEEDED|UNLOCKED|LEAKED|stolen|DIFFER/.test(line)) return color("31", line);
  if (/RESULT: BLOCKED|RESULT: DETECTED|✓/.test(line)) return color("32", line);
  if (/⚠|ALERT|quarantin|late|missing|WARN/i.test(line)) return color("33", line);
  const m = line.match(/^(\[[^\]]+\])(.*)$/);
  if (m) return color("90", m[1]) + m[2];
  return line;
}

export function Term({
  lines,
  className,
  placeholder,
}: {
  lines: string[];
  className?: string;
  placeholder?: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const written = useRef<string[]>([]);

  useEffect(() => {
    const t = new Terminal({
      disableStdin: true,
      convertEol: true,
      cursorBlink: false,
      cursorStyle: "bar",
      cursorInactiveStyle: "none",
      fontFamily: '"JetBrains Mono", "Cascadia Code", ui-monospace, monospace',
      fontSize: 14,
      lineHeight: 1.2,
      scrollback: 2000,
      theme: {
        background: "#05070c",
        foreground: "#e6ebf5",
        cursor: "#05070c",
        selectionBackground: "#60a5fa55",
      },
    });
    const fit = new FitAddon();
    t.loadAddon(fit);
    t.open(host.current!);
    term.current = t;
    written.current = [];
    const refit = () => {
      try {
        fit.fit();
      } catch {
        /* hidden panel: no size yet */
      }
    };
    refit();
    const ro = new ResizeObserver(refit);
    ro.observe(host.current!);
    return () => {
      ro.disconnect();
      t.dispose();
      term.current = null;
    };
  }, []);

  useEffect(() => {
    const t = term.current;
    if (!t) return;
    const prev = written.current;
    const shown = lines.length ? lines : placeholder ? [placeholder] : [];
    // Append when the new list extends what we wrote; otherwise redraw.
    let same = 0;
    const overlap = prev.length && shown.length ? findOverlap(prev, shown) : -1;
    if (overlap >= 0) {
      same = prev.length - overlap;
    } else {
      t.reset();
    }
    for (const line of shown.slice(overlap >= 0 ? same : 0)) t.writeln(paint(line));
    written.current = shown;
  }, [lines, placeholder]);

  return <div ref={host} className={className} />;
}

/** Where `next` continues `prev`: index in prev from which prev's tail equals next's head. */
function findOverlap(prev: string[], next: string[]): number {
  // Common case: next is prev with more lines appended (same object prefix).
  if (next.length >= prev.length && prev.every((l, i) => l === next[i])) return 0;
  // Capped lists drop old lines from the front: find prev's last line in next.
  const last = prev[prev.length - 1];
  for (let k = next.length - 1; k >= 0; k--) {
    if (next[k] !== last) continue;
    const start = prev.length - 1 - k;
    if (start < 0) continue;
    let ok = true;
    for (let i = 0; i <= k; i++) {
      if (prev[start + i] !== next[i]) {
        ok = false;
        break;
      }
    }
    if (ok) return start;
  }
  return -1;
}
