/**
 * In-house shell parser for the bash path pre-check. It covers the subset of
 * bash syntax that matters for finding file arguments: quoting, command
 * separators, redirections, heredocs, here-strings, and nested command /
 * process substitutions. Control flow (`if`, `for`, `case`, functions) is not
 * modelled; keywords simply appear as argv words, which the extractor skips.
 *
 * It implements {@link ShellParser} so it can be swapped for a full parser.
 */
import type { Heredoc, Redirect, ShellParser, ShellWord, SimpleCommand } from "./shell-ast.ts";

/** Nesting limit for `$(...)`, backticks and process substitutions. */
const MAX_DEPTH = 8;

const WORD_END = new Set([" ", "\t", "\n", ";", "&", "|", "<", ">", "(", ")"]);

function newCommand(): SimpleCommand {
  return { assignments: [], argv: [], redirects: [], heredocs: [], hereStrings: [] };
}

/**
 * Index of the `)` closing a group whose body starts at `start`, or the end of
 * the source when unterminated. Quotes and escapes are skipped.
 */
function findClose(src: string, start: number): number {
  let depth = 1;
  for (let j = start; j < src.length; j++) {
    const ch = src[j];
    if (ch === "\\") {
      j++;
    } else if (ch === "'") {
      const end = src.indexOf("'", j + 1);
      j = end < 0 ? src.length : end;
    } else if (ch === '"') {
      j++;
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\") j++;
        j++;
      }
    } else if (ch === "(") {
      depth++;
    } else if (ch === ")") {
      depth--;
      if (depth === 0) return j;
    }
  }
  return src.length;
}

class Parser {
  private readonly commands: SimpleCommand[] = [];
  private cmd = newCommand();
  private pending: Heredoc[] = [];
  private i = 0;

  constructor(
    private readonly src: string,
    private readonly depth: number,
  ) {}

  run(): SimpleCommand[] {
    const { src } = this;
    while (this.i < src.length) {
      const c = src[this.i]!;
      const next = src[this.i + 1];
      if (c === " " || c === "\t" || c === "\r") {
        this.i++;
      } else if (c === "\\" && next === "\n") {
        this.i += 2;
      } else if (c === "\n") {
        this.flush();
        this.i++;
        this.readHeredocBodies();
      } else if (c === "#") {
        while (this.i < src.length && src[this.i] !== "\n") this.i++;
      } else if ((c === "<" || c === ">") && next === "(") {
        const close = findClose(src, this.i + 2);
        this.nested(src.slice(this.i + 2, close));
        this.i = close + 1;
      } else if (c === "<" || c === ">" || (c === "&" && next === ">")) {
        this.readRedirect();
      } else if (c === ";" || c === "&" || c === "|" || c === "(" || c === ")") {
        this.flush();
        this.i++;
        if (src[this.i] === c || (c === "|" && src[this.i] === "&")) this.i++;
      } else {
        const word = this.readWord();
        // A bare number directly before `<`/`>` is a file descriptor (`2>file`).
        const fdPrefix =
          !word.quoted && /^\d+$/.test(word.text) && (src[this.i] === "<" || src[this.i] === ">");
        if (!fdPrefix) this.addWord(word);
      }
    }
    this.flush();
    return this.commands;
  }

  private flush(): void {
    const { cmd } = this;
    if (
      cmd.argv.length ||
      cmd.assignments.length ||
      cmd.redirects.length ||
      cmd.heredocs.length ||
      cmd.hereStrings.length
    ) {
      this.commands.push(cmd);
    }
    this.cmd = newCommand();
  }

  private addWord(word: ShellWord): void {
    if (!word.text && !word.quoted && !word.dynamic) return;
    if (this.cmd.argv.length === 0 && !word.quoted && /^[A-Za-z_]\w*\+?=/.test(word.text)) {
      this.cmd.assignments.push(word);
    } else {
      this.cmd.argv.push(word);
    }
  }

  private nested(source: string): void {
    if (this.depth >= MAX_DEPTH) return;
    this.commands.push(...new Parser(source, this.depth + 1).run());
  }

  private skipBlanks(): void {
    while (this.src[this.i] === " " || this.src[this.i] === "\t") this.i++;
  }

  private readRedirect(): void {
    const { src } = this;
    const at = (s: string) => src.startsWith(s, this.i);
    if (at("<<<")) {
      this.i += 3;
      this.skipBlanks();
      this.cmd.hereStrings.push(this.readWord());
      return;
    }
    if (at("<<")) {
      this.i += 2;
      const stripTabs = src[this.i] === "-";
      if (stripTabs) this.i++;
      this.skipBlanks();
      const word = this.readWord();
      const heredoc: Heredoc = { delimiter: word.text, quoted: word.quoted, stripTabs, body: "" };
      this.cmd.heredocs.push(heredoc);
      this.pending.push(heredoc);
      return;
    }
    let op: Redirect["op"] | "<&" | ">&";
    if (at("<>")) op = "<>";
    else if (at("<&")) op = "<&";
    else if (at("<")) op = "<";
    else if (at("&>>")) op = "&>>";
    else if (at("&>")) op = "&>";
    else if (at(">>")) op = ">>";
    else if (at(">|")) op = ">|";
    else if (at(">&")) op = ">&";
    else op = ">";
    this.i += op.length;
    this.skipBlanks();
    const target = this.readWord();
    if (!target.text && !target.dynamic) return;
    if (op === "<&" || op === ">&") {
      // `>&2` / `<&-` duplicate descriptors; `>& file` is bash shorthand for `&> file`.
      if (op === ">&" && !(!target.quoted && /^(\d+|-)$/.test(target.text))) {
        this.cmd.redirects.push({ op: "&>", target });
      }
      return;
    }
    this.cmd.redirects.push({ op, target });
  }

  private readHeredocBodies(): void {
    const { src } = this;
    for (const heredoc of this.pending) {
      const lines: string[] = [];
      while (this.i < src.length) {
        const lineEnd = src.indexOf("\n", this.i);
        const raw = src.slice(this.i, lineEnd < 0 ? src.length : lineEnd);
        this.i = lineEnd < 0 ? src.length : lineEnd + 1;
        const line = heredoc.stripTabs ? raw.replace(/^\t+/, "") : raw;
        if (line.replace(/\r$/, "") === heredoc.delimiter) break;
        lines.push(line);
      }
      heredoc.body = lines.join("\n");
    }
    this.pending = [];
  }

  private readWord(): ShellWord {
    const { src } = this;
    const word: ShellWord = { text: "", quoted: false, dynamic: false, glob: false };
    while (this.i < src.length) {
      const c = src[this.i]!;
      if (WORD_END.has(c)) break;
      if (c === "\\") {
        if (src[this.i + 1] === "\n") {
          this.i += 2;
        } else {
          if (this.i + 1 < src.length) word.text += src[this.i + 1];
          word.quoted = true;
          this.i += 2;
        }
      } else if (c === "'") {
        const end = src.indexOf("'", this.i + 1);
        const stop = end < 0 ? src.length : end;
        word.text += src.slice(this.i + 1, stop);
        word.quoted = true;
        this.i = stop + 1;
      } else if (c === '"') {
        this.readDoubleQuoted(word);
      } else if (c === "$" && src[this.i + 1] === "'") {
        // ANSI-C quoting; escapes are kept raw, which is enough for path checks.
        let j = this.i + 2;
        while (j < src.length && src[j] !== "'") j += src[j] === "\\" ? 2 : 1;
        word.text += src.slice(this.i + 2, Math.min(j, src.length));
        word.quoted = true;
        this.i = j + 1;
      } else if (c === "$" && src[this.i + 1] === '"') {
        this.i++;
      } else if (c === "$" || c === "`") {
        this.readExpansion(word);
      } else {
        if (c === "*" || c === "?" || c === "[") word.glob = true;
        word.text += c;
        this.i++;
      }
    }
    return word;
  }

  private readDoubleQuoted(word: ShellWord): void {
    const { src } = this;
    word.quoted = true;
    this.i++;
    while (this.i < src.length && src[this.i] !== '"') {
      const c = src[this.i]!;
      if (c === "\\" && this.i + 1 < src.length) {
        const next = src[this.i + 1]!;
        if (next !== "\n") word.text += '$`"\\'.includes(next) ? next : c + next;
        this.i += 2;
      } else if (c === "$" || c === "`") {
        this.readExpansion(word);
      } else {
        word.text += c;
        this.i++;
      }
    }
    this.i++;
  }

  /** `$name`, `${...}`, `$(...)`, `$((...))` or a backtick substitution at `this.i`. */
  private readExpansion(word: ShellWord): void {
    const { src } = this;
    if (src[this.i] === "`") {
      let j = this.i + 1;
      while (j < src.length && src[j] !== "`") j += src[j] === "\\" ? 2 : 1;
      this.nested(src.slice(this.i + 1, Math.min(j, src.length)));
      word.dynamic = true;
      this.i = j + 1;
      return;
    }
    const next = src[this.i + 1];
    if (next === "(") {
      const close = findClose(src, this.i + 2);
      if (src[this.i + 2] !== "(") this.nested(src.slice(this.i + 2, close));
      word.dynamic = true;
      this.i = close + 1;
      return;
    }
    if (next === "{") {
      let depth = 0;
      let j = this.i + 1;
      for (; j < src.length; j++) {
        if (src[j] === "{") depth++;
        else if (src[j] === "}" && --depth === 0) break;
      }
      const raw = src.slice(this.i, Math.min(j + 1, src.length));
      if (!/^\$\{\w+\}$/.test(raw)) word.dynamic = true;
      word.text += raw;
      this.i = j + 1;
      return;
    }
    const name = /^\$(\w+)/.exec(src.slice(this.i, this.i + 256));
    if (name) {
      word.text += name[0];
      this.i += name[0].length;
      return;
    }
    if (next !== undefined && "?$!#@*-".includes(next)) {
      word.dynamic = true;
      word.text += src.slice(this.i, this.i + 2);
      this.i += 2;
      return;
    }
    word.text += "$";
    this.i++;
  }
}

export const inHouseShellParser: ShellParser = {
  parse: (source) => new Parser(source, 0).run(),
};
