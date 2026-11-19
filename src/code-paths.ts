/**
 * Find file paths in inline interpreter code (heredocs, `-c`/`-e` arguments,
 * here-strings) by looking for well-known file IO calls whose path argument is
 * a plain string literal. Everything else in the code is ignored: operators,
 * comments and regex literals no longer look like paths, and paths built at
 * runtime (variables, f-strings, `${}` templates) are left to the OS sandbox.
 */

export type Access = "read" | "write";
export type CodeLanguage = "python" | "ruby" | "javascript";

export interface CodePath {
  path: string;
  access: Access;
}

interface StringSpan {
  start: number;
  /** Exclusive. */
  end: number;
  value: string;
  /** Contains interpolation, so the value is not static. */
  interpolated: boolean;
}

interface Scanned {
  /** Source with comments and string contents blanked, same length as the input. */
  structure: string;
  strings: StringSpan[];
}

const blank = (s: string) => s.replace(/[^\n]/g, " ");

function unescape(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}

/** Blank comments and string contents so call sites and argument lists can be found safely. */
function scan(code: string, language: CodeLanguage): Scanned {
  const strings: StringSpan[] = [];
  let structure = "";
  let i = 0;
  const lineComment = language === "javascript" ? "//" : "#";
  while (i < code.length) {
    const c = code[i]!;
    if (code.startsWith(lineComment, i)) {
      const end = code.indexOf("\n", i);
      const stop = end < 0 ? code.length : end;
      structure += blank(code.slice(i, stop));
      i = stop;
      continue;
    }
    if (language === "javascript" && code.startsWith("/*", i)) {
      const end = code.indexOf("*/", i + 2);
      const stop = end < 0 ? code.length : end + 2;
      structure += blank(code.slice(i, stop));
      i = stop;
      continue;
    }
    const quotes = language === "javascript" ? "'\"`" : "'\"";
    if (quotes.includes(c)) {
      // Python string prefixes (r, b, u, f, rb, ...) sit directly before the quote.
      let start = i;
      let raw = false;
      let formatted = false;
      if (language === "python") {
        const prefix = /[rRbBuUfF]{1,2}$/.exec(structure)?.[0] ?? "";
        if (prefix && !/[\w]/.test(structure[structure.length - prefix.length - 1] ?? "")) {
          start -= prefix.length;
          raw = /[rR]/.test(prefix);
          formatted = /[fF]/.test(prefix);
        }
      }
      const triple = language === "python" && code.startsWith(c.repeat(3), i);
      const delimiter = triple ? c.repeat(3) : c;
      let j = i + delimiter.length;
      while (j < code.length && !code.startsWith(delimiter, j)) {
        if (code[j] === "\\") j++;
        else if (!triple && c !== "`" && code[j] === "\n") break;
        j++;
      }
      const contentEnd = Math.min(j, code.length);
      const content = code.slice(i + delimiter.length, contentEnd);
      const end = Math.min(contentEnd + delimiter.length, code.length);
      const interpolated =
        formatted ||
        (language === "ruby" && c === '"' && content.includes("#{")) ||
        (language === "javascript" && c === "`" && content.includes("${"));
      strings.push({
        start,
        end,
        value: raw ? content : unescape(content),
        interpolated: interpolated || triple,
      });
      structure += code.slice(i, i + delimiter.length) + blank(content);
      structure += code.slice(contentEnd, end);
      i = end;
      continue;
    }
    structure += c;
    i++;
  }
  return { structure, strings };
}

interface Arg {
  start: number;
  end: number;
  /** Keyword name for `name=value` (Python) or `name: value` (Ruby). */
  keyword?: string;
  literal?: string;
}

/**
 * Split the argument list starting at `start` (just after `(`, or after the
 * callee for a paren-less Ruby call) into top-level arguments.
 */
function readArgs(scanned: Scanned, start: number, parens: boolean): Arg[] {
  const { structure } = scanned;
  const args: Arg[] = [];
  let depth = 0;
  let argStart = start;
  let i = start;
  const push = (end: number) => {
    let s = argStart;
    let e = end;
    while (s < e && /\s/.test(structure[s]!)) s++;
    while (e > s && /\s/.test(structure[e - 1]!)) e--;
    if (s === e) return;
    const arg: Arg = { start: s, end: e };
    const keyword = /^(\w+)\s*(?:=(?!=)|:(?!:))\s*/.exec(structure.slice(s, e));
    if (keyword) {
      arg.keyword = keyword[1];
      arg.start = s + keyword[0].length;
    }
    const span = scanned.strings.find((str) => str.start === arg.start && str.end === e);
    if (span && !span.interpolated) arg.literal = span.value;
    args.push(arg);
  };
  for (; i < structure.length; i++) {
    const c = structure[i]!;
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) break;
      depth--;
    } else if (c === "," && depth === 0) {
      push(i);
      argStart = i + 1;
    } else if (!parens && depth === 0 && (c === "\n" || c === ";")) break;
  }
  push(i);
  return args;
}

/** Index just past the `)` that closes the argument list starting at `start`. */
function closeParen(structure: string, start: number): number {
  let depth = 0;
  for (let i = start; i < structure.length; i++) {
    const c = structure[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) return i + 1;
      depth--;
    }
  }
  return structure.length;
}

type ArgRule = { index: number; keyword?: string; access: Access };

interface CallRule {
  callee: RegExp;
  args: ArgRule[];
  /** Mode argument (open-style): a literal containing w, a, x or + makes the path a write. */
  mode?: { index: number; keyword: string };
  /** A method chained onto the call result that writes (e.g. `Path(p).write_text(...)`). */
  writeChain?: RegExp;
}

const r = (index: number, keyword?: string): ArgRule => ({ index, keyword, access: "read" });
const w = (index: number, keyword?: string): ArgRule => ({ index, keyword, access: "write" });

const PYTHON_RULES: CallRule[] = [
  {
    callee: /^(?:open|io\.open|codecs\.open|builtins\.open)$/,
    args: [r(0, "file")],
    mode: { index: 1, keyword: "mode" },
  },
  {
    callee: /^(?:pathlib\.)?(?:Path|PurePath|PosixPath|WindowsPath)$/,
    args: [r(0)],
    writeChain:
      /^\s*\.\s*(?:write_text|write_bytes|mkdir|touch|unlink|rmdir|rename|replace|symlink_to|hardlink_to|chmod)\b|^\s*\.\s*open\s*\(\s*(?:mode\s*=\s*)?[rRbB]?["'][^"']*[wax+]/,
  },
  {
    callee:
      /^(?:os\.(?:listdir|scandir|walk|stat|lstat|access|readlink|open)|os\.path\.(?:exists|isfile|isdir|islink|getsize|getmtime|realpath)|glob\.i?glob|(?:np|numpy)\.(?:load|loadtxt|genfromtxt|fromfile)|(?:pd|pandas)\.read_\w+|tarfile\.open|zipfile\.ZipFile|(?:yaml|toml|tomllib)\.load_file)$/,
    args: [r(0)],
    mode: { index: 1, keyword: "mode" },
  },
  {
    callee:
      /^(?:os\.(?:remove|unlink|rmdir|removedirs|mkdir|makedirs|chmod|chown|truncate)|shutil\.rmtree|(?:np|numpy)\.(?:save|savez|savetxt)|sqlite3\.connect|.*\.to_(?:csv|json|parquet|excel|pickle|feather|hdf|html|latex|markdown|xml))$/,
    args: [w(0)],
  },
  { callee: /^(?:os\.(?:rename|renames|replace)|shutil\.move)$/, args: [w(0), w(1)] },
  {
    callee: /^(?:shutil\.(?:copy|copy2|copyfile|copytree|copymode|copystat)|os\.(?:symlink|link))$/,
    args: [r(0), w(1)],
  },
];

const RUBY_RULES: CallRule[] = [
  {
    callee: /^(?:File|IO)\.(?:open|new)$/,
    args: [r(0)],
    mode: { index: 1, keyword: "mode" },
  },
  {
    callee:
      /^(?:(?:File|IO)\.(?:read|readlines|foreach|binread|readlink|stat|lstat|size|exist\?|file\?|directory\?|readable\?)|Dir\.(?:glob|entries|children|each_child|foreach|exist\?|open|new)|Pathname\.new|(?:YAML|JSON|Psych)\.load_file|CSV\.(?:read|foreach|open|parse_file)|Kernel\.(?:open|load|require_relative)|load|require_relative)$/,
    args: [r(0)],
  },
  {
    callee:
      /^(?:(?:File|IO)\.(?:write|binwrite|delete|unlink|truncate|chmod|chown|mkfifo)|Dir\.(?:mkdir|rmdir|delete|unlink)|FileUtils\.(?:rm|rm_r|rm_rf|rm_f|remove|remove_dir|remove_entry|rmdir|mkdir|mkdir_p|makedirs|touch|chmod|chmod_R))$/,
    args: [w(0)],
  },
  { callee: /^(?:File\.rename|FileUtils\.(?:mv|move))$/, args: [w(0), w(1)] },
  {
    callee:
      /^(?:File\.(?:symlink|link)|FileUtils\.(?:cp|copy|cp_r|copy_file|copy_entry|install|ln|ln_s|ln_sf|symlink))$/,
    args: [r(0), w(1)],
  },
];

// Generic names (stat, open, rm, ...) only count with an fs-like receiver.
const FS = "(?:fs|fsp|fse|promises|fs\\.promises|Deno|fsExtra)";

const JS_RULES: CallRule[] = [
  {
    callee: new RegExp(
      `^(?:.*\\.)?(?:readFileSync|readFile|readdirSync|readdir|opendirSync|opendir|createReadStream|existsSync|statSync|lstatSync|accessSync|readlinkSync|realpathSync|readTextFile|readTextFileSync|readDirSync|readDir|readJson|readJsonSync)$|^${FS}\\.(?:stat|lstat|access|exists|readlink|realpath|open)$|^(?:require|import|Bun\\.file)$`,
    ),
    args: [r(0)],
  },
  {
    callee: new RegExp(
      `^(?:.*\\.)?(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|rmSync|rmdirSync|unlinkSync|truncateSync|chmodSync|mkdtempSync|writeTextFile|writeTextFileSync|outputFile|outputFileSync|writeJson|writeJsonSync|removeSync|emptyDirSync|ensureDirSync|ensureFileSync)$|^${FS}\\.(?:mkdir|rm|rmdir|unlink|truncate|chmod|mkdtemp|remove|emptyDir|ensureDir|ensureFile)$|^Bun\\.write$`,
    ),
    args: [w(0)],
  },
  {
    callee: new RegExp(`^(?:.*\\.)?(?:renameSync|moveSync)$|^${FS}\\.(?:rename|move)$`),
    args: [w(0), w(1)],
  },
  {
    callee: new RegExp(
      `^(?:.*\\.)?(?:copyFileSync|copyFile|cpSync|symlinkSync|linkSync|copySync)$|^${FS}\\.(?:cp|copy|symlink|link)$`,
    ),
    args: [r(0), w(1)],
  },
];

const RULES: Record<CodeLanguage, CallRule[]> = {
  python: PYTHON_RULES,
  ruby: RUBY_RULES,
  javascript: JS_RULES,
};

/** JS/TS module specifiers are only paths when relative or absolute. */
const isModulePath = (specifier: string) => /^(?:\.{1,2}\/|\/)/.test(specifier);

function argFor(args: Arg[], rule: { index: number; keyword?: string }): Arg | undefined {
  const keyword = rule.keyword ? args.find((arg) => arg.keyword === rule.keyword) : undefined;
  if (keyword) return keyword;
  const positional = args.filter((arg) => arg.keyword === undefined);
  return positional[rule.index];
}

export function extractCodePaths(code: string, language: CodeLanguage): CodePath[] {
  const scanned = scan(code, language);
  const { structure } = scanned;
  const found: CodePath[] = [];
  // A dotted callee followed by `(`; Ruby also allows `File.read "x"` without parens.
  const callRe =
    language === "ruby"
      ? /(?<![\w$.])((?:[A-Za-z_$][\w$]*[?!]?\s*\.\s*)*[A-Za-z_$][\w$]*[?!]?)(\s*\(|[ \t]+(?=["']))/g
      : /(?<![\w$.])((?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Za-z_$][\w$]*)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = callRe.exec(structure)) !== null) {
    const callee = match[1]!.replace(/\s+/g, "");
    const rule = RULES[language].find((candidate) => candidate.callee.test(callee));
    if (!rule) continue;
    const argsStart = match.index + match[0].length;
    const parens = language !== "ruby" || match[2]!.includes("(");
    const args = readArgs(scanned, argsStart, parens);
    let modeWrites = false;
    if (rule.mode) {
      const mode = argFor(args, rule.mode)?.literal;
      modeWrites = mode !== undefined && /[wax+]/.test(mode);
    }
    let chainWrites = false;
    if (rule.writeChain && parens) {
      chainWrites = rule.writeChain.test(structure.slice(closeParen(structure, argsStart)));
    }
    for (const argRule of rule.args) {
      const literal = argFor(args, argRule)?.literal;
      if (!literal) continue;
      if ((callee === "require" || callee === "import") && !isModulePath(literal)) continue;
      const access = modeWrites || chainWrites ? "write" : argRule.access;
      found.push({ path: literal, access });
    }
  }
  // Static ES module imports: `import x from "./a"`, `export * from "./b"`, `import "./c"`.
  if (language === "javascript") {
    for (const span of scanned.strings) {
      if (span.interpolated || !isModulePath(span.value)) continue;
      if (/\b(?:from|import)\s*$/.test(structure.slice(Math.max(0, span.start - 32), span.start))) {
        found.push({ path: span.value, access: "read" });
      }
    }
  }
  return found;
}
