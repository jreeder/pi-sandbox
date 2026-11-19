import type { ShellParser, ShellWord, SimpleCommand } from "./shell-ast.ts";

/**
 * Find file paths a bash command will touch, for the pre-execution policy
 * check. Candidates are graded by how sure we are that the word is a path:
 *
 * - `high`: an argument in a file position of a known tool (`cat`, `sed`,
 *   `cp`, ...), a redirection target, an interpreter script, or a string
 *   literal passed to a file IO call in inline Python/Ruby/JS code.
 * - `low`: a path-shaped word (`/x`, `./x`, `~/x`, `$VAR/x`) passed to a
 *   command we know nothing about.
 *
 * Heredoc bodies are only inspected when an interpreter or shell consumes
 * them; text fed to anything else (`cat > f.py <<EOF`) is data.
 */
import { type Access, type CodeLanguage, extractCodePaths } from "./code-paths.ts";
import { inHouseShellParser } from "./shell-parse.ts";

export type { Access };
export type Confidence = "high" | "low";

export interface PathCandidate {
  path: string;
  access: Access;
  confidence: Confidence;
  /** Where the path came from, for messages and debugging (e.g. `cat`, `python heredoc`). */
  source: string;
}

/** Recursion limit for `bash -c`, shell heredocs, `eval` and `find -exec`. */
const MAX_DEPTH = 4;

// ---------------------------------------------------------------------------
// Option parsing

interface OptionSpec {
  /** Options that take a value (`-n 5`, `-n5`, `--lines=5`, `--lines 5`). */
  values?: readonly string[];
  /** Value-taking options whose value is a path. */
  paths?: Readonly<Record<string, Access>>;
  /** Short options whose value can only be attached (`sed -i.bak`). */
  attachedOnly?: readonly string[];
  /** Options that take two values (`jq --arg name value`). */
  pairs?: readonly string[];
}

interface ParsedArgs {
  /** Every option name seen. */
  options: Set<string>;
  /** Values of value-taking options, by option name. */
  values: Map<string, ShellWord[]>;
  positionals: ShellWord[];
}

function withText(word: ShellWord, text: string): ShellWord {
  return { ...word, text };
}

function parseArgs(args: readonly ShellWord[], spec: OptionSpec): ParsedArgs {
  const takesValue = (name: string) =>
    (spec.values?.includes(name) ?? false) || (spec.paths?.[name] ?? null) !== null;
  const parsed: ParsedArgs = { options: new Set(), values: new Map(), positionals: [] };
  const record = (name: string, value: ShellWord | undefined) => {
    parsed.options.add(name);
    if (!value) return;
    const list = parsed.values.get(name) ?? [];
    list.push(value);
    parsed.values.set(name, list);
  };
  for (let k = 0; k < args.length; k++) {
    const word = args[k]!;
    const text = word.text;
    if (text === "--") {
      parsed.positionals.push(...args.slice(k + 1));
      break;
    }
    if (text.startsWith("--") && text.length > 2) {
      const eq = text.indexOf("=");
      const name = eq < 0 ? text : text.slice(0, eq);
      if (eq < 0 && spec.pairs?.includes(name)) {
        record(name, args[k + 2]);
        k += 2;
      } else if (eq >= 0) record(name, withText(word, text.slice(eq + 1)));
      else if (takesValue(name)) record(name, args[++k]);
      else record(name, undefined);
      continue;
    }
    if (text.startsWith("-") && text.length > 1) {
      for (let p = 1; p < text.length; p++) {
        const name = `-${text[p]}`;
        const rest = text.slice(p + 1);
        if (spec.attachedOnly?.includes(name)) {
          record(name, rest ? withText(word, rest) : undefined);
          break;
        }
        if (takesValue(name)) {
          record(name, rest ? withText(word, rest) : args[++k]);
          break;
        }
        record(name, undefined);
      }
      continue;
    }
    parsed.positionals.push(word);
  }
  return parsed;
}

const hasAny = (parsed: ParsedArgs, ...names: string[]) =>
  names.some((name) => parsed.options.has(name));

// ---------------------------------------------------------------------------
// Tool table

type Hit = { word: ShellWord; access: Access };

interface ToolSpec extends OptionSpec {
  /** Access for each positional; `null` means the positional is not a path. */
  positionals?: (count: number, parsed: ParsedArgs) => (Access | null)[];
  /** Fully custom handling, for tools whose syntax doesn't fit option parsing. */
  custom?: (args: readonly ShellWord[], ctx: Context) => Hit[];
}

const all =
  (access: Access) =>
  (count: number): Access[] =>
    Array(count).fill(access);
const allRead = all("read");
const allWrite = all("write");
/** First positional is a pattern/script/mode unless one of `options` supplied it. */
const afterFirst =
  (access: (parsed: ParsedArgs) => Access, ...options: string[]) =>
  (count: number, parsed: ParsedArgs): (Access | null)[] => {
    const result: (Access | null)[] = allRead(count).map(() => access(parsed));
    if (!hasAny(parsed, ...options) && count > 0) result[0] = null;
    return result;
  };
/** `cp a b dest`: sources are read, the destination is written (unless `-t DIR`). */
const lastWrite = (count: number, parsed: ParsedArgs): Access[] => {
  const result: Access[] = allRead(count);
  if (count > 1 && !hasAny(parsed, "-t", "--target-directory")) result[count - 1] = "write";
  return result;
};

/** Fixed accesses for the first positionals, `rest` for the others. */
const leading =
  (rest: Access | null, ...head: (Access | null)[]) =>
  (count: number): (Access | null)[] =>
    Array.from({ length: count }, (_, k) => (k < head.length ? head[k]! : rest));

const isRemote = (text: string) => /^[^/]*:/.test(text) && !/^\.{0,2}\//.test(text);
const remoteAware =
  (inner: (count: number, parsed: ParsedArgs) => (Access | null)[]) =>
  (count: number, parsed: ParsedArgs) =>
    inner(count, parsed).map((access, k) =>
      isRemote(parsed.positionals[k]!.text) ? null : access,
    );

const GREP_VALUES = [
  "-e",
  "--regexp",
  "-m",
  "--max-count",
  "-A",
  "-B",
  "-C",
  "--after-context",
  "--before-context",
  "--context",
  "-d",
  "-D",
  "--include",
  "--exclude",
  "--exclude-dir",
  "--color",
  "--colour",
  "--label",
  "--binary-files",
  "--devices",
  "--directories",
  "--group-separator",
];

const RG_VALUES = [
  "-e",
  "--regexp",
  "-g",
  "--glob",
  "--iglob",
  "-t",
  "--type",
  "-T",
  "--type-not",
  "--type-add",
  "--type-clear",
  "-m",
  "--max-count",
  "-A",
  "-B",
  "-C",
  "--context",
  "--after-context",
  "--before-context",
  "-r",
  "--replace",
  "-M",
  "--max-columns",
  "-j",
  "--threads",
  "--color",
  "--colors",
  "--sort",
  "--sortr",
  "-E",
  "--encoding",
  "-d",
  "--max-depth",
  "--max-filesize",
  "--pre",
  "--pre-glob",
  "--path-separator",
  "--engine",
  "--context-separator",
  "--field-match-separator",
  "--field-context-separator",
];

const COMPRESSOR: ToolSpec = {
  values: ["-S", "--suffix", "-b", "-T", "--threads"],
  paths: { "-o": "write" },
  positionals: (count, parsed) =>
    all(hasAny(parsed, "-c", "--stdout", "-l", "--list", "-t", "--test") ? "read" : "write")(count),
};

const READERS: Record<string, ToolSpec> = {
  cat: { values: [] },
  tac: { values: ["-s", "--separator"] },
  nl: { values: ["-b", "-d", "-f", "-h", "-i", "-l", "-n", "-s", "-v", "-w"] },
  bat: {
    values: [
      "-l",
      "--language",
      "-H",
      "--highlight-line",
      "--style",
      "--theme",
      "-r",
      "--line-range",
      "--tabs",
      "--wrap",
      "--terminal-width",
      "--color",
      "--decorations",
      "--paging",
      "--pager",
      "-m",
      "--map-syntax",
      "--file-name",
    ],
  },
  less: {
    values: ["-p", "-x", "-y", "-z", "-b", "-h", "-j", "-P", "-T"],
    paths: { "-o": "write" },
  },
  more: { values: ["-n", "-p"] },
  head: { values: ["-n", "-c", "--lines", "--bytes"] },
  tail: { values: ["-n", "-c", "--lines", "--bytes", "-s", "--sleep-interval", "--pid"] },
  wc: { values: [], paths: { "--files0-from": "read" } },
  file: { values: ["-e", "-F", "-P"], paths: { "-m": "read", "-f": "read" } },
  stat: { values: ["-c", "--format", "--printf", "-t"] },
  od: { values: ["-A", "-t", "-j", "-N", "-w", "-S"] },
  hexdump: { values: ["-e", "-n", "-s"], paths: { "-f": "read" } },
  strings: { values: ["-n", "-t", "-e"] },
  md5sum: {},
  sha1sum: {},
  sha224sum: {},
  sha256sum: {},
  sha384sum: {},
  sha512sum: {},
  b2sum: {},
  cksum: {},
  shasum: { values: ["-a", "--algorithm"] },
  md5: {},
  cut: {
    values: [
      "-d",
      "-f",
      "-c",
      "-b",
      "--delimiter",
      "--fields",
      "--characters",
      "--bytes",
      "--output-delimiter",
    ],
  },
  paste: { values: ["-d", "--delimiters"] },
  join: { values: ["-t", "-1", "-2", "-j", "-o", "-e", "-a", "-v"] },
  comm: { values: ["--output-delimiter"] },
  cmp: { values: ["-i", "-n", "--ignore-initial", "--bytes"] },
  diff: {
    values: ["-U", "-C", "-L", "--label", "-x", "--exclude", "-I", "--unified", "--context", "-W"],
    paths: { "-X": "read", "--exclude-from": "read" },
  },
  sort: {
    values: [
      "-k",
      "-t",
      "-S",
      "--key",
      "--field-separator",
      "--buffer-size",
      "--parallel",
      "--batch-size",
    ],
    paths: { "-o": "write", "--output": "write", "-T": "read", "--temporary-directory": "read" },
  },
  zcat: {},
  bzcat: {},
  xzcat: {},
  zstdcat: {},
  zless: {},
  zgrep: { values: GREP_VALUES, paths: { "-f": "read", "--file": "read" } },
  readlink: {},
  realpath: { values: ["--relative-to", "--relative-base"] },
  ls: {
    values: [
      "-I",
      "--ignore",
      "-w",
      "--width",
      "--format",
      "--sort",
      "--color",
      "--time-style",
      "--hide",
      "--block-size",
      "--indicator-style",
      "--quoting-style",
      "-T",
      "--tabsize",
      "--time",
    ],
  },
  eza: { values: ["-L", "--level", "-I", "--ignore-glob", "--sort", "-s", "--color", "--time"] },
  exa: { values: ["-L", "--level", "-I", "--ignore-glob", "--sort", "-s", "--color", "--time"] },
  lsd: { values: ["--depth", "-I", "--ignore-glob", "--color", "--sort"] },
  tree: {
    values: ["-L", "-I", "-P", "--filelimit", "--charset", "--sort", "--timefmt"],
    paths: { "-o": "write", "--fromfile": "read" },
  },
  du: {
    values: [
      "-d",
      "--max-depth",
      "--exclude",
      "-B",
      "--block-size",
      "-t",
      "--threshold",
      "--time-style",
    ],
    paths: { "-X": "read", "--exclude-from": "read", "--files0-from": "read" },
  },
  source: {},
  ".": {},
};

const TOOLS: Record<string, ToolSpec> = {
  ...READERS,
  grep: {
    values: GREP_VALUES,
    paths: { "-f": "read", "--file": "read", "--exclude-from": "read" },
    positionals: afterFirst(() => "read", "-e", "--regexp", "-f", "--file"),
  },
  rg: {
    values: RG_VALUES,
    paths: { "-f": "read", "--file": "read", "--ignore-file": "read" },
    positionals: afterFirst(
      () => "read",
      "-e",
      "--regexp",
      "-f",
      "--file",
      "--files",
      "--type-list",
    ),
  },
  ag: {
    values: ["-G", "--file-search-regex", "--ignore", "-A", "-B", "-C", "-m", "--depth", "--pager"],
    paths: { "-p": "read", "--path-to-ignore": "read" },
    positionals: afterFirst(() => "read", "-g"),
  },
  ack: {
    values: ["--type", "--ignore-dir", "--ignore-file", "-A", "-B", "-C", "-m", "--output"],
    positionals: afterFirst(() => "read", "-f", "-g"),
  },
  sed: {
    values: ["-e", "--expression", "-l", "--line-length"],
    paths: { "-f": "read", "--file": "read" },
    attachedOnly: ["-i"],
    positionals: afterFirst(
      (parsed) => (hasAny(parsed, "-i", "--in-place") ? "write" : "read"),
      "-e",
      "--expression",
      "-f",
      "--file",
    ),
  },
  awk: {
    values: ["-F", "-v", "--field-separator", "--assign"],
    paths: { "-f": "read", "--file": "read", "-i": "read", "--include": "read" },
    positionals: (count, parsed) =>
      afterFirst(
        () => "read",
        "-f",
        "--file",
      )(count, parsed).map((access, k) =>
        /^[A-Za-z_]\w*=/.test(parsed.positionals[k]!.text) ? null : access,
      ),
  },
  jq: {
    values: ["--indent"],
    pairs: ["--arg", "--argjson", "--slurpfile", "--rawfile"],
    paths: { "-f": "read", "--from-file": "read", "-L": "read" },
    positionals: afterFirst(() => "read", "-f", "--from-file", "-n", "--null-input"),
  },
  yq: {
    values: ["--arg", "-I", "--indent", "-o", "--output-format", "-p", "--input-format"],
    paths: { "--from-file": "read" },
    positionals: afterFirst(() => "read", "--from-file", "-n", "--null-input"),
  },
  fd: {
    values: [
      "-e",
      "--extension",
      "-t",
      "--type",
      "-d",
      "--max-depth",
      "--min-depth",
      "--exact-depth",
      "-E",
      "--exclude",
      "-j",
      "--threads",
      "-S",
      "--size",
      "--changed-within",
      "--changed-before",
      "-o",
      "--owner",
      "--max-results",
      "--color",
      "-c",
      "--path-separator",
    ],
    paths: {
      "--search-path": "read",
      "--ignore-file": "read",
      "--base-directory": "read",
    },
    positionals: afterFirst(() => "read"),
  },
  cp: {
    values: ["-S", "--suffix", "--sparse", "--reflink", "--preserve", "--no-preserve"],
    paths: { "-t": "write", "--target-directory": "write" },
    positionals: lastWrite,
  },
  mv: {
    values: ["-S", "--suffix"],
    paths: { "-t": "write", "--target-directory": "write" },
    positionals: allWrite,
  },
  ln: {
    values: ["-S", "--suffix"],
    paths: { "-t": "write", "--target-directory": "write" },
    positionals: lastWrite,
  },
  install: {
    values: ["-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix"],
    paths: { "-t": "write", "--target-directory": "write" },
    positionals: (count, parsed) =>
      hasAny(parsed, "-d", "--directory") ? allWrite(count) : lastWrite(count, parsed),
  },
  rsync: {
    values: [
      "-e",
      "--rsh",
      "--exclude",
      "--include",
      "--filter",
      "-f",
      "--chmod",
      "--chown",
      "--port",
      "--rsync-path",
      "--bwlimit",
      "--timeout",
      "-T",
      "--temp-dir",
      "--partial-dir",
      "--backup-dir",
      "--suffix",
      "--compare-dest",
      "--link-dest",
      "--copy-dest",
      "--max-size",
      "--min-size",
      "--info",
      "--debug",
      "--out-format",
    ],
    paths: {
      "--exclude-from": "read",
      "--include-from": "read",
      "--files-from": "read",
      "--password-file": "read",
      "--log-file": "write",
    },
    positionals: remoteAware(lastWrite),
  },
  scp: {
    values: ["-P", "-o", "-c", "-l", "-S", "-J"],
    paths: { "-i": "read", "-F": "read" },
    positionals: remoteAware(lastWrite),
  },
  tee: { values: ["--output-error"], positionals: allWrite },
  touch: {
    values: ["-d", "--date", "-t"],
    paths: { "-r": "read", "--reference": "read" },
    positionals: allWrite,
  },
  truncate: {
    values: ["-s", "--size"],
    paths: { "-r": "read", "--reference": "read" },
    positionals: allWrite,
  },
  mkdir: { values: ["-m", "--mode"], positionals: allWrite },
  rmdir: { positionals: allWrite },
  rm: { positionals: allWrite },
  unlink: { positionals: allWrite },
  shred: {
    values: ["-n", "--iterations", "-s", "--size", "--random-source"],
    positionals: allWrite,
  },
  chmod: {
    paths: { "--reference": "read" },
    positionals: afterFirst(() => "write", "--reference"),
  },
  chown: {
    paths: { "--reference": "read" },
    positionals: afterFirst(() => "write", "--reference"),
  },
  chgrp: {
    paths: { "--reference": "read" },
    positionals: afterFirst(() => "write", "--reference"),
  },
  xxd: {
    values: ["-s", "-l", "-c", "-g", "-o", "-n", "-C", "--seek", "--len", "--cols", "--groupsize"],
    positionals: leading("read", "read", "write"),
  },
  uniq: {
    values: ["-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"],
    positionals: leading("read", "read", "write"),
  },
  zip: {
    values: ["-x", "-i", "-P", "--password", "-b", "-n", "-Z"],
    positionals: leading("read", "write"),
  },
  unzip: {
    values: ["-x", "-P"],
    paths: { "-d": "write" },
    positionals: leading(null, "read"),
  },
  gzip: COMPRESSOR,
  gunzip: COMPRESSOR,
  bzip2: COMPRESSOR,
  bunzip2: COMPRESSOR,
  xz: COMPRESSOR,
  unxz: COMPRESSOR,
  zstd: COMPRESSOR,
  unzstd: COMPRESSOR,
  lz4: COMPRESSOR,
  curl: {
    values: [
      "-H",
      "--header",
      "-X",
      "--request",
      "-u",
      "--user",
      "-A",
      "--user-agent",
      "-e",
      "--referer",
      "-m",
      "--max-time",
      "--connect-timeout",
      "-w",
      "--write-out",
      "-x",
      "--proxy",
      "-b",
      "--cookie",
      "--retry",
      "-r",
      "--range",
      "-d",
      "--data",
      "--data-binary",
      "--data-raw",
      "--data-urlencode",
      "--json",
      "-F",
      "--form",
    ],
    paths: {
      "-o": "write",
      "--output": "write",
      "-T": "read",
      "--upload-file": "read",
      "-K": "read",
      "--config": "read",
      "-c": "write",
      "--cookie-jar": "write",
      "--cacert": "read",
      "--cert": "read",
      "--key": "read",
      "-D": "write",
      "--dump-header": "write",
      "--output-dir": "write",
    },
    positionals: leading(null),
  },
  wget: {
    values: ["-U", "--user-agent", "--header", "-t", "--tries", "-T", "--timeout", "-e"],
    paths: {
      "-O": "write",
      "--output-document": "write",
      "-P": "write",
      "--directory-prefix": "write",
      "-i": "read",
      "--input-file": "read",
      "-o": "write",
      "--output-file": "write",
      "-a": "write",
      "--append-output": "write",
    },
    positionals: leading(null),
  },
  find: { custom: findPaths },
  tar: { custom: tarPaths },
  dd: { custom: ddPaths },
};

const ALIASES: Record<string, string> = {
  batcat: "bat",
  egrep: "grep",
  fgrep: "grep",
  rgrep: "grep",
  gawk: "awk",
  mawk: "awk",
  nawk: "awk",
  fdfind: "fd",
  gsed: "sed",
  gtar: "tar",
  bsdtar: "tar",
  gojq: "jq",
};

/** Commands whose arguments are never file paths. */
const NO_PATH_ARGS = new Set([
  "echo",
  "printf",
  "true",
  "false",
  ":",
  "export",
  "unset",
  "cd",
  "pushd",
  "popd",
  "alias",
  "unalias",
  "set",
  "shift",
  "return",
  "exit",
  "read",
  "sleep",
  "kill",
  "pkill",
  "which",
  "type",
  "hash",
  "whoami",
  "date",
  "pwd",
  "id",
  "uname",
  "hostname",
  "seq",
  "yes",
  "basename",
  "dirname",
  "expr",
  "test",
  "[",
  "[[",
  "let",
  "local",
  "declare",
  "typeset",
  "readonly",
  "wait",
  "trap",
  "jobs",
  "fg",
  "bg",
  "disown",
  "umask",
  "ulimit",
]);

/** Shell keywords that may precede a command word. */
const KEYWORDS = new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "do",
  "done",
  "while",
  "until",
  "!",
  "{",
  "}",
  "time",
  "esac",
]);

function findPaths(args: readonly ShellWord[], ctx: Context): Hit[] {
  const hits: Hit[] = [];
  let k = 0;
  // Leading -H/-L/-P, -D debugopts, -Olevel come before the start points.
  while (k < args.length && /^-(?:[HLP]|O\d*|D)$/.test(args[k]!.text)) {
    k += args[k]!.text === "-D" ? 2 : 1;
  }
  for (; k < args.length; k++) {
    const text = args[k]!.text;
    if (text.startsWith("-") || text === "(" || text === "!") break;
    hits.push({ word: args[k]!, access: "read" });
  }
  for (; k < args.length; k++) {
    const text = args[k]!.text;
    const next = args[k + 1];
    if (/^-(?:newer|anewer|cnewer|samefile|newer[acmtB][acmtB])$/.test(text) && next) {
      hits.push({ word: next, access: "read" });
      k++;
    } else if (/^-(?:fprint0?|fprintf|fls)$/.test(text) && next) {
      hits.push({ word: next, access: "write" });
      k++;
    } else if (/^-(?:exec|execdir|ok|okdir)$/.test(text)) {
      const end = args.findIndex((word, j) => j > k && (word.text === ";" || word.text === "+"));
      const stop = end < 0 ? args.length : end;
      const sub = args.slice(k + 1, stop).filter((word) => word.text !== "{}");
      if (ctx.depth < MAX_DEPTH) analyzeArgv(sub, { ...ctx, depth: ctx.depth + 1 });
      k = stop;
    }
  }
  return hits;
}

function tarPaths(args: readonly ShellWord[]): Hit[] {
  // Old-style `tar xzf archive` bundles its options into the first word.
  const normalized = [...args];
  if (normalized[0] && /^[A-Za-z]+$/.test(normalized[0].text)) {
    normalized[0] = withText(normalized[0], `-${normalized[0].text}`);
  }
  const parsed = parseArgs(normalized, {
    values: [
      "-b",
      "--blocking-factor",
      "--exclude",
      "--transform",
      "--strip-components",
      "-I",
      "--use-compress-program",
      "--owner",
      "--group",
      "--mode",
      "--mtime",
      "-H",
      "--format",
      "-N",
      "--newer",
      "-f",
      "--file",
      "-C",
      "--directory",
    ],
    paths: { "-T": "read", "--files-from": "read", "-X": "read", "--exclude-from": "read" },
  });
  const creating = hasAny(parsed, "-c", "--create", "-r", "--append", "-u", "--update");
  const extracting = hasAny(parsed, "-x", "--extract", "--get");
  const hits: Hit[] = [];
  const add = (names: string[], access: Access) => {
    for (const name of names) {
      for (const word of parsed.values.get(name) ?? []) hits.push({ word, access });
    }
  };
  add(["-f", "--file"], creating ? "write" : "read");
  add(["-C", "--directory"], extracting ? "write" : "read");
  add(["-T", "--files-from", "-X", "--exclude-from"], "read");
  if (creating) for (const word of parsed.positionals) hits.push({ word, access: "read" });
  return hits;
}

function ddPaths(args: readonly ShellWord[]): Hit[] {
  const hits: Hit[] = [];
  for (const word of args) {
    const operand = /^(if|of)=(.*)$/.exec(word.text);
    if (operand) {
      hits.push({
        word: withText(word, operand[2]!),
        access: operand[1] === "if" ? "read" : "write",
      });
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Interpreters

interface InterpreterSpec extends OptionSpec {
  language: CodeLanguage | "shell";
  /** Options whose value is inline code. */
  code?: readonly string[];
  /** Options after which the code is the first positional (`bash -c 'cmd'`). */
  codeIsFirstPositional?: readonly string[];
  /** Options that run something other than a script file (`python -m mod`). */
  noScript?: readonly string[];
  /** Subcommands to skip before the script (`deno run`), and ones whose next word is code. */
  subcommands?: readonly string[];
  evalSubcommands?: readonly string[];
}

const SHELL: InterpreterSpec = {
  language: "shell",
  values: ["-o", "-O", "+o", "+O"],
  paths: { "--rcfile": "read", "--init-file": "read" },
  codeIsFirstPositional: ["-c"],
};

const NODE: InterpreterSpec = {
  language: "javascript",
  code: ["-e", "--eval", "-p", "--print"],
  values: [
    "-r",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--input-type",
    "-C",
    "--conditions",
    "--inspect-port",
    "--title",
  ],
  paths: { "--env-file": "read" },
};

const INTERPRETERS: Record<string, InterpreterSpec> = {
  python: {
    language: "python",
    code: ["-c"],
    values: ["-W", "-X", "-Q"],
    noScript: ["-m"],
  },
  ruby: {
    language: "ruby",
    code: ["-e"],
    values: ["-r", "-E", "-F", "--encoding"],
    paths: { "-I": "read", "-C": "read" },
  },
  node: NODE,
  nodejs: NODE,
  tsx: NODE,
  "ts-node": NODE,
  bun: { ...NODE, subcommands: ["run", "x"] },
  deno: {
    language: "javascript",
    values: ["--config", "-c", "--import-map"],
    subcommands: ["run", "test", "check"],
    evalSubcommands: ["eval"],
  },
  bash: SHELL,
  sh: SHELL,
  zsh: SHELL,
  dash: SHELL,
  ksh: SHELL,
};

function interpreterName(name: string): string | undefined {
  if (INTERPRETERS[name]) return name;
  const unversioned = name.replace(/[\d.]+$/, "");
  if (/^(?:python|pypy)$/.test(unversioned)) return "python";
  if (unversioned === "ruby" || unversioned === "node") return unversioned;
  return undefined;
}

// ---------------------------------------------------------------------------
// Wrappers (`sudo`, `env`, `timeout`, ...) whose payload is another command

const WRAPPERS: Record<string, OptionSpec & { leading?: number }> = {
  sudo: { values: ["-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D"] },
  doas: { values: ["-u", "-C"] },
  env: { values: ["-u", "--unset", "-C", "--chdir", "-S", "--split-string"] },
  nohup: {},
  command: {},
  builtin: {},
  exec: { values: ["-a"] },
  nice: { values: ["-n", "--adjustment"] },
  ionice: { values: ["-c", "-n", "-p", "--class", "--classdata"] },
  stdbuf: { values: ["-i", "-o", "-e", "--input", "--output", "--error"] },
  timeout: { values: ["-s", "--signal", "-k", "--kill-after"], leading: 1 },
  xargs: {
    values: ["-I", "-i", "-n", "-P", "-d", "-E", "-e", "-L", "-l", "-s", "--max-args"],
    paths: { "-a": "read", "--arg-file": "read" },
  },
  watch: { values: ["-n", "--interval", "-d"] },
  caffeinate: {},
  unbuffer: {},
};

/**
 * Strip shell keywords and wrapper commands, returning the payload command
 * and any path hits contributed by the wrappers' own options.
 */
function unwrap(argv: readonly ShellWord[]): { argv: ShellWord[]; hits: Hit[] } {
  let words = [...argv];
  const hits: Hit[] = [];
  for (let guard = 0; guard < 16 && words.length > 0; guard++) {
    const name = commandName(words[0]!);
    if (KEYWORDS.has(name)) {
      words = words.slice(1);
      continue;
    }
    const wrapper = WRAPPERS[name];
    if (!wrapper) break;
    if (name === "command" && words.some((word) => /^-[vV]$/.test(word.text)))
      return { argv: [], hits };
    // Options belong to the wrapper until the first positional, which starts the payload.
    const rest = words.slice(1);
    let k = 0;
    while (k < rest.length && rest[k]!.text.startsWith("-") && rest[k]!.text !== "-") {
      const text = rest[k]!.text;
      if (text === "--") {
        k++;
        break;
      }
      const option = text.startsWith("--") ? text.split("=")[0]! : text.slice(0, 2);
      const consumesNext =
        !text.includes("=") &&
        (text.startsWith("--") ? true : text.length === 2) &&
        ((wrapper.values?.includes(option) ?? false) || wrapper.paths?.[option] !== undefined);
      const pathAccess = wrapper.paths?.[option];
      if (pathAccess) {
        const value = consumesNext ? rest[k + 1] : withText(rest[k]!, text.slice(2));
        if (value) hits.push({ word: value, access: pathAccess });
      }
      k += consumesNext ? 2 : 1;
    }
    if (name === "env") while (k < rest.length && /^[A-Za-z_]\w*=/.test(rest[k]!.text)) k++;
    k += wrapper.leading ?? 0;
    words = rest.slice(k);
  }
  return { argv: words, hits };
}

function commandName(word: ShellWord): string {
  const base = word.text.slice(word.text.lastIndexOf("/") + 1);
  return ALIASES[base] ?? base;
}

// ---------------------------------------------------------------------------
// Extraction

interface Context {
  parser: ShellParser;
  depth: number;
  out: PathCandidate[];
  /** Stdin code attached to the command being analyzed (heredocs and here-strings). */
  stdin: string[];
}

function push(
  ctx: Context,
  word: ShellWord,
  access: Access,
  confidence: Confidence,
  source: string,
) {
  if (word.dynamic) return;
  let text = word.text;
  if (!text || text === "-") return;
  if (word.glob) {
    // Only the static directory prefix of a glob is a known path.
    const segments = text.split("/");
    const firstGlob = segments.findIndex((segment) => /[*?[]/.test(segment));
    text = segments.slice(0, firstGlob).join("/") || (text.startsWith("/") ? "/" : ".");
  }
  ctx.out.push({ path: text, access, confidence, source });
}

function pushCode(ctx: Context, code: string, language: CodeLanguage | "shell", source: string) {
  if (language === "shell") {
    if (ctx.depth < MAX_DEPTH) collect(code, { ...ctx, depth: ctx.depth + 1, stdin: [] });
    return;
  }
  for (const found of extractCodePaths(code, language)) {
    ctx.out.push({ path: found.path, access: found.access, confidence: "high", source });
  }
}

const PATH_SHAPED = /^(?:~(?:\/|$)|\.{1,2}\/|\$\{?\w+\}?\/|\/)/;

/** Low-confidence scan of an unknown command's arguments. */
function pushPathShaped(ctx: Context, words: readonly ShellWord[], source: string) {
  for (const word of words) {
    let candidate = word;
    // `--opt=/path` and `NAME=/path`
    const assignment = /^(?:-{1,2}[\w-]+|[A-Za-z_]\w*)=(.*)$/.exec(word.text);
    if (assignment) candidate = withText(word, assignment[1]!);
    if (PATH_SHAPED.test(candidate.text)) push(ctx, candidate, "read", "low", source);
  }
}

function analyzeInterpreter(name: string, spec: InterpreterSpec, args: ShellWord[], ctx: Context) {
  let rest = args;
  // Subcommands come before options for deno/bun (`deno run -A x.ts`).
  if (spec.evalSubcommands?.includes(rest[0]?.text ?? "")) {
    const code = parseArgs(rest.slice(1), spec).positionals[0];
    if (code && !code.dynamic) pushCode(ctx, code.text, spec.language, `${name} eval`);
    return;
  }
  if (spec.subcommands?.includes(rest[0]?.text ?? "")) rest = rest.slice(1);
  const parsed = parseArgs(rest, {
    ...spec,
    values: [...(spec.values ?? []), ...(spec.code ?? [])],
  });
  for (const [option, access] of Object.entries(spec.paths ?? {})) {
    for (const word of parsed.values.get(option) ?? []) push(ctx, word, access, "high", name);
  }
  let positionals = parsed.positionals;
  let hasCode = false;
  for (const option of spec.code ?? []) {
    for (const word of parsed.values.get(option) ?? []) {
      hasCode = true;
      if (!word.dynamic) pushCode(ctx, word.text, spec.language, `${name} ${option}`);
    }
  }
  if (spec.codeIsFirstPositional?.some((option) => parsed.options.has(option))) {
    hasCode = true;
    const code = positionals[0];
    if (code && !code.dynamic) pushCode(ctx, code.text, spec.language, `${name} -c`);
    positionals = positionals.slice(1);
  } else if (!hasCode && !spec.noScript?.some((option) => parsed.options.has(option))) {
    const script = positionals[0];
    if (script && script.text !== "-") {
      push(ctx, script, "read", "high", name);
      positionals = positionals.slice(1);
      hasCode = true;
    } else if (script) {
      positionals = positionals.slice(1);
    }
  }
  // With no script or inline code, stdin (heredoc / here-string) is the program.
  if (!hasCode) {
    for (const code of ctx.stdin) pushCode(ctx, code, spec.language, `${name} heredoc`);
  }
  // Arguments to the script: unknown semantics.
  pushPathShaped(ctx, positionals, `${name} argument`);
}

function analyzeArgv(argv: readonly ShellWord[], ctx: Context): void {
  const unwrapped = unwrap(argv);
  for (const hit of unwrapped.hits) push(ctx, hit.word, hit.access, "high", "wrapper option");
  const [first, ...args] = unwrapped.argv;
  if (!first || first.dynamic) {
    pushPathShaped(ctx, args, "dynamic command");
    return;
  }
  const name = commandName(first);
  if (NO_PATH_ARGS.has(name)) return;
  if (name === "eval") {
    if (ctx.depth < MAX_DEPTH && args.every((word) => !word.dynamic)) {
      collect(args.map((word) => word.text).join(" "), { ...ctx, depth: ctx.depth + 1, stdin: [] });
    }
    return;
  }
  const interpreter = interpreterName(name);
  if (interpreter) {
    analyzeInterpreter(name, INTERPRETERS[interpreter]!, args, ctx);
    return;
  }
  const tool = TOOLS[name];
  if (!tool) {
    pushPathShaped(ctx, args, name);
    return;
  }
  if (tool.custom) {
    for (const hit of tool.custom(args, ctx)) push(ctx, hit.word, hit.access, "high", name);
    return;
  }
  const parsed = parseArgs(args, tool);
  for (const [option, access] of Object.entries(tool.paths ?? {})) {
    for (const word of parsed.values.get(option) ?? []) push(ctx, word, access, "high", name);
  }
  const accesses = (tool.positionals ?? allRead)(parsed.positionals.length, parsed);
  parsed.positionals.forEach((word, k) => {
    const access = accesses[k];
    if (access) push(ctx, word, access, "high", name);
  });
}

function analyzeCommand(command: SimpleCommand, ctx: Context): void {
  for (const redirect of command.redirects) {
    const access: Access = redirect.op === "<" ? "read" : "write";
    push(ctx, redirect.target, access, "high", `redirect ${redirect.op}`);
  }
  pushPathShaped(ctx, command.assignments, "assignment");
  const stdin = [
    ...command.heredocs.map((heredoc) => heredoc.body),
    ...command.hereStrings.filter((word) => !word.dynamic).map((word) => word.text),
  ];
  analyzeArgv(command.argv, { ...ctx, stdin });
}

function collect(source: string, ctx: Context): void {
  for (const command of ctx.parser.parse(source)) analyzeCommand(command, ctx);
}

/**
 * Extract path candidates from a bash command. Duplicates are collapsed,
 * keeping the most specific grade (high over low, write over read).
 */
export function extractBashPathCandidates(
  command: string,
  parser: ShellParser = inHouseShellParser,
): PathCandidate[] {
  const out: PathCandidate[] = [];
  collect(command, { parser, depth: 0, out, stdin: [] });
  const byPath = new Map<string, PathCandidate>();
  for (const candidate of out) {
    const key = `${candidate.path}\0${candidate.access}`;
    const existing = byPath.get(key);
    if (!existing || (existing.confidence === "low" && candidate.confidence === "high")) {
      byPath.set(key, candidate);
    }
  }
  return [...byPath.values()];
}
