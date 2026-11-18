import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";

import ignore from "ignore";

export function decideWritePolicy(
  path: string,
  allowWrite: string[],
  denyWrite: string[],
  baseCwd: string = process.cwd(),
) {
  if (matchesPattern(path, denyWrite, baseCwd)) return "deny";
  if (allowWrite.length === 0 || !matchesPattern(path, allowWrite, baseCwd)) return "prompt";
  return "allow";
}

/**
 * Paths declared in `credentials.files`. The read/write/edit tools run in
 * pi's own process, outside the OS sandbox, so they would see a masked file's
 * real contents: they block every declared path. Bash runs inside the sandbox,
 * where mask mode substitutes the contents, so its pre-check only needs the
 * `deny` entries (`denyOnly`).
 */
export function credentialFilePaths(
  credentials: { files?: { path: string; mode: string }[] } | undefined,
  denyOnly = false,
): string[] {
  return (credentials?.files ?? [])
    .filter((file) => !denyOnly || file.mode === "deny")
    .map((file) => file.path);
}

/**
 * Expand `$VAR` and `${VAR}` in a path token extracted from a bash command.
 * Returns null when a referenced variable is unset — the token's real target
 * is unknowable pre-execution, so the caller should skip it and rely on the
 * OS sandbox as the backstop rather than prompt for a garbled path.
 */
export function expandCommandToken(token: string): string | null {
  let unresolved = false;
  const expanded = token.replace(/\$(?:\{(\w+)\}|(\w+))/g, (_, braced, bare) => {
    const value = process.env[braced ?? bare];
    if (value === undefined) {
      unresolved = true;
      return "";
    }
    return value;
  });
  return unresolved ? null : expanded;
}

export async function resolveWritePermission({
  path,
  allowWrite,
  denyWrite,
  baseCwd,
  prompt,
  saveWritePermission,
}: {
  path: string;
  allowWrite: string[];
  denyWrite: string[];
  baseCwd?: string;
  prompt: (path: string) => Promise<{
    action: "abort" | "session" | "project" | "global";
    value: string;
  }>;
  saveWritePermission: (choice: "session" | "project" | "global", value: string) => Promise<void>;
}) {
  const policy = decideWritePolicy(path, allowWrite, denyWrite, baseCwd);
  if (policy !== "prompt") return { action: policy };

  const choice = await prompt(path);
  if (choice.action === "abort") return { action: "abort", value: choice.value };

  await saveWritePermission(choice.action, choice.value);
  return { action: "granted", value: choice.value };
}

/**
 * Extract hosts from literal http(s) URLs in a command, skipping userinfo
 * (`user:pass@`) and lowercasing. Hosts built from shell expansions
 * (`https://$HOST/`), single-label names (`localhost`) and IPv6 literals are
 * skipped; the OS sandbox proxy still enforces whatever is connected to.
 */
export function extractDomainsFromCommand(command: string): string[] {
  // The host is the leading run of hostname characters, so trailing shell
  // punctuation (`,` `;` `&&` `)`) ends it. A host that runs into `$`, `{`, `%`
  // or `_` is being built by an expansion and its real value is unknown.
  const urlRegex = /https?:\/\/(?:[^\s/?#@]*@)?([a-z0-9.-]+)(?![\w$%{.-])/gi;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(command)) !== null) {
    const host = match[1]!.toLowerCase().replace(/\.+$/, "");
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host)) domains.add(host);
  }
  return [...domains];
}

export function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

export function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

export function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((pattern) => domainMatchesPattern(domain, pattern));
}

function expandPath(filePath: string, baseCwd: string = process.cwd()): string {
  // Relative entries resolve against the session cwd (baseCwd), not the pi
  // process cwd — these can differ when pi is embedded in a host process
  // (e.g. the pi-web UI) whose cwd is not the project directory.
  return resolve(baseCwd, filePath.replace(/^~(?=$|\/)/, homedir()));
}

/** Expand `${VAR}` references and a leading `~` in a config pattern string. */
export function expandEnvVars(pattern: string): string {
  return pattern
    .replace(/\$\{([^}]+)\}/g, (_, name) => process.env[name] ?? `\${${name}}`)
    .replace(/^~(?=$|\/)/, homedir());
}

export function expandPatternList(patterns: string[]): string[] {
  return patterns.map(expandEnvVars);
}

export function canonicalizePath(filePath: string, baseCwd: string = process.cwd()): string {
  const absolutePath = expandPath(filePath, baseCwd);
  try {
    return realpathSync.native(absolutePath);
  } catch {
    const tail: string[] = [];
    let probe = absolutePath;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return absolutePath;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return absolutePath;
    }
  }
}

/**
 * Matches a file path against a list of patterns. Absolute patterns (and
 * globs) are matched directly against the canonicalized path. Relative
 * patterns are matched against the path relative to `baseCwd` using gitignore
 * semantics (via the `ignore` package), so entries like `.env` or `*.pem`
 * behave the way they would in a `.gitignore` file.
 */
export function matchesPattern(
  filePath: string,
  patterns: string[],
  baseCwd: string = process.cwd(),
): boolean {
  const absolutePath = canonicalizePath(filePath, baseCwd);
  const relativePatterns: string[] = [];
  const absolutePatterns: string[] = [];
  for (const pattern of patterns) {
    // Classify on the pattern itself (after ~ expansion only) — `resolve()`
    // inside expandPath would make every pattern look absolute, since it
    // resolves relative patterns against baseCwd.
    const homeExpanded = pattern.replace(/^~(?=$|\/)/, homedir());
    if (isAbsolute(homeExpanded)) {
      absolutePatterns.push(expandPath(pattern, baseCwd));
    } else {
      // Relative patterns match two ways: gitignore semantics under baseCwd,
      // and (for non-globs) as baseCwd-anchored path prefixes, so entries like
      // "." (the whole working directory) or "Library" keep their directory
      // meaning — gitignore has no equivalent of ".".
      if (!pattern.includes("*")) {
        absolutePatterns.push(canonicalizePath(pattern, baseCwd));
      }
      relativePatterns.push(pattern);
    }
  }

  for (const absolutePattern of absolutePatterns) {
    if (absolutePattern.includes("*")) {
      // Single pass so no replacement is rewritten by a later one: `**/` is
      // zero or more directories, `**` crosses segments, `*` stays in one.
      const escaped = absolutePattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*\*\/|\*\*|\*/g, (glob) =>
          glob === "**/" ? "(?:.*/)?" : glob === "**" ? ".*" : "[^/]*",
        );
      if (new RegExp(`^${escaped}$`).test(absolutePath)) return true;
    } else {
      const separator = absolutePattern.endsWith("/") ? "" : "/";
      if (
        absolutePath === absolutePattern ||
        absolutePath.startsWith(absolutePattern + separator)
      ) {
        return true;
      }
    }
  }

  if (relativePatterns.length > 0) {
    const rel = relative(baseCwd, absolutePath);
    // rel is "" when the path IS cwd — ignore() throws on empty paths, and
    // the cwd-anchored prefix branch above already covers that case.
    if (rel !== "" && !rel.startsWith("..") && !isAbsolute(rel)) {
      if (ignore().add(relativePatterns).ignores(rel)) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Filesystem root guard

export const ROOT_RULE_MESSAGE =
  "Access to the filesystem root (/) cannot be granted while the sandbox is enabled. " +
  "If you really need it, add it to the sandbox config file manually.";

/** True when `path` is the filesystem root. */
export function isRootPath(path: string, baseCwd: string = process.cwd()): boolean {
  return canonicalizePath(path, baseCwd) === "/";
}

/**
 * True when an allow rule would cover the whole filesystem: `/`, or `/`
 * followed only by globs (`/*`, `/**`). Rules for the home directory are
 * ordinary rules and may be granted.
 */
export function isRootRule(rule: string, baseCwd: string = process.cwd()): boolean {
  const expanded = expandCommandToken(expandEnvVars(rule.trim())) ?? rule.trim();
  const absolute = expanded.startsWith("/");
  let base = expanded.replace(/(?:\/*\*+)+\/*$/, "").replace(/\/+$/, "");
  if (base === "") base = absolute ? "/" : ".";
  return isRootPath(base, baseCwd);
}

// ---------------------------------------------------------------------------
// Bash pre-check decisions

/**
 * How strictly bash commands are checked before they run:
 * - `strict`: every candidate path outside the read allow-list prompts.
 * - `tools` (default): paths in known file positions prompt; other path-shaped
 *   words prompt only when they exist on disk.
 * - `off`: no pre-check; the OS sandbox alone enforces policy.
 */
export type BashPathCheck = "strict" | "tools" | "off";
export const BASH_PATH_CHECK_LEVELS: readonly BashPathCheck[] = ["strict", "tools", "off"];

export type BashCandidateDecision = "allow" | "prompt" | "deny" | "credential" | "root";

/** Device files that are always safe to reference (`2>/dev/null`). */
const SAFE_DEVICE = /^\/dev\/(?:null|zero|random|urandom|full|stdin|stdout|stderr|tty|fd\/\d+)$/;

/**
 * Decide how one path referenced by a bash command is handled before it runs.
 *
 * Credential files and `denyWrite` matches hard-block at every confidence.
 * Writes are otherwise left to the OS sandbox, whose `allowWrite` is already an
 * allow-list. Reads outside the read allow-list prompt, except that `/` is
 * never grantable (blocked when certain, ignored when the word was only
 * path-shaped) and, in `tools` mode, low-confidence words only prompt when
 * they name something that exists.
 */
export function decideBashCandidate(
  candidate: { path: string; access: "read" | "write"; confidence: "high" | "low" },
  options: {
    mode: BashPathCheck;
    readPaths: string[];
    denyWrite: string[];
    credentialDeny: string[];
    cwd: string;
    exists?: (path: string) => boolean;
  },
): BashCandidateDecision {
  const { mode, readPaths, denyWrite, credentialDeny, cwd } = options;
  const exists = options.exists ?? existsSync;
  if (mode === "off") return "allow";
  const canonical = canonicalizePath(candidate.path, cwd);
  if (SAFE_DEVICE.test(canonical)) return "allow";
  if (credentialDeny.length > 0 && matchesPattern(canonical, credentialDeny, cwd)) {
    return "credential";
  }
  if (denyWrite.length > 0 && matchesPattern(canonical, denyWrite, cwd)) return "deny";
  if (candidate.access === "write") return "allow";
  if (matchesPattern(canonical, readPaths, cwd)) return "allow";
  const certain = mode === "strict" || candidate.confidence === "high";
  if (isRootPath(canonical, cwd)) return certain ? "root" : "allow";
  if (certain) return "prompt";
  return exists(canonical) ? "prompt" : "allow";
}
