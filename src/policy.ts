import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";

import ignore from "ignore";

export function decideWritePolicy(
  path: string,
  allowWrite: string[],
  denyWrite: string[],
  cwd: string,
) {
  if (matchesPattern(path, denyWrite, cwd)) return "deny";
  if (allowWrite.length === 0 || !matchesPattern(path, allowWrite, cwd)) return "prompt";
  return "allow";
}

/**
 * Decide how a candidate path referenced by a bash command is handled before
 * the command runs: `denyWrite` matches are hard-blocked; anything outside the
 * effective read paths (allowRead + allowWrite + session grants) prompts, the
 * same allow-list semantics the read tool uses. The OS sandbox cannot provide
 * this — it only deny-lists reads, so paths outside `denyRead` would otherwise
 * be silently readable from bash.
 */
export function decideBashPathPolicy(
  path: string,
  readPaths: string[],
  denyWrite: string[],
  cwd: string,
): "deny" | "prompt" | "allow" {
  if (denyWrite.length > 0 && matchesPattern(path, denyWrite, cwd)) return "deny";
  if (!matchesPattern(path, readPaths, cwd)) return "prompt";
  return "allow";
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
  cwd,
  prompt,
  saveWritePermission,
}: {
  path: string;
  allowWrite: string[];
  denyWrite: string[];
  cwd: string;
  prompt: (path: string) => Promise<{
    action: "abort" | "session" | "project" | "global";
    value: string;
  }>;
  saveWritePermission: (choice: "session" | "project" | "global", value: string) => Promise<void>;
}) {
  const policy = decideWritePolicy(path, allowWrite, denyWrite, cwd);
  if (policy !== "prompt") return { action: policy };

  const choice = await prompt(path);
  if (choice.action === "abort") return { action: "abort", value: choice.value };

  await saveWritePermission(choice.action, choice.value);
  return { action: "granted", value: choice.value };
}

export function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(command)) !== null) domains.add(match[1]);
  return [...domains];
}

/**
 * Extract candidate file paths from a bash command string for pre-execution
 * policy checks. Only tokens that already look like paths are matched — a
 * leading ./ ../ ~/ ${VAR}/ or / — so bare names like `cat .env` are left to
 * the OS sandbox layer. False positives cost an extra prompt (paths outside
 * allowRead) or an unnecessary block (denyWrite); false negatives mean a
 * sensitive file is only caught post-execution by the OS sandbox.
 */
export function extractPathsFromCommand(command: string): string[] {
  // Strip comments and quoted strings to reduce noise, then tokenize.
  const stripped = command
    .replace(/#[^\n]*/g, "") // strip # comments
    .replace(/'[^']*'/g, " ") // strip single-quoted strings
    .replace(/"[^"]*"/g, " "); // strip double-quoted strings (rough)

  const re = /(?:^|[\s=|(;&`])((~\/|\.{1,2}\/|\$\{?\w+\}?\/|\/[\w])[^\s;|&'"<>]*)/g;
  const paths = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = re.exec(stripped)) !== null) {
    const path = match[1]!.replace(/[);,]+$/, ""); // trim trailing punctuation
    if (path) paths.add(path);
  }
  return [...paths];
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

function expandPath(filePath: string): string {
  return resolve(filePath.replace(/^~(?=$|\/)/, homedir()));
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

export function canonicalizePath(filePath: string): string {
  const absolutePath = expandPath(filePath);
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
 * patterns are matched against the path relative to `cwd` using gitignore
 * semantics (via the `ignore` package), so entries like `.env` or `*.pem`
 * behave the way they would in a `.gitignore` file.
 */
export function matchesPattern(filePath: string, patterns: string[], cwd: string): boolean {
  const absolutePath = canonicalizePath(filePath);
  const relativePatterns: string[] = [];
  const absolutePatterns: string[] = [];
  for (const pattern of patterns) {
    // Classify on the pattern itself (after ~ expansion only) — `resolve()`
    // inside expandPath would make every pattern look absolute, since it
    // resolves relative patterns against the process cwd.
    const homeExpanded = pattern.replace(/^~(?=$|\/)/, homedir());
    if (isAbsolute(homeExpanded)) {
      absolutePatterns.push(expandPath(pattern));
    } else {
      // Relative patterns match two ways: gitignore semantics under cwd, and
      // (for non-globs) as cwd-anchored path prefixes, so entries like "."
      // (the whole working directory) or "Library" keep their directory
      // meaning — gitignore has no equivalent of ".".
      if (!pattern.includes("*")) {
        absolutePatterns.push(canonicalizePath(resolve(cwd, pattern)));
      }
      relativePatterns.push(pattern);
    }
  }

  for (const absolutePattern of absolutePatterns) {
    if (absolutePattern.includes("*")) {
      const escaped = absolutePattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*\*/g, "[^]*")
        .replace(/\*/g, "[^/]*");
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
    const rel = relative(cwd, absolutePath);
    // rel is "" when the path IS cwd — ignore() throws on empty paths, and
    // the cwd-anchored prefix branch above already covers that case.
    if (rel !== "" && !rel.startsWith("..") && !isAbsolute(rel)) {
      if (ignore().add(relativePatterns).ignores(rel)) return true;
    }
  }

  return false;
}
