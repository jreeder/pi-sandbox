/**
 * Minimal shell syntax model consumed by the bash path pre-check.
 *
 * This is the seam between parsing and policy: `bash-paths.ts` only reads
 * these types, so the in-house parser in `shell-parse.ts` can be replaced by
 * an adapter over a full bash parser (e.g. mvdan-sh or tree-sitter-bash)
 * that produces the same shape.
 */

export interface ShellWord {
  /** Text after quote removal. `$VAR` and `${VAR}` are kept verbatim. */
  text: string;
  /** Any part of the word was quoted. */
  quoted: boolean;
  /**
   * The word's value cannot be known statically: it contains a command
   * substitution, arithmetic expansion, or a non-trivial `${...}` expansion.
   */
  dynamic: boolean;
  /** An unquoted glob character (`*`, `?`, `[`) appears in the word. */
  glob: boolean;
}

export type RedirectOp = "<" | "<>" | ">" | ">>" | ">|" | "&>" | "&>>";

export interface Redirect {
  op: RedirectOp;
  target: ShellWord;
}

export interface Heredoc {
  delimiter: string;
  /** Quoted delimiter: the body is literal (no expansion). */
  quoted: boolean;
  /** `<<-`: leading tabs are stripped from body lines. */
  stripTabs: boolean;
  body: string;
}

export interface SimpleCommand {
  /** Leading `NAME=value` assignments. */
  assignments: ShellWord[];
  /** Command name and arguments. Empty for assignment- or redirect-only commands. */
  argv: ShellWord[];
  /** File redirections. fd duplications (`2>&1`, `<&-`) are omitted. */
  redirects: Redirect[];
  /** Heredocs fed to this command's stdin, in source order. */
  heredocs: Heredoc[];
  /** `<<<` here-strings fed to this command's stdin. */
  hereStrings: ShellWord[];
}

export interface ShellParser {
  /**
   * Parse a command string into a flat list of simple commands, including
   * commands nested in `$(...)`, backticks and process substitutions. Must not
   * throw: malformed input yields a best-effort result.
   */
  parse(source: string): SimpleCommand[];
}
