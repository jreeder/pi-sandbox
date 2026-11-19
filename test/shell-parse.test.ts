import test from "node:test";

import assert from "node:assert/strict";

import { inHouseShellParser } from "../src/shell-parse.ts";

const parse = (source: string) => inHouseShellParser.parse(source);
const argv = (source: string) => parse(source).map((cmd) => cmd.argv.map((word) => word.text));

test("splits commands on separators and keeps quoted text as one word", () => {
  assert.deepEqual(argv("a 'b c' \"d $X\" e\\ f; g && h || i | j & k\nl"), [
    ["a", "b c", "d $X", "e f"],
    ["g"],
    ["h"],
    ["i"],
    ["j"],
    ["k"],
    ["l"],
  ]);
  assert.deepEqual(argv("a # comment / here\nb#notcomment"), [["a"], ["b#notcomment"]]);
  assert.deepEqual(argv("a \\\n  b"), [["a", "b"]]);
});

test("parses nested command and process substitutions as their own commands", () => {
  const commands = parse('echo "$(cat /a)" `head /b` <(tail /c) $((1 / 2))');
  assert.deepEqual(commands.map((cmd) => cmd.argv[0]?.text).sort(), [
    "cat",
    "echo",
    "head",
    "tail",
  ]);
  const echo = commands.find((cmd) => cmd.argv[0]?.text === "echo")!;
  assert.ok(echo.argv.slice(1).every((word) => word.dynamic));
});

test("records file redirections and ignores descriptor duplication", () => {
  const [cmd] = parse("x <in >out 2>>err &>both 2>&1 >&2 <&- >& file 3<>rw");
  assert.deepEqual(
    cmd!.redirects.map((r) => [r.op, r.target.text]),
    [
      ["<", "in"],
      [">", "out"],
      [">>", "err"],
      ["&>", "both"],
      ["&>", "file"],
      ["<>", "rw"],
    ],
  );
  assert.deepEqual(
    cmd!.argv.map((word) => word.text),
    ["x"],
  );
});

test("captures heredoc bodies with quoted, unquoted and tab-stripped delimiters", () => {
  const commands = parse(
    "python3 - <<'PY' && cat <<-EOF > out\nprint(1 // 2)\nPY\n\tbody $X\n\tEOF\nnext <<< 'here'",
  );
  const [python, cat, next] = commands;
  assert.deepEqual(python!.heredocs, [
    { delimiter: "PY", quoted: true, stripTabs: false, body: "print(1 // 2)" },
  ]);
  assert.deepEqual(cat!.heredocs, [
    { delimiter: "EOF", quoted: false, stripTabs: true, body: "body $X" },
  ]);
  assert.deepEqual(
    cat!.redirects.map((r) => r.target.text),
    ["out"],
  );
  assert.deepEqual(
    next!.hereStrings.map((word) => word.text),
    ["here"],
  );
});

test("marks dynamic and glob words", () => {
  const [cmd] = parse("x ${A} ${A:-b} $1 $? *.txt '*.txt'");
  assert.deepEqual(
    cmd!.argv.slice(1).map((word) => [word.text, word.dynamic, word.glob]),
    [
      ["${A}", false, false],
      ["${A:-b}", true, false],
      ["$1", false, false],
      ["$?", true, false],
      ["*.txt", false, true],
      ["*.txt", false, false],
    ],
  );
});

test("separates leading assignments and tolerates malformed input", () => {
  const [cmd] = parse("FOO=1 BAR=/x cmd a=b");
  assert.deepEqual(
    cmd!.assignments.map((word) => word.text),
    ["FOO=1", "BAR=/x"],
  );
  assert.deepEqual(
    cmd!.argv.map((word) => word.text),
    ["cmd", "a=b"],
  );
  assert.doesNotThrow(() => parse("cat 'unterminated $(foo <<EOF"));
});
