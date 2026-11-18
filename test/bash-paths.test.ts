import test from "node:test";

import assert from "node:assert/strict";

import { extractBashPathCandidates } from "../src/bash-paths.ts";
import { extractCodePaths } from "../src/code-paths.ts";

/** Compact `confidence access path` strings, sorted, for table assertions. */
const paths = (command: string) =>
  extractBashPathCandidates(command)
    .map((c) => `${c.confidence} ${c.access} ${c.path}`)
    .sort();

test("interpreter heredocs yield only IO-call literals, not operators, comments or regexes", () => {
  assert.deepEqual(
    paths(
      [
        "python3 - <<'EOF'",
        "x = a // b  # see /etc/x",
        "pattern = re.compile(r'/foo/')",
        'with open("/etc/hosts") as f: print(f.read())',
        "open('out.txt', 'w').write(s)",
        "print('open(\"/not/a/call\")')",
        "EOF",
      ].join("\n"),
    ),
    ["high read /etc/hosts", "high write out.txt"],
  );
  assert.deepEqual(
    paths(
      [
        "node <<EOF",
        "// comment /etc",
        "const r = /foo\\/bar/; const half = n / 2;",
        "fs.readFileSync(\"./a.json\"); fs.promises.writeFile('/tmp/o', x);",
        'import y from "../lib/y.js"; import _ from "lodash";',
        "fs.readFileSync(`${dir}/x`);",
        "EOF",
      ].join("\n"),
    ),
    ["high read ../lib/y.js", "high read ./a.json", "high write /tmp/o"],
  );
  assert.deepEqual(
    paths(
      `ruby <<'RB'\nx = 4 / 2 # /etc\nFile.read "/etc/passwd"\nFileUtils.cp("a", "/opt/b")\nFile.read("#{d}/x")\nRB`,
    ),
    ["high read /etc/passwd", "high read a", "high write /opt/b"],
  );
});

test("inline -c / -e code, bash -c and eval are analyzed", () => {
  assert.deepEqual(paths(`python -c "import json; json.load(open('/x/y.json'))"`), [
    "high read /x/y.json",
  ]);
  assert.deepEqual(paths(`ruby -e 'IO.write("/tmp/w", "x")'`), ["high write /tmp/w"]);
  assert.deepEqual(paths(`node -e 'require("./mod")'`), ["high read ./mod"]);
  assert.deepEqual(paths(`bash -lc 'cat ~/.ssh/id_rsa'`), ["high read ~/.ssh/id_rsa"]);
  assert.deepEqual(paths(`eval cat /etc/shadow`), ["high read /etc/shadow"]);
  assert.deepEqual(paths(`python3 script.py --out /data/x`), [
    "high read script.py",
    "low read /data/x",
  ]);
  // stdin is data when the interpreter already has a script.
  assert.deepEqual(paths(`python3 run.py <<'EOF'\nopen("/etc/x")\nEOF`), ["high read run.py"]);
  assert.deepEqual(paths(`python -m http.server 8000`), []);
});

test("heredocs fed to non-interpreters are opaque data", () => {
  assert.deepEqual(paths(`cat > script.py <<'EOF'\nimport os\nos.listdir("/")\nx = 1 // 2\nEOF`), [
    "high write script.py",
  ]);
  assert.deepEqual(paths(`git commit -F - <<'EOF'\nfix /api route\nEOF`), []);
  assert.deepEqual(paths(`bash <<'EOF'\ncat /etc/motd\nEOF`), ["high read /etc/motd"]);
});

test("known tools: file positions are high confidence, patterns and scripts are skipped", () => {
  const cases: Record<string, string[]> = {
    'cat "/etc/passwd" ./b .env': ["high read ./b", "high read .env", "high read /etc/passwd"],
    "bat -l rs --style=plain src/main.rs": ["high read src/main.rs"],
    "head -n 5 /var/log/syslog": ["high read /var/log/syslog"],
    "grep -rn '/api/' src /etc/hosts": ["high read /etc/hosts", "high read src"],
    "grep -e pat -f /p.txt file": ["high read /p.txt", "high read file"],
    "rg --files /opt": ["high read /opt"],
    "sed -n '/start/,/end/p' notes.txt": ["high read notes.txt"],
    "sed -i.bak 's/a/b/' cfg.yml": ["high write cfg.yml"],
    "sed -f /x.sed in": ["high read /x.sed", "high read in"],
    "awk -F: '{print $1 / 2}' v=1 /etc/passwd": ["high read /etc/passwd"],
    "awk -f /prog.awk data": ["high read /prog.awk", "high read data"],
    "jq --arg n /v '.a' data.json": ["high read data.json"],
    "cp -r /src/a /src/b dest": ["high read /src/a", "high read /src/b", "high write dest"],
    "cp -t /dest a": ["high read a", "high write /dest"],
    "mv a /b": ["high write /b", "high write a"],
    "rsync -av host:/remote/ ./local/": ["high write ./local/"],
    "tee -a /tmp/log": ["high write /tmp/log"],
    "chmod 755 bin/x": ["high write bin/x"],
    "tar czf out.tgz -C /src lib": ["high read /src", "high read lib", "high write out.tgz"],
    "tar -xf in.tar -C /dest": ["high read in.tar", "high write /dest"],
    "dd if=/dev/sda of=disk.img": ["high read /dev/sda", "high write disk.img"],
    "curl -o /tmp/out -T up.bin https://x.com/a": ["high read up.bin", "high write /tmp/out"],
    "unzip a.zip member -d /out": ["high read a.zip", "high write /out"],
    "gzip -c data > data.gz": ["high read data", "high write data.gz"],
    "find / -name x -newer ref -exec cat {} \\;": ["high read /", "high read ref"],
    "ls; du -sh /": ["high read /"],
  };
  for (const [command, expected] of Object.entries(cases)) {
    assert.deepEqual(paths(command), expected, command);
  }
});

test("redirections, wrappers and globs", () => {
  assert.deepEqual(paths("sort < /in > /out 2>/dev/null"), [
    "high read /in",
    "high write /dev/null",
    "high write /out",
  ]);
  assert.deepEqual(paths("sudo -u root cat /root/x"), ["high read /root/x"]);
  assert.deepEqual(paths("env -u X FOO=1 timeout -s KILL 5 cat /a"), ["high read /a"]);
  assert.deepEqual(paths("xargs -a /list.txt rm"), ["high read /list.txt"]);
  assert.deepEqual(paths("cat *.txt /etc/*.conf"), ["high read .", "high read /etc"]);
  assert.deepEqual(paths("if test -f /x; then cat /y; fi"), ["high read /y"]);
});

test("unknown commands contribute only path-shaped words, at low confidence", () => {
  assert.deepEqual(paths("some-tool --config=/opt/conf ./local plain sub/dir ~/x $HOME/y"), [
    "low read $HOME/y",
    "low read ./local",
    "low read /opt/conf",
    "low read ~/x",
  ]);
  // Arithmetic, echo and printf never produce candidates.
  assert.deepEqual(paths("expr 4 / 2; echo / ; printf '%s\\n' /etc"), []);
  // Dynamic words are skipped.
  assert.deepEqual(paths('cat "$(pick)" ${A:-/x}'), []);
});

test("extractCodePaths handles keyword arguments, modes and write chains", () => {
  assert.deepEqual(extractCodePaths('open(file="/a", mode="a")', "python"), [
    { path: "/a", access: "write" },
  ]);
  assert.deepEqual(extractCodePaths('Path("/b").write_text("x")', "python"), [
    { path: "/b", access: "write" },
  ]);
  assert.deepEqual(extractCodePaths('Path("/c").read_text()', "python"), [
    { path: "/c", access: "read" },
  ]);
  assert.deepEqual(extractCodePaths('shutil.copy("/s", "/d")', "python"), [
    { path: "/s", access: "read" },
    { path: "/d", access: "write" },
  ]);
  assert.deepEqual(extractCodePaths('open(f"{d}/x"); df.to_csv("out.csv")', "python"), [
    { path: "out.csv", access: "write" },
  ]);
  assert.deepEqual(extractCodePaths('File.open("/f", "w") { |f| f << 1 }', "ruby"), [
    { path: "/f", access: "write" },
  ]);
  assert.deepEqual(extractCodePaths('stat("/x"); fs.stat("/y")', "javascript"), [
    { path: "/y", access: "read" },
  ]);
});
