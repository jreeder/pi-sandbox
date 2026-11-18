import { mkdtempSync, mkdirSync, symlinkSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  allowsAllDomains,
  canonicalizePath,
  credentialFilePaths,
  decideBashCandidate,
  decideWritePolicy,
  domainIsAllowed,
  expandCommandToken,
  expandEnvVars,
  extractDomainsFromCommand,
  isBroadPath,
  isBroadRule,
  matchesPattern,
  resolveWritePermission,
} from "../src/policy.ts";

test("extracts and deduplicates literal HTTP domains", () => {
  assert.deepEqual(
    extractDomainsFromCommand("curl https://api.example.com/a http://api.example.com/b"),
    ["api.example.com"],
  );
});

test("extracts short, IP, userinfo and mixed-case hosts; skips expansions and single labels", () => {
  assert.deepEqual(
    extractDomainsFromCommand(
      'curl https://x.com/a "https://1.2.3.4:8080/b" https://user:pw@Git.Example.ORG/c HTTPS://y.io.',
    ),
    ["x.com", "1.2.3.4", "git.example.org", "y.io"],
  );
  assert.deepEqual(
    extractDomainsFromCommand(
      "curl https://$HOST/a https://${HOST}/b https://a$B.com http://localhost:3000 http://[::1]/c",
    ),
    [],
  );
  assert.deepEqual(
    extractDomainsFromCommand(
      "curl https://a.com, https://b.com; (curl https://c.com)&& curl https://d.com|x",
    ),
    ["a.com", "b.com", "c.com", "d.com"],
  );
});

test("credentialFilePaths lists declared files, optionally only deny-mode ones", () => {
  const credentials = {
    files: [
      { path: "/a", mode: "deny" },
      { path: "/b", mode: "mask" },
    ],
  };
  assert.deepEqual(credentialFilePaths(credentials), ["/a", "/b"]);
  assert.deepEqual(credentialFilePaths(credentials, true), ["/a"]);
  assert.deepEqual(credentialFilePaths(undefined), []);
});

test("matches exact, wildcard, and all-domain policies", () => {
  assert.equal(domainIsAllowed("github.com", ["github.com"]), true);
  assert.equal(domainIsAllowed("api.github.com", ["*.github.com"]), true);
  assert.equal(domainIsAllowed("notgithub.com", ["*.github.com"]), false);
  assert.equal(allowsAllDomains(["*"]), true);
});

test("decides write policy from deny and allow lists", () => {
  assert.equal(decideWritePolicy("/tmp/file", ["/tmp"], ["/tmp/file"], "/tmp"), "deny");
  assert.equal(decideWritePolicy("/tmp/file", ["/tmp"], [], "/tmp"), "allow");
  assert.equal(decideWritePolicy("/tmp/file", ["/var"], [], "/tmp"), "prompt");
  assert.equal(decideWritePolicy("/tmp/file", [], [], "/tmp"), "prompt");
});

test("resolves write permission without prompting for denied or allowed paths", async () => {
  const calls: string[] = [];
  const prompt = async () => {
    calls.push("prompt");
    return { action: "session" as const, value: "/tmp" };
  };
  const apply = async () => {
    calls.push("apply");
  };

  assert.deepEqual(
    await resolveWritePermission({
      path: "/tmp/file",
      allowWrite: ["/tmp"],
      denyWrite: ["/tmp/file"],
      baseCwd: "/tmp",
      prompt,
      saveWritePermission: apply,
    }),
    { action: "deny" },
  );
  assert.deepEqual(
    await resolveWritePermission({
      path: "/tmp/file",
      allowWrite: ["/tmp"],
      denyWrite: [],
      baseCwd: "/tmp",
      prompt,
      saveWritePermission: apply,
    }),
    { action: "allow" },
  );
  assert.deepEqual(calls, []);
});

test("resolves write permission prompt choices", async () => {
  const applied: string[] = [];
  assert.deepEqual(
    await resolveWritePermission({
      path: "/tmp/file",
      allowWrite: [],
      denyWrite: [],
      baseCwd: "/tmp",
      prompt: async () => ({ action: "abort", value: "/tmp/file" }),
      saveWritePermission: async (choice, value) => {
        applied.push(`${choice}:${value}`);
      },
    }),
    { action: "abort", value: "/tmp/file" },
  );
  assert.deepEqual(applied.length, 0);

  assert.deepEqual(
    await resolveWritePermission({
      path: "/tmp/file",
      allowWrite: [],
      denyWrite: [],
      baseCwd: "/tmp",
      prompt: async () => ({ action: "session", value: "/tmp" }),
      saveWritePermission: async (choice, value) => {
        applied.push(`${choice}:${value}`);
      },
    }),
    { action: "granted", value: "/tmp" },
  );
  assert.deepEqual(applied, ["session:/tmp"]);
});

test("path patterns support directory prefixes and globs", () => {
  const root = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-policy-")));
  assert.equal(matchesPattern(join(root, "nested", "file.txt"), [root], root), true);
  assert.equal(matchesPattern(join(root, "file.pem"), [join(root, "*.pem")], root), true);
  assert.equal(matchesPattern(join(root, "file.txt"), [join(root, "*.pem")], root), false);
});

test("absolute globs: * stays within a segment, ** crosses segments", () => {
  const root = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-policy-")));
  assert.equal(matchesPattern(join(root, "a"), [join(root, "*")], root), true);
  assert.equal(matchesPattern(join(root, "a", "b"), [join(root, "*")], root), false);
  assert.equal(matchesPattern(join(root, "a"), [join(root, "**")], root), true);
  assert.equal(matchesPattern(join(root, "a", "b", "c"), [join(root, "**")], root), true);
  assert.equal(
    matchesPattern(join(root, "a", "b", "c.pem"), [join(root, "**", "*.pem")], root),
    true,
  );
  assert.equal(matchesPattern(join(root, "c.pem"), [join(root, "**", "*.pem")], root), true);
  assert.equal(
    matchesPattern(join(root, "a", "b", "c.txt"), [join(root, "**", "*.pem")], root),
    false,
  );
});

test("blanket '.' and bare relative directory patterns anchor to cwd", () => {
  const root = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-cwd-")));
  // "." must cover the entire working directory (default allowRead/allowWrite).
  assert.equal(matchesPattern(join(root, "src", "policy.ts"), ["."], root), true);
  assert.equal(matchesPattern(root, ["."], root), true);
  assert.equal(matchesPattern("/etc/passwd", ["."], root), false);
  // A bare directory name anchors to cwd like the pre-refactor prefix matching.
  assert.equal(matchesPattern(join(root, "Library", "x"), ["Library"], root), true);
  // A path equal to cwd must not throw when only glob relative patterns exist.
  assert.equal(matchesPattern(root, ["*.pem"], root), false);
});

test("relative patterns are matched with gitignore semantics under cwd", () => {
  const root = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-gitignore-")));
  assert.equal(matchesPattern(join(root, ".env"), [".env"], root), true);
  assert.equal(matchesPattern(join(root, ".env.local"), [".env.*"], root), true);
  assert.equal(matchesPattern(join(root, "keep.txt"), [".env"], root), false);
  assert.equal(matchesPattern(join(root, "nested", "secret.pem"), ["*.pem"], root), true);
  // Outside cwd, relative patterns never match.
  assert.equal(matchesPattern("/etc/.env", [".env"], root), false);
});

test("expandEnvVars expands ${VAR} references and a leading ~", () => {
  const original = process.env.PI_SANDBOX_TEST_VAR;
  process.env.PI_SANDBOX_TEST_VAR = "/custom/path";
  try {
    assert.equal(expandEnvVars("${PI_SANDBOX_TEST_VAR}/file"), "/custom/path/file");
    assert.equal(expandEnvVars("${PI_SANDBOX_UNSET_VAR}/file"), "${PI_SANDBOX_UNSET_VAR}/file");
    assert.equal(expandEnvVars("~"), homedir());
    assert.equal(expandEnvVars("~/foo"), join(homedir(), "foo"));
  } finally {
    if (original === undefined) delete process.env.PI_SANDBOX_TEST_VAR;
    else process.env.PI_SANDBOX_TEST_VAR = original;
  }
});

test("relative paths resolve against baseCwd, not process.cwd()", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-basecwd-"));
  const project = canonicalizePath(root);

  // "." and relative entries resolve against the passed baseCwd.
  assert.equal(canonicalizePath(".", project), project);
  assert.equal(canonicalizePath("sub/file", project), join(project, "sub", "file"));

  // matchesPattern honors baseCwd for both the path and the pattern.
  assert.equal(matchesPattern(join(project, "f.txt"), ["."], project), true);
  assert.equal(matchesPattern("f.txt", ["."], project), true);
  assert.equal(matchesPattern("f.txt", ["other"], project), false);

  // decideWritePolicy threads baseCwd through to the pattern match.
  assert.equal(decideWritePolicy("f.txt", ["."], [], project), "allow");
  assert.equal(decideWritePolicy("f.txt", [], [], project), "prompt");
});

test("canonicalizes symlinks and nonexistent descendants", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-canonical-"));
  const real = join(root, "real");
  const link = join(root, "link");
  mkdirSync(real);
  symlinkSync(real, link);
  assert.equal(
    canonicalizePath(join(link, "new", "file")),
    join(canonicalizePath(real), "new", "file"),
  );
});

test("decideBashCandidate hard-blocks deny rules and prompts for reads outside the allow-list", () => {
  const cwd = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-bashpolicy-")));
  const base = {
    mode: "tools" as const,
    readPaths: [cwd, "/tmp"],
    denyWrite: ["*.pem", join(homedir(), ".ssh")],
    credentialDeny: [join(cwd, "auth.json")],
    cwd,
    exists: () => true,
  };
  const read = (path: string, confidence: "high" | "low" = "high") =>
    decideBashCandidate({ path, access: "read", confidence }, base);

  assert.equal(read(join(cwd, "src/main.ts")), "allow");
  assert.equal(read("/tmp/scratch.txt"), "allow");
  assert.equal(read(join(homedir(), ".orbstack/config")), "prompt");
  assert.equal(read("/etc/passwd"), "prompt");
  // denyWrite and credentials win over everything, at any confidence.
  assert.equal(read(join(cwd, "cert.pem"), "low"), "deny");
  assert.equal(read(join(homedir(), ".ssh/id_rsa")), "deny");
  assert.equal(read(join(cwd, "auth.json"), "low"), "credential");
  // Device files are always fine.
  assert.equal(read("/dev/null"), "allow");
  // Writes are left to the OS sandbox's allowWrite unless denied.
  assert.equal(
    decideBashCandidate({ path: "/opt/out", access: "write", confidence: "high" }, base),
    "allow",
  );
  assert.equal(
    decideBashCandidate({ path: join(cwd, "k.pem"), access: "write", confidence: "high" }, base),
    "deny",
  );
});

test("decideBashCandidate gates low-confidence words on existence and never grants / or home", () => {
  const cwd = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-bashpolicy-")));
  const options = (mode: "strict" | "tools" | "off", exists: boolean) => ({
    mode,
    readPaths: [cwd],
    denyWrite: [],
    credentialDeny: [],
    cwd,
    exists: () => exists,
  });
  const decide = (
    path: string,
    confidence: "high" | "low",
    mode: "strict" | "tools" | "off",
    exists = true,
  ) => decideBashCandidate({ path, access: "read", confidence }, options(mode, exists));

  assert.equal(decide("/opt/conf", "low", "tools", true), "prompt");
  assert.equal(decide("/opt/conf", "low", "tools", false), "allow");
  assert.equal(decide("/opt/conf", "low", "strict", false), "prompt");
  assert.equal(decide("/opt/conf", "high", "tools", false), "prompt");
  assert.equal(decide("/opt/conf", "high", "off"), "allow");
  // Root and home: blocked when certain, ignored when merely path-shaped.
  assert.equal(decide("/", "high", "tools"), "broad");
  assert.equal(decide("//", "high", "tools"), "broad");
  assert.equal(decide(homedir(), "high", "tools"), "broad");
  assert.equal(decide("/", "low", "tools"), "allow");
  assert.equal(decide("~", "low", "tools"), "allow");
  assert.equal(decide("/", "low", "strict"), "broad");
  // A manually configured broad rule is honoured.
  assert.equal(
    decideBashCandidate(
      { path: "/", access: "read", confidence: "high" },
      { ...options("tools", true), readPaths: ["/"] },
    ),
    "allow",
  );
});

test("isBroadRule rejects root and home rules in any spelling", () => {
  const cwd = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-broad-")));
  for (const rule of [
    "/",
    "//",
    "/*",
    "/**",
    "/**/",
    "~",
    "~/",
    "~/**",
    "${HOME}",
    "$HOME/*",
    homedir(),
  ]) {
    assert.equal(isBroadRule(rule, cwd), true, rule);
  }
  for (const rule of [
    "/etc",
    "/etc/**",
    "~/.config",
    "~/src/**",
    ".",
    "*.pem",
    "**/*.py",
    "/home",
  ]) {
    assert.equal(isBroadRule(rule, cwd), false, rule);
  }
  // "." is broad when the working directory is the home directory itself.
  assert.equal(isBroadRule(".", homedir()), true);
  assert.equal(isBroadPath("/", cwd), true);
  assert.equal(isBroadPath(join(homedir(), "x"), cwd), false);
});

test("expandCommandToken expands $VAR and ${VAR}, returning null for unset variables", () => {
  const original = process.env.PI_SANDBOX_TEST_VAR;
  process.env.PI_SANDBOX_TEST_VAR = "/custom/path";
  delete process.env.PI_SANDBOX_UNSET_VAR;
  try {
    assert.equal(expandCommandToken("${PI_SANDBOX_TEST_VAR}/file"), "/custom/path/file");
    assert.equal(expandCommandToken("$PI_SANDBOX_TEST_VAR/file"), "/custom/path/file");
    assert.equal(expandCommandToken("~/plain/token"), "~/plain/token");
    assert.equal(expandCommandToken("${PI_SANDBOX_UNSET_VAR}/file"), null);
    assert.equal(expandCommandToken("$PI_SANDBOX_UNSET_VAR/file"), null);
  } finally {
    if (original === undefined) delete process.env.PI_SANDBOX_TEST_VAR;
    else process.env.PI_SANDBOX_TEST_VAR = original;
  }
});
