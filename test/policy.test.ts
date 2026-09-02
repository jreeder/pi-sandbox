import { mkdtempSync, mkdirSync, symlinkSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  allowsAllDomains,
  canonicalizePath,
  decideBashPathPolicy,
  decideWritePolicy,
  domainIsAllowed,
  expandCommandToken,
  expandEnvVars,
  extractDomainsFromCommand,
  extractPathsFromCommand,
  matchesPattern,
  resolveWritePermission,
} from "../src/policy.ts";

test("extracts and deduplicates literal HTTP domains", () => {
  assert.deepEqual(
    extractDomainsFromCommand("curl https://api.example.com/a http://api.example.com/b"),
    ["api.example.com"],
  );
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
      cwd: "/tmp",
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
      cwd: "/tmp",
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
      cwd: "/tmp",
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
      cwd: "/tmp",
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

test("extractPathsFromCommand pulls plausible file paths and ignores quoted strings", () => {
  // Bare relative names with no ./ ../ ~/ prefix are intentionally not
  // matched — only tokens that already look like paths are considered.
  assert.deepEqual(extractPathsFromCommand("cat .env"), []);
  assert.deepEqual(extractPathsFromCommand("cat ./.env"), ["./.env"]);
  assert.deepEqual(extractPathsFromCommand("cat ./config/secret.pem"), ["./config/secret.pem"]);
  assert.deepEqual(extractPathsFromCommand("echo 'not/a/path' && cat ./real.pem"), ["./real.pem"]);
  assert.deepEqual(extractPathsFromCommand("cat /etc/passwd"), ["/etc/passwd"]);
});

test("extractPathsFromCommand catches root traversals and slash variants", () => {
  assert.deepEqual(extractPathsFromCommand("find / -name secrets"), ["/"]);
  assert.deepEqual(extractPathsFromCommand("du -sh /"), ["/"]);
  assert.deepEqual(extractPathsFromCommand("find // -type f"), ["//"]);
  assert.deepEqual(extractPathsFromCommand("cat //etc/passwd"), ["//etc/passwd"]);
  assert.deepEqual(extractPathsFromCommand("cat /.dockerenv"), ["/.dockerenv"]);
  // Slashes inside URLs and mid-token are not candidates.
  assert.deepEqual(extractPathsFromCommand("curl https://example.com/path"), []);
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

test("decideBashPathPolicy hard-blocks denyWrite and prompts outside the read allow-list", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-bashpolicy-"));
  const readPaths = [cwd, "/tmp"];
  const denyWrite = ["*.pem", join(homedir(), ".ssh")];

  assert.equal(decideBashPathPolicy(join(cwd, "src/main.ts"), readPaths, denyWrite, cwd), "allow");
  assert.equal(decideBashPathPolicy("/tmp/scratch.txt", readPaths, denyWrite, cwd), "allow");
  // Outside allowRead/allowWrite: prompt, even though nothing deny-lists it.
  assert.equal(
    decideBashPathPolicy(join(homedir(), ".orbstack/config"), readPaths, denyWrite, cwd),
    "prompt",
  );
  assert.equal(decideBashPathPolicy("/etc/passwd", readPaths, denyWrite, cwd), "prompt");
  // denyWrite wins over everything, without a prompt.
  assert.equal(decideBashPathPolicy(join(cwd, "cert.pem"), readPaths, denyWrite, cwd), "deny");
  assert.equal(
    decideBashPathPolicy(join(homedir(), ".ssh/id_rsa"), readPaths, denyWrite, cwd),
    "deny",
  );
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
