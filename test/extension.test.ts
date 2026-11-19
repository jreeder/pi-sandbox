import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import assert from "node:assert/strict";

import extension from "../src/extension.ts";

type Handler = (event: any, ctx: ExtensionContext) => any;

// Enabling the sandbox initializes the real runtime, which needs sandbox-exec
// on macOS, or bwrap + socat and unprivileged user namespaces on Linux.
function sandboxAvailable(): boolean {
  if (process.platform === "darwin") return true;
  if (process.platform !== "linux") return false;
  const ok = (cmd: string, args: string[]) => spawnSync(cmd, args).status === 0;
  return (
    ok("which", ["bwrap"]) &&
    ok("which", ["socat"]) &&
    ok("bwrap", [
      "--ro-bind",
      "/",
      "/",
      "--unshare-user",
      "--unshare-pid",
      "--proc",
      "/proc",
      "true",
    ])
  );
}
const noSandbox = !sandboxAvailable();

function session(cwd: string, flags: Record<string, boolean> = {}) {
  const handlers = new Map<string, Handler>();
  const commands = new Map<string, (args: string, ctx: ExtensionContext) => Promise<void>>();
  const statuses: string[] = [];
  const api = {
    on: (name: string, handler: Handler) => handlers.set(name, handler),
    registerTool: () => {},
    registerFlag: () => {},
    registerShortcut: () => {},
    registerCommand: (name: string, command: { handler: any }) =>
      commands.set(name, command.handler),
    getFlag: (name: string) => flags[name] ?? false,
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd,
    hasUI: false,
    isProjectTrusted: () => true,
    ui: {
      notify: () => {},
      setStatus: (_key: string, text: string) => statuses.push(text),
      theme: { fg: (_color: string, text: string) => text },
    },
  } as unknown as ExtensionContext;
  extension(api);
  return {
    statuses,
    start: () => handlers.get("session_start")!({ reason: "startup" }, ctx),
    shutdown: () => handlers.get("session_shutdown")!({ reason: "quit" }, ctx),
    command: (name: string) => commands.get(name)!("", ctx),
    toolCall: (toolName: string, input: Record<string, unknown>) =>
      handlers.get("tool_call")!({ toolName, input }, ctx),
  };
}

function setup(t: TestContext, config: object = {}) {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-ext-"));
  const agentDir = join(root, "agent");
  mkdirSync(agentDir);
  writeFileSync(join(agentDir, "sandbox.json"), JSON.stringify(config));
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  const originalEnvProxy = process.env.NODE_USE_ENV_PROXY;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  delete process.env.NODE_USE_ENV_PROXY;
  t.after(() => {
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    if (originalEnvProxy === undefined) delete process.env.NODE_USE_ENV_PROXY;
    else process.env.NODE_USE_ENV_PROXY = originalEnvProxy;
    rmSync(root, { recursive: true, force: true });
  });
  return { root, agentDir };
}

test("the footer shows the sandbox as disabled when started with --no-sandbox", async (t) => {
  const { root } = setup(t);
  const current = session(root, { "no-sandbox": true });
  await current.start();
  assert.deepEqual(current.statuses, ["Sandbox: disabled"]);
});

test("the footer shows the sandbox as disabled when the config disables it", async (t) => {
  const { root } = setup(t, { enabled: false });
  const current = session(root);
  await current.start();
  assert.deepEqual(current.statuses, ["Sandbox: disabled"]);
});

test(
  "pi credential files are hard-blocked even when their directory is allowed",
  { skip: noSandbox, timeout: 15_000 },
  async (t) => {
    const { root, agentDir } = setup(t);
    writeFileSync(
      join(agentDir, "sandbox.json"),
      JSON.stringify({ filesystem: { allowRead: [agentDir], allowWrite: [root] } }),
    );
    const current = session(root);
    t.after(() => current.shutdown());
    await current.start();

    const authJson = join(agentDir, "auth.json");
    const token = join(agentDir, "mcp-oauth", "server.json");
    for (const result of [
      await current.toolCall("read", { path: authJson }),
      await current.toolCall("read", { path: token }),
      await current.toolCall("write", { path: authJson, content: "x" }),
      await current.toolCall("edit", { path: token, edits: [] }),
      await current.toolCall("bash", { command: `cat ${authJson}` }),
    ]) {
      assert.equal(result?.block, true);
      assert.match(result.reason, /protected credential file/);
    }
    // A sibling in the same allowed directory is still readable.
    assert.equal(
      await current.toolCall("read", { path: join(agentDir, "settings.json") }),
      undefined,
    );
  },
);

test(
  "disable releases NODE_USE_ENV_PROXY and shows the disabled status; re-enable restores both",
  { skip: noSandbox || process.versions.node.split(".")[0] === "20", timeout: 15_000 },
  async (t) => {
    const { root } = setup(t);
    const current = session(root);
    t.after(() => current.shutdown());

    await current.start();
    assert.equal(process.env.NODE_USE_ENV_PROXY, "1");

    await current.command("sandbox-disable");
    assert.equal(process.env.NODE_USE_ENV_PROXY, undefined);
    assert.equal(current.statuses.at(-1), "Sandbox: disabled");

    await current.command("sandbox-enable");
    assert.equal(process.env.NODE_USE_ENV_PROXY, "1");
    assert.match(current.statuses.at(-1)!, /^🔒 Sandbox:/);
  },
);

test(
  "bash pre-check ignores code noise, gates unknown words on existence and never grants /",
  { skip: noSandbox, timeout: 20_000 },
  async (t) => {
    const outside = mkdtempSync(join(tmpdir(), "pi-sandbox-outside-"));
    t.after(() => rmSync(outside, { recursive: true, force: true }));
    const secret = join(outside, "secret.txt");
    writeFileSync(secret, "x");
    const missing = join(outside, "missing", "file");

    const run = async (command: string, bashPathCheck?: string) => {
      const { root } = setup(t);
      writeFileSync(
        join(process.env.PI_CODING_AGENT_DIR!, "sandbox.json"),
        JSON.stringify({ bashPathCheck, filesystem: { allowRead: [root], allowWrite: [root] } }),
      );
      const current = session(root);
      await current.start();
      try {
        return await current.toolCall("bash", { command });
      } finally {
        await current.shutdown();
      }
    };
    const notAllowed = /not in allowRead/;
    const root = /cannot be granted while the sandbox is enabled/;

    // Interpreter heredocs: operators, comments and regexes are not paths.
    assert.equal(
      await run(`python3 - <<'EOF'\nx = 1 // 2  # /etc\nre.sub(r"/a/", "", s)\nEOF`),
      undefined,
    );
    // ...but literal IO calls are, at high confidence.
    assert.match(
      (await run(`python3 - <<'EOF'\nopen("${secret}").read()\nEOF`)).reason,
      notAllowed,
    );
    // Code written to a file is data.
    assert.equal(await run(`cat > x.py <<'EOF'\nos.listdir("/")\nEOF`), undefined);
    // Root is never grantable when it is certainly a path.
    assert.match((await run("find / -name x")).reason, root);
    // Home is an ordinary path: outside the allow-list it prompts.
    assert.match((await run("ls ~")).reason, notAllowed);
    // Known tools prompt for paths outside the allow-list.
    assert.match((await run(`cat ${secret}`)).reason, notAllowed);
    // Unknown commands: only words naming something that exists prompt.
    assert.match((await run(`some-tool ${secret}`)).reason, notAllowed);
    assert.equal(await run(`some-tool ${missing}`), undefined);
    assert.equal(await run("expr 4 / 2"), undefined);
    // Levels.
    assert.match((await run(`some-tool ${missing}`, "strict")).reason, notAllowed);
    assert.equal(await run(`cat ${secret}`, "off"), undefined);
  },
);

test(
  "read/write tools refuse / but treat the home directory as an ordinary path",
  { skip: noSandbox, timeout: 15_000 },
  async (t) => {
    const { root } = setup(t, { filesystem: { allowRead: [], allowWrite: [] } });
    const current = session(root);
    t.after(() => current.shutdown());
    await current.start();
    for (const result of [
      await current.toolCall("read", { path: "/" }),
      await current.toolCall("write", { path: "/", content: "x" }),
    ]) {
      assert.equal(result?.block, true);
      assert.match(result.reason, /cannot be granted while the sandbox is enabled/);
    }
    // Home prompts (aborted here, as there is no UI) instead of being refused.
    const home = await current.toolCall("read", { path: "~" });
    assert.equal(home?.block, true);
    assert.match(home.reason, /read access denied/);
    assert.doesNotMatch(home.reason, /cannot be granted/);
  },
);

test(
  "the home directory is usable when it is the working directory",
  { skip: noSandbox, timeout: 15_000 },
  async (t) => {
    const { root } = setup(t, { filesystem: { allowRead: ["."], allowWrite: ["."] } });
    const originalHome = process.env.HOME;
    process.env.HOME = root;
    t.after(() => {
      if (originalHome === undefined) delete process.env.HOME;
      else process.env.HOME = originalHome;
    });
    const current = session(root);
    t.after(() => current.shutdown());
    await current.start();
    assert.equal(await current.toolCall("read", { path: "~" }), undefined);
    assert.equal(await current.toolCall("read", { path: join(root, "notes.txt") }), undefined);
    assert.equal(await current.toolCall("bash", { command: "ls ~ && cat ~/notes.txt" }), undefined);
  },
);
