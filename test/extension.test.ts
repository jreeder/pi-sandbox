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
