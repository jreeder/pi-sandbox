# pi-sandbox

Sandbox for [pi](https://pi.dev/).

Sandboxes pi like this:
- read/write/edit: direct control using allow/deny lists
- bash: uses [`@carderne/sandbox-runtime`](https://www.npmjs.com/package/@carderne/sandbox-runtime) to control network and file system access

Blocked read/write/edit tool calls and detected network requests prompt for
temporary or permanent permission. Bash filesystem failures are returned without
automatically granting permissions or retrying the command.

![demo](./demo/demo.gif)

## About this fork

This is a fork of [carderne/pi-sandbox](https://github.com/carderne/pi-sandbox)
that tracks upstream releases (currently synced to upstream 0.8.2) and adds
stricter filesystem policy checks on top. The OS-level sandbox and runtime
configuration are unchanged from upstream; the differences are all in the
extension's own policy layer.

`pi install npm:pi-sandbox` installs the upstream package, without these changes.
To use this fork, install it from git:

```bash
pi install git:github.com/jreeder/pi-sandbox
```

### Differences from upstream

- **Bash commands are checked against the filesystem policy before they run.**
  Upstream relies on the OS sandbox for bash, and the OS sandbox only
  deny-lists reads: anything outside `denyRead` is silently readable from bash.
  This fork parses each bash command (quoting, pipelines, redirections,
  heredocs, `$(...)`) and grades the paths it finds:
  - **High confidence:** file arguments of known tools (`cat`, `bat`, `head`,
    `grep`/`rg`, `sed`, `awk`, `jq`, `find`, `ls`, `cp`, `mv`, `tar`, `curl -o`,
    ... — patterns and scripts such as `sed`'s first argument are skipped),
    redirection targets, interpreter script files, and string literals passed
    to file IO calls (`open(...)`, `File.read`, `fs.readFileSync`, ...) in
    Python, Ruby and JavaScript code given via heredoc, here-string, `-c` or
    `-e`. `bash -c`, shell heredocs, `eval` and `find -exec` are followed.
  - **Low confidence:** path-shaped words (`/x`, `./x`, `~/x`, `$VAR/x`) passed
    to commands not in the tool table.

  Heredocs fed to anything other than an interpreter or shell
  (`cat > script.py <<EOF`) are treated as data and not scanned, so operators,
  comments and regex literals in code no longer look like paths.

  Then, controlled by `bashPathCheck`:
  - a path in `credentials.files` (deny mode) or `denyWrite` hard-blocks;
  - a write target is otherwise left to the OS sandbox, which enforces
    `allowWrite` as an allow-list;
  - a read outside `allowRead`/`allowWrite` prompts if it is high confidence,
    or (in the default `tools` mode) if it is low confidence and exists on
    disk. Granting adds the rule to `allowRead`.

  `$VAR`/`${VAR}` are expanded from the environment; words that reference an
  unset variable or a command substitution are skipped and left to the OS
  sandbox, as are paths built at runtime inside interpreter code (variables,
  f-strings, `${}` templates) and the arguments of commands like `echo`,
  `printf`, `expr` and `test`. A glob contributes its static directory
  (`cat /etc/*.conf` checks `/etc`). Standard devices (`/dev/null`, ...) never
  prompt.
- **`/` and the home directory can never be granted while the sandbox is
  enabled.** Permission prompts, `/sandbox-allow` and `sandbox_request_access`
  reject rules that cover the filesystem root or the home directory itself
  (`/`, `/**`, `~`, `~/**`, `$HOME`, or `.` when the working directory is
  home). A bash command that certainly reads one of them is blocked; a
  low-confidence `/` (e.g. `a / b`) is ignored. Add such a rule to the config
  file by hand if you really need it.
- **Relative patterns use gitignore semantics.** In `allowRead`, `denyRead`,
  `allowWrite` and `denyWrite`, an entry without a leading `/` or `~` (e.g.
  `.env`, `*.pem`, `Library`) is matched relative to the session working
  directory the way it would be in a `.gitignore` file, so it matches at any
  depth. `.env` matches `./sub/.env`, not just `./.env`. Non-glob relative
  entries also still match as a directory prefix under the working directory,
  so `.` keeps meaning "the whole working directory".
- **`*` in absolute patterns stays within one path segment.** `/tmp/*` matches
  `/tmp/a` but not `/tmp/a/b`; use `**` to cross segments (`/tmp/**`), and
  `**/` matches zero or more directories (`/tmp/**/*.pem` matches `/tmp/c.pem`).
  Upstream's `*` matches across `/`.
- **Environment variables in config patterns.** Filesystem patterns may use
  `${VAR}` (e.g. `"${HOME}/secrets"`), expanded when the config is loaded and
  applied to both the tool checks and the OS sandbox. Unset variables are left
  as literal text.
- **Pi's own credential files are always denied.** `auth.json` (API keys) and
  `mcp-oauth/` (MCP OAuth tokens) in Pi's agent directory (`~/.pi/agent` by
  default; respects `PI_CODING_AGENT_DIR`) are added to `credentials.files` with
  `mode: "deny"` on every config load, alongside any entries you declare. The OS
  sandbox makes them unreadable from bash even when an ancestor such as `~/.pi`
  is in `allowRead`, and the read/write/edit tools and the bash pre-check
  hard-block them with no prompt. The tools also hard-block every other
  `credentials.files` entry, including `mode: "mask"` ones: they run outside the
  OS sandbox, so they would otherwise see the real contents. For the same
  reason `sandbox_request_access` refuses read/write requests for any
  `credentials.files` entry instead of prompting.
- **Fixes not yet in upstream:**
  - Disabling the sandbox removes `NODE_USE_ENV_PROXY` if the extension set
    it. The variable is shared by every session in the process (e.g.
    subagents), so it is removed only when the last sandboxed session releases
    it.
  - The footer shows `Sandbox: disabled` when the sandbox is off (via
    `--no-sandbox`, config, a toggle, or a failed initialization) instead of
    clearing the indicator.

The pattern-matching differences apply to the read/write/edit tool checks and
the bash pre-check. The OS sandbox receives the same filesystem patterns as
upstream, so on Linux glob entries in `allowWrite`/`denyWrite` are still
unenforced at the OS level (see [Configure](#configure)).

## Notes
There is an example config at [sandbox.json](./sandbox.json). It was quite a few things added to get this extension to work with [agent-browser](https://agent-browser.dev/) and other common tools.

These open significant security loopholes, so shouldn't be used in a sensitive context or when you don't need browser support.

You may need to trial and error to find additional things you need to allow.

## Quickstart

#### Prerequisites

`pi-sandbox` delegates the OS-level bash sandbox to
[`@carderne/sandbox-runtime`](https://www.npmjs.com/package/@carderne/sandbox-runtime),
published from the fork at <https://github.com/carderne/sandbox-runtime>,
which is forked from Anthropic's
[`anthropic-experimental/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime).
The sandbox runtime checks for [`ripgrep`](https://github.com/BurntSushi/ripgrep) (the
`rg` binary) on **both macOS and Linux** at sandbox-init time. If `rg`
is not on the `PATH` that pi was launched with, sandbox initialization
fails with:

```
Sandbox initialization failed: Sandbox dependencies not available: ripgrep (rg) not found
```

Install ripgrep before enabling the extension:

| Platform | Install |
|---|---|
| macOS (Homebrew) | `brew install ripgrep` |
| macOS (MacPorts) | `sudo port install ripgrep` |
| Linux (Debian/Ubuntu) | `sudo apt install ripgrep` |
| Linux (Fedora/RHEL) | `sudo dnf install ripgrep` |
| Linux (Arch) | `sudo pacman -S ripgrep` |
| From source / other | <https://github.com/BurntSushi/ripgrep#installation> |

Experimental Android/Termux support uses the Linux backend and requires `ripgrep`,
`which`, `socat`, and a [compatible `bwrap`](https://gist.github.com/spurreiter/caa34d367b7ebbd82806a640bf41157a).
Support depends on the device's kernel and isolation capabilities.

If `which rg` succeeds in your shell but pi still reports `rg not
found`, pi is being launched from a parent process whose `PATH` does
not include the directory containing `rg` (common when GUI launchers
inherit a minimal non-login `PATH`). On macOS, `/opt/homebrew/bin` and
`/usr/local/bin` are the usual culprits — make sure your launcher's
environment includes whichever one your install uses.

#### Install
```bash
pi install npm:pi-sandbox
```

#### Configure
Add a config like this either to Pi's global agent directory (by default, `~/.pi/agent/sandbox.json`; respects `PI_CODING_AGENT_DIR`) or to `.pi/sandbox.json` (local).
The local config is loaded only when Pi trusts the project. Scalar settings in the local config take precedence over global settings, except `allowProcessSignals`, which is global-only. The
path and domain arrays from both files are combined and deduplicated, so a
project can add permissions without repeating the global configuration. Built-in
defaults are used for an array only when neither file configures it.

On Linux, glob patterns (`*`, `?`, `[...]`) in `allowWrite`/`denyWrite` cannot be
enforced for bash commands (bubblewrap binds concrete paths only), so they are
silently ignored there; use literal paths. A one-time warning is shown if your own
config adds such globs (built-in defaults are excluded). Direct read/write/edit
tools still honor globs on all platforms.

Note below that the order of precedence for filesystem read and write are opposite.

```json
{
  "enabled": true,
  "enableAccessRequestTool": false, // Enable sandbox_status and sandbox_request_access
  "sandboxUserShell": false,       // Sandbox commands entered with `!`. Defaults to true
  "permissionPromptTimeoutSeconds": 600, // Defaults to 10 minutes; 0 waits indefinitely
  "bashPathCheck": "tools",        // Bash pre-check: "strict" | "tools" (default) | "off"; see below
  "allowBrowserProcess": true,     // If you want to use agent-browser or similar Chrome setup
  "network": {
    "allowLocalBinding": true,     // ditto
    "allowAllUnixSockets": true,   // ditto
    "allowUnauthenticatedSocksProxy": true, // Enables Git-over-SSH on macOS
    "disabled": false,             // Set true for direct network access (no proxy/--unshare-net) while keeping filesystem sandboxing
    "allowSSHAgentSocket": true, // Allow the current SSH agent socket (macOS SSH commit signing)
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": []
  },
  "filesystem": {
    // For READS:
    // - ANY read is prompted unless the path is in allowRead or allowWrite
    // - Granting a prompt adds to allowRead, which overrides denyRead
    // - denyRead is not a hard-block; it just marks regions as denied by default
    "denyRead": ["/Users", "/home"],
    "allowRead": [".", "~/.config", "~/.local", "Library"],

    // For WRITES:
    // - allowWrite also grants read access to the same paths
    // - empty ALLOW means no write access at all
    // - DENY takes precedence and is never prompted
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", ".env.*", "*.pem", "*.key"]
  }
}
```

`bashPathCheck` sets how bash commands are checked before they run:

| Level | Behaviour |
|-------|-----------|
| `strict` | Every read outside `allowRead`/`allowWrite` prompts, including low-confidence words that don't exist; a low-confidence `/` or home directory blocks |
| `tools` (default) | High-confidence reads prompt; low-confidence words prompt only if they exist on disk; low-confidence `/` and home are ignored |
| `off` | No pre-check; the OS sandbox alone enforces the policy (credential `deny` files are still unreadable at the OS level) |

Filesystem patterns may reference environment variables with `${VAR}` syntax
(e.g. `"${HOME}/secrets"`) and a leading `~` is expanded to the home
directory; both are resolved when the config is loaded.

#### Usage

```
pi --no-sandbox                  disable sandboxing for the session
Alt+S                            toggle sandboxing on/off for the session
/sandbox                         show current configuration and session allowances
/sandbox-enable                  enable the sandbox for this session
/sandbox-disable                 disable the sandbox for this session
/sandbox-allow domain <url>      prompt to add a domain to allowedDomains
/sandbox-allow read <path>       prompt to add a path to allowRead
/sandbox-allow write <path>      prompt to add a path to allowWrite
```

With `enableAccessRequestTool: true`, the agent can use `sandbox_status` to inspect
current rules, including session-only grants, and `sandbox_request_access` to ask
for additional access with a reason. Already-allowed requests do not prompt.
Approvals return the actual rule and scope to the agent, including any edits you
make in the permission prompt.

## What it does

**Bash commands** are wrapped with `sandbox-exec` (macOS) or `bubblewrap`
(Linux) to enforce network and filesystem restrictions at the OS level. Commands
entered with `!` are sandboxed by default; set `sandboxUserShell` to `false` to
leave those commands unsandboxed.

**Read, write, and edit tool calls** are intercepted before execution and
checked against the same filesystem policy. The OS-level sandbox cannot cover
these tools because they run directly in the Node.js process rather than in a
subprocess.

When a block is triggered, a permission widget appears above the input editor with
four options. Concurrent requests are queued per extension instance. The widget
accepts input while the main Pi editor (including `CustomEditor` subclasses) has
focus; other dialogs keep their own keyboard input, and permission selection
resumes when they close. Operation cancellation, sandbox disable, and session
shutdown abort pending requests without granting access. The input draft is left
untouched.

Focus inspection uses Pi's `getFocusedComponent()` when available and the
`focusedComponent` instance field on Pi 0.80. If neither is available, the request
fails rather than intercepting input without knowing which dialog owns it.

Permission prompts automatically select **Abort (keep blocked)** after 10 minutes
by default. Set
`permissionPromptTimeoutSeconds` to a positive number to use a different timeout,
or set it to `0` to wait indefinitely. A timeout never grants permission.

- Abort (keep blocked)
- Allow for this session only
- Allow for this project — written to `.pi/sandbox.json`
- Allow for all projects — written to Pi's global agent directory (by default, `~/.pi/agent/sandbox.json`; respects `PI_CODING_AGENT_DIR`)

**Session allowances** are held in memory only. They are never written to disk
and the agent has no way to read or modify them. They are reset when the
extension reloads or pi restarts. Parent agents and subagents have separate
sandbox managers and session allowances; shutting down one does not affect another.

Saved project or global permission changes are not broadcast to other running
sessions' sandbox managers. Restart affected sessions to apply grants or revocations
consistently.

### What is prompted vs. hard-blocked

| Rule | Behaviour |
|------|-----------|
| Domain not in `allowedDomains` | Prompted (bash and `!cmd`, unless `sandboxUserShell` is disabled) |
| Path not in `allowRead` or `allowWrite` | Prompted (read tool); granting adds to `allowRead` |
| Path not in `allowWrite` | Prompted (write/edit tools) |
| Path in `denyWrite` | Hard-blocked, no prompt |
| Path in `credentials.files` (includes Pi's `auth.json` and `mcp-oauth/`) | Hard-blocked for read/write/edit and the bash pre-check, no prompt; `deny` entries are also unreadable from bash at the OS level |
| Path read by a bash command, not in `allowRead` or `allowWrite` | Prompted before the command runs (subject to `bashPathCheck`); granting adds to `allowRead` |
| Path written by a bash command, not in `allowWrite` | Not prompted; blocked by the OS sandbox |
| Path in `denyWrite` referenced by a bash command | Hard-blocked before the command runs, no prompt |
| `/` or the home directory | Never grantable from a prompt; read/write/edit and certain bash references are hard-blocked unless configured manually |
| Domain in `deniedDomains` | Hard-blocked at OS level, no prompt |

Bash filesystem errors do not identify whether a read, write, or execution was
blocked. In particular, `Operation not permitted` does not imply a write failure,
and `command not found` can mean an executable is unreadable inside the sandbox.
Use `/sandbox-allow read <path>` or `/sandbox-allow write <path>` after identifying
the required access, then rerun the command explicitly. Retrying automatically
could repeat side effects from commands that partially completed.

If a path is added to `allowWrite` via a prompt but is also present in
`denyWrite`, it remains blocked. A warning is shown explaining which config
files to check.

Bash commands are also scanned for candidate file paths (best-effort — only
tokens that already look like a path, e.g. `./`, `../`, `~/`, `${VAR}/`, or an
absolute path) before they run. A candidate matching `denyWrite` hard-blocks
the command; a candidate outside `allowRead`/`allowWrite` prompts before the
command runs, the same allow-list semantics as the read tool — this matters
because the OS sandbox only deny-lists reads, so paths outside `denyRead`
would otherwise be silently readable from bash. Expect prompts for system
paths a command merely mentions (`/usr/bin/...`, `/dev/null`, `/etc/...`);
grant them once with a broad rule or pre-add them to `allowRead`. `$VAR` and
`${VAR}` references in candidates are expanded from the environment; tokens
referencing unset variables are skipped and left to the OS sandbox backstop.
Filesystem entries without a leading `/` or `~` (e.g. `.env`, `*.pem`) are
matched using gitignore semantics relative to the working directory, the same
way they'd behave in a `.gitignore` file. Entries starting with `/` or `~` are
matched as absolute path prefixes or globs.

`allowedDomains` supports `*.example.com` wildcards. It also supports `"*"` to
allow all domains; pi-sandbox shows a warning when this is configured because it
removes per-domain prompts and can be easy to add accidentally. `allowWrite` uses prefix
matching, so `.` covers the entire current working directory. Write access also
implies read access; paths do not need to be repeated in `allowRead`.

`allowUnauthenticatedSocksProxy` is enabled by default on macOS so Git-over-SSH
works with the built-in `nc`. Domain filtering still applies, but another local process
that discovers the temporary proxy port can use it while the sandbox is running.

On macOS, set `"allowProcessSignals": true` in your **global** `sandbox.json`
(by default `~/.pi/agent/sandbox.json`) to let commands signal processes outside
their own sandbox, such as stopping a dev server started by an earlier command.
It is disabled by default and ignored in project-local configuration.
**Security warning:** this also permits signaling unrelated processes the user
has permission to signal, including terminating or suspending other applications
and agents. It is not limited to processes started by Pi. Linux and Windows
behavior is unchanged. Restart Pi after changing this setting; newly wrapped
commands get the permission, while existing processes keep their original policy.

`network.disabled` turns off network sandboxing entirely: no `--unshare-net` and
no proxy, so the sandboxed process gets direct network access via the host's
routing, DNS, and VPN. Filesystem sandboxing is unaffected. This is useful for
tools that don't honour `HTTP(S)_PROXY`/`ALL_PROXY`, mTLS/gRPC/WebSocket edge
cases, or local-network access. It is opt-in and reduces protection — `allowedDomains`
filtering no longer applies when set.

`allowSSHAgentSocket` is disabled by default. When enabled, pi-sandbox resolves
`SSH_AUTH_SOCK` to a real path when the sandbox is built and adds that path to
`allowUnixSockets` only if it is an existing Unix socket. This is intended for the
macOS system ssh-agent, whose path changes every boot and whose `/var` location is
a symlink to `/private/var`. Existing `allowUnixSockets` entries are kept. Prefer
this over allowing `/private/var/run` or setting `allowAllUnixSockets`. The option
has no effect when `SSH_AUTH_SOCK` is unset, missing, or not a socket. On Linux,
this setting alone does not make the SSH agent usable.

> **⚠️ Read and write have different precedence rules:**
>
> - **Read:** Every read is prompted unless the path is in `allowRead` or `allowWrite`.
>   `denyRead` is not a hard-block — it marks regions as denied by default, but
>   granting a prompt adds the path to `allowRead`, overriding `denyRead`.
> - **Write:** `denyWrite` takes precedence over `allowWrite` and is never
>   prompted. A path in `denyWrite` is always blocked, even if it matches
>   `allowWrite`.

If neither file configures an array, its built-in defaults apply (see above for
the defaults). Once an array is configured, only its combined global and local
entries are used, so an explicit empty array disables that default.

The footer shows a lock indicator while the sandbox is active, and `Sandbox: disabled` while it is off.

## Ackowledgements
Based on code from
[badlogic/pi-mono](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts)
by Mario Zechner, used under the
[MIT License](https://github.com/badlogic/pi-mono/blob/main/LICENSE).
