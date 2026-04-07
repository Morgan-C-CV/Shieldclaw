# 🛡️ ShieldClaw — Secure Fork of OpenClaw

ShieldClaw is a focused fork of OpenClaw that exists solely to harden its agent sandbox configuration for environments where a fully trusted CLI can’t be assumed. While the upstream project works through feature and security evolution, ShieldClaw permanently keeps the CLI name, identity, and docs aligned with the security guardrails this fork imposes.

## Why this fork exists

During routine security work we discovered that the OpenClaw CLI profiles could be launched without any configuration that would constrain the file system surface. In particular:

- Access Zones (/security access zones / path-based allowlisten) were defined only inside `openclaw.json`, which meant per-profile or per-session JSON parsing could simply omit them; `node scripts/run-node.mjs --profile safeclaw-test tui` ran with `security.accessZones.enabled` defaulting to `false`, so `pi-tools.read`, `pi-tools.write`, and other helpers were allowed to read/write anywhere the host OS permitted.
- The default `tools.fs.workspaceOnly` guard is `false`, so any `shieldclaw`-style run invoked a tool that could read `/Users/**` (or `/root` on Linux) without restriction if the profile did not turn `workspaceOnly` on.
- The only place Access Zones lived was the agent’s configuration JSON file, which meant an attacker with workspace write permission could rewrite `security.accessZones` and disable enforcement.

These gaps meant an agent (main or spawned subagent) could escalate from the workspace into the rest of the user’s home directory and exfiltrate files just by invoking the bundled read/write tools. That’s unacceptable when the CLI is meant to keep end-user data local.

## What ShieldClaw enforces

ShieldClaw reworks the configuration so the allowlist can no longer be tampered with by the agent tooling:

1. The Access Zones policy now lives in an `ACCESS_ZONES.md` located next to the `openclaw.json` file (parent directory of that config). Because the policy file is owned by the CLI runtime, the agent tooling runs with a strict workspace-only scope by default, and no tool can write back to `ACCESS_ZONES.md` even if it has `write` privileges elsewhere.
2. The default policy is “workspace-only” with `enforce: true`, `defaultMode: "deny"`, and `roots` locked to the workspace directory, so launching `shieldclaw` without touching your config already prevents arbitrary host reads.
3. `ACCESS_ZONES.md` is created during initialization with symlink-aware canonicalization so symlink attacks can’t escape the root, and the file is governed by `chmod` semantics that the tools cannot override.
4. The agent tooling now refuses to touch host files unless the policy explicitly lists them and the principal has the right scope. The `pi-tools` helpers, `apply-patch`, and workspace-specific subagent launcher all check `authorizePathAccess` again the Access Zones data before any IO operation occurs.

You still get the same CLI surface (`shieldclaw gateway`, `shieldclaw onboard`, `shieldclaw agent ...`, etc.), but the runtime operating as ShieldClaw never ships without these defenses.

## Upstream coordination

The issue should be shared with the upstream OpenClaw maintainers so the same safeguards can eventually land there. Until that report is public, treat ShieldClaw’s README and commit history as the canonical description of the exploit path, remediation plan, and fixes carried in this branch.

## Installing and running

Install or update the CLI via npm/pnpm/bun:

```bash
npm install -g shieldclaw@latest
# or
pnpm add -g shieldclaw@latest
# or
bunx https://github.com/wangmorgan/shieldclaw
```

Run onboarding:

```bash
shieldclaw onboard --install-daemon
shieldclaw gateway --serve
shieldclaw dashboard
```

ShieldClaw reuses the OpenClaw RPC runtime under the hood, so you can pair the CLI with existing companion apps and channel plugins. Configuration still lives in `~/.openclaw/openclaw.json`, but the Access Zones policy is decoupled into `ACCESS_ZONES.md` as described above.

## Contributing

Submit PRs to the `wangmorgan/shieldclaw` repository. ShieldClaw only accepts patches that preserve the Access Zones guardrails or improve documentation around their usage. If you believe you’ve found a new issue in the policy, update `ACCESS_ZONES.md`, add tests in `src/infra`, and link the upstream OpenClaw report once one exists so maintainers can follow along.

## License

ShieldClaw is still MIT-licensed. The `LICENSE` file in this repo (credit: Peter Steinberger and the original OpenClaw authors) must appear in any redistribution.
