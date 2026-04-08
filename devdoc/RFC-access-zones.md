# RFC: Access Zones — Path-Scoped Read/Write/Admin Isolation for OpenClaw

- Status: Draft
- Author: Lucas
- Date: 2026-04-07
- Target: OpenClaw

## Summary

OpenClaw's current permission model is effective for **control-plane authorization** (for example: who can read status, create sessions, approve pairing, or modify config), but it is too coarse for **resource-plane isolation**.

In particular, `operator.read` is currently too broad in practical effect. Without path-scoped enforcement, a principal that can read may be able to read far more of the host filesystem than intended. This creates unnecessary leakage risk for:

- secrets and tokens
- SSH keys
- unrelated workspaces
- memory files belonging to other agents
- user-private files outside the intended workspace

This RFC proposes **Access Zones**: a path-scoped authorization layer that restricts filesystem access by **zone roots + per-principal permissions**. This makes workspace isolation real instead of advisory.

---

## Problem

### Current model

OpenClaw today primarily expresses permissions through operator scopes such as:

- `operator.read`
- `operator.write`
- `operator.admin`
- `operator.approvals`
- `operator.pairing`
- `operator.talk.secrets`

These are appropriate for control-plane decisions such as:

- can this caller inspect gateway state?
- can this caller create or steer sessions?
- can this caller approve pairing requests?
- can this caller modify config?

However, they do **not** directly answer:

- which files can this agent read?
- which directories can this session write to?
- can this subagent access another workspace?
- is “independent workspace” a real security boundary or only a convention?

### Security gap

If tool-layer path access is not constrained, then `operator.read` can degrade into something close to **global filesystem read**.

That creates avoidable risk:

- a low-privilege principal can read secrets outside the intended workspace
- one agent can inspect another agent’s memory or files
- “workspace separation” is not a reliable isolation boundary
- sensitive local files become reachable by accident or prompt injection

### Core issue

OpenClaw currently answers **“what methods may be called?”** more strongly than **“what resources may be touched?”**.

For multi-agent, multi-workspace, and least-privilege deployments, that is the wrong layer to rely on exclusively.

---

## Goals

1. Introduce **path-scoped authorization** for filesystem access.
2. Make workspace isolation a **hard boundary**, not a soft convention.
3. Preserve the current operator-scope model for control-plane checks.
4. Require both:
   - control-plane permission to invoke a tool or method, and
   - resource-plane permission to access a target path.
5. Support progressive rollout with audit-only and legacy-compatible modes.

---

## Non-Goals

This RFC does not attempt to solve, in its first version:

- full network egress policy isolation
- secret storage redesign
- full OS-level sandbox replacement
- static shell command path analysis
- memory isolation across all subsystems

These can be layered later.

---

## Design Overview

This RFC introduces a second authorization layer: **Access Zones**.

### Layer 1: Control-plane authorization

Existing operator scopes remain in place:

- `operator.read`
- `operator.write`
- `operator.admin`
- `operator.approvals`
- `operator.pairing`
- `operator.talk.secrets`

These continue to answer:

- can the caller invoke this RPC/method?
- can the caller create/steer sessions?
- can the caller approve pairing?
- can the caller edit config?

### Layer 2: Resource-plane authorization

Access Zones answer:

- can this principal read this path?
- can this principal write this path?
- is this path inside an authorized root?

This layer is based on:

- zone roots (absolute filesystem roots)
- principal identity
- per-zone permission sets (`read`, `write`, `admin`)

The two layers are both required.

A tool being callable does **not** imply unrestricted file access.

---

## Access Zone Model

### Zone definition

An Access Zone defines:

- a stable `id`
- a `kind` (initially `filesystem` only)
- one or more absolute `roots`
- a mapping from principals to allowed actions

### Initial zone actions

- `read`
- `write`
- `admin`

These are **zone-local** actions, not global operator scopes.

For example:

- `operator.admin` = control-plane admin
- `zone admin` = admin over resources inside one zone

These must remain distinct concepts.

---

## Configuration Schema (Draft)

```json5
{
  security: {
    accessZones: {
      enabled: true,
      defaultMode: "deny", // deny | legacy-allow
      resolveSymlinks: true,
      zones: [
        {
          id: "workspace-main",
          kind: "filesystem",
          roots: ["/Users/wangmorgan/.openclaw/workspace"],
          principals: {
            "agent:main": ["read", "write", "admin"],
            "device:local-cli": ["read"],
          },
        },
        {
          id: "workspace-apeey",
          kind: "filesystem",
          roots: ["/Users/wangmorgan/.openclaw/workspace_Apeey"],
          principals: {
            "agent:apeey": ["read", "write", "admin"],
            "device:local-cli": ["read", "write"],
          },
        },
      ],
    },
  },
}
```

### Field notes

#### `enabled`

Turns Access Zones on/off.

#### `defaultMode`

- `deny`: any path outside authorized zones is denied.
- `legacy-allow`: if no zone matches, preserve legacy behavior. Useful for migration.

#### `resolveSymlinks`

When true, evaluate access using canonical real paths. This should be the secure default.

#### `zones[].kind`

MVP supports:

- `filesystem`

Future extensions may include:

- `memory`
- `secrets`
- `network`

#### `zones[].roots`

Absolute directory roots that define the authorized subtree.

#### `zones[].principals`

Maps principals to allowed actions.

---

## Principals

Principals are the subjects that receive zone access.

Examples:

- `agent:main`
- `agent:apeey`
- `session:agent:main:main`
- `device:<deviceId>`
- `runtime:subagent`

### Resolution order

Recommended order:

1. session principal
2. agent principal
3. device principal
4. runtime principal
5. fallback anonymous principal

This ensures explicit bindings override broad defaults.

---

## Permission Semantics

### `read`

Allows:

- file reads
- directory listing
- stat / metadata access
- text/image reads
- search rooted within the zone

Does not allow:

- file modification
- deletion
- rename
- zone escape via symlink/path traversal

### `write`

Allows:

- file creation
- file modification
- deletion
- rename
- directory creation inside zone roots

Does not imply:

- global config mutation
- cross-zone moves
- control-plane admin actions

### `admin`

Zone-local admin for the resource area.

Potential future use:

- zone metadata maintenance
- privileged maintenance operations inside a zone
- optional zone-bound exec authority

This is intentionally distinct from `operator.admin`.

---

## Enforcement Points

### 1. File tools

The first required enforcement targets are:

- `read`
- `write`
- `edit`

All path-taking file tools must:

1. normalize path
2. resolve `..`
3. compute canonical real path (when configured)
4. verify the path falls under an authorized root
5. verify the principal has sufficient zone permission

### 2. Search tools

Any search functionality backed by the filesystem must be rooted inside allowed zones only.

Examples:

- grep-like wrappers
- recursive file listing
- project search

### 3. Session spawn / subagents

Subagents and new sessions must become zone-aware.

Recommended rule:

- every spawned session is either explicitly bound to one or more zone IDs, or
- implicitly bound by its `cwd` if that `cwd` resolves into an allowed zone

Without a zone binding, the session should either:

- fail closed, or
- run only in `legacy-allow` migration mode

### 4. ACP harness sessions

ACP-bound sessions should inherit or declare their allowed zones explicitly.

### 5. Exec

`exec` is high-risk and should not be fully trusted based only on a directory allowlist.

For MVP, only partial support is recommended:

- require `workdir` to be inside an allowed zone
- continue relying on existing sandbox/exec policy for command safety
- do **not** claim that shell argument path analysis is complete

A future stronger model may add zone-bound exec capability with tighter guarantees.

---

## Internal Authorization API

Introduce a single internal gate:

```ts
authorizePathAccess({
  principal,
  action, // "read" | "write" | "admin"
  path,
  followSymlinks: true,
});
```

Suggested return value:

```ts
{
  ok: boolean,
  zoneId?: string,
  reason?: string,
}
```

Supporting helpers:

```ts
resolvePrincipalForSession(session);
resolveZonesForPrincipal(principal);
```

This keeps authorization logic centralized and testable.

---

## Session Binding Model

### Proposed behavior

When a session or subagent is created:

- infer zones from `cwd`, or
- accept explicit `zoneIds`, or
- inherit zones from parent session

Recommended precedence:

1. explicit session `zoneIds`
2. parent session inheritance
3. `cwd`-derived zone inference
4. deny / legacy fallback

### Why this matters

This turns “independent workspace” into a real isolation boundary.

A child session bound to `workspace_Apeey` must not be able to read `workspace` unless explicitly granted.

---

## Security Details

### Path normalization

Every path check must account for:

- `path.resolve`
- `..` traversal
- trailing slash normalization
- platform-specific path behavior

### Symlink handling

This is mandatory.

The system must defend against:

- symlink inside zone pointing outside zone
- nested symlink escapes
- relative symlink traversal

Recommended rule:

- validate access against the final canonical real path
- canonicalize zone roots too

### Hard links

Hard-link edge cases may remain out of scope for MVP, but should be documented as a limitation if not fully addressed.

### Cross-zone rename/move

Cross-zone operations should be rejected unless explicitly supported and both sides authorize the action.

---

## Relationship to Existing Operator Scopes

This RFC is additive, not a replacement.

### Example

To read a file successfully, both must be true:

1. the tool invocation is allowed by control-plane authorization
2. the path is allowed by Access Zones

So:

- `operator.read` means “may invoke read-capable operations”
- zone `read` means “may read this path subtree”

Both are required.

This prevents a broad control-plane permission from silently becoming broad filesystem visibility.

---

## Migration Plan

### Phase 0: Audit mode

Support audit-only rollout:

```json5
{
  security: {
    accessZones: {
      enabled: true,
      enforce: false,
      logViolations: true,
      defaultMode: "legacy-allow",
    },
  },
}
```

Behavior:

- do not block yet
- log out-of-zone reads/writes
- help users observe current implicit access patterns

### Phase 1: Enforce on file tools

Enable hard checks for:

- `read`
- `write`
- `edit`

### Phase 2: Bind sessions/subagents to zones

Require new sessions and subagents to carry zone context.

### Phase 3: Restrict exec working directory

Require `exec.workdir` to stay within authorized zones.

### Phase 4: Tighten defaults

For new installs, make `defaultMode: "deny"` the recommended default.

---

## Backward Compatibility

### `legacy-allow`

Migration-friendly mode keeps existing deployments running while emitting warnings.

### Auto-generated default zone

For single-workspace users, OpenClaw may auto-suggest or auto-generate:

```json5
{
  id: "default-workspace",
  kind: "filesystem",
  roots: ["<agents.defaults.workspace>"],
  principals: {
    "agent:<default>": ["read", "write", "admin"],
  },
}
```

This minimizes migration friction.

---

## MVP Scope

### Include in MVP

1. `security.accessZones` config
2. centralized path authorization API
3. enforcement for `read`, `write`, `edit`
4. session/subagent zone binding
5. audit mode + logging
6. legacy-compatible migration mode

### Exclude from MVP

1. full shell argument path analysis
2. memory zones
3. secrets zones
4. network zones
5. complete hard-link handling

---

## Expected Benefits

### Security

- reduces filesystem overexposure
- makes workspace isolation real
- lowers accidental secret leakage
- improves multi-agent safety

### Product

- matches user mental model (“this agent can only access this workspace”)
- feels more like an IDE/workspace sandbox
- makes permissions easier to explain
- improves trust in independent workspaces

### Architecture

- creates a clean base for later resource-scoped policy
- prepares OpenClaw for multi-agent and multi-tenant growth

---

## Open Questions

1. Should zone permissions attach primarily to agents, sessions, devices, or all three?
2. Should session creation require explicit zone binding in strict mode?
3. Should `exec` remain outside Access Zones initially, or should `workdir` checks be part of MVP?
4. How should zone policy interact with future sandbox modes?
5. Should OpenClaw expose zone information in `/status` or session metadata for debugging?

---

## Recommendation

Proceed with an MVP implementation focused on:

- filesystem zones only
- file tool enforcement first
- zone-aware session/subagent binding
- audit-first migration mode

This solves the highest-priority risk: the gap between broad control-plane `read` and the need for **resource-scoped least privilege**.

---

## One-Line Conclusion

OpenClaw currently controls **what a caller may do** more strongly than **what a caller may touch**. Access Zones add the missing resource boundary so `read/write/admin` can become path-scoped, least-privilege, and workspace-realistic.
