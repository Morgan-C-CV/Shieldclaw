# PLAN: Access Zones implementation in Safeclaw

Status: draft
Date: 2026-04-07

## Goal

Implement path-scoped resource authorization (Access Zones) in Safeclaw so filesystem access is restricted by authorized roots and principals, instead of relying only on broad operator scopes.

## User intent

- Reduce the effective breadth of current read capability.
- Make workspace isolation real.
- Move toward IDE-like scoped access (specific areas get read/write/admin), not global read.

## High-level rollout

1. Add config schema for `security.accessZones`
2. Add centralized authorization helper for path access
3. Enforce on file tools first (`read` / `write` / `edit`)
4. Bind sessions/subagents to zones
5. Restrict exec by zone-aware workdir as a later phase

## Working assumptions

- Keep existing operator scopes for control-plane authorization.
- Add a second layer for resource-plane authorization.
- MVP should support filesystem zones only.
- Migration should support legacy-allow / audit-first mode.

## Files / areas to inspect next

### Config and schema

- src/config/types.ts
- src/config/types.openclaw.ts
- src/config/schema.ts
- src/config/runtime-schema.ts
- src/config/zod-schema.ts
- src/config/zod-schema.core.ts
- src/config/zod-schema.session.ts

### Session / session metadata / subagent binding

- src/config/sessions/types.ts
- src/config/sessions/metadata.ts
- src/config/sessions/targets.ts
- src/config/sessions/\*
- session creation / subagent spawn implementation (exact files to identify)

### Existing security / allowlist / path-related infra

- src/infra/exec-approvals-allowlist.ts
- src/infra/system-run-approval-binding.ts
- any shared path normalization / root checking helpers

### File tools / path-taking tools

- locate concrete implementation files for read / write / edit
- locate any shared tool path wrappers

### Method / permission context

- method scope definitions only for compatibility understanding; main implementation should happen at resource authorization layer

## Output needed from next pass

- exact file list to modify
- what each file is responsible for
- recommended new module(s)
- MVP implementation order
- test strategy and migration notes

## Concrete implementation checklist (v2)

### A. Config and schema layer

#### Files to modify

- `src/config/types.ts`
- `src/config/schema.ts`
- `src/config/runtime-schema.ts`
- `src/config/zod-schema.ts`
- `src/config/zod-schema.core.ts`
- likely also `src/config/types.openclaw.ts`
- likely also `src/config/zod-schema.session.ts`

#### Purpose

Add first-class config for `security.accessZones`.

#### Draft config shape

- `enabled: boolean`
- `enforce: boolean`
- `logViolations: boolean`
- `defaultMode: "deny" | "legacy-allow"`
- `resolveSymlinks: boolean`
- `zones: AccessZone[]`

#### Draft zone shape

- `id: string`
- `kind: "filesystem"`
- `roots: string[]`
- `principals: Record<string, ("read" | "write" | "admin")[]>`

#### Notes

- Keep this additive; do not redefine existing operator scopes.
- Runtime schema must expose these values so session/tool code can consume them without raw config parsing.

### B. Central authorization layer

#### New file to add

- `src/infra/access-zones.ts`

#### Purpose

Centralize principal-aware path authorization.

#### Planned responsibilities

- resolve principal for current session/tool call
- read access-zone config from runtime snapshot
- map requested action (`read` / `write` / `admin`) to zone permission
- select matching zone(s)
- delegate root containment and escape prevention to existing boundary helpers
- return structured allow/deny results

#### Suggested API surface

- `authorizePathAccess(...)`
- `resolvePrincipalForSession(...)`
- `resolveZonesForPrincipal(...)`

#### Important design rule

Do **not** move all logic into `boundary-path.ts`.

- `boundary-path.ts` should remain a root-containment primitive.
- `access-zones.ts` should become the policy layer that chooses which root(s) are valid for a principal.

### C. Existing boundary/path infrastructure to reuse

#### Files already identified

- `src/infra/boundary-path.ts`
- `src/infra/boundary-file-read.ts`
- `src/infra/fs-safe.ts`
- `src/infra/fs-pinned-write-helper.ts`
- `src/infra/path-alias-guards.ts`
- `src/infra/hardlink-guards.ts`

#### Why these matter

These files already implement the hard parts of path safety:

- canonicalization
- boundary containment
- symlink escape detection
- hardlink guard behavior
- safe file open / safe write helpers

#### Planned approach

Reuse them as building blocks under Access Zones rather than replacing them.

### D. File-tool enforcement layer

#### Target capability scope for MVP

- `read`
- `write`
- `edit`

#### Likely integration points

- direct file tool handlers once located precisely
- shared file IO helpers already identified:
  - `src/infra/boundary-file-read.ts`
  - `src/infra/fs-safe.ts`
  - `src/infra/fs-pinned-write-helper.ts`

#### Planned enforcement rule

Before any file IO is performed:

1. resolve session/device/agent principal
2. authorize requested action against Access Zones
3. verify path stays inside matched zone root using boundary helpers
4. proceed only on success

#### Goal

Prevent broad control-plane read permission from turning into broad filesystem visibility.

### E. Session / subagent zone binding

#### Files to modify / inspect further

- `src/agents/tools/sessions-spawn-tool.ts`
- `src/config/sessions/types.ts`
- `src/config/sessions/metadata.ts`
- `src/config/sessions/targets.ts`
- related session creation implementation files still to pinpoint

#### Why this is a key entry point

`sessions-spawn-tool.ts` already supports `cwd`, making it the cleanest place to infer or bind Access Zones for spawned sessions/subagents.

#### Planned model

Add session-level zone context, preferably:

- `zoneIds?: string[]`

Prefer zone IDs over raw roots to keep policy centralized.

#### Suggested binding precedence

1. explicit `zoneIds`
2. infer from `cwd`
3. inherit from parent session
4. deny (strict mode) or warn+allow (legacy mode)

### F. Exec integration ✅ Implemented

#### Relevant files

- `src/node-host/invoke-system-run.ts` — `enforceExecAccessZone()` added
- `src/node-host/invoke-system-run.test.ts` — 3 new tests

#### Implementation

- Added `enforceExecAccessZone()` helper that calls `authorizePathAccess()` with `action: "write"` on the effective cwd before any allowlist/policy evaluation.
- If no explicit cwd is provided, falls back to `process.cwd()`.
- Denied reason is `"access-zone-denied"` with a descriptive `SYSTEM_RUN_DENIED:` message.
- Existing exec approval/sandbox controls remain unchanged.
- Full shell/path analysis is NOT attempted — only `workdir` is checked.

#### Tests

- Denies exec when cwd is outside authorized zones (enforce + deny mode).
- Allows exec when cwd is inside an authorized zone.
- Allows exec in `legacy-allow` mode for unmatched paths.

### G. Implementation order

1. Add config types + schema for `security.accessZones`
2. Add `src/infra/access-zones.ts`
3. Hook Access Zones into file read/write/edit paths
4. Add zone context to session/subagent creation
5. Add audit logs / legacy-compatible migration behavior
6. Add optional exec workdir restriction as phase 2

### H. Secondary checks still needed in next pass

- locate the exact final handlers for `read` / `write` / `edit`
- identify the exact session store / runtime metadata write path for attaching `zoneIds`
- verify whether `fs-safe.ts` is already the common chokepoint for file mutations
- verify whether file read paths consistently route through `boundary-file-read.ts`

### I. Initial test plan

#### New/updated test areas

- config schema validation tests for `security.accessZones`
- unit tests for `access-zones.ts`
- boundary integration tests for allowed/denied zone reads
- boundary integration tests for allowed/denied zone writes
- session spawn tests for `cwd -> zone` inference
- session inheritance tests for child sessions/subagents
- legacy-allow mode tests

#### Specific security cases to cover

- `..` traversal
- symlink escape out of zone root
- hardlink edge behavior (document or enforce)
- overlapping roots / most-specific zone selection
- unmatched path in strict deny mode

## Constraints

- Do not start by redesigning pairing scopes.
- Do not start by changing operator.read semantics at protocol level.
- Focus first on path/resource enforcement.
