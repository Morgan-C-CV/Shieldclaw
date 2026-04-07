import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import { resolveAccessZonesPolicyPath } from "./access-zones-policy-file.js";
import {
  AccessZoneDeniedError,
  assertAuthorizedPathAccess,
  authorizePathAccess,
} from "./access-zones.js";

describe("access zones", () => {
  let tmpDir: string;
  let zoneRoot: string;
  let outsideRoot: string;
  let previousConfigPath: string | undefined;

  const makeConfig = (): OpenClawConfig => ({});

  async function writeAccessZonesPolicy(accessZones: Record<string, unknown>) {
    await fs.writeFile(
      resolveAccessZonesPolicyPath(),
      [
        "# OpenClaw Access Zones",
        "",
        "```json5",
        JSON.stringify(accessZones, null, 2),
        "```",
        "",
      ].join("\n"),
      "utf-8",
    );
  }

  beforeEach(async () => {
    previousConfigPath = process.env.OPENCLAW_CONFIG_PATH;
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-access-zones-"));
    zoneRoot = path.join(tmpDir, "zone");
    outsideRoot = path.join(tmpDir, "outside");
    await fs.mkdir(zoneRoot);
    await fs.mkdir(outsideRoot);
    process.env.OPENCLAW_CONFIG_PATH = path.join(tmpDir, "openclaw.json");
    await writeAccessZonesPolicy({
      enabled: true,
      zones: [
        {
          id: "workspace",
          kind: "filesystem",
          roots: [zoneRoot],
          principals: {
            "runtime:agent": ["read"],
            "agent:writer": ["read", "write"],
          },
        },
      ],
    });
  });

  afterEach(async () => {
    if (previousConfigPath === undefined) {
      delete process.env.OPENCLAW_CONFIG_PATH;
    } else {
      process.env.OPENCLAW_CONFIG_PATH = previousConfigPath;
    }
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("allows a principal action inside an authorized filesystem zone", async () => {
    const result = await authorizePathAccess({
      config: makeConfig(),
      action: "write",
      path: path.join(zoneRoot, "notes.txt"),
      principal: { agentId: "writer" },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.zoneId).toBe("workspace");
    }
  });

  it("hard-denies missing actions with a user authorization instruction", async () => {
    const result = await authorizePathAccess({
      config: makeConfig(),
      action: "write",
      path: path.join(zoneRoot, "notes.txt"),
      principal: { agentId: "reader" },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("ACCESS_ZONE_DENIED");
      expect(result.message).toContain('Action "write"');
      expect(result.message).toContain("Ask the user to grant access");
    }
  });

  it("hard-denies paths outside bound zone ids", async () => {
    await expect(
      assertAuthorizedPathAccess({
        config: makeConfig(),
        action: "read",
        path: path.join(outsideRoot, "secret.txt"),
        principal: { zoneIds: ["workspace"] },
      }),
    ).rejects.toMatchObject({
      code: "ACCESS_ZONE_DENIED",
      reason: "path is outside bound access zones (workspace)",
    } satisfies Partial<AccessZoneDeniedError>);
  });

  it("keeps legacy-allow compatible for unmatched paths", async () => {
    await writeAccessZonesPolicy({
      enabled: true,
      defaultMode: "legacy-allow",
      zones: [],
    });

    const result = await authorizePathAccess({
      config: makeConfig(),
      action: "read",
      path: path.join(outsideRoot, "legacy.txt"),
    });

    expect(result.ok).toBe(true);
  });

  it("blocks agent file-tool writes to the user-managed access zone policy file", async () => {
    const policyPath = resolveAccessZonesPolicyPath();

    const result = await authorizePathAccess({
      config: makeConfig(),
      action: "write",
      path: policyPath,
      principal: { agentId: "writer" },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("user-managed");
      expect(result.message).toContain("Ask the user to grant access");
    }
  });

  it("blocks agent writes through a symlink to the user-managed access zone policy file", async () => {
    await writeAccessZonesPolicy({
      enabled: true,
      enforce: false,
      zones: [
        {
          id: "workspace",
          kind: "filesystem",
          roots: [zoneRoot],
          principals: {
            "agent:writer": ["read", "write"],
          },
        },
      ],
    });
    const policyLink = path.join(zoneRoot, "policy-link.md");
    await fs.symlink(resolveAccessZonesPolicyPath(), policyLink);

    const result = await authorizePathAccess({
      config: makeConfig(),
      action: "write",
      path: policyLink,
      principal: { agentId: "writer" },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("user-managed");
    }
  });

  it("creates a default workspace-only policy when missing", async () => {
    await fs.rm(resolveAccessZonesPolicyPath(), { force: true });
    const workspaceDir = path.join(tmpDir, "default-workspace");
    const result = await authorizePathAccess({
      config: {
        agents: { defaults: { workspace: workspaceDir } },
      } as OpenClawConfig,
      action: "read",
      path: path.join(outsideRoot, "secret.txt"),
    });

    expect(result.ok).toBe(false);
    await expect(fs.readFile(resolveAccessZonesPolicyPath(), "utf-8")).resolves.toContain(
      workspaceDir,
    );
  });
});
