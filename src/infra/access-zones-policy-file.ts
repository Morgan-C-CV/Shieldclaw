import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import JSON5 from "json5";
import type { OpenClawConfig } from "../config/config.js";
import { resolveConfigPath, resolveStateDir } from "../config/paths.js";
import type { AccessZonesConfig } from "../config/types.security.js";
import { AccessZonesConfigSchema } from "../config/zod-schema.security.js";
import { resolveRequiredHomeDir } from "./home-dir.js";

export const ACCESS_ZONES_POLICY_FILENAME = "ACCESS_ZONES.md";

const DEFAULT_AGENT_ID = "main";

export function resolveAccessZonesPolicyPath(
  env: NodeJS.ProcessEnv = process.env,
  homedir: () => string = os.homedir,
): string {
  const stateDir = resolveStateDir(env, homedir);
  return path.join(
    path.dirname(resolveConfigPath(env, stateDir, homedir)),
    ACCESS_ZONES_POLICY_FILENAME,
  );
}

function resolveUserPath(input: string, env: NodeJS.ProcessEnv): string {
  if (input.startsWith("~/") || input === "~") {
    return path.resolve(resolveRequiredHomeDir(env, os.homedir), input.slice(2));
  }
  return path.resolve(input);
}

function resolveDefaultAccessZoneRoot(config: OpenClawConfig | undefined): string {
  const env = process.env;
  const agents = config?.agents;
  const entries = Array.isArray(agents?.list) ? agents.list : [];
  const defaultEntry = entries.find((entry) => entry?.default) ?? entries[0];
  const configuredWorkspace =
    defaultEntry?.workspace?.trim() || agents?.defaults?.workspace?.trim();
  if (configuredWorkspace) {
    return resolveUserPath(configuredWorkspace, env);
  }
  const home = resolveRequiredHomeDir(env, os.homedir);
  const profile = env.OPENCLAW_PROFILE?.trim();
  if (profile && profile.toLowerCase() !== "default") {
    return path.join(home, ".openclaw", `workspace-${profile}`);
  }
  return path.join(home, ".openclaw", "workspace");
}

function buildDefaultAccessZonesConfig(params: {
  config?: OpenClawConfig;
  defaultWorkspaceDir?: string;
}): AccessZonesConfig {
  const root = params.defaultWorkspaceDir
    ? path.resolve(params.defaultWorkspaceDir)
    : resolveDefaultAccessZoneRoot(params.config);
  return {
    enabled: true,
    enforce: true,
    logViolations: true,
    defaultMode: "deny",
    resolveSymlinks: true,
    zones: [
      {
        id: "default-workspace",
        kind: "filesystem",
        roots: [root],
        principals: {
          "runtime:agent": ["read", "write", "admin"],
          [`agent:${DEFAULT_AGENT_ID}`]: ["read", "write", "admin"],
        },
      },
    ],
  };
}

function formatAccessZonesPolicyMarkdown(config: AccessZonesConfig): string {
  return [
    "# OpenClaw Access Zones",
    "",
    "This file is user-managed. Agents must not edit it.",
    "",
    "Access Zones are intentionally stored outside `openclaw.json` so agent config",
    "writes cannot grant broader filesystem access.",
    "",
    "```json5",
    JSON.stringify(config, null, 2),
    "```",
    "",
  ].join("\n");
}

function extractPolicyPayload(raw: string): unknown {
  const fence = raw.match(/```(?:json5|json)?\s*\n([\s\S]*?)\n```/i);
  const payload = fence?.[1] ?? raw;
  return JSON5.parse(payload);
}

function normalizePolicyPayload(parsed: unknown): AccessZonesConfig {
  const candidate =
    parsed &&
    typeof parsed === "object" &&
    "accessZones" in parsed &&
    (parsed as { accessZones?: unknown }).accessZones
      ? (parsed as { accessZones: unknown }).accessZones
      : parsed;
  const result = AccessZonesConfigSchema.safeParse(candidate);
  if (!result.success) {
    const issue = result.error.issues[0];
    const issuePath = issue?.path.length ? issue.path.join(".") : "<root>";
    throw new Error(`Invalid Access Zones policy at ${issuePath}: ${issue?.message ?? "invalid"}`);
  }
  return result.data;
}

export function ensureAccessZonesPolicyFile(
  params: {
    config?: OpenClawConfig;
    defaultWorkspaceDir?: string;
  } = {},
): string {
  const policyPath = resolveAccessZonesPolicyPath();
  if (fs.existsSync(policyPath)) {
    return policyPath;
  }
  fs.mkdirSync(path.dirname(policyPath), { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") {
    try {
      fs.chmodSync(path.dirname(policyPath), 0o700);
    } catch {
      // Best-effort directory hardening only.
    }
  }
  fs.writeFileSync(
    policyPath,
    formatAccessZonesPolicyMarkdown(buildDefaultAccessZonesConfig(params)),
    {
      encoding: "utf-8",
      flag: "wx",
      mode: 0o600,
    },
  );
  return policyPath;
}

export function loadAccessZonesPolicy(
  params: {
    config?: OpenClawConfig;
    defaultWorkspaceDir?: string;
  } = {},
): AccessZonesConfig {
  const policyPath = ensureAccessZonesPolicyFile(params);
  return normalizePolicyPayload(extractPolicyPayload(fs.readFileSync(policyPath, "utf-8")));
}
