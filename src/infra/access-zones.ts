import fs from "node:fs";
import path from "node:path";
import type { OpenClawConfig } from "../config/config.js";
import { resolveConfigPath } from "../config/paths.js";
import type { AccessZone, AccessZoneAction, AccessZonesConfig } from "../config/types.security.js";
import { logWarn } from "../logger.js";
import { normalizeAgentId, parseAgentSessionKey } from "../routing/session-key.js";
import { loadAccessZonesPolicy, resolveAccessZonesPolicyPath } from "./access-zones-policy-file.js";
import { resolveBoundaryPath } from "./boundary-path.js";
import { isPathInside } from "./path-guards.js";

export type AccessZonePrincipalContext = {
  sessionKey?: string;
  agentId?: string;
  zoneIds?: string[];
};

export type AccessZoneAuthorizationResult =
  | { ok: true; zoneId?: string; rootPath?: string; canonicalPath?: string }
  | {
      ok: false;
      code: "ACCESS_ZONE_DISABLED" | "ACCESS_ZONE_DENIED";
      reason: string;
      message: string;
      principalCandidates: string[];
      action: AccessZoneAction;
      path: string;
      zoneId?: string;
    };

export class AccessZoneDeniedError extends Error {
  readonly code = "ACCESS_ZONE_DENIED";
  readonly reason: string;
  readonly action: AccessZoneAction;
  readonly pathValue: string;
  readonly zoneId?: string;

  constructor(denial: Extract<AccessZoneAuthorizationResult, { ok: false }>) {
    super(denial.message);
    this.name = "AccessZoneDeniedError";
    this.reason = denial.reason;
    this.action = denial.action;
    this.pathValue = denial.path;
    this.zoneId = denial.zoneId;
  }
}

function getAccessZonesConfig(params?: {
  config?: OpenClawConfig;
  defaultWorkspaceDir?: string;
}): AccessZonesConfig | undefined {
  return loadAccessZonesPolicy(params);
}

export function isAccessZonesEnabled(config?: OpenClawConfig): boolean {
  return getAccessZonesConfig({ config })?.enabled === true;
}

function shouldEnforce(config?: AccessZonesConfig): boolean {
  return config?.enforce !== false;
}

function getDefaultMode(config?: AccessZonesConfig): "deny" | "legacy-allow" {
  return config?.defaultMode === "legacy-allow" ? "legacy-allow" : "deny";
}

function getResolveSymlinks(config?: AccessZonesConfig): boolean {
  return config?.resolveSymlinks !== false;
}

function normalizeZoneIds(zoneIds?: string[]): Set<string> | undefined {
  const normalized = (zoneIds ?? []).map((id) => id.trim()).filter(Boolean);
  return normalized.length > 0 ? new Set(normalized) : undefined;
}

export function resolveAccessZonePrincipalCandidates(
  context?: AccessZonePrincipalContext,
): string[] {
  const values: string[] = [];
  const sessionKey = context?.sessionKey?.trim();
  if (sessionKey) {
    values.push(`session:${sessionKey}`);
  }
  const parsedAgentId = sessionKey ? parseAgentSessionKey(sessionKey)?.agentId : undefined;
  const agentId = context?.agentId?.trim() || parsedAgentId;
  if (agentId) {
    values.push(`agent:${normalizeAgentId(agentId)}`);
  }
  values.push("runtime:agent", "anonymous");
  return Array.from(new Set(values));
}

function hasZoneAction(
  zone: AccessZone,
  principals: readonly string[],
  action: AccessZoneAction,
): boolean {
  return principals.some((principal) => Boolean(zone.principals[principal]?.includes(action)));
}

async function resolvePathForZone(params: {
  zone: AccessZone;
  rootPath: string;
  absolutePath: string;
  action: AccessZoneAction;
  resolveSymlinks: boolean;
}): Promise<{ ok: true; canonicalPath: string } | { ok: false; reason: string }> {
  if (params.resolveSymlinks) {
    try {
      const resolved = await resolveBoundaryPath({
        absolutePath: params.absolutePath,
        rootPath: params.rootPath,
        boundaryLabel: `access zone ${params.zone.id}`,
        intent: params.action === "read" ? "read" : "write",
      });
      return { ok: true, canonicalPath: resolved.canonicalPath };
    } catch (error) {
      return {
        ok: false,
        reason: error instanceof Error ? error.message : "path is outside access zone",
      };
    }
  }

  const root = path.resolve(params.rootPath);
  const target = path.resolve(params.absolutePath);
  if (!isPathInside(root, target)) {
    return { ok: false, reason: "path is outside access zone root" };
  }
  return { ok: true, canonicalPath: target };
}

function buildDenial(params: {
  reason: string;
  action: AccessZoneAction;
  absolutePath: string;
  principals: string[];
  zoneId?: string;
}): Extract<AccessZoneAuthorizationResult, { ok: false }> {
  const principalText = params.principals.join(", ");
  const message =
    `ACCESS_ZONE_DENIED: ${params.reason}. ` +
    `Action "${params.action}" on "${params.absolutePath}" is not authorized for ${principalText}. ` +
    `Ask the user to grant access by updating ${resolveAccessZonesPolicyPath()}.`;
  return {
    ok: false,
    code: "ACCESS_ZONE_DENIED",
    reason: params.reason,
    message,
    principalCandidates: params.principals,
    action: params.action,
    path: params.absolutePath,
    zoneId: params.zoneId,
  };
}

function isProtectedAccessZonesConfigWrite(params: {
  absolutePath: string;
  action: AccessZoneAction;
}): boolean {
  if (params.action === "read") {
    return false;
  }
  const resolved = path.resolve(params.absolutePath);
  const targetRealPath = resolveExistingRealPath(resolved);
  const configRealPath = resolveExistingRealPath(resolveConfigPath());
  const policyRealPath = resolveExistingRealPath(resolveAccessZonesPolicyPath());
  return (
    resolved === path.resolve(resolveConfigPath()) ||
    resolved === path.resolve(resolveAccessZonesPolicyPath()) ||
    (targetRealPath !== undefined && targetRealPath === configRealPath) ||
    (targetRealPath !== undefined && targetRealPath === policyRealPath)
  );
}

function resolveExistingRealPath(filePath: string): string | undefined {
  try {
    return fs.realpathSync.native(filePath);
  } catch {
    return undefined;
  }
}

function maybeLogViolation(
  config: AccessZonesConfig | undefined,
  denial: Extract<AccessZoneAuthorizationResult, { ok: false }>,
): void {
  if (config?.logViolations === true) {
    logWarn(denial.message);
  }
}

export async function authorizePathAccess(params: {
  config?: OpenClawConfig;
  action: AccessZoneAction;
  path: string;
  defaultWorkspaceDir?: string;
  principal?: AccessZonePrincipalContext;
}): Promise<AccessZoneAuthorizationResult> {
  const accessZones = getAccessZonesConfig({
    config: params.config,
    defaultWorkspaceDir: params.defaultWorkspaceDir,
  });
  const principals = resolveAccessZonePrincipalCandidates(params.principal);
  const absolutePath = path.resolve(params.path);

  if (isProtectedAccessZonesConfigWrite({ absolutePath, action: params.action })) {
    const denial = buildDenial({
      reason: "Access Zones policy is user-managed and cannot be modified by agent file tools",
      action: params.action,
      absolutePath,
      principals,
    });
    maybeLogViolation(accessZones, denial);
    return denial;
  }

  if (accessZones?.enabled !== true) {
    return { ok: true };
  }

  const allowedZoneIds = normalizeZoneIds(params.principal?.zoneIds);
  const zones = accessZones.zones ?? [];
  let deniedWithinZone:
    | { zone: AccessZone; rootPath: string; canonicalPath: string; reason: string }
    | undefined;
  let lastPathReason: string | undefined;

  for (const zone of zones) {
    if (zone.kind !== "filesystem") {
      continue;
    }
    if (allowedZoneIds && !allowedZoneIds.has(zone.id)) {
      continue;
    }
    for (const rootPath of zone.roots) {
      const resolved = await resolvePathForZone({
        zone,
        rootPath,
        absolutePath,
        action: params.action,
        resolveSymlinks: getResolveSymlinks(accessZones),
      });
      if (!resolved.ok) {
        lastPathReason = resolved.reason;
        continue;
      }
      if (!hasZoneAction(zone, principals, params.action)) {
        deniedWithinZone = {
          zone,
          rootPath,
          canonicalPath: resolved.canonicalPath,
          reason: `principal lacks "${params.action}" permission in zone "${zone.id}"`,
        };
        continue;
      }
      return {
        ok: true,
        zoneId: zone.id,
        rootPath,
        canonicalPath: resolved.canonicalPath,
      };
    }
  }

  if (getDefaultMode(accessZones) === "legacy-allow" && !deniedWithinZone) {
    return { ok: true };
  }

  const denial = deniedWithinZone
    ? buildDenial({
        reason: deniedWithinZone.reason,
        action: params.action,
        absolutePath,
        principals,
        zoneId: deniedWithinZone.zone.id,
      })
    : buildDenial({
        reason: allowedZoneIds
          ? `path is outside bound access zones (${Array.from(allowedZoneIds).join(", ")})`
          : lastPathReason || "path does not match any authorized access zone",
        action: params.action,
        absolutePath,
        principals,
      });
  maybeLogViolation(accessZones, denial);
  return shouldEnforce(accessZones) ? denial : { ok: true };
}

export async function assertAuthorizedPathAccess(
  params: Parameters<typeof authorizePathAccess>[0],
): Promise<Extract<AccessZoneAuthorizationResult, { ok: true }>> {
  const result = await authorizePathAccess(params);
  if (!result.ok) {
    throw new AccessZoneDeniedError(result);
  }
  return result;
}

export async function resolveAuthorizedZoneIdsForPath(params: {
  config?: OpenClawConfig;
  action: AccessZoneAction;
  path: string;
  defaultWorkspaceDir?: string;
  principal?: AccessZonePrincipalContext;
}): Promise<string[]> {
  const accessZones = getAccessZonesConfig({
    config: params.config,
    defaultWorkspaceDir: params.defaultWorkspaceDir,
  });
  if (accessZones?.enabled !== true) {
    return [];
  }
  const result = await authorizePathAccess(params);
  return result.ok && result.zoneId ? [result.zoneId] : [];
}
