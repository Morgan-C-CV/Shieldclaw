export type AccessZoneAction = "read" | "write" | "admin";

export type AccessZone = {
  id: string;
  kind: "filesystem";
  roots: string[];
  principals: Record<string, AccessZoneAction[]>;
};

export type AccessZonesConfig = {
  enabled?: boolean;
  enforce?: boolean;
  logViolations?: boolean;
  defaultMode?: "deny" | "legacy-allow";
  resolveSymlinks?: boolean;
  zones?: AccessZone[];
};

export type SecurityConfig = Record<string, never>;
