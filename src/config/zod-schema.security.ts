import path from "node:path";
import { z } from "zod";

const ACCESS_ZONE_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/;
const ACCESS_ZONE_PRINCIPAL_PATTERN = /^[a-z][a-z0-9_-]*:[^\s]{1,256}$/i;

function isAbsolutePath(value: string): boolean {
  return (
    path.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value) || /^\\\\[^\\]+\\[^\\]+/.test(value)
  );
}

export const AccessZoneActionSchema = z.union([
  z.literal("read"),
  z.literal("write"),
  z.literal("admin"),
]);

export const AccessZoneSchema = z
  .object({
    id: z
      .string()
      .regex(
        ACCESS_ZONE_ID_PATTERN,
        "Access Zone id must start with an alphanumeric character and contain only letters, numbers, dots, underscores, colons, or hyphens.",
      ),
    kind: z.literal("filesystem"),
    roots: z
      .array(
        z
          .string()
          .min(1)
          .refine((value) => isAbsolutePath(value), "Access Zone roots must be absolute paths."),
      )
      .min(1)
      .max(64),
    principals: z
      .record(
        z
          .string()
          .regex(
            ACCESS_ZONE_PRINCIPAL_PATTERN,
            'Access Zone principals must use a scoped form such as "agent:main" or "session:agent:main:main".',
          ),
        z.array(AccessZoneActionSchema).min(1).max(3),
      )
      .optional()
      .default({}),
  })
  .strict();

export const AccessZonesConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    enforce: z.boolean().optional(),
    logViolations: z.boolean().optional(),
    defaultMode: z.union([z.literal("deny"), z.literal("legacy-allow")]).optional(),
    resolveSymlinks: z.boolean().optional(),
    zones: z.array(AccessZoneSchema).max(256).optional(),
  })
  .strict();

export const SecuritySchema = z.object({}).strict().optional();
