import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveAccessZonesPolicyPath } from "../infra/access-zones-policy-file.js";

vi.mock("@mariozechner/pi-ai", async () => {
  const original =
    await vi.importActual<typeof import("@mariozechner/pi-ai")>("@mariozechner/pi-ai");
  return {
    ...original,
  };
});

vi.mock("@mariozechner/pi-ai/oauth", async () => {
  const actual = await vi.importActual<typeof import("@mariozechner/pi-ai/oauth")>(
    "@mariozechner/pi-ai/oauth",
  );
  return {
    ...actual,
    getOAuthApiKey: () => undefined,
    getOAuthProviders: () => [],
  };
});

import { createOpenClawCodingTools } from "./pi-tools.js";

describe("FS tools with workspaceOnly=false", () => {
  let tmpDir: string;
  let workspaceDir: string;
  let outsideFile: string;
  let previousConfigPath: string | undefined;

  const hasToolError = (result: { content: Array<{ type: string; text?: string }> }) =>
    result.content.some((content) => {
      if (content.type !== "text") {
        return false;
      }
      return content.text?.toLowerCase().includes("error") ?? false;
    });

  const toolsFor = (workspaceOnly: boolean | undefined) =>
    createOpenClawCodingTools({
      workspaceDir,
      config:
        workspaceOnly === undefined
          ? {}
          : {
              tools: {
                fs: {
                  workspaceOnly,
                },
              },
            },
    });

  const toolsWithAccessZones = () =>
    createOpenClawCodingTools({
      workspaceDir,
      config: {
        tools: {
          fs: {
            workspaceOnly: false,
          },
        },
      },
    });

  async function writeAccessZonesPolicy() {
    await fs.writeFile(
      resolveAccessZonesPolicyPath(),
      [
        "# OpenClaw Access Zones",
        "",
        "```json5",
        JSON.stringify(
          {
            enabled: true,
            zones: [
              {
                id: "workspace",
                kind: "filesystem",
                roots: [workspaceDir],
                principals: {
                  "runtime:agent": ["read", "write"],
                },
              },
            ],
          },
          null,
          2,
        ),
        "```",
        "",
      ].join("\n"),
      "utf-8",
    );
  }

  const expectFsToolRejects = async (
    toolName: "write" | "edit" | "read",
    callId: string,
    input: Record<string, unknown>,
    workspaceOnly: boolean | undefined,
  ) => {
    const tool = toolsFor(workspaceOnly).find((candidate) => candidate.name === toolName);
    expect(tool).toBeDefined();
    await expect(tool!.execute(callId, input)).rejects.toThrow();
  };

  beforeEach(async () => {
    previousConfigPath = process.env.OPENCLAW_CONFIG_PATH;
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-test-"));
    workspaceDir = path.join(tmpDir, "workspace");
    await fs.mkdir(workspaceDir);
    process.env.OPENCLAW_CONFIG_PATH = path.join(tmpDir, "openclaw.json");
    outsideFile = path.join(tmpDir, "outside.txt");
  });

  afterEach(async () => {
    if (previousConfigPath === undefined) {
      delete process.env.OPENCLAW_CONFIG_PATH;
    } else {
      process.env.OPENCLAW_CONFIG_PATH = previousConfigPath;
    }
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("blocks write outside the default Access Zone when workspaceOnly=false", async () => {
    await expectFsToolRejects(
      "write",
      "test-call-1",
      {
        path: outsideFile,
        content: "test content",
      },
      false,
    );
  });

  it("should still block writes outside Access Zones when workspaceOnly=false", async () => {
    await writeAccessZonesPolicy();
    const writeTool = toolsWithAccessZones().find((tool) => tool.name === "write");
    expect(writeTool).toBeDefined();

    await expect(
      writeTool!.execute("test-call-access-zone-deny", {
        path: outsideFile,
        content: "blocked",
      }),
    ).rejects.toThrow(/ACCESS_ZONE_DENIED: .*Ask the user to grant access/);
  });

  it("blocks write outside the default Access Zone via ../ path when workspaceOnly=false", async () => {
    const relativeOutsidePath = path.join("..", "outside-relative-write.txt");

    await expectFsToolRejects(
      "write",
      "test-call-1b",
      {
        path: relativeOutsidePath,
        content: "relative test content",
      },
      false,
    );
  });

  it("blocks edit outside the default Access Zone when workspaceOnly=false", async () => {
    await fs.writeFile(outsideFile, "old content");

    await expectFsToolRejects(
      "edit",
      "test-call-2",
      {
        path: outsideFile,
        edits: [{ oldText: "old content", newText: "new content" }],
      },
      false,
    );
  });

  it("blocks edit outside the default Access Zone via ../ path when workspaceOnly=false", async () => {
    const relativeOutsidePath = path.join("..", "outside-relative-edit.txt");
    const outsideRelativeFile = path.join(tmpDir, "outside-relative-edit.txt");
    await fs.writeFile(outsideRelativeFile, "old relative content");

    await expectFsToolRejects(
      "edit",
      "test-call-2b",
      {
        path: relativeOutsidePath,
        edits: [{ oldText: "old relative content", newText: "new relative content" }],
      },
      false,
    );
  });

  it("blocks read outside the default Access Zone when workspaceOnly=false", async () => {
    await fs.writeFile(outsideFile, "test read content");

    await expectFsToolRejects(
      "read",
      "test-call-3",
      {
        path: outsideFile,
      },
      false,
    );
  });

  it("blocks write outside the default Access Zone when workspaceOnly is unset", async () => {
    const outsideUnsetFile = path.join(tmpDir, "outside-unset-write.txt");
    await expectFsToolRejects(
      "write",
      "test-call-3a",
      {
        path: outsideUnsetFile,
        content: "unset write content",
      },
      undefined,
    );
  });

  it("blocks edit outside the default Access Zone when workspaceOnly is unset", async () => {
    const outsideUnsetFile = path.join(tmpDir, "outside-unset-edit.txt");
    await fs.writeFile(outsideUnsetFile, "before");
    await expectFsToolRejects(
      "edit",
      "test-call-3b",
      {
        path: outsideUnsetFile,
        edits: [{ oldText: "before", newText: "after" }],
      },
      undefined,
    );
  });

  it("should block write outside workspace when workspaceOnly=true", async () => {
    const tools = toolsFor(true);
    const writeTool = tools.find((t) => t.name === "write");
    expect(writeTool).toBeDefined();

    // When workspaceOnly=true, the guard throws an error
    await expect(
      writeTool!.execute("test-call-4", {
        path: outsideFile,
        content: "test content",
      }),
    ).rejects.toThrow(/Path escapes (workspace|sandbox) root/);
  });

  it("restricts memory-triggered writes to append-only canonical memory files", async () => {
    const allowedRelativePath = "memory/2026-03-07.md";
    const allowedAbsolutePath = path.join(workspaceDir, allowedRelativePath);
    await fs.mkdir(path.dirname(allowedAbsolutePath), { recursive: true });
    await fs.writeFile(allowedAbsolutePath, "seed");

    const tools = createOpenClawCodingTools({
      workspaceDir,
      trigger: "memory",
      memoryFlushWritePath: allowedRelativePath,
      config: {
        tools: {
          exec: {
            applyPatch: {},
          },
        },
      },
      modelProvider: "openai",
      modelId: "gpt-5",
    });

    const writeTool = tools.find((tool) => tool.name === "write");
    expect(writeTool).toBeDefined();
    expect(tools.map((tool) => tool.name).toSorted()).toEqual(["read", "write"]);

    await expect(
      writeTool!.execute("test-call-memory-deny", {
        path: outsideFile,
        content: "should not write here",
      }),
    ).rejects.toThrow(/Memory flush writes are restricted to memory\/2026-03-07\.md/);

    const result = await writeTool!.execute("test-call-memory-append", {
      path: allowedRelativePath,
      content: "new note",
    });
    expect(hasToolError(result)).toBe(false);
    expect(result.content).toContainEqual({
      type: "text",
      text: "Appended content to memory/2026-03-07.md.",
    });
    await expect(fs.readFile(allowedAbsolutePath, "utf-8")).resolves.toBe("seed\nnew note");
  });
});
