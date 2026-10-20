import { access, mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, expect, it, vi } from "vitest";

import { GhidraClient } from "./GhidraClient.js";
import * as GhidraTransport from "./GhidraTransport.js";

const parents: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    parents
      .splice(0)
      .map((parent) => rm(parent, { recursive: true, force: true })),
  );
});

it("creates and cleans the private runtime under the selected project's parent", async () => {
  const parent = await mkdtemp(join(tmpdir(), "rea-ghidra-project-parent-"));
  parents.push(parent);
  let runtimeRoot: string | undefined;
  vi.spyOn(GhidraTransport, "createGhidraEndpoint").mockImplementation(
    async (root) => {
      runtimeRoot = root;
      throw new Error("controlled endpoint failure");
    },
  );
  const client = new GhidraClient({
    launcher: {
      launch: async () => {
        throw new Error("endpoint setup should fail before launching Ghidra");
      },
    },
    targetPath: process.execPath,
    targetSha256: "a".repeat(64),
    providerVersion: "12.1.4",
    profileDigest: "b".repeat(64),
    runtimeParent: parent,
  });

  const started = await client.start();
  expect(started.ok).toBe(false);
  if (started.ok) throw new Error("Expected the controlled endpoint failure");
  expect(runtimeRoot).toBeDefined();
  expect(dirname(runtimeRoot ?? "")).toBe(parent);
  await expect(access(runtimeRoot ?? "")).rejects.toMatchObject({
    code: "ENOENT",
  });
  expect((await client.close()).ok).toBe(true);
});

it.skipIf(process.platform === "win32")(
  "keeps the private runtime out of an existing Ghidra .rep data directory",
  async () => {
    const parent = await mkdtemp(join(tmpdir(), "rea-ghidra-source-data-"));
    parents.push(parent);
    const projectData = join(parent, "Minecraft_Import_Only.rep");
    await mkdir(projectData);
    let runtimeRoot: string | undefined;
    vi.spyOn(GhidraTransport, "createGhidraEndpoint").mockImplementation(
      async (root) => {
        runtimeRoot = root;
        throw new Error("controlled endpoint failure");
      },
    );
    const client = new GhidraClient({
      launcher: {
        launch: async () => {
          throw new Error("endpoint setup should fail before launching Ghidra");
        },
      },
      targetPath: process.execPath,
      targetSha256: "a".repeat(64),
      providerVersion: "12.1.4",
      profileDigest: "b".repeat(64),
      runtimeParent: projectData,
    });

    const started = await client.start();
    expect(started.ok).toBe(false);
    if (started.ok) throw new Error("Expected the controlled endpoint failure");
    expect(runtimeRoot).toBeDefined();
    expect(runtimeRoot?.startsWith(`${projectData}/`)).toBe(false);
    expect(await readdir(projectData)).toEqual([]);
    await expect(access(runtimeRoot ?? "")).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect((await client.close()).ok).toBe(true);
  },
);
