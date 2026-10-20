import { constants as fsConstants, mkdirSync, writeFileSync } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { win32 } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

const windowsPrivateRuntime = vi.hoisted(() => vi.fn());

vi.mock(
  "../../../../src/windows/WindowsPrivateRuntime.js",
  async (importOriginal) => {
    const actual =
      await importOriginal<
        typeof import("../../../../src/windows/WindowsPrivateRuntime.js")
      >();
    return { ...actual, windowsPrivateRuntime };
  },
);

import {
  copyExistingGhidraProject,
  GhidraHeadlessLauncher,
} from "../../../../src/ghidra/GhidraLauncher.js";
import type { OwnedProviderProcessSpawnOptions } from "../../../../src/process/ProviderProcess.js";

type FakeWindowsRuntime = {
  readonly observation: { readonly path: string };
  readonly snapshots: ReturnType<typeof vi.fn>;
  mkdir(relativePath: string): void;
  writeFile(relativePath: string, content: string): void;
  snapshot(
    sourcePath: string,
    relativePath: string,
    signal?: AbortSignal,
  ): Promise<void>;
  withSourceDirectory<T>(
    sourcePath: string,
    operation: () => Promise<T>,
  ): Promise<T>;
  withSourceFile<T>(
    sourcePath: string,
    operation: () => Promise<T>,
  ): Promise<T>;
};

const temporaryRoots: string[] = [];
const readOnlyFiles: string[] = [];

afterEach(async () => {
  for (const path of readOnlyFiles.splice(0))
    await chmod(path, 0o666).catch(() => undefined);
  for (const root of temporaryRoots.splice(0))
    await rm(root, { recursive: true, force: true });
  windowsPrivateRuntime.mockReset();
});

const createRoot = async (): Promise<string> => {
  const root = await mkdtemp(win32.join(tmpdir(), "rea-ghidra-existing-"));
  temporaryRoots.push(root);
  return root;
};

const createFakeRuntime = (
  runtimeRoot: string,
  failSourcePath?: string,
): FakeWindowsRuntime => {
  const snapshots = vi.fn();
  const sourceEntry = async (
    sourcePath: string,
    directory: boolean,
  ): Promise<void> => {
    const metadata = await lstat(sourcePath);
    if (
      metadata.isSymbolicLink() ||
      (directory ? !metadata.isDirectory() : !metadata.isFile())
    )
      throw new Error(`synthetic reparse or type rejection: ${sourcePath}`);
  };
  const runtime: FakeWindowsRuntime = {
    observation: { path: runtimeRoot },
    snapshots,
    mkdir: (relativePath) => mkdirSync(win32.join(runtimeRoot, relativePath)),
    writeFile: (relativePath, content) =>
      writeFileSync(win32.join(runtimeRoot, relativePath), content, {
        flag: "wx",
      }),
    snapshot: async (sourcePath, relativePath, signal) => {
      signal?.throwIfAborted();
      snapshots(sourcePath, relativePath);
      if (sourcePath === failSourcePath)
        throw new Error("synthetic private-copy failure");
      await copyFile(
        sourcePath,
        win32.join(runtimeRoot, relativePath),
        fsConstants.COPYFILE_EXCL,
      );
      signal?.throwIfAborted();
    },
    withSourceDirectory: async (sourcePath, operation) => {
      await sourceEntry(sourcePath, true);
      return operation();
    },
    withSourceFile: async (sourcePath, operation) => {
      await sourceEntry(sourcePath, false);
      return operation();
    },
  };
  windowsPrivateRuntime.mockReturnValue(runtime);
  return runtime;
};

const createProject = async (
  parent: string,
  projectName = "Saved Project_日本語",
): Promise<string> => {
  const sourceRoot = win32.join(parent, "source files ü");
  await mkdir(sourceRoot);
  const projectPath = win32.join(sourceRoot, projectName);
  await writeFile(`${projectPath}.gpr`, "saved marker", "utf8");
  await mkdir(win32.join(`${projectPath}.rep`, "nested folder"), {
    recursive: true,
  });
  await writeFile(
    win32.join(`${projectPath}.rep`, "nested folder", "map 東京.bin"),
    "saved project data",
    "utf8",
  );
  return projectPath;
};

const copyProject = async (
  projectPath: string,
  projectName: string,
  runtimeRoot: string,
  signal?: AbortSignal,
): Promise<void> =>
  copyExistingGhidraProject(
    projectPath,
    projectName,
    win32.join(runtimeRoot, "project"),
    {
      ...(signal === undefined ? {} : { signal }),
      platform: "win32",
    },
  );

const windowsSession = (runtimeRoot: string, parent: string) => ({
  runtimeRoot,
  transport: "authenticated-loopback-tcp" as const,
  endpointPath: win32.join(runtimeRoot, "bridge-endpoint.json"),
  token: "fixture-token",
  runId: "d6fcbb66-e829-4ff6-a535-0035aec63139",
  targetPath: win32.join(parent, "selected-target.exe"),
  targetSha256: "b".repeat(64),
  providerVersion: "12.1.4",
  profileDigest: "a".repeat(64),
});

describe.skipIf(process.platform !== "win32")(
  "Windows existing Ghidra projects",
  () => {
    it("copies only the selected project with spaces and Unicode, preserving a read-only original", async () => {
      const parent = await createRoot();
      const runtimeRoot = win32.join(parent, "private runtime");
      await mkdir(runtimeRoot);
      const projectName = "Saved Project_日本語";
      const projectPath = await createProject(parent, projectName);
      const markerPath = `${projectPath}.gpr`;
      await chmod(markerPath, 0o444);
      readOnlyFiles.push(markerPath);
      const runtime = createFakeRuntime(runtimeRoot);

      await copyProject(projectPath, projectName, runtimeRoot);

      expect(
        await readFile(
          win32.join(runtimeRoot, "project", `${projectName}.gpr`),
          "utf8",
        ),
      ).toBe("saved marker");
      expect(
        await readFile(
          win32.join(
            runtimeRoot,
            "project",
            `${projectName}.rep`,
            "nested folder",
            "map 東京.bin",
          ),
          "utf8",
        ),
      ).toBe("saved project data");
      expect(await readFile(markerPath, "utf8")).toBe("saved marker");
      expect(runtime.snapshots).toHaveBeenCalledTimes(2);
      expect((await lstat(markerPath)).isSymbolicLink()).toBe(false);
    });

    it("rejects a network project path before filesystem access", async () => {
      const parent = await createRoot();
      const runtimeRoot = win32.join(parent, "private runtime");
      await mkdir(runtimeRoot);
      const runtime = createFakeRuntime(runtimeRoot);

      await expect(
        copyProject(
          "\\\\server\\share\\Saved Project_日本語",
          "Saved Project_日本語",
          runtimeRoot,
        ),
      ).rejects.toThrow(/local drive-absolute Windows path/u);

      expect(runtime.snapshots).not.toHaveBeenCalled();
      expect(windowsPrivateRuntime).not.toHaveBeenCalled();
    });

    it("rejects missing project pairs before creating a private copy", async () => {
      const parent = await createRoot();
      const runtimeRoot = win32.join(parent, "private runtime");
      await mkdir(runtimeRoot);
      const projectPath = win32.join(parent, "missing project");
      const runtime = createFakeRuntime(runtimeRoot);

      await expect(
        copyProject(projectPath, "missing project", runtimeRoot),
      ).rejects.toThrow(/requires a regular/u);

      expect(runtime.snapshots).not.toHaveBeenCalled();
      await expect(
        lstat(win32.join(runtimeRoot, "project")),
      ).rejects.toMatchObject({ code: "ENOENT" });
    });

    it("rejects a junction in the selected project tree", async () => {
      const parent = await createRoot();
      const runtimeRoot = win32.join(parent, "private runtime");
      await mkdir(runtimeRoot);
      const projectName = "Saved Project_日本語";
      const projectPath = await createProject(parent, projectName);
      const external = win32.join(parent, "outside project tree");
      await mkdir(external);
      await writeFile(win32.join(external, "outside.bin"), "external data");
      await symlink(
        external,
        win32.join(`${projectPath}.rep`, "junction"),
        "junction",
      );
      const runtime = createFakeRuntime(runtimeRoot);

      await expect(
        copyProject(projectPath, projectName, runtimeRoot),
      ).rejects.toThrow(/symbolic link|reparse/u);

      expect(
        runtime.snapshots.mock.calls.some(([sourcePath]) =>
          String(sourcePath).startsWith(external),
        ),
      ).toBe(false);
      await expect(
        lstat(
          win32.join(
            runtimeRoot,
            "project",
            `${projectName}.rep`,
            "junction",
            "outside.bin",
          ),
        ),
      ).rejects.toMatchObject({ code: "ENOENT" });
    });

    it("does not launch Ghidra when a private project snapshot fails", async () => {
      const parent = await createRoot();
      const runtimeRoot = win32.join(parent, "private runtime");
      await mkdir(runtimeRoot);
      const projectName = "Saved Project_日本語";
      const projectPath = await createProject(parent, projectName);
      createFakeRuntime(runtimeRoot, `${projectPath}.gpr`);
      const spawnProcess = vi.fn(
        async (_options: OwnedProviderProcessSpawnOptions) => {
          throw new Error("spawn must not run after a copy failure");
        },
      );
      const javaLaunch = vi.fn(async () => {
        throw new Error("Java preparation must not run after a copy failure");
      });
      const launcher = new GhidraHeadlessLauncher({
        environment: { ComSpec: "C:\\Windows\\System32\\cmd.exe" },
        analyzeHeadlessPath: "C:\\tools\\ghidra\\support\\analyzeHeadless.bat",
        configurationDirectoryName: "ghidra_12.1.4_PUBLIC",
        bridgeScriptPath: "C:\\REA Package\\bridge\\ReaGhidraBridge.java",
        platform: "win32",
        existingProject: {
          projectPath,
          projectName,
          programName: "Minecraft.Windows.exe",
        },
        javaLaunch,
        spawnProcess,
      });

      const launched = await launcher.launch(
        windowsSession(runtimeRoot, parent),
      );

      expect(launched.ok).toBe(false);
      if (launched.ok) throw new Error("launch unexpectedly succeeded");
      expect(String(launched.error.cause)).toContain(
        "synthetic private-copy failure",
      );
      expect(javaLaunch).not.toHaveBeenCalled();
      expect(spawnProcess).not.toHaveBeenCalled();
    });
  },
);
