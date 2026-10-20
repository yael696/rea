import { afterEach, expect, it, vi } from "vitest";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import * as binaryComposition from "../../../src/composition/binary.js";
import { createCli } from "../../../src/cli.js";
import type { AppConfig } from "../../../src/config/types.js";

const previousExitCode = process.exitCode;
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = previousExitCode;
});

it("passes existing Ghidra project configuration from the public CLI into shared composition", async () => {
  let received: AppConfig | undefined;
  const session = composeBinarySession(new AnalysisProviderRegistry([]));
  vi.spyOn(binaryComposition, "createBinarySession").mockImplementation(
    (config) => {
      received = config;
      return session;
    },
  );
  const environment = {
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_GHIDRA_EXISTING_PROJECT_PATH:
      "/home/user/ghidra-projects/Minecraft_Import_Only",
    REA_GHIDRA_EXISTING_PROGRAM_NAME: "Minecraft.Windows.exe",
  };
  const cli = createCli(environment);
  let stdout = "";
  await cli.serve(
    ["analyze", process.execPath, "--provider", "ghidra", "--json"],
    {
      env: {},
      stdout: (text) => {
        stdout += text;
      },
      exit: () => undefined,
    },
  );
  expect(JSON.parse(stdout)).toMatchObject({ code: expect.any(String) });
  expect(received?.ghidraExistingProject).toEqual({
    projectPath: "/home/user/ghidra-projects/Minecraft_Import_Only",
    projectName: "Minecraft_Import_Only",
    programName: "Minecraft.Windows.exe",
  });
});
