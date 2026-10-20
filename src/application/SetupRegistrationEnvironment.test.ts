import { expect, it } from "vitest";

import { explicitSetupRegistrationEnvironment } from "./SetupRegistrationEnvironment.js";

it("preserves caller-selected existing Ghidra project identity for MCP setup", () => {
  expect(
    explicitSetupRegistrationEnvironment({
      REA_GHIDRA_EXISTING_PROJECT_PATH:
        "/home/user/ghidra-projects/Minecraft_Import_Only",
      REA_GHIDRA_EXISTING_PROGRAM_NAME: "Minecraft.Windows.exe",
      UNRELATED_SETTING: "not copied",
    }),
  ).toEqual({
    REA_GHIDRA_EXISTING_PROJECT_PATH:
      "/home/user/ghidra-projects/Minecraft_Import_Only",
    REA_GHIDRA_EXISTING_PROGRAM_NAME: "Minecraft.Windows.exe",
  });
});
