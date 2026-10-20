import { expect, it } from "vitest";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { ok } from "../../../src/domain/result.js";
import { GhidraHeadlessLauncher } from "../../../src/ghidra/GhidraLauncher.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import type { GhidraProviderClientFactory } from "../../../src/ghidra/GhidraProviderClient.js";
import { GHIDRA_SESSION_CAPABILITIES } from "../../../src/ghidra/GhidraSessionValues.js";
import type { GhidraSessionInfo } from "../../../src/ghidra/GhidraSessionValues.js";
import { silentLogger } from "../../../src/logger.js";
import { createServer } from "../../../src/server/createServer.js";
import { ghidraInstallationHost } from "./ghidraMcpHarness.js";

const projectPath = "/home/user/ghidra-projects/Minecraft_Import_Only";
const projectName = "Minecraft_Import_Only";
const programName = "Minecraft.Windows.exe";

it("opens the configured private Ghidra project through MCP and lists its selected program", async () => {
  const config = parseConfig({
    GHIDRA_INSTALL_DIR: "/opt/ghidra_12.1.4_PUBLIC",
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_GHIDRA_EXISTING_PROJECT_PATH: projectPath,
    REA_GHIDRA_EXISTING_PROGRAM_NAME: programName,
  });
  if (!config.ok) throw config.error;

  let launcherOptions: GhidraHeadlessLauncher["options"] | undefined;
  let clientOptions: Parameters<GhidraProviderClientFactory>[0] | undefined;
  const factory: GhidraProviderClientFactory = (options) => {
    clientOptions = options;
    if (!(options.launcher instanceof GhidraHeadlessLauncher))
      throw new Error("Expected the production Ghidra headless launcher");
    launcherOptions = options.launcher.options;
    const info: GhidraSessionInfo = {
      name: "REA Ghidra bridge",
      run_id: "11111111-1111-4111-8111-111111111111",
      profile_digest: options.profileDigest,
      provider: { id: "ghidra", version: options.providerVersion },
      read_only: false,
      analysis_complete: false,
      analysis_timed_out: false,
      analysis_skipped: true,
      capabilities: [...GHIDRA_SESSION_CAPABILITIES],
      target: {
        name: programName,
        language_id: "x86:LE:64:default",
        compiler_spec_id: "windows",
        image_base: "0x140000000",
        default_address_space: "ram",
        sha256: options.targetSha256,
      },
    };
    return {
      start: () => Promise.resolve(ok(info)),
      callTool: (operation) =>
        Promise.resolve(
          ok(
            jsonValueSchema.parse(
              operation === "list_documents" ? [programName] : null,
            ),
          ),
        ),
      close: () => Promise.resolve(ok(null)),
    };
  };

  const provider = new GhidraProvider(
    config.value,
    silentLogger,
    {},
    ghidraInstallationHost(),
    factory,
  );
  const session = composeBinarySession(
    new AnalysisProviderRegistry([provider]),
  );
  const server = createServer(
    { kind: "session", session },
    { logger: silentLogger },
  );
  const mcp = new Client({
    name: "existing-ghidra-project-test",
    version: "1.0.0",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await mcp.connect(clientTransport);
    const opened = await mcp.callTool({
      name: "open_binary",
      arguments: { path: process.execPath, provider_id: "ghidra" },
    });
    expect(opened.isError).not.toBe(true);

    const documents = await mcp.callTool({
      name: "list_documents",
      arguments: {},
    });
    expect(documents.isError).not.toBe(true);
    const evidence = parseEvidence(documents.structuredContent);
    expect(evidence.normalized_result).toEqual([programName]);
    expect(evidence.limitations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("REA did not run global auto-analysis"),
      ]),
    );
    expect(launcherOptions?.existingProject).toEqual({
      projectPath,
      projectName,
      programName,
    });
    expect(session.analysisProfile()?.parameters).toMatchObject({
      import_mode: "existing-project-private-copy-noanalysis-v1",
      analyzer_preset: "saved-project-state-noanalysis-v1",
      no_return_repair: "skipped-existing-project-noanalysis-v1",
      existing_project: {
        project_path: projectPath,
        project_name: projectName,
        program_name: programName,
      },
    });
    expect(clientOptions).toMatchObject({
      expectedProgramName: programName,
      expectedAnalysisSkipped: true,
      runtimeParent: "/home/user/ghidra-projects",
    });
  } finally {
    await Promise.allSettled([mcp.close(), server.close()]);
    await session.close();
  }
});
