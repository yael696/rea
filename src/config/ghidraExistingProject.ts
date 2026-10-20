import { basename, isAbsolute, resolve } from "node:path";
import { z } from "zod";

const ghidraName = z
  .string()
  .min(1)
  .max(255)
  .refine((value) => value.trim() !== "", "must not be blank")
  .refine(
    (value) => !/[\\/\u0000-\u001f\u007f]/u.test(value),
    "must be a single name without path separators or control characters",
  );

/** One filesystem-safe Ghidra project name; spaces and Unicode are preserved. */
export const ghidraExistingProjectNameSchema = ghidraName
  .refine(
    (value) => value !== "." && value !== ".." && !value.startsWith("."),
    "must be a valid Ghidra project name",
  )
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= 255,
    "must fit in one filesystem name",
  );

/** Exact Program name supplied to analyzeHeadless `-process`. */
export const ghidraExistingProgramNameSchema = ghidraName.refine(
  (value) => !/[?*]/u.test(value),
  "must not contain Ghidra -process wildcard characters",
);

/** Project name is the basename of the suffix-free selected project path. */
export const ghidraExistingProjectNameFromPath = (
  projectPath: string,
): string => basename(resolve(projectPath));

/** Absolute Ghidra project basename without its `.gpr` or `.rep` suffix. */
export const ghidraExistingProjectPathSchema = z
  .string()
  .min(1)
  .refine(isAbsolute, "must be an absolute local filesystem path")
  .refine(
    (value) =>
      ghidraExistingProjectNameSchema.safeParse(
        ghidraExistingProjectNameFromPath(value),
      ).success,
    "must end in a valid Ghidra project name without a .gpr or .rep suffix",
  );
