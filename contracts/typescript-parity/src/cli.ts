import { resolve } from "node:path";
import { ContractInputError, runParity } from "./parity";

function repositoryRootArgument(): string | undefined {
  let repositoryRoot: string | undefined;
  const args = process.argv.slice(2);
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current !== "--repo-root") {
      throw new ContractInputError(
        current?.startsWith("--") ? "unknown_input" : "malformed_input",
        "parity CLI accepts only --repo-root",
      );
    }
    const next = args[index + 1];
    if (repositoryRoot !== undefined || !next || next.startsWith("--")) {
      throw new ContractInputError("malformed_input", "--repo-root requires one value");
    }
    repositoryRoot = next;
    index += 1;
  }
  return repositoryRoot;
}

try {
  const repoRoot = resolve(repositoryRootArgument() ?? process.cwd());
  const report = await runParity(repoRoot);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} catch (error) {
  const failure = error instanceof ContractInputError
    ? { code: error.code, message: error.message }
    : { code: "unexpected_failure", message: "parity check failed without a contract error" };
  process.stderr.write(`${JSON.stringify({ ok: false, error: failure })}\n`);
  process.exitCode = 1;
}
