import * as fs from "fs";
import * as path from "path";
import { KanonDeployment } from "./types";

/**
 * Load a deployment record produced by `scripts/deploy.ts` for the given chainId.
 * Defaults to looking under `<repoRoot>/deployments/`.
 */
export function loadDeployment(chainId: number, deploymentsDir?: string): KanonDeployment {
  const dir = deploymentsDir ?? path.resolve(__dirname, "..", "..", "..", "deployments");
  const file = path.join(dir, `${chainId}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`No deployment for chainId=${chainId} at ${file}. Run scripts/deploy.ts first.`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8")) as KanonDeployment;
}
