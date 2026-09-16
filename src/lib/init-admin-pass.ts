/**
 * init-admin-pass.ts — flair#837: the missing-file + persisted-Harper-user
 * case that #827 could not close.
 *
 * #827 made `flair init` reuse `~/.flair/admin-pass` when the file is already
 * present. The remaining footgun is the file MISSING while Harper's data dir
 * already holds an admin user: `HDB_ADMIN_PASSWORD` only seeds a brand-new
 * install, so generating a fresh file there desyncs from the stored hash and
 * the next ops-API call 401s.
 *
 * This module is the single decision + the two exits that can actually be
 * right: re-persist a supplied original credential, or rotate the stored
 * hash through the ops-API domain socket (`alter_user`, no Authorization —
 * Harper's `bypassLocalAuth` on the socket is an else-if on "no header").
 * Silent regeneration is never a decision here.
 *
 * Pure decision helpers are exported for unit tests. The socket POST is a
 * thin `node:http` client against `dataDir/operations-server`.
 */
import { request as httpRequest } from "node:http";
import { existsSync } from "node:fs";
import { join } from "node:path";

/** Copy-pasteable recovery commands. Tests assert these strings verbatim. */
export const INIT_RESET_ADMIN_PASS_COMMAND = "flair init --reset-admin-pass";
export const INIT_ADMIN_PASS_FILE_COMMAND = "flair init --admin-pass-file <path>";
export const INIT_STOP_FOREIGN_COMMAND = "flair stop";

export type InitAdminPasswordDecision =
  | "reuse-existing"
  | "generate-new"
  | "re-persist"
  | "rotate"
  | "refuse";

export type InitAdminPasswordRefuseReason =
  | "persisted-missing-file"
  | "foreign-instance"
  | "reset-without-socket";

export interface InitAdminPasswordContext {
  /** Harper already has a user record in THIS data dir (hdb_user mdb). */
  persistedAdminUser?: boolean;
  /**
   * Something is already answering on the chosen HTTP port, but THIS data
   * dir has no persisted user — a leftover process from a previous install
   * (the 2026-09-02 canary variant).
   */
  foreignInstanceOnPort?: boolean;
  /** Operator supplied --admin-pass / --admin-pass-file / FLAIR_ADMIN_PASS / HDB_ADMIN_PASSWORD. */
  explicitCredential?: boolean;
  /** Operator asked to rotate (`--reset-admin-pass`). */
  resetRequested?: boolean;
  /**
   * The ops socket is reachable now, or init is about to start Harper so it
   * will be. False only when `--skip-start` and nothing is listening.
   */
  opsSocketAvailable?: boolean;
}

/**
 * Decide the admin-password action for `flair init`.
 *
 * One-arg form (`adminPassFileExists`) is the #827 contract and must keep
 * answering `reuse-existing` / `generate-new`. The optional second argument
 * is the #837 persisted-user / foreign-instance / reset context. On a call
 * that omits it, a missing file is still a fresh install.
 */
export function resolveInitAdminPasswordSource(
  adminPassFileExists: boolean,
  ctx: InitAdminPasswordContext = {},
): InitAdminPasswordDecision {
  const persisted = !!ctx.persistedAdminUser;
  const foreign = !!ctx.foreignInstanceOnPort;
  const explicit = !!ctx.explicitCredential;
  const reset = !!ctx.resetRequested;
  const socketOk = ctx.opsSocketAvailable !== false;

  if (foreign && !adminPassFileExists && !explicit) {
    return "refuse";
  }

  if (adminPassFileExists && !reset) {
    return "reuse-existing";
  }

  if (!adminPassFileExists && !persisted && !reset) {
    return "generate-new";
  }

  if (persisted && explicit && !reset) {
    return "re-persist";
  }

  if (reset) {
    return socketOk ? "rotate" : "refuse";
  }

  if (persisted && !adminPassFileExists) {
    return "refuse";
  }

  return adminPassFileExists ? "reuse-existing" : "generate-new";
}

/** Why a `refuse` decision was reached — drives the exact recovery command. */
export function resolveInitAdminPasswordRefuseReason(
  adminPassFileExists: boolean,
  ctx: InitAdminPasswordContext = {},
): InitAdminPasswordRefuseReason | null {
  if (resolveInitAdminPasswordSource(adminPassFileExists, ctx) !== "refuse") return null;
  if (ctx.foreignInstanceOnPort && !adminPassFileExists && !ctx.explicitCredential) {
    return "foreign-instance";
  }
  if (ctx.resetRequested && ctx.opsSocketAvailable === false) {
    return "reset-without-socket";
  }
  return "persisted-missing-file";
}

/**
 * Harper's own install-validator signal that a rootPath already has a user
 * record (`system/hdb_user/data.mdb` or the legacy `system/hdb_user.mdb`).
 * Config presence alone is not enough — an interrupted install can write
 * harper-config.yaml before the user hash lands.
 */
export function detectPersistedAdminUser(dataDir: string): boolean {
  const dir = dataDir;
  return (
    existsSync(join(dir, "system", "hdb_user", "data.mdb")) ||
    existsSync(join(dir, "system", "hdb_user.mdb"))
  );
}

export function initAdminPassRefusalMessage(
  reason: InitAdminPasswordRefuseReason,
  opts: { dataDir?: string; httpPort?: number; adminPassPath?: string } = {},
): string {
  if (reason === "foreign-instance") {
    const port = opts.httpPort ?? 19926;
    return (
      `A Harper instance is already answering on port ${port} and this data directory has no persisted admin user. ` +
      `Stop that process before initializing a new instance:\n  ${INIT_STOP_FOREIGN_COMMAND}`
    );
  }
  if (reason === "reset-without-socket") {
    return (
      `Cannot rotate the admin password: Harper is not running and --skip-start was set, so the operations socket is unreachable. ` +
      `Start the instance, then run:\n  ${INIT_RESET_ADMIN_PASS_COMMAND}`
    );
  }
  const dataDir = opts.dataDir ?? "<data-dir>";
  const passPath = opts.adminPassPath ?? "~/.flair/admin-pass";
  return (
    `Harper already has an admin user in ${dataDir}, but ${passPath} is missing. ` +
    `HDB_ADMIN_PASSWORD only seeds a brand-new install and will not rotate the stored hash, ` +
    `so generating a new file would 401 every later ops-API call.\n` +
    `If you have the original password:\n  ${INIT_ADMIN_PASS_FILE_COMMAND}\n` +
    `If you do not:\n  ${INIT_RESET_ADMIN_PASS_COMMAND}`
  );
}

/**
 * Doctor / status finding for the disk-visible half of #837: file gone,
 * user record still in the data dir. Live 401 probes (file present but
 * wrong) are a separate authenticated check the caller can layer on.
 */
export function adminPassDesyncFinding(input: {
  adminPassFileExists: boolean;
  persistedAdminUser: boolean;
  dataDir?: string;
  adminPassPath?: string;
}): { flagged: boolean; message: string; remedy: string } | null {
  if (input.adminPassFileExists || !input.persistedAdminUser) return null;
  return {
    flagged: true,
    message: "admin-pass file missing; Harper still has a persisted admin user",
    remedy: initAdminPassRefusalMessage("persisted-missing-file", {
      dataDir: input.dataDir,
      adminPassPath: input.adminPassPath,
    }),
  };
}

export interface OpsSocketCallResult {
  status: number;
  body: string;
}

/**
 * POST an operations payload over the domain socket. Sends NO Authorization
 * header: Harper's socket `bypassLocalAuth` is an else-if on "no header
 * present", so attaching Basic/Bearer opts out of the local-admin channel
 * and 401s (harper `bin/cliOperations.ts`).
 */
export function callOpsSocket(
  socketPath: string,
  body: Record<string, unknown>,
  timeoutMs = 10_000,
): Promise<OpsSocketCallResult> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        socketPath,
        path: "/",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`ops socket timed out after ${timeoutMs}ms`));
    });
    req.write(payload);
    req.end();
  });
}

export async function rotateAdminPasswordViaOpsSocket(
  socketPath: string,
  username: string,
  password: string,
): Promise<void> {
  const result = await callOpsSocket(socketPath, {
    operation: "alter_user",
    username,
    password,
    role: "super_user",
    active: true,
  });
  if (result.status >= 400) {
    throw new Error(
      `Operations socket alter_user failed (${result.status}): ${result.body || "(empty)"}`,
    );
  }
}
