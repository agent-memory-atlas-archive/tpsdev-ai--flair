/**
 * init-admin-pass-persisted.test.ts — flair#837
 *
 * `flair init` with ~/.flair/admin-pass missing and Harper already holding a
 * persisted admin user used to generate a fresh file. HDB_ADMIN_PASSWORD
 * does not rotate a stored hash, so the instance 401'd on the next ops call.
 *
 * Decision + detection + refusal text + ops-socket alter_user are pure /
 * locally mocked here. No live Harper.
 */
import { describe, test, expect, afterEach } from "bun:test";
import { createServer } from "node:http";
import { mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  resolveInitAdminPasswordSource,
  resolveInitAdminPasswordRefuseReason,
  detectPersistedAdminUser,
  initAdminPassRefusalMessage,
  adminPassDesyncFinding,
  callOpsSocket,
  rotateAdminPasswordViaOpsSocket,
  INIT_RESET_ADMIN_PASS_COMMAND,
  INIT_ADMIN_PASS_FILE_COMMAND,
  INIT_STOP_FOREIGN_COMMAND,
} from "../../src/lib/init-admin-pass.ts";

function makeTmpDir(): string {
  const dir = join(tmpdir(), `flair-837-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

describe("resolveInitAdminPasswordSource — flair#837 persisted user", () => {
  test("one-arg form keeps the #827 contract", () => {
    expect(resolveInitAdminPasswordSource(true)).toBe("reuse-existing");
    expect(resolveInitAdminPasswordSource(false)).toBe("generate-new");
  });

  test("FAILS-FIRST: persisted user + missing file is not generate-new", () => {
    expect(resolveInitAdminPasswordSource(false, { persistedAdminUser: true })).not.toBe("generate-new");
  });

  test("bare init against a persisted user refuses (does not guess)", () => {
    expect(resolveInitAdminPasswordSource(false, { persistedAdminUser: true })).toBe("refuse");
    expect(resolveInitAdminPasswordRefuseReason(false, { persistedAdminUser: true })).toBe("persisted-missing-file");
  });

  test("explicit credential + persisted user re-persists the file", () => {
    expect(resolveInitAdminPasswordSource(false, {
      persistedAdminUser: true,
      explicitCredential: true,
    })).toBe("re-persist");
  });

  test("--reset-admin-pass + socket available rotates via alter_user", () => {
    expect(resolveInitAdminPasswordSource(false, {
      persistedAdminUser: true,
      resetRequested: true,
      opsSocketAvailable: true,
    })).toBe("rotate");
  });

  test("--reset-admin-pass without a reachable socket refuses with the start command", () => {
    expect(resolveInitAdminPasswordSource(false, {
      persistedAdminUser: true,
      resetRequested: true,
      opsSocketAvailable: false,
    })).toBe("refuse");
    expect(resolveInitAdminPasswordRefuseReason(false, {
      persistedAdminUser: true,
      resetRequested: true,
      opsSocketAvailable: false,
    })).toBe("reset-without-socket");
  });

  test("foreign instance on the port (fresh data dir) refuses with flair stop", () => {
    expect(resolveInitAdminPasswordSource(false, {
      foreignInstanceOnPort: true,
      persistedAdminUser: false,
    })).toBe("refuse");
    expect(resolveInitAdminPasswordRefuseReason(false, {
      foreignInstanceOnPort: true,
    })).toBe("foreign-instance");
  });

  test("existing file still reuses even when a persisted user is present", () => {
    expect(resolveInitAdminPasswordSource(true, { persistedAdminUser: true })).toBe("reuse-existing");
  });
});

describe("detectPersistedAdminUser — Harper's own user-record paths", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) {
      try { rmSync(d, { recursive: true, force: true }); } catch { /* */ }
    }
  });

  test("empty data dir is not a persisted user", () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    expect(detectPersistedAdminUser(dir)).toBe(false);
  });

  test("harper-config.yaml alone is not a persisted user", () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    writeFileSync(join(dir, "harper-config.yaml"), "http:\n  port: 19926\n");
    expect(detectPersistedAdminUser(dir)).toBe(false);
  });

  test("system/hdb_user/data.mdb is a persisted user", () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    mkdirSync(join(dir, "system", "hdb_user"), { recursive: true });
    writeFileSync(join(dir, "system", "hdb_user", "data.mdb"), "user-hash");
    expect(detectPersistedAdminUser(dir)).toBe(true);
  });

  test("legacy system/hdb_user.mdb is a persisted user", () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    mkdirSync(join(dir, "system"), { recursive: true });
    writeFileSync(join(dir, "system", "hdb_user.mdb"), "user-hash");
    expect(detectPersistedAdminUser(dir)).toBe(true);
  });
});

describe("refusal names the exact recovery command", () => {
  test("persisted-missing-file names both exits verbatim", () => {
    const msg = initAdminPassRefusalMessage("persisted-missing-file", {
      dataDir: "/tmp/flair-data",
      adminPassPath: "/tmp/admin-pass",
    });
    expect(msg).toContain(INIT_RESET_ADMIN_PASS_COMMAND);
    expect(msg).toContain(INIT_ADMIN_PASS_FILE_COMMAND);
    expect(msg).toContain("/tmp/flair-data");
    expect(msg).toContain("/tmp/admin-pass");
    expect(msg).not.toMatch(/generate/i);
  });

  test("foreign-instance names flair stop verbatim", () => {
    const msg = initAdminPassRefusalMessage("foreign-instance", { httpPort: 19926 });
    expect(msg).toContain(INIT_STOP_FOREIGN_COMMAND);
    expect(msg).toContain("19926");
  });

  test("reset-without-socket names flair init --reset-admin-pass", () => {
    const msg = initAdminPassRefusalMessage("reset-without-socket");
    expect(msg).toContain(INIT_RESET_ADMIN_PASS_COMMAND);
  });
});

describe("adminPassDesyncFinding — doctor report-only", () => {
  test("flags missing file + persisted user", () => {
    const finding = adminPassDesyncFinding({
      adminPassFileExists: false,
      persistedAdminUser: true,
      dataDir: "/data",
      adminPassPath: "/pass",
    });
    expect(finding?.flagged).toBe(true);
    expect(finding?.remedy).toContain(INIT_RESET_ADMIN_PASS_COMMAND);
    expect(finding?.remedy).toContain(INIT_ADMIN_PASS_FILE_COMMAND);
  });

  test("silent when the file exists or there is no persisted user", () => {
    expect(adminPassDesyncFinding({ adminPassFileExists: true, persistedAdminUser: true })).toBeNull();
    expect(adminPassDesyncFinding({ adminPassFileExists: false, persistedAdminUser: false })).toBeNull();
  });
});

describe("rotateAdminPasswordViaOpsSocket — no Authorization header", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) {
      try { rmSync(d, { recursive: true, force: true }); } catch { /* */ }
    }
  });

  test("POSTs alter_user over the unix socket without Authorization", async () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    const socketPath = join(dir, "operations-server");
    const seen: { headers: Record<string, string | string[] | undefined>; body: unknown }[] = [];

    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on("end", () => {
        seen.push({
          headers: req.headers as Record<string, string | string[] | undefined>,
          body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "ok" }));
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.listen(socketPath, () => resolve());
      server.on("error", reject);
    });
    try {
      await rotateAdminPasswordViaOpsSocket(socketPath, "admin", "new-secret");
      expect(seen).toHaveLength(1);
      expect(seen[0]!.headers.authorization).toBeUndefined();
      expect(seen[0]!.body).toEqual({
        operation: "alter_user",
        username: "admin",
        password: "new-secret",
        role: "super_user",
        active: true,
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("callOpsSocket surfaces a 401 instead of writing a success", async () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    const socketPath = join(dir, "operations-server");
    const server = createServer((_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Login failed" }));
    });
    await new Promise<void>((resolve, reject) => {
      server.listen(socketPath, () => resolve());
      server.on("error", reject);
    });
    try {
      await expect(rotateAdminPasswordViaOpsSocket(socketPath, "admin", "x")).rejects.toThrow(/401/);
      expect(existsSync(join(dir, "admin-pass"))).toBe(false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test("callOpsSocket is the transport rotate uses (same socket POST)", async () => {
    const dir = makeTmpDir();
    dirs.push(dir);
    const socketPath = join(dir, "operations-server");
    const server = createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
    await new Promise<void>((resolve, reject) => {
      server.listen(socketPath, () => resolve());
      server.on("error", reject);
    });
    try {
      const result = await callOpsSocket(socketPath, { operation: "list_users" });
      expect(result.status).toBe(200);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
