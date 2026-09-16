/**
 * federation-pair-local-access.test.ts — flair#820 (fails-first)
 *
 * On main, `flair federation pair` dumps Harper's raw AccessViolation
 * JSON when the identity GET 403s. The contract is a named error whose
 * message names the LOCAL side, the path, the missing role/grant, and
 * the pairing-role fix command (`flair init --remote` → flair_pair_initiator).
 *
 * The pair action itself calls api() + process.exit, so (same convention
 * as cli-federation-status-fetch.test.ts) the helpers are what we unit-test.
 * A source-text tripwire pins the action to the rewriter.
 */

import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ApiHttpError } from "../../src/lib/auth-resolve.ts";
import { program } from "../../src/cli.ts";
import {
  ADMIN_AGENTS_ENV,
  FEDERATION_INSTANCE_PATH,
  FEDERATION_PAIR_HUB_ACCESS_ERROR_NAME,
  FEDERATION_PAIR_LOCAL_ACCESS_ERROR_NAME,
  PAIR_INITIATOR_FIX_COMMAND,
  PAIR_INITIATOR_ROLE,
  PRINCIPAL_PROMOTE_COMMAND,
  FederationPairHubAccessError,
  FederationPairLocalAccessError,
  describeFederationPairHubAccessError,
  describeFederationPairLocalAccessError,
  isFederationInstanceAccessViolation,
  isFederationPairHubAccessDenial,
  rewriteFederationPairHubAccessError,
  rewriteFederationPairLocalAccessError,
} from "../../src/lib/federation-pair-access.ts";

const RAW_ACCESS_VIOLATION =
  '{"type":"error:AccessViolation","error":"forbidden","instance":"/FederationInstance"}';
const IDENTITY_URL = "http://localhost:9926";
const AGENT_ID = "agent-spoke-1";

function pairActionSource(): string {
  const src = readFileSync(join(import.meta.dir, "../../src/commands/federation.ts"), "utf8");
  const start = src.indexOf('.command("pair <hub-url>")');
  const end = src.indexOf('.command("token")', start);
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return src.slice(start, end);
}

function assertLocalMessageShape(msg: string): void {
  expect(msg).toContain("pair:");
  expect(msg).toContain("LOCAL");
  expect(msg).toContain(FEDERATION_INSTANCE_PATH);
  expect(msg).toContain("403");
  expect(msg).toContain("AccessViolation");
  expect(msg).toMatch(/role\/grant/i);
  expect(msg).toContain(ADMIN_AGENTS_ENV);
  expect(msg).toContain(PRINCIPAL_PROMOTE_COMMAND);
  expect(msg).toContain(PAIR_INITIATOR_FIX_COMMAND);
  expect(msg).toContain(PAIR_INITIATOR_ROLE);
  expect(msg).not.toMatch(/^\s*\{\s*"type"\s*:\s*"error:AccessViolation"/);
}

describe("describeFederationPairLocalAccessError — message shape (flair#820)", () => {
  test("names LOCAL side, path, 403, missing role/grant, and init --remote fix", () => {
    const msg = describeFederationPairLocalAccessError({
      url: IDENTITY_URL,
      agentId: AGENT_ID,
    });
    assertLocalMessageShape(msg);
    expect(msg).toContain(`GET ${IDENTITY_URL}${FEDERATION_INSTANCE_PATH} → 403 AccessViolation`);
    expect(msg).toContain(`agent '${AGENT_ID}'`);
    expect(msg).toContain(`flair principal promote ${AGENT_ID}`);
  });

  test("unknown agent still names the grant and pairing-role fix", () => {
    const msg = describeFederationPairLocalAccessError({ url: IDENTITY_URL });
    assertLocalMessageShape(msg);
    expect(msg).toContain("agent '<unknown>'");
  });
});

describe("rewriteFederationPairLocalAccessError", () => {
  test("wraps ApiHttpError 403 AccessViolation as the named error", () => {
    const raw = new ApiHttpError(403, RAW_ACCESS_VIOLATION);
    const rewritten = rewriteFederationPairLocalAccessError(raw, {
      url: IDENTITY_URL,
      agentId: AGENT_ID,
    });
    expect(rewritten).toBeInstanceOf(FederationPairLocalAccessError);
    expect((rewritten as Error).name).toBe(FEDERATION_PAIR_LOCAL_ACCESS_ERROR_NAME);
    assertLocalMessageShape((rewritten as Error).message);
    expect((rewritten as FederationPairLocalAccessError).status).toBe(403);
    expect((rewritten as FederationPairLocalAccessError).side).toBe("LOCAL");
    expect((rewritten as FederationPairLocalAccessError).path).toBe(FEDERATION_INSTANCE_PATH);
  });

  test("wraps a bare AccessViolation message (no status field)", () => {
    const rewritten = rewriteFederationPairLocalAccessError(new Error(RAW_ACCESS_VIOLATION), {
      url: "http://127.0.0.1:19926",
      agentId: AGENT_ID,
    });
    expect(rewritten).toBeInstanceOf(FederationPairLocalAccessError);
    assertLocalMessageShape((rewritten as Error).message);
  });

  test("leaves connect failures and non-403 HTTP errors untouched", () => {
    const connect = new Error("fetch failed");
    const notFound = new ApiHttpError(404, "HTTP 404");
    expect(rewriteFederationPairLocalAccessError(connect, { url: IDENTITY_URL })).toBe(connect);
    expect(rewriteFederationPairLocalAccessError(notFound, { url: IDENTITY_URL })).toBe(notFound);
    expect(isFederationInstanceAccessViolation(connect)).toBe(false);
    expect(isFederationInstanceAccessViolation(notFound)).toBe(false);
  });
});

describe("hub pairing-role denial — init --remote fix command", () => {
  test("hub 403 message names flair_pair_initiator and flair init --remote", () => {
    const msg = describeFederationPairHubAccessError({
      hubUrl: "https://hub.example:19926",
      status: 403,
    });
    expect(msg).toContain("pair:");
    expect(msg).toContain("HUB");
    expect(msg).toContain("/FederationPair");
    expect(msg).toContain("403");
    expect(msg).toMatch(/role\/grant/i);
    expect(msg).toContain(PAIR_INITIATOR_ROLE);
    expect(msg).toContain(PAIR_INITIATOR_FIX_COMMAND);
    const named = rewriteFederationPairHubAccessError(
      403,
      "https://hub.example:19926",
      RAW_ACCESS_VIOLATION,
    );
    expect(named).toBeInstanceOf(FederationPairHubAccessError);
    expect(named?.name).toBe(FEDERATION_PAIR_HUB_ACCESS_ERROR_NAME);
    expect(isFederationPairHubAccessDenial(400, "role not found: flair_pair_initiator")).toBe(true);
    expect(isFederationPairHubAccessDenial(401, "invalid_or_expired_pairing_token")).toBe(false);
  });
});

describe("wiring — pair identity GET uses the named rewriter", () => {
  test("LOCAL rewriter is scoped to the identity GET only (Flint #820)", () => {
    const pairSrc = pairActionSource();
    const getIdx = pairSrc.indexOf('api("GET", "/FederationInstance"');
    const localRewriteIdx = pairSrc.indexOf("rewriteFederationPairLocalAccessError");
    const hubRewriteIdx = pairSrc.indexOf("rewriteFederationPairHubAccessError");
    const secretKeyIdx = pairSrc.indexOf("loadInstanceSecretKey");
    const hubPostIdx = pairSrc.indexOf("/FederationPair");
    expect(getIdx).toBeGreaterThan(-1);
    expect(localRewriteIdx).toBeGreaterThan(getIdx);
    expect(localRewriteIdx).toBeLessThan(secretKeyIdx);
    expect(hubRewriteIdx).toBeGreaterThan(secretKeyIdx);
    expect(hubPostIdx).toBeGreaterThan(secretKeyIdx);
    expect(pairSrc.split("rewriteFederationPairLocalAccessError").length - 1).toBe(1);
  });
});

/**
 * PLAN ACCEPTED condition (tps-flint on #1711): every remedy the new
 * errors name must resolve against the CLI command table or current docs.
 * A fix hint that names a missing surface is worse than none.
 */
function findCommand(root: { commands: readonly { name: () => string }[] }, path: string[]): any {
  let node: any = root;
  for (const name of path) {
    node = node.commands.find((c: any) => c.name() === name);
    if (!node) return null;
  }
  return node;
}

function backtickSpans(text: string): string[] {
  return [...text.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

function resolveFlairInvocation(invocation: string): void {
  expect(invocation.startsWith("flair ")).toBe(true);
  const tokens = invocation.slice("flair ".length).trim().split(/\s+/);
  let node: any = program;
  let i = 0;
  while (i < tokens.length && !tokens[i].startsWith("-")) {
    const next = node.commands?.find((c: any) => c.name() === tokens[i]);
    if (!next) break;
    node = next;
    i++;
  }
  expect(node).not.toBe(program);
  expect(node?.name?.()).toBeTruthy();
  while (i < tokens.length) {
    const token = tokens[i];
    if (token.startsWith("--")) {
      const longs = (node.options ?? []).map((o: any) => o.long);
      expect(longs, `${invocation} names missing flag ${token} on \`${node.name()}\``).toContain(token);
    }
    i++;
  }
}

describe("pair-access remedies resolve against CLI / docs (PLAN ACCEPTED #820)", () => {
  const localMsg = describeFederationPairLocalAccessError({
    url: IDENTITY_URL,
    agentId: AGENT_ID,
  });
  const hubMsg = describeFederationPairHubAccessError({
    hubUrl: "https://hub.example:19926",
    status: 403,
  });
  const named = `${localMsg}\n${hubMsg}`;

  test("messages still name the accepted remedies", () => {
    expect(named).toContain(ADMIN_AGENTS_ENV);
    expect(named).toContain(PRINCIPAL_PROMOTE_COMMAND);
    expect(named).toContain(PAIR_INITIATOR_FIX_COMMAND);
    expect(named).toContain(PAIR_INITIATOR_ROLE);
  });

  test("every backtick flair invocation exists on the CLI command table", () => {
    const invocations = backtickSpans(named).filter((span) => span.startsWith("flair "));
    expect(invocations.length).toBeGreaterThan(0);
    expect(invocations.some((s) => s.startsWith(PRINCIPAL_PROMOTE_COMMAND))).toBe(true);
    expect(invocations).toContain(PAIR_INITIATOR_FIX_COMMAND);
    for (const invocation of invocations) resolveFlairInvocation(invocation);
  });

  test("FLAIR_ADMIN_AGENTS is a current server-process env surface", () => {
    const example = readFileSync(join(import.meta.dir, "../../.env.example"), "utf8");
    const reader = readFileSync(join(import.meta.dir, "../../resources/agent-auth.ts"), "utf8");
    expect(example).toContain(ADMIN_AGENTS_ENV);
    expect(example).toMatch(new RegExp(`${ADMIN_AGENTS_ENV}=agent-a,agent-b flair start`));
    expect(reader).toContain(`process.env.${ADMIN_AGENTS_ENV}`);
  });

  test("flair principal promote is on the CLI command table", () => {
    const promote = findCommand(program, ["principal", "promote"]);
    expect(promote, "missing `flair principal promote`").not.toBeNull();
    expect(promote.name()).toBe("promote");
  });

  test("flair init --remote exists and restores flair_pair_initiator", () => {
    const init = findCommand(program, ["init"]);
    expect(init, "missing `flair init`").not.toBeNull();
    const longs = init.options.map((o: any) => o.long);
    expect(longs).toContain("--remote");
    const initSrc = readFileSync(join(import.meta.dir, "../../src/commands/init.ts"), "utf8");
    expect(initSrc).toContain("if (opts.remote)");
    expect(initSrc).toContain("ensureFlairPairInitiatorRole");
    const docs = readFileSync(join(import.meta.dir, "../../docs/federation.md"), "utf8");
    expect(docs).toContain(PAIR_INITIATOR_ROLE);
    expect(docs).toContain(PAIR_INITIATOR_FIX_COMMAND);
  });
});
