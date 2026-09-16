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
import {
  FEDERATION_INSTANCE_PATH,
  FEDERATION_PAIR_HUB_ACCESS_ERROR_NAME,
  FEDERATION_PAIR_LOCAL_ACCESS_ERROR_NAME,
  PAIR_INITIATOR_FIX_COMMAND,
  PAIR_INITIATOR_ROLE,
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
  expect(msg).toContain("FLAIR_ADMIN_AGENTS");
  expect(msg).toContain("flair principal promote");
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
  test("pair action rewrites the local FederationInstance GET, not the hub POST", () => {
    const pairSrc = pairActionSource();
    expect(pairSrc).toContain("rewriteFederationPairLocalAccessError");
    expect(pairSrc).toContain("rewriteFederationPairHubAccessError");
    expect(pairSrc).toContain('api("GET", "/FederationInstance"');
  });
});
