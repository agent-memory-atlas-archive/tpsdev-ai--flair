/**
 * Spoke pair local-identity denial (flair#820).
 *
 * `flair federation pair` starts with a signed GET of /FederationInstance
 * (CLI tooling — peers never call this path during the handshake). That
 * resource is allowAdmin. When the invoking agent is not a runtime admin,
 * Harper returns a raw `error:AccessViolation` JSON body and pair printed
 * it unchanged — operators read a HUB auth failure and spent hours on
 * hub theories. The failing call is LOCAL.
 *
 * Named error + operator sentence live here so the contract can be
 * unit-tested without driving process.exit. Pair wraps only the identity
 * GET; later failures (token, hub POST, local Peer write) keep their
 * own messages.
 */

export const FEDERATION_INSTANCE_PATH = "/FederationInstance";
export const FEDERATION_PAIR_LOCAL_ACCESS_ERROR_NAME = "FederationPairLocalAccessError";
export const FEDERATION_PAIR_HUB_ACCESS_ERROR_NAME = "FederationPairHubAccessError";
export const PAIR_INITIATOR_ROLE = "flair_pair_initiator";
export const PAIR_INITIATOR_FIX_COMMAND = "flair init --remote";

export type FederationPairAccessSide = "LOCAL" | "REMOTE";

export class FederationPairLocalAccessError extends Error {
  readonly status = 403;
  readonly side: FederationPairAccessSide;
  readonly path = FEDERATION_INSTANCE_PATH;
  constructor(message: string, side: FederationPairAccessSide = "LOCAL") {
    super(message);
    this.name = FEDERATION_PAIR_LOCAL_ACCESS_ERROR_NAME;
    this.side = side;
  }
}

export class FederationPairHubAccessError extends Error {
  readonly status: number;
  readonly side = "HUB" as const;
  constructor(message: string, status = 403) {
    super(message);
    this.name = FEDERATION_PAIR_HUB_ACCESS_ERROR_NAME;
    this.status = status;
  }
}

function errorText(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && err && "message" in err) {
    return String((err as { message?: unknown }).message ?? err);
  }
  return String(err);
}

function errorStatus(err: unknown): number | undefined {
  if (typeof err === "object" && err && "status" in err) {
    const status = (err as { status?: unknown }).status;
    return typeof status === "number" ? status : undefined;
  }
  return undefined;
}

/**
 * True for the Harper AccessViolation 403 pair's identity GET surfaces
 * today (ApiHttpError.status === 403, or a body/message carrying
 * `error:AccessViolation`). Connect failures stay out.
 */
export function isFederationInstanceAccessViolation(err: unknown): boolean {
  if (!err) return false;
  if (errorStatus(err) === 403) return true;
  return /AccessViolation/i.test(errorText(err));
}

export function describeFederationPairLocalAccessError(opts: {
  url: string;
  side?: FederationPairAccessSide;
  agentId?: string | null;
}): string {
  const side = opts.side ?? "LOCAL";
  const base = opts.url.replace(/\/$/, "");
  const agent = opts.agentId && opts.agentId.trim() ? opts.agentId.trim() : "<unknown>";
  return (
    `pair: cannot read ${side} instance identity ` +
    `(GET ${base}${FEDERATION_INSTANCE_PATH} → 403 AccessViolation). ` +
    `Missing role/grant: agent '${agent}' is not a runtime admin ` +
    `(${FEDERATION_INSTANCE_PATH} is allowAdmin). ` +
    `Fix: add '${agent}' to FLAIR_ADMIN_AGENTS in the SERVER process env ` +
    `(not just .env), or grant the admin role with \`flair principal promote ${agent}\`. ` +
    `Hub pairing role: if pairing later fails because the hub is missing ` +
    `${PAIR_INITIATOR_ROLE}, restore it with \`${PAIR_INITIATOR_FIX_COMMAND}\`.`
  );
}

export function rewriteFederationPairLocalAccessError(
  err: unknown,
  opts: { url: string; side?: FederationPairAccessSide; agentId?: string | null },
): unknown {
  if (!isFederationInstanceAccessViolation(err)) return err;
  return new FederationPairLocalAccessError(
    describeFederationPairLocalAccessError(opts),
    opts.side ?? "LOCAL",
  );
}

/**
 * Hub POST /FederationPair 403 (or a role-not-found body) is a different
 * side and a different missing role: `flair_pair_initiator`, created by
 * `flair init --remote`. Same named-error family so pair never dumps a
 * raw AccessViolation for this path either.
 */
export function isFederationPairHubAccessDenial(status: number, body: string): boolean {
  if (status === 403) return true;
  return /AccessViolation|role[- ]?not[- ]?found|flair_pair_initiator/i.test(body);
}

export function describeFederationPairHubAccessError(opts: {
  hubUrl: string;
  status: number;
}): string {
  const hub = opts.hubUrl.replace(/\/$/, "");
  return (
    `pair: HUB rejected the pairing request ` +
    `(POST ${hub}/FederationPair → ${opts.status}). ` +
    `Missing role/grant: the hub may lack ${PAIR_INITIATOR_ROLE}. ` +
    `Fix: re-run \`${PAIR_INITIATOR_FIX_COMMAND}\` on the hub to restore ` +
    `the pairing role, mint a new token, then retry.`
  );
}

export function rewriteFederationPairHubAccessError(
  status: number,
  hubUrl: string,
  body: string,
): FederationPairHubAccessError | null {
  if (!isFederationPairHubAccessDenial(status, body)) return null;
  return new FederationPairHubAccessError(
    describeFederationPairHubAccessError({ hubUrl, status, body }),
    status,
  );
}
