/**
 * Dropbox -> Make webhook shim (Cloudflare Worker).
 *
 * This Worker is ONLY the Dropbox hook: it does not classify or move files.
 *
 * Flow:
 *   1. Dropbox sends a webhook notification ("an account changed", no file path).
 *   2. The Worker verifies X-Dropbox-Signature (HMAC-SHA256 over the raw body).
 *   3. It answers 200 immediately (Dropbox requires a response within ~10s)
 *      and does the real work asynchronously via `ctx.waitUntil`.
 *   4. For each watched folder, it resolves what changed with
 *      `files/list_folder/continue` using a stored cursor, keeps only new PDFs
 *      that sit directly in that folder, deduplicates them, and forwards each
 *      file's metadata to the Make webhook.
 *
 * Watched folders come from the `DROPBOX_SOURCE` secret: a comma-separated list
 * of Dropbox paths (e.g. `/Scans,/Inbox/Invoices`). Each folder is watched
 * non-recursively. An empty value or `/` means the Dropbox root.
 *
 * State (Cloudflare KV, binding STATE):
 *   - `cursor:<folder>`  : folder state, one per watched folder
 *                          (JSON: {cursor, since}; a bare cursor string is
 *                          still accepted for backward compatibility)
 *   - `token`            : cached Dropbox access token (JSON: {access_token, exp})
 *   - `seen:<id>:<rev>`  : dedup marker with a 24h TTL
 *
 * KV writes are capped at 1,000/day on the Workers Free plan, so the Worker
 * only writes when something actually changed: a folder's cursor is saved only
 * when its listing returned entries, and the access token is also cached in
 * memory to avoid needless KV traffic.
 *
 * A single Dropbox account is assumed (one refresh token).
 *
 * @module
 */

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

/** Subset of a Dropbox `Metadata` entry returned by `files/list_folder`. */
interface DbxEntry {
  ".tag": "file" | "folder" | "deleted";
  id: string;
  name: string;
  path_lower: string;
  path_display: string;
  rev?: string;
  size?: number;
  server_modified?: string;
  content_hash?: string;
}

/** Response of `files/list_folder` and `files/list_folder/continue`. */
interface DbxListResult {
  entries: DbxEntry[];
  cursor: string;
  has_more: boolean;
}

/** Entries collected from a listing, plus the cursor to resume from. */
interface ListOutcome {
  entries: DbxEntry[];
  newCursor: string;
  /** `true` when Dropbox reset the cursor and the folder was fully re-listed. */
  reset: boolean;
}

/** Per-folder state stored under `cursor:<folder>`. */
interface FolderState {
  cursor: string;
  /**
   * Epoch ms at which the listing that produced `cursor` started. Files
   * modified before it were already seen; used to avoid re-forwarding the
   * whole folder after a cursor reset. `0` when unknown.
   */
  since: number;
}

/** Cached Dropbox access token. */
interface CachedToken {
  access_token: string;
  exp: number;
}

/** Error raised when a Dropbox API call fails with a non-retryable status. */
class DropboxError extends Error {
  /**
   * @param endpoint - Dropbox RPC endpoint that failed (e.g. `/files/list_folder`).
   * @param status - HTTP status code returned by Dropbox.
   * @param body - Raw response body (Dropbox error JSON or text).
   * @param requestId - Value of the `x-dropbox-request-id` response header.
   */
  constructor(
    readonly endpoint: string,
    readonly status: number,
    readonly body: string,
    readonly requestId: string,
  ) {
    super(
      `Dropbox ${endpoint} failed status=${status} requestId=${requestId} response=${body}`,
    );
    this.name = "DropboxError";
  }
}

/* -------------------------------------------------------------------------- */
/* Config                                                                     */
/* -------------------------------------------------------------------------- */

const DBX_API = "https://api.dropboxapi.com/2";
const DBX_OAUTH = "https://api.dropbox.com/oauth2/token";
/** Dedup window for `seen:<id>:<rev>` markers. */
const SEEN_TTL_SECONDS = 60 * 60 * 24;
/** Retries for 429 / 5xx Dropbox responses (on top of the first attempt). */
const MAX_DROPBOX_RETRIES = 4;
/**
 * Upper bound for a single retry delay. Background work only has ~30s after
 * the webhook response, so an unbounded `Retry-After` would get it killed.
 */
const MAX_RETRY_DELAY_MS = 5_000;
/** Timeout for the Make webhook call. */
const MAKE_TIMEOUT_MS = 10_000;
/**
 * Safety margin applied to `FolderState.since` after a cursor reset, to absorb
 * clock skew between Cloudflare and Dropbox `server_modified`.
 */
const RESET_SKEW_MS = 5 * 60 * 1000;

/** In-memory token cache, shared by requests served by the same isolate. */
let memoryToken: CachedToken | undefined;

/* -------------------------------------------------------------------------- */
/* Entry points                                                               */
/* -------------------------------------------------------------------------- */

export default {
  /**
   * HTTP entry point.
   * - `GET`: Dropbox webhook verification; echoes the `challenge` query param.
   * - `POST`: change notification; verifies the signature, acknowledges, then
   *   processes changes in the background.
   *
   * @param request - Incoming request from Dropbox.
   * @param env - Worker bindings and secrets.
   * @param ctx - Execution context, used to run work after the response.
   * @returns The HTTP response sent back to Dropbox.
   */
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    if (request.method === "GET") {
      const challenge = new URL(request.url).searchParams.get("challenge") ?? "";
      return new Response(challenge, {
        headers: {
          "Content-Type": "text/plain",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    if (request.method === "POST") {
      // The signature is computed over the exact raw body.
      const raw = await request.text();
      const signature = request.headers.get("X-Dropbox-Signature") ?? "";

      if (!(await verifySignature(raw, signature, env.DROPBOX_APP_SECRET))) {
        console.warn("Rejected webhook: invalid signature");
        return new Response("invalid signature", { status: 403 });
      }

      ctx.waitUntil(
        processChanges(env).catch((e) =>
          console.error("processChanges failed", e),
        ),
      );
      return new Response("ok", { status: 200 });
    }

    return new Response("method not allowed", { status: 405 });
  },

  /**
   * Cron entry point: reconciles on a schedule in case a webhook was missed.
   *
   * @param _event - Scheduled event (unused).
   * @param env - Worker bindings and secrets.
   * @param ctx - Execution context, used to keep the work alive.
   */
  async scheduled(
    _event: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(
      processChanges(env).catch((e) =>
        console.error("scheduled reconcile failed", e),
      ),
    );
  },
} satisfies ExportedHandler<Env>;

/* -------------------------------------------------------------------------- */
/* Core                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Process pending changes for every folder listed in `DROPBOX_SOURCE`.
 * A failure in one folder is logged and does not block the others.
 *
 * @param env - Worker bindings and secrets.
 */
async function processChanges(env: Env): Promise<void> {
  const folders = parseSourceFolders(env.DROPBOX_SOURCE);
  let token = await getAccessToken(env);

  let forwarded = 0;
  for (const folder of folders) {
    try {
      try {
        forwarded += await processFolder(env, token, folder);
      } catch (e) {
        // The cached token may have been revoked or expired early: refresh
        // it once and retry the folder.
        if (!(e instanceof DropboxError && e.status === 401)) throw e;
        console.warn("Dropbox token rejected (401); refreshing and retrying.");
        token = await getAccessToken(env, true);
        forwarded += await processFolder(env, token, folder);
      }
    } catch (e) {
      console.error(`Processing failed for folder "${folder || "/"}"`, e);
    }
  }

  console.log(`processChanges done: ${forwarded} file(s) forwarded.`);
}

/**
 * Resolve changes in one folder and forward new PDFs to Make.
 *
 * The cursor is only advanced when every eligible file was forwarded, so a
 * failed forward is retried on the next webhook or cron run. Files already
 * forwarded are skipped thanks to the dedup markers.
 *
 * To save KV writes, the cursor is not saved when the listing returned no
 * entries: the previous cursor stays valid and simply yields nothing new.
 *
 * After a cursor reset, only files modified since the previous listing are
 * forwarded, so the whole folder is not sent to Make again.
 *
 * @param env - Worker bindings and secrets.
 * @param token - Valid Dropbox access token.
 * @param folder - Normalized Dropbox folder path (`""` for the root).
 * @returns Number of files forwarded to Make.
 */
async function processFolder(
  env: Env,
  token: string,
  folder: string,
): Promise<number> {
  const folderLower = folder.toLowerCase();
  const cursorKey = `cursor:${folderLower}`;
  const state = parseFolderState(await env.STATE.get(cursorKey));
  const startedAt = Date.now();

  const { entries, newCursor, reset } = state
    ? await listChanges(token, state.cursor, folder)
    : await listFolder(token, folder);

  if (!state) {
    console.log(
      `Initialized cursor for "${folder || "/"}" with ${entries.length} existing entries.`,
    );
  }

  // After a reset, skip files that predate the previous listing (they were
  // already handled). Without a known timestamp, fall back to forwarding all.
  const resetCutoff =
    reset && state && state.since > 0 ? state.since - RESET_SKEW_MS : 0;

  let forwarded = 0;
  let failed = 0;

  for (const entry of entries) {
    if (!isTargetPdf(entry, folderLower)) continue;
    if (resetCutoff && modifiedBefore(entry, resetCutoff)) continue;

    const dedupKey = `seen:${entry.id}:${entry.rev}`;
    if (await env.STATE.get(dedupKey)) {
      console.log(`Skip duplicate: ${entry.path_display}`);
      continue;
    }

    try {
      await forwardToMake(env, entry);
      await env.STATE.put(dedupKey, "1", { expirationTtl: SEEN_TTL_SECONDS });
      forwarded++;
      console.log(`Forwarded to Make: ${entry.path_display}`);
    } catch (e) {
      failed++;
      console.error(`Forward failed for ${entry.path_display}`, e);
    }
  }

  if (failed === 0) {
    // Nothing listed means nothing to remember: keep the old cursor and save
    // a KV write. A reset always re-saves, since the old cursor is invalid.
    if (!state || reset || (entries.length > 0 && newCursor !== state.cursor)) {
      const next: FolderState = { cursor: newCursor, since: startedAt };
      await env.STATE.put(cursorKey, JSON.stringify(next));
    }
  } else {
    console.warn(
      `Cursor for "${folder || "/"}" not advanced: ${failed} forward(s) failed, will retry.`,
    );
  }

  return forwarded;
}

/**
 * Parse `DROPBOX_SOURCE` into a list of normalized, unique folder paths.
 *
 * @example
 * parseSourceFolders("/Scans, /Inbox/Invoices/") // ["/Scans", "/Inbox/Invoices"]
 * parseSourceFolders("")                         // [""] (Dropbox root)
 *
 * @param raw - Comma-separated Dropbox paths. Empty or `/` means the root.
 * @returns Normalized folder paths, deduplicated case-insensitively.
 * @throws {Error} If a path does not start with `/`.
 */
function parseSourceFolders(raw: string | undefined): string[] {
  const parts = (raw ?? "")
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "");
  if (parts.length === 0) return [""];

  const unique = new Map<string, string>();
  for (const part of parts) {
    const folder = normalizeDropboxPath(part);
    unique.set(folder.toLowerCase(), folder);
  }
  return [...unique.values()];
}

/**
 * Normalize a Dropbox folder path for the API: trims whitespace and trailing
 * slashes, and maps the root (`/`) to `""` as Dropbox expects.
 *
 * @param path - Raw folder path.
 * @returns Normalized path.
 * @throws {Error} If the path is neither empty nor starts with `/`.
 */
function normalizeDropboxPath(path: string): string {
  const trimmed = path.trim();
  if (trimmed === "" || trimmed === "/") return "";

  if (!trimmed.startsWith("/")) {
    throw new Error(`DROPBOX_SOURCE paths must start with "/": ${trimmed}`);
  }
  return trimmed.replace(/\/+$/, "");
}

/**
 * Keep only `.pdf` files that live DIRECTLY in the watched folder.
 *
 * @param entry - Dropbox metadata entry.
 * @param folderLower - Lower-cased normalized folder path.
 * @returns `true` if the entry should be forwarded.
 */
function isTargetPdf(entry: DbxEntry, folderLower: string): boolean {
  if (entry[".tag"] !== "file") return false; // ignore deletes / folders
  if (!entry.name.toLowerCase().endsWith(".pdf")) return false;
  const parent = entry.path_lower.slice(0, entry.path_lower.lastIndexOf("/"));
  return parent === folderLower;
}

/**
 * Parse the value stored under `cursor:<folder>`. Accepts the JSON
 * {@link FolderState} and, for backward compatibility, a bare cursor string.
 *
 * @param raw - Stored value, or `null` if the key is missing.
 * @returns The folder state, or `undefined` if none is stored.
 */
function parseFolderState(raw: string | null): FolderState | undefined {
  if (!raw) return undefined;
  if (raw.startsWith("{")) {
    try {
      const parsed = JSON.parse(raw) as Partial<FolderState>;
      if (typeof parsed.cursor === "string" && parsed.cursor) {
        return { cursor: parsed.cursor, since: Number(parsed.since) || 0 };
      }
    } catch {
      // Fall through: treat as corrupted and start over.
    }
    console.warn("Ignoring unreadable folder state; re-initializing.");
    return undefined;
  }
  return { cursor: raw, since: 0 };
}

/**
 * Whether a file was last modified on Dropbox strictly before `cutoff`.
 *
 * @param entry - Dropbox file entry.
 * @param cutoff - Epoch ms.
 * @returns `false` when the modification time is unknown.
 */
function modifiedBefore(entry: DbxEntry, cutoff: number): boolean {
  const modified = Date.parse(entry.server_modified ?? "");
  return Number.isFinite(modified) && modified < cutoff;
}

/**
 * POST a file's metadata to the Make webhook.
 *
 * @param env - Worker bindings and secrets (`MAKE_WEBHOOK_URL`, `MAKE_SHARED_SECRET`).
 * @param entry - Dropbox file entry to forward.
 * @throws {Error} If Make answers with a non-2xx status.
 */
async function forwardToMake(env: Env, entry: DbxEntry): Promise<void> {
  const payload = {
    event: "new_file",
    source: "dropbox-classement-worker",
    ts: new Date().toISOString(),
    dedup_key: `${entry.id}:${entry.rev}`,
    dropbox: {
      id: entry.id,
      name: entry.name,
      path_lower: entry.path_lower,
      path_display: entry.path_display,
      rev: entry.rev,
      size: entry.size,
      server_modified: entry.server_modified,
      content_hash: entry.content_hash,
    },
  };

  const res = await fetch(env.MAKE_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Make checks this header so it only accepts events from this Worker.
      "X-Make-Apikey": env.MAKE_SHARED_SECRET,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(MAKE_TIMEOUT_MS),
  });

  if (!res.ok) {
    throw new Error(`Make webhook returned ${res.status}: ${await res.text()}`);
  }
}

/* -------------------------------------------------------------------------- */
/* Dropbox API                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Return a valid Dropbox access token, refreshing it when the cached one is
 * missing or expired. The token is cached in memory first, then in KV.
 *
 * @param env - Worker bindings and secrets.
 * @param forceRefresh - Ignore cached tokens (e.g. after a 401).
 * @returns A short-lived Dropbox access token.
 * @throws {Error} If the refresh request fails.
 */
async function getAccessToken(
  env: Env,
  forceRefresh = false,
): Promise<string> {
  if (!forceRefresh) {
    if (memoryToken && Date.now() < memoryToken.exp) {
      return memoryToken.access_token;
    }

    const cached = parseCachedToken(await env.STATE.get("token"));
    if (cached && Date.now() < cached.exp) {
      memoryToken = cached;
      return cached.access_token;
    }
  }

  const res = await fetch(DBX_OAUTH, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: env.DROPBOX_REFRESH_TOKEN,
      client_id: env.DROPBOX_APP_KEY,
      client_secret: env.DROPBOX_APP_SECRET,
    }),
  });
  if (!res.ok) {
    throw new Error(`Token refresh failed: ${res.status} ${await res.text()}`);
  }

  const data = (await res.json()) as {
    access_token: string;
    expires_in: number;
  };
  // Refresh a minute early to avoid edge expiry.
  const exp = Date.now() + (data.expires_in - 60) * 1000;
  memoryToken = { access_token: data.access_token, exp };
  await env.STATE.put("token", JSON.stringify(memoryToken));
  return data.access_token;
}

/**
 * Parse the KV `token` value, tolerating a missing or corrupted entry.
 *
 * @param raw - Stored value, or `null`.
 * @returns The cached token, or `undefined` if unusable.
 */
function parseCachedToken(raw: string | null): CachedToken | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw) as Partial<CachedToken>;
    if (typeof parsed.access_token === "string" && typeof parsed.exp === "number") {
      return { access_token: parsed.access_token, exp: parsed.exp };
    }
  } catch {
    // Corrupted value: a fresh token will be fetched.
  }
  return undefined;
}

/**
 * List the full current content of a folder (non-recursive) and return the
 * cursor at the end of the listing. Used when no cursor exists yet.
 *
 * @param token - Dropbox access token.
 * @param folder - Normalized folder path (`""` for the root).
 * @returns All entries and the cursor to resume from.
 */
async function listFolder(token: string, folder: string): Promise<ListOutcome> {
  const first = await dbx<DbxListResult>(token, "/files/list_folder", {
    path: folder,
    recursive: false,
    include_deleted: false,
  });
  return drain(token, first, false);
}

/**
 * List changes since `cursor`. If Dropbox reports the cursor as reset
 * (409 `reset`), fall back to a full listing of the folder.
 *
 * @param token - Dropbox access token.
 * @param cursor - Cursor stored after the previous run.
 * @param folder - Normalized folder path, used for the reset fallback.
 * @returns Changed entries and the new cursor.
 */
async function listChanges(
  token: string,
  cursor: string,
  folder: string,
): Promise<ListOutcome> {
  let first: DbxListResult;
  try {
    first = await dbx<DbxListResult>(token, "/files/list_folder/continue", {
      cursor,
    });
  } catch (e) {
    if (e instanceof DropboxError && isCursorReset(e)) {
      console.warn(`Cursor reset by Dropbox for "${folder || "/"}"; re-listing.`);
      const relisted = await listFolder(token, folder);
      return { ...relisted, reset: true };
    }
    throw e;
  }
  return drain(token, first, false);
}

/**
 * Whether a Dropbox error is the `list_folder/continue` "reset" error, i.e.
 * the cursor is no longer valid and the folder must be listed again.
 *
 * @param e - Dropbox error.
 * @returns `true` for a 409 whose `error_summary` starts with `reset`.
 */
function isCursorReset(e: DropboxError): boolean {
  if (e.status !== 409) return false;
  try {
    const parsed = JSON.parse(e.body) as { error_summary?: string };
    return parsed.error_summary?.startsWith("reset") ?? false;
  } catch {
    return false;
  }
}

/**
 * Follow `has_more` pages until the listing is complete.
 *
 * @param token - Dropbox access token.
 * @param page - First page already fetched.
 * @param reset - Value to report as {@link ListOutcome.reset}.
 * @returns All entries across pages and the final cursor.
 */
async function drain(
  token: string,
  page: DbxListResult,
  reset: boolean,
): Promise<ListOutcome> {
  const entries = [...page.entries];
  while (page.has_more) {
    page = await dbx<DbxListResult>(token, "/files/list_folder/continue", {
      cursor: page.cursor,
    });
    entries.push(...page.entries);
  }
  return { entries, newCursor: page.cursor, reset };
}

/**
 * Minimal Dropbox RPC helper (JSON in / JSON out). Retries 429 and 5xx
 * responses, honouring `Retry-After` or falling back to exponential backoff.
 *
 * @typeParam T - Expected response shape.
 * @param token - Dropbox access token.
 * @param endpoint - RPC endpoint path, e.g. `/files/list_folder`.
 * @param args - JSON request body.
 * @returns Parsed JSON response.
 * @throws {DropboxError} On a non-retryable error or once retries are exhausted.
 */
async function dbx<T>(
  token: string,
  endpoint: string,
  args: unknown,
): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(`${DBX_API}${endpoint}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(args),
    });

    const body = await res.text();
    if (res.ok) return JSON.parse(body) as T;

    const requestId = res.headers.get("x-dropbox-request-id") ?? "unavailable";
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= MAX_DROPBOX_RETRIES) {
      throw new DropboxError(endpoint, res.status, body, requestId);
    }

    const retryAfter = Number(res.headers.get("retry-after"));
    const delayMs = Math.min(
      Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : 2 ** attempt * 1000,
      MAX_RETRY_DELAY_MS,
    );

    console.warn("Dropbox request failed; retrying", {
      endpoint,
      status: res.status,
      requestId,
      attempt: attempt + 1,
      delayMs,
      response: body,
    });
    await sleep(delayMs);
  }
}

/**
 * Wait for the given duration.
 *
 * @param ms - Delay in milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* -------------------------------------------------------------------------- */
/* Signature verification                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Verify the HMAC-SHA256 signature Dropbox sends in `X-Dropbox-Signature`.
 *
 * @param raw - Raw request body, exactly as received.
 * @param signatureHex - Hex-encoded signature from the header.
 * @param secret - Dropbox app secret used as HMAC key.
 * @returns `true` if the signature matches.
 */
async function verifySignature(
  raw: string,
  signatureHex: string,
  secret: string,
): Promise<boolean> {
  if (!signatureHex) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(raw));
  const expectedHex = [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return timingSafeEqual(expectedHex, signatureHex.toLowerCase());
}

/**
 * Constant-time string comparison (for equal-length inputs).
 *
 * @param a - First string.
 * @param b - Second string.
 * @returns `true` if both strings are identical.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
