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
 *   - `cursor:<folder>`  : Dropbox list_folder cursor, one per watched folder
 *   - `token`            : cached Dropbox access token (JSON: {access_token, exp})
 *   - `seen:<id>:<rev>`  : dedup marker with a 24h TTL
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
  const token = await getAccessToken(env);

  let forwarded = 0;
  for (const folder of folders) {
    try {
      forwarded += await processFolder(env, token, folder);
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
  const cursor = await env.STATE.get(cursorKey);

  const { entries, newCursor } = cursor
    ? await listChanges(token, cursor, folder)
    : await listFolder(token, folder);

  if (!cursor) {
    console.log(
      `Initialized cursor for "${folder || "/"}" with ${entries.length} existing entries.`,
    );
  }

  let forwarded = 0;
  let failed = 0;

  for (const entry of entries) {
    if (!isTargetPdf(entry, folderLower)) continue;

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
    await env.STATE.put(cursorKey, newCursor);
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
  });

  if (!res.ok) {
    throw new Error(`Make webhook returned ${res.status}: ${await res.text()}`);
  }
}

/* -------------------------------------------------------------------------- */
/* Dropbox API                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Return a valid Dropbox access token, refreshing it (and caching it in KV)
 * when the cached one is missing or expired.
 *
 * @param env - Worker bindings and secrets.
 * @returns A short-lived Dropbox access token.
 * @throws {Error} If the refresh request fails.
 */
async function getAccessToken(env: Env): Promise<string> {
  const cached = await env.STATE.get("token");
  if (cached) {
    const { access_token, exp } = JSON.parse(cached) as {
      access_token: string;
      exp: number;
    };
    if (Date.now() < exp) return access_token;
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
  await env.STATE.put(
    "token",
    JSON.stringify({ access_token: data.access_token, exp }),
  );
  return data.access_token;
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
  return drain(token, first);
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
    if (e instanceof DropboxError && e.status === 409 && e.body.includes("reset")) {
      console.warn(`Cursor reset by Dropbox for "${folder || "/"}"; re-listing.`);
      return listFolder(token, folder);
    }
    throw e;
  }
  return drain(token, first);
}

/**
 * Follow `has_more` pages until the listing is complete.
 *
 * @param token - Dropbox access token.
 * @param page - First page already fetched.
 * @returns All entries across pages and the final cursor.
 */
async function drain(token: string, page: DbxListResult): Promise<ListOutcome> {
  const entries = [...page.entries];
  while (page.has_more) {
    page = await dbx<DbxListResult>(token, "/files/list_folder/continue", {
      cursor: page.cursor,
    });
    entries.push(...page.entries);
  }
  return { entries, newCursor: page.cursor };
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
    const delayMs =
      Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : 2 ** attempt * 1000;

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
