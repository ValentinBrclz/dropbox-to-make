/**
 * Dropbox -> Make webhook shim (Cloudflare Worker)
 * ------------------------------------------------
 * Role: this Worker is ONLY the Dropbox hook. It does not classify or move files.
 *
 * Flow:
 *   1. Dropbox sends a webhook notification ("an account changed", no file path).
 *   2. The Worker verifies the X-Dropbox-Signature (HMAC-SHA256 over the raw body).
 *   3. It answers 200 immediately (Dropbox requires a response within ~10s),
 *      then does the real work asynchronously via ctx.waitUntil.
 *   4. It resolves what actually changed with files/list_folder/continue using a
 *      stored cursor, keeps only new PDFs that sit directly in the intake folder,
 *      deduplicates them, and forwards each file's metadata to the Make webhook.
 *
 * State (Cloudflare KV, binding STATE):
 *   - "cursor"            : the Dropbox list_folder cursor for the intake folder
 *   - "token"             : cached Dropbox access token (JSON: {access_token, exp})
 *   - "seen:<id>:<rev>"   : dedup marker, short TTL (guards against burst duplicates)
 *
 * Single Dropbox account is assumed (one refresh token).
 */

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

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

interface DbxListResult {
  entries: DbxEntry[];
  cursor: string;
  has_more: boolean;
}

/* -------------------------------------------------------------------------- */
/* Config                                                                     */
/* -------------------------------------------------------------------------- */
const DBX_API = "https://api.dropboxapi.com/2";
const DBX_OAUTH = "https://api.dropbox.com/oauth2/token";
const SEEN_TTL_SECONDS = 60 * 60 * 24; // 24h dedup window
const MAX_DROPBOX_RETRIES = 4;

/* -------------------------------------------------------------------------- */
/* Default                                                                    */
/* -------------------------------------------------------------------------- */

export default {
  /** HTTP entry point: GET = webhook verification, POST = change notification. */
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    // Dropbox webhook verification handshake: echo back the challenge.
    if (request.method === "GET") {
      const challenge = url.searchParams.get("challenge") ?? "";
      return new Response(challenge, {
        headers: {
          "Content-Type": "text/plain",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    if (request.method === "POST") {
      // Read the RAW body once; needed both for signature check and (ignored) JSON.
      const raw = await request.text();
      const signature = request.headers.get("X-Dropbox-Signature") ?? "";

      const valid = await verifySignature(
        raw,
        signature,
        env.DROPBOX_APP_SECRET,
      );
      if (!valid) {
        console.warn("Rejected webhook: invalid signature");
        return new Response("invalid signature", { status: 403 });
      }

      // Acknowledge fast, process out of band.
      ctx.waitUntil(
        processChanges(env).catch((e) =>
          console.error("processChanges failed", e),
        ),
      );
      return new Response("ok", { status: 200 });
    }

    return new Response("method not allowed", { status: 405 });
  },

  /** Optional safety net: reconcile on a schedule in case a webhook was missed. */
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
/* Core                                                                        */
/* -------------------------------------------------------------------------- */

async function processChanges(env: Env): Promise<void> {
  const token = await getAccessToken(env);
  const cursor = await env.STATE.get("cursor");

  const { entries, newCursor } = cursor
    ? await listChanges(token, cursor)
    : await listInitialState(env, token);

  await env.STATE.put("cursor", newCursor);

  if (!cursor) {
    console.log(
      `Automatically initialized Dropbox cursor with ${entries.length} existing entries.`,
    );
  }

  const intakeLower = env.DROPBOX_SOURCE.toLowerCase();
  let forwarded = 0;

  for (const entry of entries) {
    if (!isTargetPdf(entry, intakeLower)) continue;

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
      // Do not mark as seen, so the cron safety net retries it next cycle.
      console.error(`Forward failed for ${entry.path_display}`, e);
    }
  }

  console.log(`processChanges done: ${forwarded} file(s) forwarded.`);
}

async function listInitialState(
  env: Env,
  token: string,
): Promise<{ entries: DbxEntry[]; newCursor: string }> {
  const source = normalizeDropboxPath(env.DROPBOX_SOURCE);

  let data = await dbx<DbxListResult>(token, "/files/list_folder", {
    path: source,
    recursive: false,
    include_deleted: false,
  });

  const entries: DbxEntry[] = [...data.entries];

  while (data.has_more) {
    data = await dbx<DbxListResult>(token, "/files/list_folder/continue", {
      cursor: data.cursor,
    });

    entries.push(...data.entries);
  }

  return {
    entries,
    newCursor: data.cursor,
  };
}

function normalizeDropboxPath(path: string | undefined): string {
  const normalized = (path ?? "").trim();

  if (normalized === "" || normalized === "/") {
    return "";
  }

  if (!normalized.startsWith("/")) {
    throw new Error(
      `DROPBOX_SOURCE must be empty or start with "/": ${normalized}`,
    );
  }

  return normalized.replace(/\/+$/, "");
}

/** Keep only .pdf files that live DIRECTLY in the intake folder (not sub-folders). */
function isTargetPdf(entry: DbxEntry, intakeLower: string): boolean {
  if (entry[".tag"] !== "file") return false; // ignore deletes / folders
  if (!entry.name.toLowerCase().endsWith(".pdf")) return false;
  const parent = entry.path_lower.slice(0, entry.path_lower.lastIndexOf("/"));
  return parent === intakeLower;
}

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
      // Make verifies this header so it only accepts events from this Worker.
      "X-Make-Apikey": env.MAKE_SHARED_SECRET,
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw new Error(`Make webhook returned ${res.status}: ${await res.text()}`);
  }
}

/* -------------------------------------------------------------------------- */
/* Dropbox API                                                                 */
/* -------------------------------------------------------------------------- */

/** Return a valid access token, refreshing (and caching in KV) when needed. */
async function getAccessToken(env: Env): Promise<string> {
  const cached = await env.STATE.get("token");
  if (cached) {
    const { access_token, exp } = JSON.parse(cached) as {
      access_token: string;
      exp: number;
    };
    if (Date.now() < exp) return access_token;
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: env.DROPBOX_REFRESH_TOKEN,
    client_id: env.DROPBOX_APP_KEY,
    client_secret: env.DROPBOX_APP_SECRET,
  });

  const res = await fetch(DBX_OAUTH, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok)
    throw new Error(`Token refresh failed: ${res.status} ${await res.text()}`);

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

async function listChanges(
  token: string,
  cursor: string,
): Promise<{ entries: DbxEntry[]; newCursor: string }> {
  const entries: DbxEntry[] = [];
  let currentCursor = cursor;
  let hasMore = true;

  while (hasMore) {
    const data = await dbx<DbxListResult>(
      token,
      "/files/list_folder/continue",
      {
        cursor: currentCursor,
      },
    );
    entries.push(...data.entries);
    currentCursor = data.cursor;
    hasMore = data.has_more;
  }

  return { entries, newCursor: currentCursor };
}

/** Minimal Dropbox RPC helper (JSON in / JSON out). */
async function dbx<T>(
  token: string,
  endpoint: string,
  args: unknown,
): Promise<T> {
  for (let attempt = 0; attempt <= MAX_DROPBOX_RETRIES; attempt++) {
    const res = await fetch(`${DBX_API}${endpoint}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(args),
    });

    const responseText = await res.text();
    const requestId = res.headers.get("x-dropbox-request-id") ?? "unavailable";

    if (res.ok) {
      return JSON.parse(responseText) as T;
    }

    const retryable = res.status === 429 || res.status >= 500;

    if (retryable && attempt < MAX_DROPBOX_RETRIES) {
      const retryAfterHeader = res.headers.get("retry-after");
      const retryAfterSeconds = retryAfterHeader
        ? Number(retryAfterHeader)
        : 2 ** attempt;

      const delayMs =
        Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
          ? retryAfterSeconds * 1000
          : 2 ** attempt * 1000;

      console.warn("Dropbox request failed; retrying", {
        endpoint,
        status: res.status,
        requestId,
        attempt: attempt + 1,
        delayMs,
        response: responseText,
      });

      await sleep(delayMs);
      continue;
    }

    throw new Error(
      [
        `Dropbox ${endpoint} failed`,
        `status=${res.status}`,
        `requestId=${requestId}`,
        `response=${responseText}`,
      ].join(" "),
    );
  }

  throw new Error(`Dropbox ${endpoint} exhausted retries`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* -------------------------------------------------------------------------- */
/* Signature verification                                                      */
/* -------------------------------------------------------------------------- */

/** Verify the HMAC-SHA256 signature Dropbox sends in X-Dropbox-Signature (hex). */
async function verifySignature(
  raw: string,
  signatureHex: string,
  secret: string,
): Promise<boolean> {
  if (!signatureHex) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(raw),
  );
  const expectedHex = [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return timingSafeEqual(expectedHex, signatureHex.toLowerCase());
}

/** Constant-time string comparison. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
