# Dropbox to Make classification shim

A Cloudflare Worker that turns Dropbox file events into clean webhook calls to Make. The Worker does only the hard Dropbox part (signature verification, cursor resolution, deduplication). Make does the classification, renaming, filing, original move, and logging.

```
ScanSnap (OCR on) -> [SOURCE]
  -> Dropbox webhook -> Cloudflare Worker (this repo)
        verify signature, resolve changed file via cursor, dedup
  -> POST metadata to Make webhook
        Make: download -> AI classify -> rename -> file to CUR tree
              -> move original to processed subfolder -> append log
```

The Worker forwards file metadata (path, id, rev, size), not the file bytes. Make downloads the PDF itself through its own Dropbox connection, which keeps the Worker tiny and avoids pushing base64 through the webhook.

## Prerequisites

- A Cloudflare account with Workers (free plan is sufficient at 30 to 150 documents/month).
- Node.js and `wrangler` installed (`npm i -g wrangler`), then `wrangler login`.
- A Dropbox account (the personal one that receives the scanner output).
- A Make account with one scenario (built below).

## 1. Create a Dropbox app

1. Go to the Dropbox App Console and create an app.
2. Access type: **Full Dropbox** if the CUR tree lives outside an app folder, or **App folder** if you scope everything under one folder. The Worker filters to the source folder either way.
3. Permissions (scopes): `files.metadata.read`, `files.content.read`.
4. Note the **App key** and **App secret**.

Note: Make needs `files.content.write` and `files.content.read` on its own Dropbox connection for the move and upload steps; that is separate from this app.

## 2. Get a Dropbox refresh token (one time)

Dropbox access tokens are short lived, so the Worker uses a long-lived refresh token.

1. In a browser, authorize the app with offline access (replace `APP_KEY`):
   ```
   https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&token_access_type=offline&response_type=code
   ```
2. Copy the authorization `code` Dropbox shows you.
3. Exchange it for a refresh token (replace `CODE`, `APP_KEY`, `APP_SECRET`):
   ```bash
   curl https://api.dropbox.com/oauth2/token \
     -d code=CODE \
     -d grant_type=authorization_code \
     -d client_id=APP_KEY \
     -d client_secret=APP_SECRET
   ```
4. Store the `refresh_token` from the JSON response.

## 3. Create the KV namespace

```bash
wrangler kv namespace create STATE
```

Paste the returned `id` into `wrangler.toml`.

## 4. Set secrets and th

e intake folder

```bash
wrangler secret put DROPBOX_APP_KEY
wrangler secret put DROPBOX_APP_SECRET
wrangler secret put DROPBOX_REFRESH_TOKEN
wrangler secret put DROPBOX_SOURCE
wrangler secret put MAKE_WEBHOOK_URL        # from step 7 (Make custom webhook URL)
wrangler secret put MAKE_SHARED_SECRET      # any long random string you choose
```

## 5. Deploy

```bash
wrangler deploy
```

Note the deployed URL, for example `https://dropbox-to-make.<subdomain>.workers.dev`.

## 6. Register the webhook in Dropbox

1. In the Dropbox App Console, under **Webhooks**, add the Worker URL.
2. Dropbox immediately sends a GET challenge; the Worker echoes it, so the webhook shows **Enabled**.
3. The first real notification initializes the cursor and processes no backlog by design (only files added after this moment are forwarded). To also process what is already sitting in the intake folder, delete the `cursor` key from KV once, or drop a fresh copy of each file in.

## 7. Build the Make scenario

Create one scenario fit to the handling you need.

1. **Webhook (custom webhook)** trigger. Copy its URL into `MAKE_WEBHOOK_URL` (step 4).
2. **Filter** right after the trigger: continue only if `X-MAKE-APIKEY` header equals your `MAKE_SHARED_SECRET`. This rejects anything not from the Worker.
3. **Dropbox > Download a file**, using `dropbox.path_lower` from the payload.
4. **AI classification** (OpenAI / Gemini / Anthropic module, your choice for accuracy). Send the PDF (or its extracted text) with your prompt. Enforce the JSON schema in the prompt.
5. **Parse JSON** on the model output (reuse your existing schema).
6. Build the values / routers / etc.
7. **Dropbox > Upload a file** at the chosen destination with `newFileName`. Choose autorename or overwrite on collision (your call).
8. **Dropbox > Move a file**: move the original from the intake folder to a processed subfolder. The Worker watches the intake folder non-recursively, so this move does not re-trigger.
9. **Logging**: append a CSV line (timestamp, original name, person_path, document_type, newFileName, needs_review, amount_chf, deadline_iso) to a Dropbox log file, mirroring your current log. Optional: add a Teams or Slack notification for successes and errors.

## Notes and limits

- **Response timing**: Dropbox requires a response within about 10 seconds. The Worker answers 200 immediately and does the work in `waitUntil`, so a burst of scans is safe.
- **Deduplication**: the Worker keys on `id:rev` with a 24h TTL to guard against Dropbox sending several notifications for the same change. Because Make moves originals out of the intake folder, re-listing does not re-forward them anyway.
- **Missed webhooks**: the optional 30-minute cron in `wrangler.jsonc` reconciles using the same cursor. Remove it if you want the webhook to be the sole trigger.
- **Cost at your volume**: Worker requests, KV operations and the cron all sit inside the Cloudflare free tier for 30 to 150 documents/month. Make Core (~9 USD/month) covers the classification and filing; a webhook-triggered Make scenario consumes one operation per real event, not per poll.
- **Single account**: the Worker assumes one Dropbox account (one refresh token). Multi-account would add an account-to-token lookup in `processChanges`.
- **PDF size**: at up to ~10 pages the Worker never touches the bytes (it forwards metadata), so size is a non-issue on the Worker side; watch Make's monthly data-transfer allowance if documents grow.
