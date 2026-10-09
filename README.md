# dropbox-to-make

Cloudflare Worker that receives Dropbox webhooks and forwards new PDF files to a Make webhook.

It verifies the Dropbox signature, resolves what changed using a stored cursor per folder, keeps only `.pdf` files placed **directly** in the watched folders (sub-folders are ignored), deduplicates them, and POSTs their metadata to Make. File bytes are not forwarded; Make downloads the file through its own Dropbox connection.

## Configuration

| Secret                  | Description                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| `DROPBOX_APP_KEY`       | Dropbox app key.                                                                                              |
| `DROPBOX_APP_SECRET`    | Dropbox app secret (also used to verify webhook signatures).                                                  |
| `DROPBOX_REFRESH_TOKEN` | Long-lived Dropbox refresh token.                                                                              |
| `DROPBOX_SOURCE`        | Comma-separated folders to watch, non-recursively, e.g. `/Scans,/Inbox/Invoices`. Empty or `/` = Dropbox root. |
| `MAKE_WEBHOOK_URL`      | Make custom webhook URL.                                                                                       |
| `MAKE_SHARED_SECRET`    | Random string sent as `X-Make-Apikey`; filter on it in Make.                                                   |

State is stored in the `STATE` KV namespace (cursors, cached access token, 24h dedup markers).

## Setup

1. **Dropbox app**: create one in the Dropbox App Console with scopes `files.metadata.read` and `files.content.read`.
2. **Refresh token**: open
   `https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&token_access_type=offline&response_type=code`,
   then exchange the code:
   ```bash
   curl https://api.dropbox.com/oauth2/token \
     -d code=CODE -d grant_type=authorization_code \
     -d client_id=APP_KEY -d client_secret=APP_SECRET
   ```
3. **KV namespace**: `npx wrangler kv namespace create STATE`, then put the returned `id` in `wrangler.toml`.
4. **Secrets**: `npx wrangler secret put <NAME>` for each secret above.
5. **Deploy**: `npm run deploy`.
6. **Webhook**: add the Worker URL under **Webhooks** in the Dropbox App Console. The Worker answers the verification challenge automatically.

For local development, copy `dev.vars.example` to `.dev.vars` and run `npm run dev`.

## Behaviour

- The first run for a folder forwards the PDFs already in it, then only new ones.
- A folder's cursor only advances when every forward succeeded; failures are retried on the next webhook or cron run.
- A cron (`*/30 * * * *` in `wrangler.toml`) reconciles in case a webhook is missed. Remove it to rely on webhooks only.
- Moving a processed file out of a watched folder (e.g. into a sub-folder) does not re-trigger it.

## Payload sent to Make

```json
{
  "event": "new_file",
  "source": "dropbox-classement-worker",
  "ts": "2026-01-01T12:00:00.000Z",
  "dedup_key": "id:abc:015f...",
  "dropbox": {
    "id": "id:abc",
    "name": "scan.pdf",
    "path_lower": "/scans/scan.pdf",
    "path_display": "/Scans/scan.pdf",
    "rev": "015f...",
    "size": 123456,
    "server_modified": "2026-01-01T11:59:58Z",
    "content_hash": "..."
  }
}
```
