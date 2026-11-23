# Blossom media server

nosfry can serve [Blossom](https://github.com/hzrd149/blossom) blobs next to
the relay: images, video and other files that Nostr clients upload and then
reference by their SHA-256 hash. It is meant for personal and community
relays that want one deployment and one membership policy for events and
media. It is off by default and costs a public relay nothing when off.

The blob server runs in the same process as the relay but on its own
listeners, behind its own hostname, with its own storage directory. It never
shares a port or an origin with the relay.

## What it implements

Read against hzrd149/blossom at `72ccc5d` (2026-11-21):

| BUD | Endpoints                                | Notes                                                                                                         |
| --- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 01  | `GET`/`HEAD /<sha256>[.ext]`, `OPTIONS`  | Single-range requests, `ETag`, `If-None-Match`, CORS, `OPTIONS` feature discovery and `405` with `Allow`.     |
| 02  | `PUT /upload`                            | Blob descriptors with an extension in `url`; `201` when newly stored, `200` when the uploader already had it. |
| 06  | `HEAD /upload`                           | Preflight from `X-SHA-256`, `X-Content-Length` and `X-Content-Type`, with `X-Reason` on refusals.             |
| 11  | `Authorization: Nostr <token>`           | Kind 24242 tokens; standard and URL-safe base64, padded or not.                                               |
| 12  | `GET /list/<pubkey>`, `DELETE /<sha256>` | Cursor pagination, `since`/`until`; listing is limited to the owner.                                          |
| 13  | `PUT /<sha256>`                          | Path-based upload. `POST /<sha256>` (mirroring) is not implemented and answers `405`.                         |

Not implemented: BUD-04 and BUD-13 mirroring, BUD-05 media optimisation,
BUD-07 payments, BUD-08 NIP-94 fields, BUD-09 reports, NIP-96, object storage
backends, the Workers edition, server-side EXIF stripping and multipart
uploads.

## Enabling it

Blossom needs a build with the `blossom` cargo feature, which the release
binaries and the container image include. Add a `[blossom]` table:

```toml
[relay]
service_url = "wss://relay.example.com"

[relay.management]
admins = ["79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"]

[blossom]
enabled = true
public_url = "https://media.example.com"
dir = "/var/lib/nosfry/blobs"

[[blossom.listen]]
address = "127.0.0.1:7778"
```

`public_url` is the address clients reach the blob server at. It goes into
every blob descriptor's `url` and its host is the domain a token's `server`
tag must name. The relay refuses to start when:

- `public_url` is missing, is not `http://` or `https://`, or has a path,
  query or fragment;
- its host equals the host of `relay.service_url` or of any
  `service_url_aliases` entry;
- a `[[blossom.listen]]` address is the same as, or overlaps, a
  `[[relay.listen]]` address (the same unix path, or the same TCP port on
  the same or an unspecified address);
- a listener is an `onion:` address (not supported for Blossom yet).

Listeners take the same `ip:port`, `[ipv6]:port` and `unix:/absolute/path`
forms as relay listeners. Every key is in the
[configuration reference](configuration.md#blossom).

## Why a separate origin

A blob server stores files that anyone with upload rights chooses, including
HTML and SVG, both of which can carry script. If such a file were served from
the relay's origin, opening its URL would run that script with the relay
origin's privileges: its cookies and storage, and whatever a NIP-07 signer
extension has already approved for that origin. So:

- Blobs are served only on the Blossom listeners, and the relay refuses a
  `public_url` on the relay's host. Use a dedicated hostname, for example
  `media.example.com` next to `relay.example.com`. A different port on the
  same host is a different origin, but cookies are shared across ports, so
  nosfry refuses the same host outright.
- Every response carries `X-Content-Type-Options: nosniff`, so browsers never
  guess a more dangerous type than the stored one.
- Every response carries
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`,
  the policy GitHub serves raw user content with. A document opened from a
  blob URL runs in an opaque origin, cannot run script, and loads no
  subresources. Images, audio and video still display, inline or embedded.
- Types a browser can execute or render as a scriptable document (HTML,
  XHTML, SVG, XML and `+xml` types, XSL, JavaScript, Flash) are served with
  `Content-Disposition: attachment`, so opening the URL downloads the file
  instead of rendering it. An SVG still renders in an `<img>` tag, where
  browsers never run its script.
- Blobs keep the type the uploader declared; nothing is rewritten, so the
  hash still matches the bytes (BUD-02 forbids modifying a blob).

One consequence: browsers do not show PDFs inline under a `sandbox` policy.
Clients that link PDFs get a download.

## Behind a reverse proxy

Terminate TLS in a proxy with a separate server block for the media
hostname. An nginx example next to the relay's site from
[deployment.md](deployment.md#reverse-proxy-and-tls), reusing that site's
`nosfry_http` rate-limit zone:

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name media.example.com;
    ssl_certificate     /etc/letsencrypt/live/media.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/media.example.com/privkey.pem;

    # Must be at least blossom.max_blob_size; 0 disables nginx's own cap.
    client_max_body_size 100m;
    # Stream uploads to nosfry instead of spooling them to disk first.
    proxy_request_buffering off;
    proxy_http_version 1.1;
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;

    location / {
        limit_req zone=nosfry_http burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:7778;
    }
}
```

Do not add or override `Content-Security-Policy`, `X-Content-Type-Options` or
`Content-Disposition` in the proxy. A CDN in front of the media hostname is
fine: blob responses are `Cache-Control: public, max-age=86400, immutable`
with a strong `ETag` (the hash), so a deletion or ban reaches the CDN's
clients within a day. Purge the CDN to remove a blob sooner. Error responses
are `no-store`.

## Who may upload

Every upload needs a signed kind 24242 token. `blossom.upload` decides whose
tokens are accepted:

- `"allowed"` (default): the `[relay.management] admins` and every pubkey on
  the relay's NIP-86 allow list (`allowpubkey`). With neither, nobody can
  upload.
- `"everyone"`: any valid token. Keep the quotas and the proxy's rate limit
  tight; the blob server is then open storage.

NIP-86 bans apply to the blob server too: a banned pubkey cannot upload or
list, and `banpubkey` takes effect at once without a restart. A banned
pubkey can still delete its own blobs. Reading blobs never needs a token.

Listing (`GET /list/<pubkey>`) needs a `list` token signed by that same
pubkey: a user can list their own uploads and nobody else's. Operators list
any owner with `nosfry blob list --owner`.

Deleting (`DELETE /<sha256>`) needs a `delete` token from an owner. Blobs
have a set of owners: when two pubkeys upload the same bytes, both own the
blob, a delete removes only the caller's ownership, and the file goes when
the last owner deletes it.

### Tokens

nosfry validates tokens as BUD-11 lists:

- kind 24242 with a valid BIP-340 signature;
- `created_at` not more than 60 seconds ahead of the server clock;
- an `expiration` tag in the future;
- a `t` tag naming the action: `upload`, `delete` or `list`;
- if the token has `server` tags, one must equal the host of `public_url`;
- for uploads and deletes, an `x` tag equal to the blob's hash.

The token travels base64-encoded in `Authorization: Nostr <token>`. BUD-11
asks for URL-safe base64 without padding, and some clients send standard,
padded base64; nosfry accepts both.

A token is reusable until it expires, as clients expect; it is not single
use. Its `t`, `x` and `server` tags limit what a captured token can do. Serve
the media hostname over TLS, and prefer clients that put a `server` tag on
delete tokens: an unscoped delete token from another server works here too
until it expires.

## Limits

| Key                              | Default           | What happens at the limit                                                                  |
| -------------------------------- | ----------------- | ------------------------------------------------------------------------------------------ |
| `blossom.max_blob_size`          | 100 MiB           | `413` before the body is read.                                                             |
| `blossom.quota_bytes`            | 1 GiB per pubkey  | `429`. A blob shared by several owners counts in full against each.                        |
| `blossom.quota_blobs`            | 10,000 per pubkey | `429`.                                                                                     |
| `blossom.max_total_bytes`        | 10 GiB            | `503 storage is full`. Counts each stored file once.                                       |
| `blossom.mime_types`             | any               | `415` for a type off the list (`"image/*"` and exact types).                               |
| `blossom.max_concurrent_uploads` | 16                | `503` when all slots are busy; each pubkey has at most 4 uploads in flight (`429` beyond). |
| `blossom.max_connections`        | 1,024             | New connections wait in the kernel's accept queue.                                         |

An upload must declare `Content-Length` (`411` otherwise). It is streamed to
disk while it is hashed and is never held in memory. A connection that sends
no body bytes for 30 seconds is cut off with `408`. Quotas are checked before
the body is read and again, authoritatively, when the upload is committed.

The size, quota, type and upload-policy keys apply on reload; the others need
a restart.

## Durability

An upload is acknowledged only after it is on disk:

1. The body is written to `<dir>/tmp/` while its SHA-256 is computed.
2. The hash and length are checked against the token, `X-SHA-256` or the path,
   and the file is `fsync`ed.
3. In one metadata transaction: the ban list and quotas are checked, the file
   is renamed to `<dir>/blobs/ab/cd/<sha256>` and its directory `fsync`ed, and
   the owner, size, type and upload time are committed.
4. Only then does the client get `201` or `200`.

A crash before step 3 leaves a temporary file, removed at the next start. A
crash between the rename and the commit leaves a complete file with no
metadata: it is never served, a re-upload adopts it, and `nosfry blob gc`
removes it. Deletes move the file to `<dir>/trash/` inside the transaction
and remove it after the commit; a crash there is repaired at the next start.

## Administration

`nosfry blob` works on `[blossom] dir`, whether the relay is running or not:

| Command                                                       | What it does                                                                              |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `nosfry blob list [--owner HEX] [--limit N] [--after SHA256]` | One JSON line per blob: in hash order, paged with `--after`; newest first with `--owner`. |
| `nosfry blob stat SHA256`                                     | Size, type, upload time, owners, ban state, and whether the file is present.              |
| `nosfry blob delete SHA256`                                   | Delete the blob for all owners.                                                           |
| `nosfry blob ban SHA256 [--reason TEXT]`                      | Delete the blob and refuse every future upload of the same bytes.                         |
| `nosfry blob unban SHA256`                                    | Lift a ban.                                                                               |
| `nosfry blob gc`                                              | Remove files without metadata; with the relay stopped, also leftover temporary files.     |
| `nosfry blob verify`                                          | Re-hash every file and recount every quota; exits `1` when anything is wrong.             |

A ban takes effect immediately for a running relay: the check runs inside the
same transaction that stores an upload, so a ban and an upload in flight
cannot both win.

## Backup and restore

Blobs are plain files named by their hash; the ownership, quota and ban
records are a separate LMDB environment in `<dir>/meta/`. Back up both:

- **Relay stopped** (or a filesystem snapshot): copy the whole `dir`.
- **Relay running**: copy the metadata first with LMDB's own tool, then the
  files:

  ```bash
  mdb_copy /var/lib/nosfry/blobs/meta /backup/blobs/meta
  rsync -a /var/lib/nosfry/blobs/blobs/ /backup/blobs/blobs/
  ```

  Blobs uploaded between the two steps are orphans in the copy and blobs
  deleted between them are missing; after a restore run `nosfry blob verify`
  to list both and `nosfry blob gc` to remove the orphans.

`tmp/` and `trash/` need no backup. To restore, stop the relay, put `meta/`
and `blobs/` back under `dir`, and start it.

The blob files are the portable part: any Blossom server can take them, and
clients re-upload or mirror by hash. The metadata format is nosfry's own and
versioned; a store written by a newer format version is refused at start.

## Monitoring

With `relay.metrics = true` the relay's `/metrics` (on the relay listener,
never on the media hostname) adds `nosfry_blossom_*` series: requests by
endpoint and status class, upload refusals and token failures by reason,
uploaded and served bytes, uploads in flight, and stored bytes and blobs.

Logs use the target `nosfry::blossom`. Each request is logged at `debug`
with its method, endpoint, status, size and duration. Stored, deleted and
banned blobs are logged at `info` with hash, size, type and owner. Query
strings, headers and tokens are never logged.
