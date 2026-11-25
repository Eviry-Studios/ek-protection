# EK-Protection — Signature feed and license

Status: **design document**. Part 1 describes what the code does today.
Parts 2 and 3 describe the planned paid feed and are **not implemented**.
Scope: Linux servers and VPS only (see the open-core section of the
[README](../README.md#open-core-model)).

---

## 1. Public feed (implemented, MIT)

The daemon updates signatures from a plain HTTPS directory. Default:

```
signatures.update_url = https://raw.githubusercontent.com/Eviry-Studios/ek-protection/main/signatures/
signatures.update_interval_hours = 24
signatures.auto_update = true
```

The directory holds two files.

### 1.1 `manifest.json`

```json
{
  "version": "2026.08.28",
  "updated_at": "2026-08-28T01:06:43Z",
  "signatures_url": "https://.../signatures.jsonl",
  "sha256": "<sha-256 of signatures.jsonl, hex>",
  "count": 1
}
```

| Field | Required | Use |
|---|---|---|
| `version` | yes | compared with the local version; equal means nothing to do |
| `signatures_url` | yes | where to download the JSONL |
| `sha256` | should be | checksum of the JSONL; mismatch means the file is rejected |
| `updated_at` | no | stored as metadata |
| `count` | no | informational |

### 1.2 `signatures.jsonl`

One JSON object per line:

```json
{"sha256": "275a02...fd0f", "name": "EICAR.Test.File", "threat_type": "Test.Signature", "severity": "baixo", "source": "ekp-official"}
```

| Field | Required | Default if missing |
|---|---|---|
| `sha256` | yes | the line is skipped |
| `name` | no | `Unknown` |
| `threat_type` | no | `Generic.Malware` |
| `severity` | no | `alto` |
| `source` | no | `import` |

### 1.3 Update flow (`ekprotection/updater/fetcher.py`)

1. download `manifest.json`;
2. if `version` equals the local version, stop;
3. download `signatures_url`;
4. if `sha256` is present, compare it with the file and reject on mismatch;
5. import into the SQLite signature DB (`import_jsonl`, duplicates ignored);
6. store `version` and `updated_at`.

Only data is downloaded. No remote code is ever executed.

### 1.4 Known limits of the public feed

- **The checksum only proves the file is intact, not where it came from.**
  `sha256` is in the manifest, which comes from the same server over the same
  HTTPS connection. Anyone who controls that server or the `update_url` config
  can serve a matching pair.
- ~~The checksum is skipped when `sha256` is missing.~~ **Fixed (Task #578,
  2026-11-25):** `sha256` is now mandatory. A manifest without it, with an
  empty value, a non-string value or anything other than 64 hex digits is
  refused with `ManifestError` *before* `signatures.jsonl` is downloaded.
  A well-formed but wrong `sha256` raises `ChecksumError`. In both cases the
  signature database is not touched and the previous feed stays in use; the
  reason is logged by the update manager. Leading/trailing whitespace and
  upper case are accepted. A manifest with the same `version` as the local
  database is still a no-op (nothing is applied, so nothing is checked).
- Heuristic rules are Python code in `ekprotection/heuristics/rules.py`. They
  ship with the engine, not with the feed. A data format for feed rules is
  not defined yet (see 2.3).

The remaining point (origin, not integrity) is addressed by the feed signature in 2.2. That
signature is also useful for the free feed. It is a code change for a
separate task, not part of this document.

---

## 2. Paid feed (planned)

Same file format as the public feed, so the engine and the import code stay
the same. Three things are added on top.

### 2.1 Authenticated download (this is where the license applies)

- The paid feed lives at a separate URL, served by EviRyKorp, not by GitHub.
- Each request carries the license token (section 3), for example in an
  `Authorization: EK1 <token>` header. The server checks it and returns the
  manifest plus a short-lived download URL (about 10 minutes) for the JSONL.
  There is no fixed public link.
- No valid license means no paid manifest. The client then falls back to the
  public feed (section 1). The engine keeps working.

**The license is checked only by the paid feed client, and only before a
download.** It is not checked by the scanner, the monitor, the quarantine,
the CLI or any other part of the engine. Those stay MIT with no license check.
A license check inside the MIT engine would be removed in a fork in minutes.
The value is in the server-side feed, which a fork cannot copy.

### 2.2 Feed signature (integrity, separate from the license)

- The manifest gets a detached Ed25519 signature (`manifest.json.sig`) made
  with an EviRyKorp **feed key**. The client ships the feed **public** key and
  rejects any manifest that does not verify. With that in place, `sha256`
  becomes mandatory.
- The feed key is different from the license key. One signs content, the
  other signs entitlements. A leak of one does not compromise the other.
- Private keys live only in EviRyKorp's secret store. They are never committed
  to this repository or shipped in a package.

### 2.3 Rules in the feed (to be defined)

The curated feed can also carry detection rules as data, for example
patterns, paths and thresholds that tune the existing heuristics. Their
format will be defined when a first rule needs it. It will be data only (JSON,
no code) and will go through the same signature check as 2.2.

---

## 3. License token (planned; prototype exists)

Prototype from the internal study MP-EST2 (2026-11-20), tested 6/6:
valid token accepted; copied to another machine, edited plan, revoked,
expired lease and forged key all rejected.

### 3.1 Format

```
EK1.<base64url(payload)>.<base64url(ed25519_signature(payload))>
```

Payload (compact JSON, sorted keys):

| Field | Meaning |
|---|---|
| `v` | token format version (`1`) |
| `lid` | license id |
| `prod` | product (`ek-protection`) |
| `plan` | plan id |
| `dev` | device fingerprint (below) |
| `iat` | issued at (unix time) |
| `exp` | lease end (unix time) |

About 280 characters. It fits in a file under `/etc/ek-protection/` with
0600 permissions, or in an environment variable. The `cryptography` package
is already a dependency, so nothing new is needed.

### 3.2 Device binding

`dev = sha256("ek-protection:" + /etc/machine-id)[:32]`

The raw machine-id never leaves the server. The product name works as a salt,
so the same machine gives different ids in different EviRyKorp products. This
keeps data to a minimum (LGPD).

### 3.3 Lease and offline use

- Lease of about 7 days, renewed silently when the server has network.
- About 7 days of grace after `exp`, with a warning in `ekp status` and logs.
- For servers without internet: a longer token (about 30 days) issued from the
  customer area and installed by hand.

### 3.4 Revocation

Refund, chargeback, fraud or end of subscription marks the license as
revoked on the server. Renewal stops, and the lease runs out within days.
After that the client is back on the public feed.

There is **no remote kill switch**. A revoked or expired license never
deletes data, stops the daemon, removes quarantine or blocks the machine.
For an antivirus that would be a security and legal risk.

### 3.5 What the license does not do

- no telemetry beyond the renewal request (license id + device fingerprint);
- no check in the engine (see 2.1);
- no obfuscation or packing of the engine.

---

## 4. Not covered here

Prices, plans, the EULA/terms, the hosted panel and the customer area
belong to the product side and are not decided yet.
