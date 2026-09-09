# Tamper-evident calibration ledger

This service records calibration reports as immutable events and periodically witnesses a
contiguous database-ordered prefix with an HMAC-signed RFC 6962 Merkle root. Revisions and
revocations append new events; no API can update or delete history, and PostgreSQL triggers
reject direct mutation as defense in depth. The submitted report itself is never persisted or
returned: only its SHA-256 digest and the public audit metadata enter the event commitment.

## Start

Requirements are Docker Engine with Compose v2. No online service is called by the application.

```sh
cp .env.example .env
# Replace both passwords and LEDGER_HMAC_KEYS_JSON with real random secrets.
docker compose up --build
curl --fail http://localhost:8000/health/ready
```

`db` first becomes healthy, the one-shot `migrate` service waits for PostgreSQL and runs Alembic,
and only a successful migration permits `api`, `sealer`, and `exporter` to start. A migration
error therefore leaves the API unavailable and is visible in `docker compose logs migrate`. API
readiness also queries both PostgreSQL and `alembic_version`. All application containers run as
UID/GID 10001, have every Linux capability dropped, use a read-only root filesystem, and expose
health checks; the PostgreSQL image uses its built-in unprivileged `postgres` user.

Scale independent sealers safely with:

```sh
docker compose up --scale sealer=3
```

Scale the independent offline-export workers the same way (see "Instrument audit packages"):

```sh
docker compose up --scale exporter=2
```

Writers hold a shared PostgreSQL transaction advisory lock while allocating/committing their
database sequence; the sealer takes the same lock exclusively and also locks the latest checkpoint
row. This prevents a later sequence from becoming visible while an earlier allocated sequence is
still in flight. Only one replica can claim a batch, and a checkpoint plus its boundary commit
atomically. A crash rolls back the entire attempt; on restart the next worker starts after the last
committed `last_event_sequence`, so replicas cannot fork or omit committed events.

## Acceptance walkthrough

Create a report. Different JSON object key order and insignificant whitespace produce the same
digest; non-finite numbers are rejected. Keep the returned event ID.

```sh
curl -sS -X POST http://localhost:8000/v1/reports \
  -H 'content-type: application/json' \
  -d '{
    "business_key":"night-2026-09-09/cal-007",
    "instrument_id":"CAL-007",
    "operator_id":"alice",
    "report":{"result":"accepted","readings":[1.001,1.002],"units":"V"}
  }'
```

Retrying exactly that request returns HTTP 200, `created: false`, and the same event. Reusing its
business key with any different committed field returns HTTP 409 `IDEMPOTENCY_CONFLICT`. Before
the sealer reaches it, `GET /v1/events/{event_id}` explicitly says `witness_status: pending`.
After sealing, that call returns the event, signed checkpoint, inclusion proof, and (when there is
a predecessor) an adjacent-checkpoint consistency proof.

Append a revision and then a revocation:

```sh
curl -sS -X POST http://localhost:8000/v1/events/EVENT_ID/revisions \
  -H 'content-type: application/json' \
  -d '{"business_key":"night-2026-09-09/cal-007-r2","instrument_id":"CAL-007","operator_id":"bob","report":{"result":"fail","readings":[1.101]}}'

curl -sS -X POST http://localhost:8000/v1/events/REVISION_ID/revocations \
  -H 'content-type: application/json' \
  -d '{"business_key":"night-2026-09-09/cal-007-revoke","operator_id":"carol","reason":"reference standard drift"}'

curl -sS http://localhost:8000/v1/records/RECORD_ID
```

The parent row remains byte-for-byte unchanged. A unique `previous_event_id` plus a row lock
allows only one successor, prevents record forks, and a revocation cannot have a successor.

## Proof construction and offline verification

Canonicalization is UTF-8 JSON with recursively sorted object keys, no insignificant whitespace,
JSON-native number rendering, and rejection of NaN/infinities. The report digest is
`SHA256(canonical_report)`. An event leaf is:

```text
SHA256(0x00 || canonical_public_event_commitment)
```

Internal nodes are `SHA256(0x01 || left || right)`. Odd leaves are **not** duplicated; the tree
uses the largest power-of-two split defined by RFC 6962. The event's zero-based proof index binds
it to database sequence order, so changing a report digest, swapping leaves, or deleting history
changes the root. The HMAC covers the checkpoint ID, root, leaf count, last database sequence,
predecessor ID/root, key version, timestamp, and schema version.

Save a receipt and an auditor keyring (the keyring file must not be committed):

```sh
curl -sS http://localhost:8000/v1/events/EVENT_ID > receipt.json
mkdir -p keys
printf '%s\n' '{"v1":"the-same-32-byte-or-longer-secret-from-the-secure-key-store"}' > keys/auditor.json
docker compose run --rm --no-deps \
  -v "$PWD/receipt.json:/tmp/receipt.json:ro" \
  -v "$PWD/keys/auditor.json:/tmp/auditor.json:ro" \
  api calibration-ledger-verify /tmp/receipt.json --keyring /tmp/auditor.json
```

For local source installs, use
`calibration-ledger-verify receipt.json --keyring keys/auditor.json`. The pure verification path
recalculates event, inclusion, consistency, linkage, and HMAC results from the supplied receipt;
it performs no database query and trusts no stored “valid” flag. `POST /v1/verify` runs the same
pure function with the server keyring. Unknown key versions and malformed proofs have distinct,
structured errors.

> The Compose container does not mount host receipts or keys by default. The command above adds
> narrowly scoped read-only mounts. Never add auditor keys to the image.

## Instrument audit packages

An auditor can freeze a trackable, offline-verifiable export for one instrument. The boundary is
fixed **at request time** to an already sealed checkpoint: events appended or sealed afterwards
can never enter that package, and a failed build can be retried without moving the boundary.

```sh
curl -sS -X POST http://localhost:8000/v1/audit-packages \
  -H 'content-type: application/json' \
  -d '{"instrument_id":"CAL-007","idempotency_key":"audit-2026-09-09-001"}'
```

Optional `"checkpoint_id"` pins an explicit boundary; without it the newest checkpoint is used.
`NO_SEALED_CHECKPOINT` (409) is returned when no checkpoint exists; `INSTRUMENT_HAS_NO_SEALED_EVENTS`
(409, retryable after more sealing) when the latest boundary contains no event for the instrument;
and `CHECKPOINT_DOES_NOT_COVER_INSTRUMENT` (409) for an explicit boundary that does not cover it.
Retrying the same `idempotency_key` with identical parameters returns the original package
(`created: false`); reusing a key with different parameters returns 409 `IDEMPOTENCY_CONFLICT`.

Track the task and download only when ready:

```sh
curl -sS http://localhost:8000/v1/audit-packages/PACKAGE_ID
# status is pending, building, ready, failed, cancelling, or cancelled; failed includes a
# failure code/reason and the attempt_count is incremented on every claim (including
# crash-timeout reclaims)
curl -fsS -o cal-007.zip \
  http://localhost:8000/v1/audit-packages/PACKAGE_ID/download
```

Downloads of `pending`, `building`, `cancelling`, `cancelled`, or `failed` packages return
409 `AUDIT_PACKAGE_NOT_READY` carrying the actual `status` (and `retryable: true` only for
`failed`); unknown packages use the standard 404 `NOT_FOUND` envelope.

### Cancelling a wrong selection

If the instrument or export range was chosen incorrectly, cancel a task that has not
finished:

```sh
curl -sS -X POST http://localhost:8000/v1/audit-packages/PACKAGE_ID/cancel
```

`pending` tasks move straight to `cancelled` inside a row-locked transaction. A `building`
task moves to `cancelling` and records `cancellation.requested_at`; the owning worker checks
the status while generating receipts and again before writing the artifact, discards its
in-memory result, and finalizes `cancelled` without ever creating a downloadable artifact.
The decision between cancellation and completion is made on the same task row lock: if the
worker's `ready` commit wins, the cancel returns 409 `AUDIT_PACKAGE_ALREADY_READY` and the
immutable ZIP remains downloadable; if the cancel commits first, the worker cannot write an
artifact. Repeating the request after a cancellation is idempotent (200, `changed: false`,
no additional state change). A `failed` task is not cancellable (409
`AUDIT_PACKAGE_NOT_CANCELLABLE`) — use retry instead. Downloads of `cancelling`/`cancelled`
packages return `AUDIT_PACKAGE_NOT_READY` with the actual status, and retry of either state
returns 409 `AUDIT_PACKAGE_NOT_RETRYABLE`; create a new package instead. Cancelling a package
never moves the fixed checkpoint boundary, changes the attempt count, appends events/checkpoints,
or touches other packages. If an exporter dies while a task is `cancelling`, the next exporter
startup (and every poll) converges the lease-expired row to `cancelled` and logs an
`audit_package_cancel_confirmed` event (`reason: lease_expired`); a live worker confirmation
logs the same event with `reason: requested`.

A terminal failure is recoverable:

```sh
curl -sS -X POST http://localhost:8000/v1/audit-packages/PACKAGE_ID/retry
```

Retry only applies to `failed` packages (other states return a distinct 409 code, including
`AUDIT_PACKAGE_NOT_RETRYABLE` for `cancelling`/`cancelled`) and requeues the task without
changing `instrument_id`, `checkpoint_id`, or the request fingerprint.

The independent `exporter` worker claims one task at a time with `FOR UPDATE SKIP LOCKED`
(SQLite uses an equivalent compare-and-set claim), so scaled replicas never build the same
package. A crash mid-build leaves the row in `building` with an expiring lease; after
`LEDGER_EXPORT_LEASE_SECONDS` any worker reclaims it and increments `attempt_count`. Database
outages never mark a task failed. Defects in the package inputs (for example a missing signing
key version) mark the package `failed` with a structured code so retry can succeed once fixed.

The archive is a deterministic ZIP (fixed 1980 entry timestamps, DEFLATE level 9,
Unix file modes, no extra fields) containing:

```text
receipts/event-<zero-padded database sequence>.json   # one existing-format receipt per event
manifest.json
```

The canonical manifest records the package id, idempotency key, instrument, the signed boundary
checkpoint, leaf/sequence bounds, the event count, every receipt file's SHA-256, and the whole
ZIP's SHA-256/size. Rebuilding from the same database inputs yields byte-identical ZIP bytes and
digest. Receipts contain only public commitments (`report_digest`, never the report) and the
signed checkpoint plus inclusion/consistency proofs; **no raw report or HMAC key ever enters the
package**. Verify every extracted receipt offline with `calibration-ledger-verify`, exactly as
shown above.

## Key rotation

Keys are a versioned environment map. Old values must remain available while their checkpoints
must still verify.

1. Generate at least 32 random bytes in the organization's secret manager.
2. Add a new entry to `LEDGER_HMAC_KEYS_JSON`, retaining old entries, for example
   `{"v1":"...old...","v2":"base64:...new..."}`.
3. Change `LEDGER_CURRENT_KEY_VERSION=v2` and recreate API/sealer containers.
4. Submit an event or wait for pending events to be sealed, then confirm the new checkpoint says
   `key_version: v2` and its consistency proof includes a valid v1 predecessor.
5. Distribute the versioned verification key through the audited offline channel. Do not remove
   v1 until its verification retention period ends.

There is no “rotate” database mutation. Old signatures identify and continue using their old key;
every newly created checkpoint uses exactly the configured current version.

## Migrations, backup, restore, and reset

Run or inspect migrations:

```sh
docker compose run --rm migrate alembic current
docker compose run --rm migrate alembic upgrade head
docker compose run --rm migrate alembic history
```

Back up PostgreSQL and the key versions as two separately controlled artifacts:

```sh
mkdir -p backups
docker compose exec -T db pg_dump -U ledger -d ledger -Fc > backups/ledger.dump
```

`backups/`, receipt exports, and auditor keyrings should be encrypted and access-controlled; add a
site-specific ignored path if they live under this checkout. To restore, stop API/sealers, create
a clean database, restore with `pg_restore --clean --if-exists`, run `alembic upgrade head`, restore
the matching versioned keyring from the separate secret backup, then fetch several receipts and
verify them offline before reopening writes. A database backup without historical HMAC keys can
recompute Merkle roots but cannot authenticate old checkpoints.

For a destructive local-only reset:

```sh
docker compose down
rm -rf -- ./.data/postgres
docker compose up --build
```

The target is the explicit ignored local data directory. Do not run that reset against a retained
environment.

## Failure behavior and drills

Every API failure uses `error.code`, `error.message`, `error.details`, and `error.request_id`.
Database driver/transaction failures return HTTP 503 `DATABASE_UNAVAILABLE` and are retryable;
idempotency keys make a retry safe even when the client did not observe the original commit.
Integrity/proof failures identify the affected event/checkpoint. The sealer emits JSON-bearing log
messages and retries database loss without advancing its boundary.

Recommended staging drills:

- **Database interruption:** pause `db`, submit a request, observe 503, unpause, retry the same
  business key, and verify exactly one event exists.
- **Sealer crash:** kill a sealer while events are pending, start two replicas, and verify one next
  checkpoint covers the exact contiguous prefix with no duplicate leaf count.
- **Exporter crash:** create an audit package, kill its exporter while it is `building`, wait past
  `LEDGER_EXPORT_LEASE_SECONDS`, and confirm another replica reclaims it (higher `attempt_count`)
  and produces a ready package whose manifest boundary is the original checkpoint.
- **Exporter failure and retry:** point the exporter at a keyring missing the checkpoint's key
  version, observe `failed` with `UNKNOWN_KEY_VERSION`, restore the key, `POST
  /v1/audit-packages/{id}/retry`, and verify the ready ZIP matches the fixed boundary.
- **Cancellation:** create two packages; cancel one while `pending` (immediate `cancelled`,
  never claimed, no artifact) and another while `building` (observe `cancelling` with
  `requested_at`, then the exporter log `audit_package_cancel_confirmed` and `cancelled`);
  repeat the cancel (idempotent), confirm 409 `AUDIT_PACKAGE_NOT_READY` downloads and 409
  `AUDIT_PACKAGE_NOT_RETRYABLE` retries carry the actual status, and cancel a package whose
  build commits `ready` simultaneously to observe 409 `AUDIT_PACKAGE_ALREADY_READY` with the
  ZIP intact. Kill an exporter while a task is `cancelling`, restart, and confirm the stale
  row converges to `cancelled` with no artifact.
- **Deterministic archive:** build the same package twice from restored identical data and compare
  both ZIP bytes and the manifest archive SHA-256.
- **Migration failure:** temporarily use a bad database URL for `migrate`; API/sealer must remain
  stopped and `docker compose logs migrate` must locate the failing revision/connection.
- **Proof corruption:** alter one hex character in `event.report_digest`, an inclusion hash, a
  checkpoint signature, or a consistency hash. Offline verification must fail.
- **Unknown key:** remove the receipt checkpoint's version from a copied auditor keyring; the
  verifier reports the missing version rather than accepting a database assertion.
- **Restore audit:** restore a backup plus keyring in isolation, verify the latest checkpoint and a
  sample from each historical key version, and compare its signed root with an auditor-held copy.

## Development and tests

Python 3.12 is required.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
ruff check .
pytest -q
```

Algorithm and service tests use temporary SQLite databases. PostgreSQL race coverage is opt-in
because it recreates tables in the explicitly supplied isolated database:

```sh
TEST_DATABASE_URL=postgresql+asyncpg://ledger:test@localhost:5432/ledger_test \
  pytest -q -m postgres
```

The suite covers canonicalization, idempotency conflict and retry, append-only revision/revocation
transitions, even/odd Merkle boundaries, proof tampering, sealing batch resume, injected clocks and
batch sizes, historical/new key verification, API error mapping, and PostgreSQL concurrent writer
and sealer races. Audit-package coverage adds package creation and idempotency conflicts, missing
and uncovered sealed boundaries, boundary isolation against later sealing, deterministic archive
bytes and digests on rebuild, per-receipt offline verification inside the ZIP, dual-worker
claiming, crash-lease recovery, terminal failure and boundary-preserving retry, download status
gating, and database-failure mapping. Cancellation coverage adds immediate `pending`
cancellation with idempotent repeats, cooperative `building` cancellation during receipt
generation, the row-lock barrier that refuses to write an artifact after a committed cancel,
the ready-wins 409 ordering, absence of artifact residue, exporter cancel-confirmation
logging, restart convergence of stale `cancelling` rows, download/retry gating for both
cancellation states, and legacy-task migration through Alembic 0003. The PostgreSQL opt-in
run additionally races concurrent exporter claims and the cancel/ready row-lock decision.
