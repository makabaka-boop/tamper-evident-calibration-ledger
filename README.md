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
and only a successful migration permits `api` and `sealer` to start. A migration error therefore
leaves the API unavailable and is visible in `docker compose logs migrate`. API readiness also
queries both PostgreSQL and `alembic_version`. All application containers run as UID/GID 10001,
have every Linux capability dropped, use a read-only root filesystem, and expose health checks;
the PostgreSQL image uses its built-in unprivileged `postgres` user.

Scale independent sealers safely with:

```sh
docker compose up --scale sealer=3
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
and sealer races.
