# CDH MitM Collector

`mitm-collector-cdh` is a standalone Go 1.27 collector for the CDH Dataset
API. It authenticates with the CNX OAuth2 machine-to-machine flow, retrieves a
dataset snapshot, encrypts it with the source's Data Encryption Key (DEK), and
writes it to the MitM `raw_ingestion` table.

The collector is designed to be started by the MitM scheduler. It receives the
Master Key (KEK) and target database configuration over the scheduler's Unix
domain socket. Standalone execution is supported through the environment
variables documented below.

## Behaviour

1. Retrieves scheduler credentials when `RUN_ID` and `SCHEDULER_SOCKET_PATH`
   are available.
2. Loads the encrypted CDH source configuration and its wrapped DEK from the
   target database.
3. Unwraps the DEK with the KEK and decrypts the source configuration.
4. Requests an OAuth2 access token, then retrieves the configured CDH dataset.
5. Validates that the response is JSON and calculates a SHA-256 snapshot
   cursor.
6. Skips ingestion when the cursor equals the previously stored cursor.
7. Encrypts a changed snapshot with AES-GCM and atomically inserts it into
   `raw_ingestion` together with the new `ingestion_cursors` value.

No API secret, access token, Master Key, decrypted payload, or decrypted
source configuration is written to logs or scheduler events.

## Requirements

- Go **1.27.0**
- A reachable PostgreSQL MitM database with the `source_credentials`,
  `storage_keys`, `raw_ingestion`, and `ingestion_cursors` tables
- An active `source_credentials` entry for the configured source name
- CDH machine-to-machine client credentials in that source configuration

## Build and test

Run the following commands from this directory:

```powershell
go test .\...
go build -ldflags "-s -w -X main.version=<version>" -o .\mitm-collector-cdh.exe .
```

The scheduler resolves the collector binary relative to its own executable
directory. Copy the built binary to that directory when registering the job.

## Scheduler job parameters

The scheduler passes its `args` JSON as the collector's sole command-line
argument.

```json
{
  "source_name": "CDH_FACILITY_PLACES",
  "topic": "cdh.dataset.data"
}
```

| Parameter | Required | Default | Description |
|---|---:|---|---|
| `source_name` | Yes | — | Name of the active `source_credentials` record to use. |
| `topic` | No | `cdh.dataset.data` | Routing topic stored with the encrypted record in `raw_ingestion`. Must not be empty. |

Example `scheduled_programs` entry:

```sql
INSERT INTO scheduled_programs (name, command, args, cron_expr, enabled, restart_on_exit)
VALUES (
  'cdh_facility_places',
  'mitm-collector-cdh',
  '{"source_name":"CDH_FACILITY_PLACES","topic":"cdh.dataset.data"}'::jsonb,
  '*/15 * * * *',
  true,
  false
);
```

## Encrypted source configuration

The selected `source_credentials.config_payload` must contain this JSON object
after decryption:

```json
{
  "client_id": "<client-id>",
  "client_secret": "<client-secret>",
  "dataset_id": "facility_places_re_base_sem",
  "hub": "global",
  "am_base_url": "https://emea.prod.alpha.sso.CNXgroup.com/auth",
  "dataset_url": "https://api.CNXgroup.net/cdh/dataset-api/v1/v1/metadata/dataset",
  "timeout_seconds": 60
}
```

| Parameter | Required | Default | Description |
|---|---:|---|---|
| `client_id` | Yes | — | OAuth2 machine-to-machine client ID. It is also used to construct the OAuth2 scope `machine2machine client_<client_id>`. |
| `client_secret` | Yes | — | OAuth2 machine-to-machine client secret. |
| `dataset_id` | Yes | — | CDH dataset identifier passed as the `dataset_id` query parameter. It is also the deterministic correlation-ID business key. |
| `hub` | No | `global` | CDH hub passed as the `hub` query parameter. |
| `am_base_url` | No | `https://emea.prod.alpha.sso.CNXgroup.com/auth` | Authentication Manager base URL. The collector appends the documented OAuth2 token path. |
| `dataset_url` | No | `https://api.CNXgroup.net/cdh/dataset-api/v1/v1/metadata/dataset` | CDH dataset API endpoint. The collector appends or replaces `dataset_id` and `hub` query parameters. |
| `timeout_seconds` | No | `60` | Timeout for each HTTP request. Must be zero or a positive integer; zero selects the default. |

## Runtime environment

The scheduler provides `RUN_ID` and `SCHEDULER_SOCKET_PATH`. When both are set,
the collector requests credentials over IPC and does not require database or
Master-Key environment variables.

For standalone diagnostics, configure the following variables:

| Variable | Required | Description |
|---|---:|---|
| `MASTER_KEY` | Yes | KEK as either a Base64-encoded 32-byte value or a raw 32-byte value. |
| `MITM_DB_CONFIG_JSON` | Preferred | JSON object containing a nested `db` object with `host`, `port`, `user`, `password`, `database`, and boolean `sslmode`. |
| `MITM_DB_DSN` | Alternative | PostgreSQL DSN used when `MITM_DB_CONFIG_JSON` is not supplied. |
| `MITM_DB_HOST` | Alternative | PostgreSQL host; used with the individual database variables below. |
| `MITM_DB_PORT` | Alternative | PostgreSQL port. |
| `MITM_DB_USER` | Alternative | PostgreSQL user. |
| `MITM_DB_PASSWORD` | Alternative | PostgreSQL password. |
| `MITM_DB_DATABASE` | Alternative | PostgreSQL database name. |
| `MITM_DB_SSLMODE` | Alternative | Boolean `true` for `sslmode=require`; `false` for `sslmode=disable`. |

Example standalone invocation:

```powershell
$env:MASTER_KEY = '<base64-encoded-32-byte-kek>'
$env:MITM_DB_CONFIG_JSON = '{"db":{"host":"localhost","port":5432,"user":"mitm","password":"<password>","database":"mitm","sslmode":false}}'
.\mitm-collector-cdh.exe '{"source_name":"CDH_FACILITY_PLACES","topic":"cdh.dataset.data"}'
```

## Cursor and idempotency

CDH metadata responses do not provide an incremental offset. The collector
therefore uses the SHA-256 hash of the trimmed JSON response as its cursor. An
unchanged response is not inserted again. The encrypted record and its cursor
are committed in one PostgreSQL transaction, ensuring that a cursor never
advances without its corresponding record.
