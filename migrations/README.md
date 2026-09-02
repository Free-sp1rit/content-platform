# Database migrations

Migration files use the numeric naming convention:

```text
00001_m1_baseline.sql
00002_identity.sql
```

Every SQL migration contains explicit goose sections:

```sql
-- +goose Up

-- +goose Down
```

Rules:

- Do not edit a migration after it has run in a shared environment.
- Correct an applied migration with a new migration file.
- Commit schema constraints and the code that depends on them in the same milestone.
- Treat `down-one` as a local-development operation; review destructive rollback SQL before using it in a shared environment.
- The server never runs migrations automatically. Use `go run ./cmd/migrate <command>`.
- The migration command loads `MigrationConfig`, so it requires the database/log configuration but does not require `AUTH_JWT_SECRET`.

Goose v3.27.1 rejects an empty migration directory before it creates its version table. M1 therefore includes `00001_m1_baseline.sql`; its Up and Down sections only execute `SELECT 1`. It creates no business table, index, or other business object. M2 is `00002_identity.sql`, which creates the `users`, `user_sessions`, and `audit_logs` tables along with their indexes and integrity constraints.

The `user_sessions.token_hash` column is a 32-byte value. M2 stores only SHA-256 of the raw 32-byte refresh secret in that column; it never stores the external `sid.secret` refresh token or its Base64URL secret text. A session's `expires_at` is fixed at login and is an absolute expiration: rotating the refresh secret updates only `token_hash`, not `expires_at`.

The audit service records actions such as `user.status_changed` and `user.mute_expired`. The schema intentionally does not restrict `action` to only those values. Status changes, required session revocation, and audit insertion are coordinated by the Identity service in one transaction; an audit insertion failure rolls the transaction back.

The `00002_identity.sql` Down section drops `audit_logs`, `user_sessions`, and `users`. It therefore deletes every M2 Identity user, password hash, session, and audit record. This is destructive data loss, not an application rollback strategy; do not run it against a shared or production environment without an explicit, reviewed recovery plan.
