# Database migrations

Migration files use the numeric naming convention:

```text
00001_m1_baseline.sql
00002_create_users.sql
00003_create_user_sessions.sql
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

Goose v3.27.1 rejects an empty migration directory before it creates its version table. M1 therefore includes `00001_m1_baseline.sql`; its Up and Down sections only execute `SELECT 1`. It creates no business table, index, or other business object. M2 starts at version `00002` with the first user and session schema.
