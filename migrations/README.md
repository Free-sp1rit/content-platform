# Database migrations

Migration files use the numeric naming convention:

```text
00001_create_users.sql
00002_create_user_sessions.sql
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

M1 intentionally contains no business migration. M2 will add the first schema for users and sessions.
