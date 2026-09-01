package identity

import (
	"context"
	"encoding/json"

	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
)

func (t *transaction) InsertAudit(ctx context.Context, entry identityservice.AuditEntry) error {
	encodedDetail, err := encodeAuditDetail(ctx, entry.Detail)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx, `
		INSERT INTO audit_logs (
			actor_type, actor_id, action, target_type, target_id, detail, created_at
		) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
		entry.ActorType,
		entry.ActorID,
		entry.Action,
		entry.TargetType,
		entry.TargetID,
		encodedDetail,
		entry.CreatedAt,
	)
	if err != nil {
		return repositoryInternalError(ctx, "insert audit log", err)
	}
	return nil
}

func encodeAuditDetail(ctx context.Context, detail map[string]any) (string, error) {
	if detail == nil {
		detail = map[string]any{}
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return "", repositoryInternalError(ctx, "encode audit detail", err)
	}
	return string(encoded), nil
}
