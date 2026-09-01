package identity

import (
	"strings"
	"testing"
)

func TestLockSessionsQueryReturnsRowsFromLockingCTEWithoutOuterRescan(t *testing.T) {
	query := normalizeSQLShape(lockSessionsQuery("id IN ($1)"))
	columns := normalizeSQLShape(sessionColumns)

	if !strings.Contains(query, "WITH locked_sessions AS ( SELECT "+columns+" FROM user_sessions") {
		t.Fatalf("locking CTE does not project the complete session row")
	}
	if !strings.Contains(query, "FOR UPDATE ) SELECT "+columns+" FROM locked_sessions ORDER BY id") {
		t.Fatalf("final SELECT does not return the EvalPlanQual-checked row from the locking CTE")
	}
	if strings.Count(query, "FROM user_sessions") != 1 || strings.Contains(query, "JOIN user_sessions") {
		t.Fatalf("query performs an outer rescan of user_sessions after locking")
	}
}

func normalizeSQLShape(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
