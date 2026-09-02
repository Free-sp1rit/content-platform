package testkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminBootstrapDocumentationEnforcesExactlyOneRow(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, path := range []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs", "superpowers", "specs", "2026-09-01-m2-identity-auth-design.md"),
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		block, ok := adminBootstrapBashBlock(string(contents))
		if !ok {
			t.Fatalf("%s does not contain an administrator bootstrap bash block", path)
		}
		for _, required := range []string{
			"--set=ON_ERROR_STOP=1",
			"BEGIN;",
		} {
			if !strings.Contains(block, required) {
				t.Errorf("%s bootstrap block does not enforce exactly one updated row; missing %q", path, required)
			}
		}
		if !strings.Contains(block, "RETURNING id\n\\gset admin_\nCOMMIT;") {
			t.Errorf("%s bootstrap block must run gset immediately after RETURNING and commit only its one-row result", path)
		}
		for _, forbidden := range []string{"DO $$", "\\if ", "\\quit", "ROLLBACK;"} {
			if strings.Contains(block, forbidden) {
				t.Errorf("%s bootstrap block must rely on ON_ERROR_STOP and transaction rollback, not %q", path, forbidden)
			}
		}
	}
}

func adminBootstrapBashBlock(contents string) (string, bool) {
	const sectionMarker = "初始 admin"
	sectionStart := strings.Index(contents, sectionMarker)
	if sectionStart < 0 {
		sectionStart = strings.Index(contents, "管理员初始化")
	}
	if sectionStart < 0 {
		return "", false
	}
	remainder := contents[sectionStart:]
	start := strings.Index(remainder, "```bash")
	if start < 0 {
		return "", false
	}
	remainder = remainder[start+len("```bash"):]
	end := strings.Index(remainder, "```")
	if end < 0 {
		return "", false
	}
	return remainder[:end], true
}
