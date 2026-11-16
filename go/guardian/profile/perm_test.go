package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProfileAndBackupFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	root := t.TempDir()
	profiles := filepath.Join(root, "profiles")
	backups := filepath.Join(root, "backups")
	m := NewManager(profiles, BackupConfig{Enabled: true, MaxBackups: 3, Dir: backups})
	content := []byte(`{"key":{"ip":"127.0.0.1"}}`)
	if err := m.Save("a", content); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := m.Save("a", content); err != nil { // second save creates a backup
		t.Fatalf("save 2: %v", err)
	}
	check := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
	check(profiles, 0o700)
	check(backups, 0o700)
	check(filepath.Join(profiles, "a"), 0o600)
	entries, _ := os.ReadDir(backups)
	if len(entries) == 0 {
		t.Fatal("no backup created")
	}
	check(filepath.Join(backups, entries[0].Name()), 0o600)
}
