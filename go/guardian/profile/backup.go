package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (m *Manager) createBackup(name, sourcePath string) error {
	if !m.backupCfg.Enabled {
		return nil
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z")
	backupPath := filepath.Join(m.backupCfg.Dir, name, id+".json")
	if err := writeFileAtomic(backupPath, data, 0o600); err != nil {
		return err
	}
	return nil
}

func (m *Manager) listBackups(name string) ([]BackupInfo, error) {
	dir := filepath.Join(m.backupCfg.Dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	backups := make([]BackupInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		backups = append(backups, BackupInfo{ID: id, Profile: name, CreatedAt: info.ModTime(), Size: info.Size()})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

func (m *Manager) restoreBackup(name, backupID string) error {
	backupPath := filepath.Join(m.backupCfg.Dir, name, backupID+".json")
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if err := m.Validate(data); err != nil {
		return fmt.Errorf("backup is invalid: %w", err)
	}
	currentPath := profilePath(m.profilesDir, name)
	if _, err := os.Stat(currentPath); err == nil {
		if err := m.createBackup(name, currentPath); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(currentPath, data, 0o600); err != nil {
		return err
	}
	return m.pruneBackups(name)
}

func (m *Manager) pruneBackups(name string) error {
	if !m.backupCfg.Enabled || m.backupCfg.MaxBackups <= 0 {
		return nil
	}
	backups, err := m.listBackups(name)
	if err != nil {
		return err
	}
	if len(backups) <= m.backupCfg.MaxBackups {
		return nil
	}
	for _, backup := range backups[m.backupCfg.MaxBackups:] {
		path := filepath.Join(m.backupCfg.Dir, name, backup.ID+".json")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
