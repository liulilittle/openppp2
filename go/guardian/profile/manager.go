package profile

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ProfileInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Profile struct {
	ProfileInfo
	Content string `json:"content"`
}

type BackupInfo struct {
	ID        string    `json:"id"`
	Profile   string    `json:"profile"`
	CreatedAt time.Time `json:"createdAt"`
	Size      int64     `json:"size"`
}

type BackupConfig struct {
	Enabled    bool
	MaxBackups int
	Dir        string
}

type Manager struct {
	profilesDir string
	backupCfg   BackupConfig
	mu          sync.Mutex
}

func NewManager(profilesDir string, backupCfg BackupConfig) *Manager {
	_ = os.MkdirAll(profilesDir, 0o700)
	if backupCfg.Enabled && backupCfg.Dir != "" {
		_ = os.MkdirAll(backupCfg.Dir, 0o700)
	}
	return &Manager{profilesDir: profilesDir, backupCfg: backupCfg}
}

func (m *Manager) List() ([]ProfileInfo, error) {
	entries, err := os.ReadDir(m.profilesDir)
	if err != nil {
		return nil, err
	}
	items := make([]ProfileInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		items = append(items, ProfileInfo{Name: entry.Name(), Path: filepath.Join(m.profilesDir, entry.Name()), Size: info.Size(), UpdatedAt: info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (m *Manager) Get(name string) (*Profile, error) {
	path := filepath.Join(m.profilesDir, filepath.Base(name))
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &Profile{ProfileInfo: ProfileInfo{Name: filepath.Base(name), Path: path, Size: info.Size(), UpdatedAt: info.ModTime()}, Content: string(content)}, nil
}

func (m *Manager) Save(name string, content []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.Validate(content); err != nil {
		return err
	}
	path := filepath.Join(m.profilesDir, filepath.Base(name))
	if m.backupCfg.Enabled {
		_ = m.createBackupLocked(name)
	}
	return os.WriteFile(path, content, 0o600)
}

func (m *Manager) Delete(name string) error {
	return os.Remove(filepath.Join(m.profilesDir, filepath.Base(name)))
}

func (m *Manager) Validate(content []byte) error {
	if len(strings.TrimSpace(string(content))) == 0 {
		return errors.New("profile content is empty")
	}
	return validateProfile(content)
}

func (m *Manager) Backups(name string) ([]BackupInfo, error) {
	if !m.backupCfg.Enabled || m.backupCfg.Dir == "" {
		return []BackupInfo{}, nil
	}
	entries, err := os.ReadDir(m.backupCfg.Dir)
	if err != nil {
		return nil, err
	}
	prefix := filepath.Base(name) + "-"
	items := make([]BackupInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		id := strings.TrimPrefix(entry.Name(), prefix)
		items = append(items, BackupInfo{ID: id, Profile: filepath.Base(name), CreatedAt: info.ModTime(), Size: info.Size()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return items, nil
}

func (m *Manager) Restore(name string, backupID string) error {
	backupPath := filepath.Join(m.backupCfg.Dir, filepath.Base(name)+"-"+filepath.Base(backupID))
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.profilesDir, filepath.Base(name)), content, 0o600)
}

func (m *Manager) createBackupLocked(name string) error {
	if m.backupCfg.Dir == "" {
		return nil
	}
	src := filepath.Join(m.profilesDir, filepath.Base(name))
	content, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := filepath.Join(m.backupCfg.Dir, filepath.Base(name)+"-"+id)
	if err := os.WriteFile(dst, content, 0o600); err != nil {
		return err
	}
	if m.backupCfg.MaxBackups > 0 {
		items, err := m.Backups(name)
		if err != nil {
			return err
		}
		for i := m.backupCfg.MaxBackups; i < len(items); i++ {
			_ = os.Remove(filepath.Join(m.backupCfg.Dir, filepath.Base(name)+"-"+items[i].ID))
		}
	}
	return nil
}
