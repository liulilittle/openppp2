package binary

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type DiscoveredBinary struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Arch    string `json:"arch"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type BinaryInfo struct {
	ID      string    `json:"id"`
	Path    string    `json:"path"`
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	Size    int64     `json:"size"`
	Arch    string    `json:"arch"`
	AddedAt time.Time `json:"addedAt"`
	Active  bool      `json:"active"`

	// execOK allows running the file to detect its version (never serialized).
	execOK bool
}

type Manager struct {
	mu          sync.Mutex
	binariesDir string
	items       map[string]BinaryInfo
	activeID    string
}

func NewManager(binariesDir string) *Manager {
	_ = os.MkdirAll(binariesDir, 0o755)
	return &Manager{binariesDir: binariesDir, items: make(map[string]BinaryInfo)}
}

func (m *Manager) List() ([]BinaryInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]BinaryInfo, 0, len(m.items))
	for _, item := range m.items {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].AddedAt.Before(items[j].AddedAt) })
	return items, nil
}

// Register records srcPath. Any existing file may be registered, but it is
// only executed for version detection when it is a plausibly named, executable
// regular file inside the configured binaries directory.
func (m *Manager) Register(srcPath string) (*BinaryInfo, error) {
	return m.register(srcPath, false)
}

// register adds the binary; trusted marks paths found by auto-discovery.
func (m *Manager) register(srcPath string, trusted bool) (*BinaryInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if srcPath == "" {
		return nil, errors.New("path is required")
	}
	cleanPath := filepath.Clean(srcPath)
	stat, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}
	sha, err := computeSHA256(cleanPath)
	if err != nil {
		return nil, err
	}
	id := sha[:12]
	if existing, ok := m.items[id]; ok {
		return &existing, nil
	}
	info := BinaryInfo{ID: id, Path: cleanPath, SHA256: sha, Size: stat.Size(), Arch: detectArch(cleanPath), Version: "", AddedAt: time.Now(), Active: len(m.items) == 0, execOK: m.mayExecute(cleanPath, stat, trusted)}
	if info.Active {
		m.activeID = id
	}
	m.items[id] = info

	// Version detection is slow — do it in background
	go func() {
		ver := detectVersion(info.Path, info.execOK)
		m.mu.Lock()
		if item, ok := m.items[id]; ok {
			item.Version = ver
			m.items[id] = item
		}
		m.mu.Unlock()
	}()

	return &info, nil
}

func (m *Manager) DetectVersionAsync(id string) {
	go func() {
		m.mu.Lock()
		info, ok := m.items[id]
		m.mu.Unlock()
		if !ok {
			return
		}
		ver := detectVersion(info.Path, info.execOK)
		m.mu.Lock()
		if info, ok := m.items[id]; ok {
			info.Version = ver
			m.items[id] = info
		}
		m.mu.Unlock()
	}()
}

func (m *Manager) Discover(dir string) ([]DiscoveredBinary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	items := make([]DiscoveredBinary, 0)
	for _, entry := range entries {
		if entry.IsDir() || !isPPPBinaryName(entry.Name()) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if info.Mode().IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}

		sha, err := computeSHA256(path)
		if err != nil {
			return nil, err
		}

		items = append(items, DiscoveredBinary{
			Path:    filepath.Clean(path),
			SHA256:  sha,
			Size:    info.Size(),
			Arch:    detectArch(path),
			Name:    entry.Name(),
			Version: "", // version detection is async
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Path) < strings.ToLower(items[j].Path)
	})

	return items, nil
}

func (m *Manager) AutoDiscover(dir string) ([]BinaryInfo, error) {
	discovered, err := m.Discover(dir)
	if err != nil {
		return nil, err
	}

	registered := make([]BinaryInfo, 0, len(discovered))
	for _, item := range discovered {
		info, err := m.register(item.Path, true)
		if err != nil {
			return nil, err
		}
		registered = append(registered, *info)
	}

	return registered, nil
}

func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[id]; !ok {
		return errors.New("binary not found")
	}
	delete(m.items, id)
	if m.activeID == id {
		m.activeID = ""
		for key, item := range m.items {
			item.Active = true
			m.items[key] = item
			m.activeID = key
			break
		}
	}
	return nil
}

func (m *Manager) GetPath(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return "", errors.New("binary not found")
	}
	return item.Path, nil
}

// isPPPBinaryName returns true if name looks like a ppp binary (e.g. ppp, ppp-ci, ppp.exe, ppp-ci.exe).
// Only extensionless names and Windows .exe names are accepted for auto-discovery.
func isPPPBinaryName(name string) bool {
	lower := strings.ToLower(name)
	base := lower
	if ext := filepath.Ext(lower); ext != "" {
		if ext != ".exe" {
			return false
		}
		base = strings.TrimSuffix(lower, ext)
	}
	return base == "ppp" || strings.HasPrefix(base, "ppp-")
}

// mayExecute decides whether a registered file may be run to read its version.
func (m *Manager) mayExecute(path string, stat os.FileInfo, trusted bool) bool {
	if !stat.Mode().IsRegular() || stat.Mode()&0o111 == 0 || !isPPPBinaryName(filepath.Base(path)) {
		return false
	}
	return trusted || m.insideBinariesDir(path)
}

func (m *Manager) insideBinariesDir(path string) bool {
	root, err := filepath.Abs(m.binariesDir)
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
