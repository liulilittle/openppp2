package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func profilePath(dir, name string) string {
	clean := strings.TrimSpace(name)
	return filepath.Join(dir, clean+".json")
}

func listProfiles(dir string) ([]ProfileInfo, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	profiles := make([]ProfileInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, ProfileInfo{
			Name:      strings.TrimSuffix(entry.Name(), ".json"),
			Path:      path,
			Size:      info.Size(),
			UpdatedAt: info.ModTime(),
		})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return profiles, nil
}

func readProfile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}

func writeFileAtomic(path string, content []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "guardian-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
