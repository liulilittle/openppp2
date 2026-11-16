package binary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var versionRe = regexp.MustCompile(`version:\s*(\S+)`)
var versionStrRe = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d{4,})\b`)

func computeSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// detectVersion reads the version from the binary. The "strings" scan is
// passive; running the file is only done when allowExec is true, i.e. the file
// is a plausible ppp binary located in a trusted directory.
func detectVersion(path string, allowExec bool) string {
	// Try strings first (faster for large binaries)
	if _, err := exec.LookPath("strings"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "strings", path)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		if err := cmd.Run(); err == nil {
			if m := versionStrRe.FindStringSubmatch(buf.String()); m != nil {
				return m[1]
			}
		}
	}

	if !allowExec {
		return "unknown"
	}

	// Fallback: run the binary and parse version line
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	cmd2 := exec.CommandContext(ctx2, path)
	var buf2 bytes.Buffer
	cmd2.Stdout = &buf2
	cmd2.Stderr = &buf2
	_ = cmd2.Run()
	if m := versionRe.FindStringSubmatch(buf2.String()); m != nil {
		return m[1]
	}

	return "unknown"
}

func detectArch(path string) string {
	if out, err := exec.Command("file", path).Output(); err == nil {
		text := strings.ToLower(string(out))
		switch {
		case strings.Contains(text, "x86-64") || strings.Contains(text, "x86_64"):
			return "amd64"
		case strings.Contains(text, "aarch64") || strings.Contains(text, "arm64"):
			return "arm64"
		case strings.Contains(text, "arm"):
			return "arm"
		case strings.Contains(text, "386") || strings.Contains(text, "i386"):
			return "386"
		}
	}
	name := strings.ToLower(filepath.Base(path))
	for _, arch := range []string{"amd64", "arm64", "arm", "386"} {
		if strings.Contains(name, arch) {
			return arch
		}
	}
	return runtime.GOARCH
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
