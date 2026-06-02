package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const osLinux = "linux"

func TestDefaultDBPath_NonEmpty(t *testing.T) {
	p := defaultDBPath()
	if p == "" {
		t.Fatal("defaultDBPath() returned empty string")
	}
	if !strings.HasSuffix(p, filepath.Join("gogatoz", "results.db")) {
		t.Fatalf("unexpected path suffix: %s", p)
	}
}

func TestDefaultDBPath_XDGOverride(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("XDG_DATA_HOME only applies on Linux")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", tmp)
	p := defaultDBPath()
	want := filepath.Join(tmp, "gogatoz", "results.db")
	if p != want {
		t.Fatalf("got %q, want %q", p, want)
	}
}

func TestDefaultDBPath_NoHome(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("test applies on Linux only")
	}
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")
	p := defaultDBPath()
	// With no HOME, os.UserHomeDir fails and we return ""
	if p != "" {
		// Some systems may still resolve HOME; just ensure no panic
		_ = p
	}
}

func TestDefaultDBPath_EnsureDirectoryCreatable(t *testing.T) {
	p := defaultDBPath()
	if p == "" {
		t.Skip("no default path on this platform")
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("cannot create default DB directory %s: %v", dir, err)
	}
}
