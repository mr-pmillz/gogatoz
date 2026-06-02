package cmd

import (
	"os"
	"path/filepath"
	"runtime"
)

// defaultDBPath returns the platform-appropriate default database path.
// Linux: $XDG_DATA_HOME/gogatoz/results.db (fallback ~/.local/share/gogatoz/results.db)
// macOS/Windows: os.UserCacheDir()/gogatoz/results.db
func defaultDBPath() string {
	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "gogatoz", "results.db")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, ".local", "share", "gogatoz", "results.db")
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "gogatoz", "results.db")
}
