package platform

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// NativeHostName is the native messaging host the extension connects to.
const NativeHostName = "com.moley.host"

// nativeHostManifest renders the Chromium host manifest.
func nativeHostManifest(exe string, origins []string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"name":            NativeHostName,
		"description":     "Moley",
		"path":            exe,
		"type":            "stdio",
		"allowed_origins": origins,
	}, "", "  ")
}

func writeManifest(path, exe string, origins []string) error {
	b, err := nativeHostManifest(exe, origins)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
