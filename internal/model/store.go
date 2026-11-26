package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Sealer encrypts profile configs (keys, passwords) at rest.
type Sealer interface {
	Seal([]byte) ([]byte, error)
	Unseal([]byte) ([]byte, error)
}

// Load reads the config at path. A missing file is an empty config.
func Load(path string, s Sealer) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{DefaultExit: ExitDirect}, nil
	}
	if err != nil {
		return cfg, err
	}
	var disk diskConfig
	if err := json.Unmarshal(b, &disk); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	cfg = disk.Config
	cfg.Profiles = make([]Profile, len(disk.Profiles))
	for i, dp := range disk.Profiles {
		p := dp.Profile
		p.Config = dp.Config // hand-written, unsealed
		if dp.Sealed != "" {
			raw, err := base64.StdEncoding.DecodeString(dp.Sealed)
			if err == nil {
				raw, err = s.Unseal(raw)
			}
			if err != nil {
				return cfg, fmt.Errorf("profile %q: unseal: %w", p.ID, err)
			}
			p.Config = raw
		}
		cfg.Profiles[i] = p
	}
	return cfg, nil
}

// Save writes cfg to path atomically, sealing each profile's config.
func Save(path string, cfg Config, s Sealer) error {
	disk := diskConfig{Config: cfg, Profiles: make([]diskProfile, len(cfg.Profiles))}
	for i, p := range cfg.Profiles {
		sealed, err := s.Seal(p.Config)
		if err != nil {
			return fmt.Errorf("profile %q: seal: %w", p.ID, err)
		}
		p.Config = nil
		disk.Profiles[i] = diskProfile{Profile: p, Sealed: base64.StdEncoding.EncodeToString(sealed)}
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type diskConfig struct {
	Config
	Profiles []diskProfile `json:"profiles"`
}

type diskProfile struct {
	Profile
	Config json.RawMessage `json:"config,omitempty"` // shadows Profile.Config; unsealed legacy
	Sealed string          `json:"sealed,omitempty"`
}

// Clone deep-copies a config.
func (c Config) Clone() Config {
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	return out
}
