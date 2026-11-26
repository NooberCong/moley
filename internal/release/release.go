// Package release signs Moley's installers and writes the update manifest
// the tray app checks (the Wails update manifest format, schema 1): each
// artifact's SHA-256 digest, signed with the release Ed25519 key whose
// public half is built into the app.
package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
)

// Keygen makes a release key pair, base64-encoded.
func Keygen() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// Artifact is one downloadable file of a release.
type Artifact struct {
	URL           string `json:"url"`
	Filename      string `json:"filename"`
	Filetype      string `json:"filetype,omitempty"`
	Size          int64  `json:"size"`
	Platform      string `json:"platform"` // windows, linux
	Arch          string `json:"arch"`     // amd64
	DigestAlgo    string `json:"digestAlgo"`
	Digest        string `json:"digest"`
	SignatureAlgo string `json:"signatureAlgo"`
	Signature     string `json:"signature"`
}

type Manifest struct {
	SchemaVersion int        `json:"schemaVersion"`
	Version       string     `json:"version"`
	Notes         string     `json:"notes,omitempty"`
	PublishedAt   string     `json:"publishedAt"`
	Artifacts     []Artifact `json:"artifacts"`
}

// Sign hashes the file in r and signs the digest with the base64 private
// key.
func Sign(r io.Reader, privateKey string, a Artifact) (Artifact, error) {
	key, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return a, err
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return a, err
	}
	digest := h.Sum(nil)
	a.Size = n
	a.DigestAlgo, a.Digest = "sha256", base64.StdEncoding.EncodeToString(digest)
	a.SignatureAlgo = "ed25519"
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), digest))
	return a, nil
}

// NewManifest describes a release of version with its signed artifacts.
func NewManifest(version, notes string, artifacts ...Artifact) ([]byte, error) {
	return json.MarshalIndent(Manifest{SchemaVersion: 1, Version: version, Notes: notes,
		PublishedAt: time.Now().UTC().Format(time.RFC3339), Artifacts: artifacts}, "", "  ")
}
