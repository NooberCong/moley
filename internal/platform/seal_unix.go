//go:build unix

package platform

// Sealer is a pass-through on Unix for now: the state file is 0600 in the
// user's config dir. Keychain/libsecret sealing is a later phase.
type Sealer struct{ Machine bool }

func (Sealer) Seal(b []byte) ([]byte, error)   { return b, nil }
func (Sealer) Unseal(b []byte) ([]byte, error) { return b, nil }
