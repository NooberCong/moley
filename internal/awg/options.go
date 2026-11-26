// Package awg adds an AmneziaWG outbound to the core. sing-box has no
// AmneziaWG support, so this wraps amneziawg-go (userspace device + gVisor
// netstack) and registers it as outbound type "amneziawg".
package awg

// Options mirrors an AmneziaWG .conf. H1-H4 are strings because AWG 2.0
// accepts ranges ("100-200"); I1-I5 are the special junk packet templates.
type Options struct {
	PrivateKey string   `json:"private_key"`
	Address    []string `json:"address"`        // interface prefixes, e.g. "10.8.0.2/32"
	DNS        []string `json:"dns,omitempty"`  // set by compile from model.Profile.DNS
	MTU        int      `json:"mtu,omitempty"`  // default 1420
	Jc         int      `json:"jc,omitempty"`   // junk packet count
	Jmin       int      `json:"jmin,omitempty"` // junk packet min size
	Jmax       int      `json:"jmax,omitempty"` // junk packet max size
	S1         int      `json:"s1,omitempty"`   // init packet padding
	S2         int      `json:"s2,omitempty"`   // response packet padding
	S3         int      `json:"s3,omitempty"`   // cookie packet padding (AWG 2.0)
	S4         int      `json:"s4,omitempty"`   // transport packet padding (AWG 2.0)
	H1         string   `json:"h1,omitempty"`   // magic headers, value or range
	H2         string   `json:"h2,omitempty"`
	H3         string   `json:"h3,omitempty"`
	H4         string   `json:"h4,omitempty"`
	I1         string   `json:"i1,omitempty"`
	I2         string   `json:"i2,omitempty"`
	I3         string   `json:"i3,omitempty"`
	I4         string   `json:"i4,omitempty"`
	I5         string   `json:"i5,omitempty"`
	Peers      []Peer   `json:"peers"`
}

type Peer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Endpoint            string   `json:"endpoint"` // host:port
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}
