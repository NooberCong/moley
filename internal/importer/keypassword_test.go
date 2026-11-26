package importer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

func TestEncryptedKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := pkcs8.MarshalPrivateKey(key, []byte("hunter2"), nil)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}))
	ovpn := "client\ndev tun\nremote vpn.example.com 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n" +
		"<cert>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</cert>\n<key>\n" + encrypted + "</key>\n"

	if _, err := Parse("work.ovpn", []byte(ovpn)); !errors.Is(err, ErrKeyEncrypted) {
		t.Fatalf("no password: got %v", err)
	}
	if _, err := ParseWith("work.ovpn", []byte(ovpn), Options{KeyPassword: "wrong"}); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("wrong password: got %v", err)
	}
	res, err := ParseWith("work.ovpn", []byte(ovpn), Options{KeyPassword: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		TLS struct {
			ClientKey []string `json:"client_key"`
		} `json:"tls"`
	}
	_ = json.Unmarshal(res.Profiles[0].Config, &cfg)
	block, _ := pem.Decode([]byte(strings.Join(cfg.TLS.ClientKey, "\n")))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("stored key is not a plain PKCS#8 PEM: %v", cfg.TLS.ClientKey)
	}
	got, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || !got.(*ecdsa.PrivateKey).Equal(key) {
		t.Fatalf("decrypted key differs: %v", err)
	}
}
