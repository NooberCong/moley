package teststack

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// BlockedHost resolves only over the stack's DNS over HTTPS, to the echo
// server: a site the network's plain DNS hides, as when an ISP rewrites
// its answers.
const BlockedHost = "blocked.test"

// startDoH serves DNS over HTTPS on loopback with a certificate from ca.
// It answers BlockedHost and nothing else (NXDOMAIN), so a name that
// resolves anyway was looked up elsewhere.
func (s *Stack) startDoH(ca string, caKey *ecdsa.PrivateKey) error {
	cert, key := newLeaf(ca, caKey, "doh", x509.ExtKeyUsageServerAuth, net.IPv4(127, 0, 0, 1))
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		return err
	}
	s.DoHURL = "https://" + ln.Addr().String() + "/dns-query"
	s.DoHCA = ca
	s.doh = &http.Server{Handler: http.HandlerFunc(serveDoH)}
	go s.doh.Serve(ln)
	return nil
}

// serveDoH answers RFC 8484 POST queries.
func serveDoH(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	var q dnsmessage.Message
	if err != nil || q.Unpack(body) != nil || len(q.Questions) != 1 {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	question := q.Questions[0]
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError},
		Questions: q.Questions,
	}
	if strings.EqualFold(strings.TrimSuffix(question.Name.String(), "."), BlockedHost) {
		resp.RCode = dnsmessage.RCodeSuccess
		if question.Type == dnsmessage.TypeA {
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			}}
		}
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(out)
}
