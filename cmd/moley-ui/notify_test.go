package main

import "testing"

// TestVPNChange walks the VPN through connecting, a drop, reconnecting,
// switching and disconnecting, and checks what each step says.
func TestVPNChange(t *testing.T) {
	steps := []struct {
		name    string
		next    vpn
		offline bool
		want    string
	}{
		{"connecting says nothing yet", vpn{exit: "tokyo"}, false, ""},
		{"connected", vpn{exit: "tokyo", up: true}, false, "Connected"},
		{"still up", vpn{exit: "tokyo", up: true}, false, ""},
		{"dropped", vpn{exit: "tokyo"}, false, "Connection lost"},
		{"still down", vpn{exit: "tokyo"}, false, ""},
		{"back", vpn{exit: "tokyo", up: true}, false, "Reconnected"},
		{"switched", vpn{exit: "paris", up: true}, false, "Connected"},
		{"turned off", vpn{}, false, "Disconnected"},
		{"still off", vpn{}, false, ""},
		{"connected to a group", vpn{exit: "fastest", up: true}, false, "Connected"},
		{"Moley stopped", vpn{}, true, "Disconnected"},
	}
	var cur vpn
	for _, s := range steps {
		var title string
		cur, title, _ = vpnChange(cur, s.next, s.offline)
		if title != s.want {
			t.Errorf("%s: said %q, want %q", s.name, title, s.want)
		}
	}
}

func TestVPNOf(t *testing.T) {
	var st status
	st.DefaultExit = "tokyo"
	st.Profiles = append(st.Profiles, profileStatus{ID: "tokyo", State: "connecting"})
	if v := vpnOf(st, false); v.exit != "tokyo" || v.up {
		t.Errorf("connecting profile: %+v", v)
	}
	st.Profiles[0].State = "connected"
	if v := vpnOf(st, false); !v.up {
		t.Errorf("connected profile: %+v", v)
	}
	if v := vpnOf(st, true); v.exit != "" {
		t.Errorf("offline: %+v", v)
	}
	st.DefaultExit = "direct"
	if v := vpnOf(st, false); v.exit != "" {
		t.Errorf("direct: %+v", v)
	}
}
