package main

import (
	"strings"
	"testing"
	"time"
)

// TestDescribeHolds: a hold names its holder in the tooltip without lighting
// the tray up, since it changes where nothing goes.
func TestDescribeHolds(t *testing.T) {
	var st status
	st.DefaultExit = "direct"
	st.Mode.TUN = true
	st.Holds = []hold{{Name: "agent-a", Until: time.Now().Add(time.Hour)}, {Name: "agent-b"}}

	mark, tip := describe(st)
	if mark != markDirect || tip != "Moley · Disconnected · All apps held by agent-a, agent-b" {
		t.Errorf("held: %v %q", mark, tip)
	}
	// Without system mode a hold keeps nothing up, so it isn't mentioned.
	st.Mode.TUN = false
	if _, tip := describe(st); strings.Contains(tip, "held") {
		t.Errorf("held without system mode: %q", tip)
	}
	if got := st.Holds[0].label(); !strings.HasPrefix(got, "Release agent-a (until ") {
		t.Errorf("menu label %q", got)
	}
}
