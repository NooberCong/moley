package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"moley/internal/cli"
	"moley/internal/teststack"
)

// TestCLI runs the real daemon against the local VPN stack and drives it
// only through the CLI, the way a script or an agent would: JSON output,
// exit codes, no prompts.
func TestCLI(t *testing.T) {
	stack, err := teststack.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	home := t.TempDir()
	t.Setenv("MOLEY_HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("MOLEY_PIPE", `\\.\pipe\moley-test-`+fmt.Sprint(time.Now().UnixNano()))
	} else {
		t.Setenv("MOLEY_PIPE", filepath.Join(home, "moley.sock"))
	}
	port := freePort(t)
	// Seed settings so the daemon listens on a free port and probes hit the stack.
	seed := fmt.Sprintf(`{"profiles":[],"exits":[],"rules":[],"default_exit":"direct","settings":{"proxy_port":%d,"health_url":%q,"ip_url":%q}}`,
		port, stack.HealthURL(), stack.PublicTraceURL())
	if err := os.WriteFile(filepath.Join(home, "moley.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	// Before the daemon runs: exit 3 with a hint.
	r := run(t, "status", "--json")
	r.code(t, cli.ExitUnreachable)
	if r.errJSON(t)["code"] != "daemon_unreachable" {
		t.Fatalf("stderr: %s", r.stderr)
	}

	done := make(chan int, 1)
	var serviceLog syncBuffer
	go func() { done <- cli.Run([]string{"service"}, &cli.Env{Stdout: &serviceLog, Stderr: &serviceLog}) }()
	waitUp(t, done, &serviceLog)

	files := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(files, name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		return p
	}

	t.Run("import", func(t *testing.T) {
		r := run(t, "import", write("work.ovpn", stack.OVPN), "--id", "sq1", "--json")
		r.code(t, cli.ExitOK)
		out := r.json(t)
		if out["v"] != float64(1) {
			t.Fatalf("missing schema version: %v", out)
		}
		p := out["profiles"].([]any)[0].(map[string]any)
		if p["id"] != "sq1" || p["kind"] != "openvpn" || p["auto_rule"] != true {
			t.Fatalf("profile: %v", p)
		}
		run(t, "import", write("wg.conf", stack.WG), "--id", "wg").code(t, cli.ExitOK)
		run(t, "import", write("awg.conf", stack.AWG), "--id", "awg").code(t, cli.ExitOK)
		run(t, "import", stack.SSLink, "--id", "ss").code(t, cli.ExitOK)
		// Same id again needs --replace: usage error, nothing changes.
		run(t, "import", stack.SSLink, "--id", "ss", "--json").code(t, cli.ExitUsage)
	})

	t.Run("profiles update", func(t *testing.T) {
		name := func(id string) any {
			for _, p := range run(t, "profiles", "--json").json(t)["profiles"].([]any) {
				if p := p.(map[string]any); p["id"] == id {
					return p["name"]
				}
			}
			t.Fatalf("no profile %q", id)
			return nil
		}
		run(t, "profiles", "update", "ss", "--name", "Tokyo").code(t, cli.ExitOK)
		if got := name("ss"); got != "Tokyo" {
			t.Fatalf("name after rename: %v", got)
		}
		// An empty --name clears it; leaving --name out keeps it.
		run(t, "profiles", "update", "ss", "--name", "").code(t, cli.ExitOK)
		if got := name("ss"); got != nil {
			t.Fatalf("name after clearing: %v", got)
		}
		run(t, "profiles", "update", "sq1", "--auto-rule", "off").code(t, cli.ExitOK)
		run(t, "profiles", "update", "sq1", "--auto-rule", "on", "--json").code(t, cli.ExitOK)
		// Auto rules are OpenVPN only; nothing to change and bad values are usage errors.
		if r := run(t, "profiles", "update", "wg", "--auto-rule", "on", "--json"); r.exit == cli.ExitOK {
			t.Fatal("auto rule on a WireGuard profile was accepted")
		}
		run(t, "profiles", "update", "ss", "--json").code(t, cli.ExitUsage)
		run(t, "profiles", "update", "ss", "--auto-rule", "maybe").code(t, cli.ExitUsage)
		run(t, "profiles", "update", "nope", "--name", "x", "--json").code(t, cli.ExitError)
	})

	t.Run("wait and probe", func(t *testing.T) {
		run(t, "wait", "--connected", "sq1", "--timeout", "20s", "--json").code(t, cli.ExitOK)
		echoPort := strings.Split(stack.EchoAddr, ":")[1]
		r := run(t, "probe", "http://"+teststack.IntranetHost+":"+echoPort+"/", "--expect-exit", "sq1", "--json")
		r.code(t, cli.ExitOK)
		if out := r.json(t); out["rule"] != "auto-sq1" || out["resolver"] != "pushed:sq1" {
			t.Fatalf("probe: %v", out)
		}
		// Split tunnel: public traffic stays direct.
		run(t, "probe", stack.TraceURL(), "--expect-exit", "direct").code(t, cli.ExitOK)
		// A mismatch is exit 4.
		run(t, "probe", stack.TraceURL(), "--expect-exit", "sq1", "--json").code(t, cli.ExitCheckFailed)
		run(t, "wait", "--healthy", "wg", "--timeout", "10s").code(t, cli.ExitOK)
		// TCP: a database port behind the work VPN, connected and nothing sent.
		r = run(t, "probe", "tcp://"+teststack.IntranetHost+":"+echoPort, "--expect-exit", "sq1")
		r.code(t, cli.ExitOK)
		if !strings.Contains(r.stdout, "connected") {
			t.Fatalf("tcp probe text: %s", r.stdout)
		}
		run(t, "probe", "tcp://"+teststack.IntranetHost, "--json").code(t, cli.ExitUsage)
	})

	t.Run("holds", func(t *testing.T) {
		run(t, "holds").code(t, cli.ExitOK)
		r := run(t, "holds", "put", "agent-1", "--for", "10m", "--json")
		r.code(t, cli.ExitOK)
		hold := r.json(t)["hold"].(map[string]any)
		if hold["name"] != "agent-1" || r.json(t)["system_routing"] != false {
			t.Fatalf("holds put: %s", r.stdout)
		}
		// Without system mode the text says the hold changes nothing yet.
		if r := run(t, "holds", "put", "agent-1"); !strings.Contains(r.stdout, "system mode is off") {
			t.Fatalf("holds put text: %s", r.stdout)
		}
		if held := run(t, "holds", "--json").json(t)["holds"].([]any); len(held) != 1 {
			t.Fatalf("holds: %v", held)
		}
		if st := run(t, "status").stdout; !strings.Contains(st, "held by agent-1") {
			t.Fatalf("status should show the hold: %s", st)
		}
		run(t, "holds", "put", "agent-1", "--for", "25h").code(t, cli.ExitUsage)
		if out := run(t, "holds", "release", "agent-1", "--json").json(t); out["removed"] != true {
			t.Fatalf("release: %v", out)
		}
		if r := run(t, "holds", "release", "agent-1"); r.exit != cli.ExitOK || !strings.Contains(r.stdout, "no hold named agent-1") {
			t.Fatalf("second release: %d %s", r.exit, r.stdout)
		}
	})

	t.Run("rules show auto", func(t *testing.T) {
		out := run(t, "rules", "show", "auto-sq1", "--json").json(t)
		learned, _ := out["learned"].(map[string]any)
		if out["live"] != true || !strings.Contains(fmt.Sprint(learned["domain_suffix"]), teststack.SearchDomain) {
			t.Fatalf("auto rule: %v", out)
		}
	})

	t.Run("exit IPs via test and exec", func(t *testing.T) {
		out := run(t, "test", "ss", "--json").json(t)
		if out["ip"] != teststack.IPShadowsocks || out["ok"] != true {
			t.Fatalf("test ss: %v", out)
		}
		// exec: the child sees proxy vars that force the exit.
		env := run(t, "env", "--exit", "wg", "--json").json(t)["env"].(map[string]any)
		if !strings.Contains(env["ALL_PROXY"].(string), "socks5h://wg:") {
			t.Fatalf("env: %v", env)
		}
		if runtime.GOOS == "windows" {
			r := run(t, "exec", "--exit", "wg", "--", "cmd", "/c", "echo %HTTPS_PROXY%")
			r.code(t, cli.ExitOK)
			if !strings.Contains(r.stdout, "@127.0.0.1:") {
				t.Fatalf("exec env: %q", r.stdout)
			}
		}
	})

	t.Run("rules and quick picks", func(t *testing.T) {
		r := run(t, "rules", "add", "pub", "--exit", "ss", "--ip-cidr", teststack.PublicIP+"/32", "--json")
		r.code(t, cli.ExitOK)
		if r.json(t)["rebuilt"] != true {
			t.Fatal("new rule should rebuild")
		}
		run(t, "probe", stack.PublicTraceURL(), "--expect-rule", "pub", "--expect-exit", "ss").code(t, cli.ExitOK)
		// Editing the same rule's match is hot.
		r = run(t, "rules", "add", "pub", "--exit", "ss", "--ip-cidr", teststack.PublicIP+"/32,10.1.0.0/16", "--json")
		if r.json(t)["rebuilt"] != false {
			t.Fatal("match edit must not rebuild")
		}
		r = run(t, "quick", teststack.EchoHost, "ss", "--json")
		if r.json(t)["rebuilt"] != false {
			t.Fatal("quick pick must not rebuild")
		}
		echoPort := strings.Split(stack.EchoAddr, ":")[1]
		run(t, "probe", "http://"+teststack.EchoHost+":"+echoPort+"/trace", "--expect-rule", "quick-ss").code(t, cli.ExitOK)
		// Removal needs --yes; without it: exit 2 and nothing changes.
		run(t, "rules", "remove", "pub", "--json").code(t, cli.ExitUsage)
		run(t, "rules", "remove", "pub", "--yes").code(t, cli.ExitOK)
		// Profiles in use can't be removed.
		r = run(t, "profiles", "remove", "ss", "--yes", "--json")
		r.code(t, cli.ExitUsage)
		if !strings.Contains(r.errJSON(t)["message"].(string), "quick pick") {
			t.Fatalf("expected a reference error: %s", r.stderr)
		}
	})

	t.Run("export and apply", func(t *testing.T) {
		exp := run(t, "export")
		exp.code(t, cli.ExitOK)
		if strings.Contains(exp.stdout, "BEGIN") || !strings.Contains(exp.stdout, `"redacted"`) {
			t.Fatal("export must redact secrets")
		}
		var cfg map[string]any
		_ = json.Unmarshal([]byte(exp.stdout), &cfg)
		cfg["default_exit"] = "wg"
		b, _ := json.Marshal(cfg)
		f := write("moley.json", string(b))
		r := run(t, "apply", "-f", f, "--dry-run", "--json")
		r.code(t, cli.ExitOK)
		if out := r.json(t); out["applied"] != false || !strings.Contains(fmt.Sprint(out["changes"]), "default exit wg") {
			t.Fatalf("dry run: %v", out)
		}
		run(t, "apply", "-f", f).code(t, cli.ExitOK)
		if run(t, "status", "--json").json(t)["default_exit"] != "wg" {
			t.Fatal("apply did not take")
		}
		// Removing a profile through apply needs --yes.
		cfg["profiles"] = cfg["profiles"].([]any)[:3]
		b, _ = json.Marshal(cfg)
		run(t, "apply", "-f", write("smaller.json", string(b)), "--json").code(t, cli.ExitUsage)
	})

	t.Run("audit log names the caller", func(t *testing.T) {
		out := run(t, "history", "--json").json(t)
		es := out["entries"].([]any)
		if len(es) < 5 {
			t.Fatalf("history: %v", out)
		}
		last := es[len(es)-1].(map[string]any)
		if last["method"] != "config.apply" || last["caller"] == "" {
			t.Fatalf("last entry: %v", last)
		}
	})

	t.Run("help and errors are machine-readable", func(t *testing.T) {
		out := run(t, "help", "--json").json(t)
		if len(out["commands"].([]any)) < 20 || len(out["methods"].([]any)) < 20 {
			t.Fatalf("help: %v", out)
		}
		r := run(t, "rules", "add", "x", "--exit", "nope", "--domain", "a.com", "--json")
		r.code(t, cli.ExitUsage)
		if r.errJSON(t)["code"] != "invalid_params" {
			t.Fatalf("stderr: %s", r.stderr)
		}
		run(t, "frobnicate").code(t, cli.ExitUsage)
		r = run(t, "rpc", "conns.list", `{"host":"echo.test","closed":true}`, "--json")
		r.code(t, cli.ExitOK)
	})

	run(t, "stop").code(t, cli.ExitOK)
	select {
	case code := <-done:
		if code != cli.ExitOK {
			t.Fatalf("service exited %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("service did not stop")
	}
}

type result struct {
	exit           int
	stdout, stderr string
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(args, &cli.Env{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	return result{code, out.String(), errb.String()}
}

func (r result) code(t *testing.T, want int) {
	t.Helper()
	if r.exit != want {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.exit, want, r.stdout, r.stderr)
	}
}

func (r result) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
	return m
}

func (r result) errJSON(t *testing.T) map[string]any {
	t.Helper()
	var m struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal([]byte(r.stderr), &m); err != nil || m.Error == nil {
		t.Fatalf("stderr is not a JSON error: %v\n%s", err, r.stderr)
	}
	return m.Error
}

func waitUp(t *testing.T, done chan int, log *syncBuffer) {
	t.Helper()
	for range 100 {
		select {
		case code := <-done:
			t.Fatalf("service exited %d:\n%s", code, log.String())
		default:
		}
		if run(t, "status").exit == cli.ExitOK {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("daemon did not come up:\n%s", log.String())
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freePort(t *testing.T) int {
	for range 50 {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if l2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p+1)); err == nil {
			l2.Close()
			return p
		}
	}
	t.Fatal("no free port pair")
	return 0
}
