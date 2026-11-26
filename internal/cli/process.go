package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"moley/internal/daemon"
	"moley/internal/engine"
	"moley/internal/model"
	"moley/internal/platform"
	"moley/internal/rpc"
)

// proxyEnv returns the proxy variables that send a program through Moley.
// With an exit, the proxy username names it (the hint inbound).
func (c *call) proxyEnv(exit string) (map[string]string, error) {
	var h daemon.HelloResult
	if err := c.rpc("client.hello", nil, &h); err != nil {
		return nil, err
	}
	host, user := fmt.Sprintf("127.0.0.1:%d", h.ProxyPort), ""
	if exit != "" {
		known := false
		for _, x := range h.Exits {
			known = known || x == exit
		}
		if !known {
			return nil, usageErr("unknown exit %q (see `moley exits`)", exit)
		}
		host = fmt.Sprintf("127.0.0.1:%d", h.HintPort)
		user = url.UserPassword(exit, h.Secret).String() + "@"
	}
	httpURL := "http://" + user + host
	return map[string]string{
		"HTTP_PROXY": httpURL, "HTTPS_PROXY": httpURL, "http_proxy": httpURL, "https_proxy": httpURL,
		"ALL_PROXY": "socks5h://" + user + host, "all_proxy": "socks5h://" + user + host,
	}, nil
}

func cmdExec(c *call) error {
	exit := c.flags.String("exit", "", "force this exit")
	if err := c.parse(0, -1); err != nil {
		return err
	}
	argv := append(c.args, c.after...)
	if len(argv) == 0 {
		return usageErr("usage: moley exec [--exit X] -- <command…>")
	}
	vars, err := c.proxyEnv(*exit)
	if err != nil {
		return err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.Env = os.Environ()
	for k, v := range vars {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// Pass the program's own exit code through.
		return &cliError{code: ee.ExitCode(), rpc: rpcErr("command_failed", fmt.Sprintf("%s exited with %d", argv[0], ee.ExitCode()))}
	}
	return err
}

func cmdEnv(c *call) error {
	exit := c.flags.String("exit", "", "force this exit")
	shell := c.flags.String("shell", defaultShell(), "pwsh, bash, cmd or fish")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	vars, err := c.proxyEnv(*exit)
	if err != nil {
		return err
	}
	if c.JSON {
		return writeJSON(c.Stdout, map[string]any{"v": SchemaVersion, "env": vars})
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		v := vars[k]
		switch *shell {
		case "pwsh", "powershell":
			fmt.Fprintf(c.Stdout, "$env:%s = '%s'\n", k, v)
		case "cmd":
			fmt.Fprintf(c.Stdout, "set %s=%s\n", k, v)
		case "fish":
			fmt.Fprintf(c.Stdout, "set -gx %s '%s'\n", k, v)
		case "bash", "sh", "zsh":
			fmt.Fprintf(c.Stdout, "export %s='%s'\n", k, v)
		default:
			return usageErr("unknown shell %q", *shell)
		}
	}
	return nil
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		return "pwsh"
	}
	return "bash"
}

func cmdService(c *call) error {
	debug := c.flags.Bool("debug", false, "verbose core logs")
	sys := c.flags.Bool("system", false, "run as the privileged service")
	var allow multi
	c.flags.Var(&allow, "allow", "Windows user SID that may use the service (repeatable)")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if *sys {
		platform.SetSystem(allow)
	}
	serve := func(ctx context.Context) error {
		dir, err := platform.DataDir()
		if err != nil {
			return err
		}
		if err := platform.PrepareDataDir(dir); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(dir, "moley.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		logs := engine.NewLogs(io.MultiWriter(c.Stderr, f), *debug)
		ln, err := platform.Listen()
		if err != nil {
			return &cliError{code: ExitError, rpc: rpcErr("listen_failed", "can't open the control pipe (is another moley running?): "+err.Error())}
		}
		d, err := daemon.Open(dir, logs)
		if err != nil {
			logs.Error("start: " + err.Error()) // `moley start` has no terminal
			ln.Close()
			return err
		}
		defer d.Close()
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		go func() {
			select {
			case <-d.Stopped():
				stop()
			case <-ctx.Done():
			}
		}()
		logs.Info("moley " + daemon.Version + " serving on " + platform.PipePath() + ", data in " + dir)
		return d.Serve(ctx, ln)
	}
	if ran, err := platform.RunService(serve); ran {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx)
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdServiceInstall(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Admit whoever is installing; a package install may not know who that
	// is, and says how to join later.
	var allow []string
	note := ""
	if user, err := platform.CurrentUser(); err == nil {
		allow = []string{user}
	} else {
		note = "to control Moley as yourself: sudo usermod -aG moley $USER, then sign in again"
	}
	// A per-user daemon would hold the control pipe and proxy port.
	if err := c.stopUserDaemon(); err != nil {
		return fmt.Errorf("stop your per-user daemon: %w", err)
	}
	moved, err := migrate()
	if err != nil {
		return fmt.Errorf("move your config to the service: %w", err)
	}
	if err := platform.InstallService(exe, allow); err != nil {
		return err
	}
	if err := platform.StartService(); err != nil {
		return err
	}
	if err := c.waitReady(); err != nil {
		return err
	}
	return c.emit(map[string]any{"installed": true, "moved_config": moved, "note": note}, func(w io.Writer) {
		fmt.Fprintln(w, "the Moley service is installed and running; turn on system mode with `moley mode --tun on`")
		if moved {
			fmt.Fprintln(w, "your profiles and rules moved to it")
		}
		if note != "" {
			fmt.Fprintln(w, note)
		}
	})
}

// stopUserDaemon ends a per-user daemon, if one runs: it holds the control
// pipe and the proxy port the service needs.
func (c *call) stopUserDaemon() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := platform.Dial(ctx)
	if err != nil {
		return nil // nothing running
	}
	pid := platform.ServerPID(conn)
	cl := rpc.NewClient(conn)
	defer cl.Close()
	var st daemon.StatusResult
	if err := cl.Call(ctx, "status", nil, &st); err == nil && st.Mode.Service {
		return nil // the service itself (a reinstall)
	}
	_ = cl.Call(ctx, "daemon.stop", nil, nil)
	if pid == 0 {
		time.Sleep(2 * time.Second)
		return nil
	}
	return platform.EndProcess(pid, 5*time.Second)
}

// migrate copies the per-user daemon's state to the service, unless the
// service already has its own. Secrets are resealed for the machine.
func migrate() (bool, error) {
	from, err := platform.InstallerUserDataDir()
	if err != nil {
		return false, err
	}
	to := platform.SystemDataDir()
	if fileExists(filepath.Join(to, "moley.json")) || !fileExists(filepath.Join(from, "moley.json")) {
		return false, nil
	}
	cfg, err := model.Load(filepath.Join(from, "moley.json"), platform.Sealer{})
	if err != nil {
		return false, err
	}
	platform.SetSystem(nil) // the service's directory and sealing
	if err := platform.PrepareDataDir(to); err != nil {
		return false, err
	}
	if err := model.Save(filepath.Join(to, "moley.json"), cfg, platform.NewSealer()); err != nil {
		return false, err
	}
	// What auto rules learned keeps intranet hosts failing closed.
	learned, _ := filepath.Glob(filepath.Join(from, "rules", "auto-*.json"))
	if len(learned) > 0 {
		if err := os.MkdirAll(filepath.Join(to, "rules"), 0o700); err != nil {
			return false, err
		}
	}
	for _, f := range learned {
		b, err := os.ReadFile(f)
		if err == nil {
			err = os.WriteFile(filepath.Join(to, "rules", filepath.Base(f)), b, 0o600)
		}
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func cmdServiceUninstall(c *call) error {
	yes := c.flags.Bool("yes", false, "confirm")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if !*yes {
		return &cliError{code: ExitUsage, rpc: rpc.Error{Code: rpc.CodeConfirm, Hint: "pass --yes to confirm",
			Message: "this removes the Moley service: system mode and the kill switch stop; its config stays in " + platform.SystemDataDir()}}
	}
	if err := platform.UninstallService(); err != nil {
		return err
	}
	return c.emit(map[string]any{"uninstalled": true}, func(w io.Writer) { fmt.Fprintln(w, "the Moley service is removed") })
}

func cmdServiceRestoreBlock(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	on, err := platform.RestoreKillSwitch()
	if err != nil {
		return err
	}
	return c.emit(map[string]any{"blocking": on}, func(w io.Writer) {
		if on {
			fmt.Fprintln(w, "persistent kill switch: blocking until Moley is up")
		}
	})
}

func cmdMode(c *call) error {
	tun := c.flags.String("tun", "", "on or off")
	kill := c.flags.String("kill-switch", "", "off, on or persistent")
	yes := c.flags.Bool("yes", false, "confirm a persistent kill switch")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if *tun == "" && *kill == "" {
		var st daemon.StatusResult
		if err := c.rpc("status", nil, &st); err != nil {
			return err
		}
		return c.emit(st.Mode, func(w io.Writer) { fmt.Fprintln(w, describeMode(st.Mode)) })
	}
	p := daemon.ModeParams{Yes: *yes}
	switch *tun {
	case "":
	case "on", "off":
		on := *tun == "on"
		p.TUN = &on
	default:
		return usageErr("--tun takes on or off")
	}
	if *kill != "" {
		p.KillSwitch = kill
	}
	var res map[string]any
	if err := c.rpc("mode.set", p, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintln(w, res["summary"]) })
}

func cmdEvents(c *call) error {
	conns := c.flags.Bool("conns", false, "also stream open connections")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if err := c.connect(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := c.client.Subscribe(ctx, "events.subscribe", daemon.SubscribeParams{Conns: *conns}, func(event string, data json.RawMessage) error {
		if c.JSON {
			return writeJSON(c.Stdout, map[string]any{"v": SchemaVersion, "event": event, "data": data})
		}
		switch event {
		case daemon.EventStatus:
			var st daemon.StatusResult
			_ = json.Unmarshal(data, &st)
			up := 0
			for _, p := range st.Profiles {
				if p.State == "connected" || p.State == "ready" {
					up++
				}
			}
			fmt.Fprintf(c.Stdout, "%s status: %d/%d profiles up · default %s · %s\n",
				time.Now().Format("15:04:05"), up, len(st.Profiles), st.DefaultExit, strings.ReplaceAll(describeMode(st.Mode), "\n", " · "))
		case daemon.EventTraffic:
			var t daemon.Traffic
			_ = json.Unmarshal(data, &t)
			fmt.Fprintf(c.Stdout, "%s traffic: ↑ %s/s ↓ %s/s · %d open\n", time.Now().Format("15:04:05"), bytes(t.Up), bytes(t.Down), t.Open)
		case daemon.EventConns:
			var cs []engine.Conn
			_ = json.Unmarshal(data, &cs)
			fmt.Fprintf(c.Stdout, "%s conns: %d open\n", time.Now().Format("15:04:05"), len(cs))
		}
		return nil
	})
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	return rpcError("events.subscribe", err)
}

func cmdStart(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var st daemon.StatusResult
	if c.rpc("status", nil, &st) == nil {
		return c.emit(map[string]any{"started": false, "running": true}, func(w io.Writer) { fmt.Fprintln(w, "already running") })
	}
	c.client = nil
	if platform.ServiceInstalled() {
		if err := platform.StartService(); err != nil {
			return checkFailed("start_failed", "", "start the Moley service: %v", err)
		}
	} else {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(exe, "service")
		platform.Detach(cmd)
		if err := cmd.Start(); err != nil {
			return err
		}
		_ = cmd.Process.Release()
	}
	if err := c.waitReady(); err != nil {
		return err
	}
	var st2 daemon.StatusResult
	_ = c.rpc("status", nil, &st2)
	return c.emit(map[string]any{"started": true, "running": true}, func(w io.Writer) {
		fmt.Fprintf(w, "started · proxy 127.0.0.1:%d\n", st2.ProxyPort)
	})
}

// waitReady waits until the daemon answers.
func (c *call) waitReady() error {
	var st daemon.StatusResult
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		c.client = nil
		if c.rpc("status", nil, &st) == nil {
			return nil
		}
	}
	dir, _ := platform.DataDir()
	return checkFailed("start_failed", "see "+filepath.Join(dir, "moley.log"), "the daemon did not come up")
}

func cmdStop(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if err := c.rpc("daemon.stop", nil, nil); err != nil {
		return err
	}
	return c.emit(map[string]any{"stopped": true}, func(w io.Writer) { fmt.Fprintln(w, "stopped") })
}

func cmdBrowserInstall(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	where, err := platform.InstallNativeHost(exe, ExtensionOrigins())
	if err != nil {
		return err
	}
	return c.emit(map[string]any{"installed": where}, func(w io.Writer) {
		for _, p := range where {
			fmt.Fprintln(w, "registered for "+p)
		}
	})
}

func cmdBrowserUninstall(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if err := platform.UninstallNativeHost(); err != nil {
		return err
	}
	return c.emit(map[string]any{"uninstalled": true}, func(w io.Writer) { fmt.Fprintln(w, "native host removed") })
}

func cmdHelp(c *call) error {
	if err := c.parse(0, 2); err != nil {
		return err
	}
	if len(c.args) > 0 {
		cmd, _ := lookup(c.args)
		if cmd == nil {
			return usageErr("unknown command %q", strings.Join(c.args, " "))
		}
		if !c.JSON {
			printCommandHelp(c.Stdout, cmd)
			return nil
		}
	}
	if !c.JSON {
		printUsage(c.Stdout)
		return nil
	}
	type cmdInfo struct {
		Command string `json:"command"`
		Args    string `json:"args,omitempty"`
		Summary string `json:"summary"`
		Example string `json:"example"`
	}
	var cmds []cmdInfo
	for _, x := range commands {
		cmds = append(cmds, cmdInfo{x.name, x.args, x.summary, x.example})
	}
	return writeJSON(c.Stdout, map[string]any{
		"v": SchemaVersion, "commands": cmds, "methods": daemon.Methods(),
		"exit_codes": map[string]string{
			strconv.Itoa(ExitOK): "ok", strconv.Itoa(ExitError): "error", strconv.Itoa(ExitUsage): "usage or confirmation needed",
			strconv.Itoa(ExitUnreachable): "daemon unreachable", strconv.Itoa(ExitCheckFailed): "check failed (unhealthy, timeout, probe mismatch)",
		},
		"global_flags": map[string]string{"--json": "machine-readable output; errors as JSON on stderr. Also MOLEY_OUTPUT=json."},
	})
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "moley: route traffic across VPNs and proxies, per site, per app, per command.")
	fmt.Fprintln(w)
	tw := table(w, "COMMAND", "")
	for _, x := range commands {
		fmt.Fprintf(tw, "  %s\t%s\n", x.name, x.summary)
	}
	tw.Flush()
	fmt.Fprintln(w, "\nEvery command takes --json. `moley help <command>` shows usage; `moley help --json` describes everything.")
}

func printCommandHelp(w io.Writer, cmd *command) {
	fmt.Fprintf(w, "moley %s %s\n\n%s\n\nexample:\n  %s\n", cmd.name, cmd.args, cmd.summary, cmd.example)
}

func rpcErr(code, msg string) rpc.Error { return rpc.Error{Code: code, Message: msg} }
