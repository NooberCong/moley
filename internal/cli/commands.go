package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"moley/internal/daemon"
	"moley/internal/engine"
	"moley/internal/model"
)

var commands []command

func init() {
	commands = []command{
		{"status", "", "Daemon state, proxy port and each profile's tunnel state.", "moley status --json", cmdStatus},
		{"import", "<file|link|-> [--id ID] [--replace] [--no-auto-rule] [--key-password-stdin]", "Import profiles: .conf (WireGuard/AmneziaWG), .ovpn, share links or a subscription body. - reads stdin. --key-password-stdin reads an encrypted key's password from stdin.", "moley import work.ovpn --id sq1", cmdImport},
		{"profiles", "", "List profiles.", "moley profiles", cmdProfiles},
		{"profiles remove", "<id> --yes", "Remove a profile.", "moley profiles remove jp --yes", cmdProfilesRemove},
		{"profiles update", "<id> [--name N] [--auto-rule on|off]", "Rename a profile (--name \"\" clears it) or turn its auto rule on or off (OpenVPN).", "moley profiles update sq1 --name Office", cmdProfilesUpdate},
		{"test", "<exit>", "Latency, exit IP and country through an exit.", "moley test sq1", cmdTest},
		{"exits", "", "List exits: direct, block, every profile, and groups.", "moley exits", cmdExits},
		{"exits put", "<id> --group manual|fastest --members a,b [--selected a]", "Create or replace a group exit.", "moley exits put asia --group fastest --members jp,hk", cmdExitsPut},
		{"exits remove", "<id> --yes", "Remove a group exit.", "moley exits remove asia --yes", cmdExitsRemove},
		{"exits select", "<group> <member>", "Pick the member of a manual group (no reconnects).", "moley exits select pick jp", cmdExitsSelect},
		{"rules", "", "List rules in match order.", "moley rules", cmdRules},
		{"rules show", "<id>", "Show a rule; auto-<profile> shows what the VPN server pushed and what was learned.", "moley rules show auto-sq1", cmdRulesShow},
		{"rules add", "<id> --exit X [--name \"Free text\"] [--domain-suffix a,b] [--domain …] [--domain-keyword …] [--domain-regex …] [--ip-cidr …] [--process-name …] [--process-path …] [--port 443,…] [--rule-set geosite-x,…] [--index N]",
			"Create or replace a rule. Match fields are OR-ed.", "moley rules add stream --exit jp --domain-suffix netflix.com,nflxvideo.net", cmdRulesAdd},
		{"rules remove", "<id> --yes", "Remove a rule.", "moley rules remove stream --yes", cmdRulesRemove},
		{"rules forget", "<auto-profile>", "Clear the sites an auto rule learned; it learns again from what the server pushes.", "moley rules forget auto-sq1", cmdRulesForget},
		{"rules move", "<id> <index>", "Move a rule (0 = first).", "moley rules move stream 0", cmdRulesMove},
		{"quick", "<host> <exit|none>", "Route a site and its subdomains via an exit (the extension's one-click pick). No reconnects.", "moley quick crunchyroll.com jp", cmdQuick},
		{"default", "<exit>", "Exit for traffic no rule matches.", "moley default direct", cmdDefault},
		{"holds", "", "Who keeps the network adapter up, and until when.", "moley holds", cmdHolds},
		{"holds put", "<name> [--for 30m]", "Keep the network adapter up (system mode) for a while without changing where anything goes, so every program follows the rules while you're disconnected. Putting a name again renews it; it lapses on its own (at most 24h).", "moley holds put my-agent --for 1h", cmdHoldsPut},
		{"holds release", "<name>", "Release a hold. Releasing one that's gone is not an error.", "moley holds release my-agent", cmdHoldsRelease},
		{"probe", "<url|tcp://host:port> [--exit X] [--expect-exit X] [--expect-rule R]", "Make a real request (HTTP GET, or a TCP connect that sends nothing) through the engine; report the rule, exit and resolver it used. Exit 4 if an expectation fails.", "moley probe tcp://db.corp.example:5432 --expect-exit sq1", cmdProbe},
		{"wait", "--connected <profile> | --healthy <exit> [--timeout 30s]", "Block until the condition holds. Exit 4 on timeout.", "moley wait --connected sq1 --timeout 20s", cmdWait},
		{"apply", "-f <file|-> [--dry-run] [--yes]", "Replace the whole config (declarative). Prints the diff; removals need --yes.", "moley apply -f moley.json --dry-run", cmdApply},
		{"export", "[--reveal]", "Print the whole config. Secrets are redacted unless --reveal; apply keeps redacted ones as they are.", "moley export > moley.json", cmdExport},
		{"conns", "[--host H] [--closed]", "Connections and the rule and exit each actually used.", "moley conns --host netflix.com --closed", cmdConns},
		{"history", "[--limit N]", "Audit log: every change and who made it.", "moley history --limit 20", cmdHistory},
		{"logs", "[--since 5m] [--limit N] [--follow]", "Daemon and core logs. --follow streams NDJSON with --json.", "moley logs --since 2m", cmdLogs},
		{"exec", "[--exit X] -- <command…>", "Run a command with its proxy env vars pointed at Moley (optionally forcing an exit).", "moley exec --exit sq1 -- curl -s https://ifconfig.co", cmdExec},
		{"env", "[--exit X] [--shell pwsh|bash|cmd|fish]", "Print proxy env vars for a shell session.", "moley env --exit jp --shell bash", cmdEnv},
		{"rpc", "<method> [json-params]", "Call any daemon method directly.", `moley rpc conns.list '{"host":"example.com"}'`, cmdRPC},
		{"help", "[command] [--json]", "Help. --json describes every command and RPC method.", "moley help --json", cmdHelp},
		{"mode", "[--tun on|off] [--kill-switch off|on|persistent] [--yes]", "System mode: route every app on this computer (tun) and block what leaves outside Moley (kill switch; persistent also while Moley is stopped, needs --yes). Needs the service.", "moley mode --tun on --kill-switch on", cmdMode},
		{"events", "[--conns]", "Stream status and traffic as they change, as NDJSON with --json. --conns adds open connections.", "moley events --json", cmdEvents},
		{"service", "[--debug] [--system --allow SID]", "Run the daemon in the foreground. --system runs it as the privileged service (what `service install` registers).", "moley service", cmdService},
		{"service install", "", "Install the privileged service for system mode and the kill switch, moving your config to it. Administrator terminal on Windows, sudo on Linux.", "moley service install", cmdServiceInstall},
		{"service uninstall", "--yes", "Remove the service and lift a persistent kill switch. Your per-user daemon (`moley start`) keeps working.", "moley service uninstall --yes", cmdServiceUninstall},
		{"service restore-block", "", "Load the persistent kill switch at boot (Linux; run by moley-killswitch.service).", "moley service restore-block", cmdServiceRestoreBlock},
		{"start", "", "Start the daemon (the service, if installed) and wait until it answers.", "moley start", cmdStart},
		{"stop", "", "Stop the daemon.", "moley stop", cmdStop},
		{"browser install", "", "Register the browser extension's native host (Chrome, Edge, Brave, Chromium) for this user.", "moley browser install", cmdBrowserInstall},
		{"browser uninstall", "", "Remove the native host registration.", "moley browser uninstall", cmdBrowserUninstall},
		{"version", "", "Print the version.", "moley version", cmdVersion},
	}
}

func cmdStatus(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var st daemon.StatusResult
	if err := c.rpc("status", nil, &st); err != nil {
		return err
	}
	return c.emit(st, func(w io.Writer) {
		fmt.Fprintf(w, "moley %s · proxy 127.0.0.1:%d · default exit %s · %d rules, %d quick picks\n",
			st.Version, st.ProxyPort, st.DefaultExit, st.Rules, st.QuickPicks)
		fmt.Fprintln(w, describeMode(st.Mode))
		for _, h := range st.Holds {
			fmt.Fprintln(w, describeHold(h))
		}
		printProfiles(w, st.Profiles)
	})
}

func describeMode(m daemon.ModeInfo) string {
	s := "browser and exec only"
	switch {
	case m.TUN && m.SystemRouting:
		s = "system mode: every app"
	case m.TUN:
		s = "system mode: every app while connected or held; browser and exec only now"
	}
	if m.KillSwitch != model.KillSwitchOff {
		s += ", kill switch " + m.KillSwitch
	}
	if !m.Service {
		s += " (per-user daemon)"
	}
	if m.Error != "" {
		s += "\n" + m.Error
	}
	return s
}

func describeHold(h daemon.Hold) string {
	return fmt.Sprintf("held by %s until %s (%s left; %s)", h.Name, h.Until.Local().Format("15:04:05"),
		time.Until(h.Until).Round(time.Second), h.Caller)
}

func cmdHolds(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var st daemon.StatusResult
	if err := c.rpc("status", nil, &st); err != nil {
		return err
	}
	return c.emit(map[string]any{"holds": st.Holds, "system_routing": st.Mode.SystemRouting}, func(w io.Writer) {
		if len(st.Holds) == 0 {
			fmt.Fprintln(w, "no holds")
		}
		for _, h := range st.Holds {
			fmt.Fprintln(w, describeHold(h))
		}
	})
}

func cmdHoldsPut(c *call) error {
	ttl := c.flags.Duration("for", daemon.DefaultHoldTTL, "how long, at most 24h")
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var res daemon.HoldResult
	if err := c.rpc("holds.put", daemon.HoldParams{Name: c.args[0], TTLMS: ttl.Milliseconds()}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) {
		fmt.Fprintln(w, describeHold(*res.Hold))
		if !res.SystemRouting {
			fmt.Fprintln(w, "system mode is off, so the hold changes nothing until `moley mode --tun on`")
		}
	})
}

func cmdHoldsRelease(c *call) error {
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var res daemon.HoldResult
	if err := c.rpc("holds.release", daemon.ReleaseParams{Name: c.args[0]}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) {
		if res.Removed {
			fmt.Fprintln(w, "released", c.args[0])
		} else {
			fmt.Fprintln(w, "no hold named", c.args[0])
		}
	})
}

func printProfiles(w io.Writer, ps []daemon.ProfileInfo) {
	if len(ps) == 0 {
		fmt.Fprintln(w, "no profiles yet: moley import <file|link>")
		return
	}
	tw := table(w, "PROFILE", "KIND", "STATE", "NOTE")
	for _, p := range ps {
		note := p.Error
		if p.AutoRule && note == "" {
			note = "auto rule " + model.AutoRuleID(p.ID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, p.Kind, p.State, note)
	}
	tw.Flush()
}

func cmdImport(c *call) error {
	id := c.flags.String("id", "", "profile id (single profile only)")
	replace := c.flags.Bool("replace", false, "overwrite a profile with the same id")
	noAuto := c.flags.Bool("no-auto-rule", false, "don't route what an OpenVPN server pushes")
	keyPass := c.flags.Bool("key-password-stdin", false, "read the private key password from stdin")
	if err := c.parse(1, 1); err != nil {
		return err
	}
	if *keyPass && c.args[0] == "-" {
		return usageErr("--key-password-stdin needs the profile as a file, not stdin")
	}
	src := c.args[0]
	p := daemon.ImportParams{ID: *id, Replace: *replace}
	if *keyPass {
		// First line of stdin; never from argv, which other processes can read.
		line, err := bufio.NewReader(c.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return usageErr("--key-password-stdin: nothing on stdin")
		}
		p.KeyPassword = strings.TrimRight(line, "\r\n")
	}
	if *noAuto {
		f := false
		p.AutoRule = &f
	}
	switch {
	case src == "-":
		b, err := io.ReadAll(c.Stdin)
		if err != nil {
			return err
		}
		p.Data = string(b)
	case strings.Contains(src, "://") && !fileExists(src):
		p.Data = src
	default:
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		p.Data, p.Name = string(b), filepath.Base(src)
	}
	var res daemon.ImportResult
	if err := c.rpc("profiles.import", p, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) {
		for _, p := range res.Profiles {
			extra := ""
			if p.AutoRule {
				extra = ", routes what the server pushes (" + model.AutoRuleID(p.ID) + ")"
			}
			fmt.Fprintf(w, "imported %s (%s)%s\n", p.ID, p.Kind, extra)
		}
		for _, warn := range res.Warnings {
			fmt.Fprintln(w, "warning: "+warn)
		}
	})
}

func cmdProfiles(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var ps []daemon.ProfileInfo
	if err := c.rpc("profiles.list", nil, &ps); err != nil {
		return err
	}
	return c.emit(map[string]any{"profiles": ps}, func(w io.Writer) { printProfiles(w, ps) })
}

func cmdProfilesRemove(c *call) error { return c.remove("profiles.remove") }
func cmdExitsRemove(c *call) error    { return c.remove("exits.remove") }
func cmdRulesRemove(c *call) error    { return c.remove("rules.remove") }

func cmdProfilesUpdate(c *call) error {
	name := c.flags.String("name", "", "display name; empty clears it")
	auto := c.flags.String("auto-rule", "", "on or off")
	if err := c.parse(1, 1); err != nil {
		return err
	}
	p := daemon.UpdateProfileParams{ID: c.args[0]}
	// --name "" clears the name, so whether it was given matters, not its value.
	c.flags.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			p.Name = name
		}
	})
	switch *auto {
	case "":
	case "on", "off":
		on := *auto == "on"
		p.AutoRule = &on
	default:
		return usageErr("--auto-rule takes on or off")
	}
	if p.Name == nil && p.AutoRule == nil {
		return usageErr("nothing to change: give --name or --auto-rule (see `moley help profiles update`)")
	}
	var res map[string]any
	if err := c.rpc("profiles.update", p, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintln(w, res["summary"]) })
}

func (c *call) remove(method string) error {
	yes := c.flags.Bool("yes", false, "confirm")
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var res map[string]any
	if err := c.rpc(method, daemon.RemoveParams{ID: c.args[0], Yes: *yes}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintf(w, "removed %s\n", c.args[0]) })
}

func cmdTest(c *call) error {
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var info engine.ExitInfo
	if err := c.rpc("profiles.test", daemon.ExitParams{Exit: c.args[0]}, &info); err != nil {
		return err
	}
	if err := c.emit(info, func(w io.Writer) {
		if info.OK {
			fmt.Fprintf(w, "%s: %s %s · %d ms\n", info.Exit, info.IP, info.Country, info.MS)
		} else {
			fmt.Fprintf(w, "%s: unreachable: %s\n", info.Exit, info.Error)
		}
	}); err != nil {
		return err
	}
	if !info.OK {
		return checkFailed("exit_unhealthy", "see `moley logs`", "exit %s is not working: %s", info.Exit, info.Error)
	}
	return nil
}

func cmdExits(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var xs []daemon.ExitInfo
	if err := c.rpc("exits.list", nil, &xs); err != nil {
		return err
	}
	return c.emit(map[string]any{"exits": xs}, func(w io.Writer) {
		tw := table(w, "EXIT", "KIND", "DETAIL")
		for _, x := range xs {
			detail := x.State
			if x.Kind == "group" {
				detail = x.Group + ": " + strings.Join(x.Members, ", ")
				if x.Selected != "" {
					detail += " (selected " + x.Selected + ")"
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", x.ID, x.Kind, detail)
		}
		tw.Flush()
	})
}

func cmdExitsPut(c *call) error {
	group := c.flags.String("group", model.GroupManual, "manual or fastest")
	members := c.flags.String("members", "", "comma-separated exits")
	selected := c.flags.String("selected", "", "initial pick (manual)")
	if err := c.parse(1, 1); err != nil {
		return err
	}
	x := model.Exit{ID: c.args[0], Group: *group, Members: list(*members), Selected: *selected}
	var res map[string]any
	if err := c.rpc("exits.put", x, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintln(w, res["summary"]) })
}

func cmdExitsSelect(c *call) error {
	if err := c.parse(2, 2); err != nil {
		return err
	}
	var res map[string]any
	if err := c.rpc("exits.select", daemon.SelectParams{ID: c.args[0], Member: c.args[1]}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintf(w, "%s → %s\n", c.args[0], c.args[1]) })
}

func cmdRules(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var rs daemon.RulesResult
	if err := c.rpc("rules.list", nil, &rs); err != nil {
		return err
	}
	return c.emit(rs, func(w io.Writer) {
		tw := table(w, "#", "RULE", "EXIT", "MATCH")
		n := 0
		for host, exit := range rs.Quick {
			fmt.Fprintf(tw, "q\tquick\t%s\t%s\n", exit, host)
		}
		for _, id := range rs.Auto {
			fmt.Fprintf(tw, "a\t%s\t%s\twhat the server pushes\n", id, strings.TrimPrefix(id, "auto-"))
		}
		for _, r := range rs.Rules {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", n, r.ID, r.Exit, describeMatch(r.Match))
			n++
		}
		fmt.Fprintf(tw, "-\tdefault\t%s\teverything else\n", rs.DefaultExit)
		tw.Flush()
	})
}

func describeMatch(m model.Match) string {
	var parts []string
	add := func(k string, v []string) {
		if len(v) > 0 {
			parts = append(parts, k+"="+strings.Join(v, ","))
		}
	}
	add("domain", m.Domain)
	add("suffix", m.DomainSuffix)
	add("keyword", m.DomainKeyword)
	add("regex", m.DomainRegex)
	add("ip", m.IPCIDR)
	add("process", m.ProcessName)
	add("path", m.ProcessPath)
	if len(m.Port) > 0 {
		parts = append(parts, fmt.Sprintf("port=%v", m.Port))
	}
	add("set", m.RuleSet)
	return strings.Join(parts, " ")
}

func cmdRulesShow(c *call) error {
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.rpc("rules.show", daemon.IDParams{ID: c.args[0]}, &raw); err != nil {
		return err
	}
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	return c.emit(v, func(w io.Writer) {
		if !strings.HasPrefix(c.args[0], "auto-") {
			var r model.Rule
			_ = json.Unmarshal(raw, &r)
			fmt.Fprintf(w, "%s → %s: %s\n", r.ID, r.Exit, describeMatch(r.Match))
			return
		}
		var a engine.AutoRule
		_ = json.Unmarshal(raw, &a)
		state := "tunnel down: learned hosts still route here and fail closed"
		if a.Live {
			state = "live"
		}
		fmt.Fprintf(w, "%s → %s (%s)\n", a.ID, a.Profile, state)
		fmt.Fprintf(w, "resolver: %s %v\n", a.Resolver, a.DNS)
		fmt.Fprintf(w, "learned: %s\n", or(describeMatch(a.Learned), "nothing yet"))
	})
}

type matchFlags struct {
	domain, suffix, keyword, regex, ip, process, path, port, set *string
}

func addMatchFlags(c *call) matchFlags {
	return matchFlags{
		domain:  c.flags.String("domain", "", ""),
		suffix:  c.flags.String("domain-suffix", "", ""),
		keyword: c.flags.String("domain-keyword", "", ""),
		regex:   c.flags.String("domain-regex", "", ""),
		ip:      c.flags.String("ip-cidr", "", ""),
		process: c.flags.String("process-name", "", ""),
		path:    c.flags.String("process-path", "", ""),
		port:    c.flags.String("port", "", ""),
		set:     c.flags.String("rule-set", "", ""),
	}
}

func (f matchFlags) match() (model.Match, error) {
	m := model.Match{
		Domain: list(*f.domain), DomainSuffix: list(*f.suffix), DomainKeyword: list(*f.keyword),
		DomainRegex: list(*f.regex), IPCIDR: list(*f.ip), ProcessName: list(*f.process),
		ProcessPath: list(*f.path), RuleSet: list(*f.set),
	}
	for _, p := range list(*f.port) {
		var n uint16
		if _, err := fmt.Sscan(p, &n); err != nil || n == 0 {
			return m, usageErr("--port %q is not a port", p)
		}
		m.Port = append(m.Port, n)
	}
	return m, nil
}

func cmdRulesAdd(c *call) error {
	exit := c.flags.String("exit", "", "exit id")
	name := c.flags.String("name", "", "display name")
	index := c.flags.Int("index", -1, "position for a new rule")
	mf := addMatchFlags(c)
	if err := c.parse(1, 1); err != nil {
		return err
	}
	m, err := mf.match()
	if err != nil {
		return err
	}
	p := daemon.PutRuleParams{Rule: model.Rule{ID: c.args[0], Name: *name, Exit: *exit, Match: m}}
	if *index >= 0 {
		p.Index = index
	}
	var res map[string]any
	if err := c.rpc("rules.put", p, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintln(w, res["summary"]) })
}

func cmdRulesForget(c *call) error {
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var res map[string]any
	if err := c.rpc("rules.forget", daemon.IDParams{ID: c.args[0]}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintf(w, "%s forgot what it learned\n", c.args[0]) })
}

func cmdRulesMove(c *call) error {
	if err := c.parse(2, 2); err != nil {
		return err
	}
	var i int
	if _, err := fmt.Sscan(c.args[1], &i); err != nil {
		return usageErr("index %q is not a number", c.args[1])
	}
	var res map[string]any
	if err := c.rpc("rules.move", daemon.MoveParams{ID: c.args[0], Index: i}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintf(w, "moved %s to %d\n", c.args[0], i) })
}

func cmdQuick(c *call) error {
	if err := c.parse(2, 2); err != nil {
		return err
	}
	exit := c.args[1]
	if exit == "none" {
		exit = ""
	}
	var res map[string]any
	if err := c.rpc("quick.set", daemon.QuickParams{Host: c.args[0], Exit: exit}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintln(w, res["summary"]) })
}

func cmdDefault(c *call) error {
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var res map[string]any
	if err := c.rpc("default.set", daemon.ExitParams{Exit: c.args[0]}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) { fmt.Fprintf(w, "default exit → %s\n", c.args[0]) })
}

func cmdProbe(c *call) error {
	exit := c.flags.String("exit", "", "force this exit")
	expectExit := c.flags.String("expect-exit", "", "fail (exit 4) unless this exit carried it")
	expectRule := c.flags.String("expect-rule", "", "fail (exit 4) unless this rule matched")
	if err := c.parse(1, 1); err != nil {
		return err
	}
	var r engine.ProbeResult
	if err := c.rpc("probe", daemon.ProbeParams{URL: c.args[0], Exit: *exit}, &r); err != nil {
		return err
	}
	if err := c.emit(r, func(w io.Writer) {
		outcome := "connected" // a TCP probe
		switch {
		case r.Error != "":
			outcome = "failed: " + r.Error
		case r.Status != 0:
			outcome = fmt.Sprintf("HTTP %d", r.Status)
		}
		fmt.Fprintf(w, "%s\n  rule %s → exit %s (%s) · resolver %s · %d ms · %s\n",
			r.URL, or(r.Rule, "?"), or(r.Exit, "?"), strings.Join(r.Chain, " → "), or(r.Resolver, "?"), r.MS, outcome)
	}); err != nil {
		return err
	}
	switch {
	case *expectExit != "" && r.Exit != *expectExit:
		return checkFailed("probe_mismatch", "", "expected exit %s, got %s", *expectExit, or(r.Exit, "none"))
	case *expectRule != "" && r.Rule != *expectRule:
		return checkFailed("probe_mismatch", "", "expected rule %s, got %s", *expectRule, or(r.Rule, "none"))
	case (*expectExit != "" || *expectRule != "") && r.Error != "":
		return checkFailed("probe_failed", "the route matched but the request failed", "%s", r.Error)
	}
	return nil
}

func cmdWait(c *call) error {
	connected := c.flags.String("connected", "", "profile id")
	healthy := c.flags.String("healthy", "", "exit id")
	timeout := c.flags.Duration("timeout", 30*time.Second, "give up after")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var res json.RawMessage
	p := daemon.WaitParams{Connected: *connected, Healthy: *healthy, TimeoutMS: int(timeout.Milliseconds())}
	if err := c.rpcTimeout("wait", p, &res, *timeout+5*time.Second); err != nil {
		return err
	}
	var v map[string]any
	_ = json.Unmarshal(res, &v)
	return c.emit(v, func(w io.Writer) { fmt.Fprintln(w, "ok") })
}

func cmdApply(c *call) error {
	file := c.flags.String("f", "", "config file, - for stdin")
	dry := c.flags.Bool("dry-run", false, "only print the diff")
	yes := c.flags.Bool("yes", false, "allow removals")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	if *file == "" {
		return usageErr("usage: moley apply -f <file|-> [--dry-run] [--yes]")
	}
	var b []byte
	var err error
	if *file == "-" {
		b, err = io.ReadAll(c.Stdin)
	} else {
		b, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	var cfg model.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return usageErr("%s: %v", *file, err)
	}
	var res daemon.ApplyResult
	if err := c.rpc("config.apply", daemon.ApplyParams{Config: cfg, DryRun: *dry, Yes: *yes}, &res); err != nil {
		return err
	}
	return c.emit(res, func(w io.Writer) {
		for _, ch := range res.Changes {
			fmt.Fprintln(w, ch)
		}
		switch {
		case len(res.Changes) == 0:
			fmt.Fprintln(w, "no changes")
		case !res.Applied:
			fmt.Fprintln(w, "(dry run: nothing applied)")
		}
	})
}

func cmdExport(c *call) error {
	reveal := c.flags.Bool("reveal", false, "include secrets")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var cfg json.RawMessage
	if err := c.rpc("config.export", daemon.ExportParams{Reveal: *reveal}, &cfg); err != nil {
		return err
	}
	// export prints the config document itself (no envelope), so it can be
	// fed straight back to `apply -f`.
	var v any
	_ = json.Unmarshal(cfg, &v)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(c.Stdout, string(b))
	return nil
}

func cmdConns(c *call) error {
	host := c.flags.String("host", "", "only this host and its subdomains")
	closed := c.flags.Bool("closed", false, "include recently closed")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var cs []engine.Conn
	if err := c.rpc("conns.list", daemon.ConnsParams{Host: *host, Closed: *closed}, &cs); err != nil {
		return err
	}
	return c.emit(map[string]any{"conns": cs}, func(w io.Writer) {
		tw := table(w, "HOST", "PORT", "RULE", "EXIT", "UP", "DOWN", "AGE")
		for _, x := range cs {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n", x.Host, x.Port, x.Rule, strings.Join(x.Chain, "→"),
				bytes(x.Up), bytes(x.Down), time.Since(x.Start).Round(time.Second))
		}
		tw.Flush()
	})
}

func cmdHistory(c *call) error {
	limit := c.flags.Int("limit", 50, "entries")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	var es []daemon.AuditEntry
	if err := c.rpc("history.list", daemon.LimitParams{Limit: *limit}, &es); err != nil {
		return err
	}
	return c.emit(map[string]any{"entries": es}, func(w io.Writer) {
		tw := table(w, "TIME", "BY", "CHANGE")
		for _, e := range es {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Time.Local().Format("01-02 15:04:05"), e.Caller, e.Summary)
		}
		tw.Flush()
	})
}

func cmdLogs(c *call) error {
	since := c.flags.Duration("since", 10*time.Minute, "how far back")
	limit := c.flags.Int("limit", 200, "lines")
	follow := c.flags.Bool("follow", false, "keep streaming")
	if err := c.parse(0, 0); err != nil {
		return err
	}
	from := time.Now().Add(-*since)
	for {
		var lines []engine.LogLine
		if err := c.rpc("logs", daemon.LogsParams{Since: from, Limit: *limit}, &lines); err != nil {
			return err
		}
		for _, l := range lines {
			if c.JSON {
				_ = writeJSON(c.Stdout, l)
			} else {
				fmt.Fprintf(c.Stdout, "%s %-5s %s\n", l.Time.Local().Format("15:04:05.000"), l.Level, l.Message)
			}
			from = l.Time
		}
		if !*follow {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func cmdRPC(c *call) error {
	if err := c.parse(1, 2); err != nil {
		return err
	}
	var params json.RawMessage
	if len(c.args) == 2 {
		params = json.RawMessage(c.args[1])
		if !json.Valid(params) {
			return usageErr("params are not valid JSON")
		}
	}
	var res json.RawMessage
	if err := c.rpc(c.args[0], params, &res); err != nil {
		return err
	}
	var v any
	_ = json.Unmarshal(res, &v)
	return c.emit(v, nil)
}

func cmdVersion(c *call) error {
	if err := c.parse(0, 0); err != nil {
		return err
	}
	return c.emit(map[string]any{"version": daemon.Version}, func(w io.Writer) { fmt.Fprintln(w, "moley "+daemon.Version) })
}

// --- helpers -----------------------------------------------------------------

func table(w io.Writer, headers ...string) *tabwriter.Writer {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	return tw
}

func list(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func bytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
