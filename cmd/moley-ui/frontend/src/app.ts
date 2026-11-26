import { Call, Events } from "/wails/runtime.js";
import { icon, isIcon, type IconName } from "./icons.js";

// --- Daemon types (the parts the window reads) ---------------------------------

type Mode = { tun: boolean; kill_switch: "off" | "on" | "persistent"; service: boolean; error?: string };
type Status = {
  version: string;
  default_exit: string;
  profiles: { id: string; kind: string; auto_rule?: boolean; state: string; error?: string }[];
  exits: string[];
  mode: Mode;
};
type Rate = { up: number; down: number };
type Traffic = Rate & { exits: Record<string, Rate>; open: number };
type Exit = { id: string; name?: string; kind: "builtin" | "profile" | "group"; protocol?: string; group?: string; members?: string[]; selected?: string; state?: string };
type Conn = { id: string; inbound: string; host: string; port: number; rule: string; exit: string; chain: string[]; up: number; down: number; start: string };
type Match = Partial<Record<"domain" | "domain_suffix" | "domain_keyword" | "domain_regex" | "ip_cidr" | "process_name" | "process_path" | "rule_set", string[]>> & { port?: number[] };
type Rule = { id: string; name?: string; exit: string; match: Match };
type Rules = { rules: Rule[]; auto: string[]; quick: Record<string, string>; default_exit: string };
type ExitInfo = { exit: string; ok: boolean; ms: number; ip?: string; country?: string; error?: string };
type RpcError = { code: string; message: string; hint?: string };
type Reply<T> = { ok: true; result: T } | { ok: false; error: RpcError };
type About = { version: string; updates: boolean; os: string };

class Failure extends Error {
  constructor(readonly error: RpcError) {
    super(error.message);
  }
}

function bridge<T>(method: string, ...args: unknown[]): Promise<T> {
  return Call.ByName(`main.Bridge.${method}`, ...args);
}

async function rpc<T>(method: string, params: unknown = null): Promise<T> {
  const r = await bridge<Reply<T>>("Call", method, params);
  if (!r.ok) throw new Failure(r.error);
  return r.result;
}

async function local(method: string, ...args: unknown[]): Promise<void> {
  const r = await bridge<Reply<unknown>>(method, ...args);
  if (!r.ok) throw new Failure(r.error);
}

// --- State ---------------------------------------------------------------------------

type View = "home" | "activity" | "rules" | "settings";
type Sheet = "" | "exits" | "import" | "rule" | "profile" | "replace";

const SAMPLES = 61; // one a second: the chart's last minute

const state = {
  status: undefined as Status | undefined,
  traffic: undefined as Traffic | undefined,
  conns: [] as Conn[],
  exits: [] as Exit[],
  rules: undefined as Rules | undefined,
  offline: false,
  view: "home" as View,
  sheet: "" as Sheet,
  confirming: "", // a row whose remove button asks "Remove?"
  editing: "", // the rule or connection a sheet edits; empty adds a rule
  test: undefined as ExitInfo | undefined, // the default exit's latency and address
  pending: "", // the default exit just asked for, shown before the daemon confirms it
  rx: new Array<number>(SAMPLES).fill(0),
  tx: new Array<number>(SAMPLES).fill(0),
};

// The last tunnel the power button connected: it reconnects to it.
const lastKey = "moley.last";
const lastExit = () => localStorage.getItem(lastKey) ?? "";

const motion = () => !matchMedia("(prefers-reduced-motion: reduce)").matches;
const EASE = "cubic-bezier(.22, 1, .36, 1)";

// --- DOM helpers -----------------------------------------------------------------------

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const SVG = "http://www.w3.org/2000/svg";

type Kid = Node | string | null | undefined | false;
type Props = Record<string, unknown> & { class?: string };

function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...kids: Kid[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === false || v === null) continue;
    if (k === "class") el.className = String(v);
    else if (k.startsWith("on")) (el as any)[k] = v;
    else if (k === "value") (el as any).value = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids) if (kid) el.append(kid);
  return el;
}

function ico(name: IconName, cls = "ico"): HTMLElement {
  const s = h("span", { class: cls });
  s.append(icon(name));
  return s;
}

function tile(content: IconName | string, cls = "", dot = ""): HTMLElement {
  const t = h("span", { class: `tile ${cls}` });
  if (isIcon(content)) t.append(icon(content));
  else t.textContent = content.replace(/^www\./, "").slice(0, 1);
  if (dot) t.append(h("span", { class: `dot ${dot}` }));
  return t;
}

function iconButton(name: IconName, label: string, onclick: () => void, cls = ""): HTMLButtonElement {
  const b = h("button", { type: "button", class: `icon-btn ${cls}`, "aria-label": label, "data-tip": label, onclick });
  b.append(icon(name));
  return b;
}

// Static icons in the markup: <span class="ico" data-icon="…">.
for (const el of document.querySelectorAll<HTMLElement>("[data-icon]")) el.append(icon(el.dataset.icon as IconName));
$("chev").append(icon("below"));
$("power").append(icon("power"));

// --- Tooltips ------------------------------------------------------------------------------
// Any element with data-tip shows it after a moment's hover, above it (or
// below near the top). One floating element serves them all.

const tipEl = h("div", { class: "tip", role: "tooltip", hidden: true });
document.body.append(tipEl);
let tipFor: HTMLElement | undefined;
let tipTimer = 0;

function hideTip(): void {
  clearTimeout(tipTimer);
  tipFor = undefined;
  tipEl.hidden = true;
}

function placeTip(el: HTMLElement): void {
  tipEl.textContent = el.dataset.tip!;
  tipEl.hidden = false;
  const r = el.getBoundingClientRect(), t = tipEl.getBoundingClientRect();
  const left = Math.min(Math.max(8, r.left + r.width / 2 - t.width / 2), innerWidth - t.width - 8);
  const below = r.top - t.height - 8 < 8;
  tipEl.style.left = `${left}px`;
  tipEl.style.top = `${below ? r.bottom + 8 : r.top - t.height - 8}px`;
  tipEl.dataset.side = below ? "below" : "above";
}

addEventListener("pointerover", (e) => {
  const el = (e.target as Element).closest<HTMLElement>("[data-tip]");
  if (el === tipFor) return;
  hideTip();
  if (!el?.dataset.tip) return;
  tipFor = el;
  tipTimer = setTimeout(() => tipFor === el && el.isConnected && placeTip(el), 450);
});
addEventListener("pointerdown", hideTip, true);
addEventListener("scroll", hideTip, true);

// notify says something as a system notification (Windows already names Moley as its sender).
function notify(message: string): void {
  void bridge("Notify", message, "");
}

function explain(e: unknown): string {
  if (e instanceof Failure) return e.error.hint ? `${e.error.message}. ${e.error.hint}` : e.error.message;
  return e instanceof Error ? e.message : String(e);
}

// Runs an action; on failure, says why.
async function act(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return true;
  } catch (e) {
    if (!(e instanceof Failure && e.error.code === "cancelled")) notify(explain(e));
    return false;
  }
}

// --- Waiting on Moley ------------------------------------------------------------------
// A change can take seconds (routing every app starts a network adapter).
// Meanwhile the control that asked spins and the rest of its group is
// locked, until the daemon's status shows the change.

const busy = new Map<string, string>(); // group ("power", "mode", …) → the control that asked
const doing = (group: string, control: string) => busy.get(group) === control;

const settling = new Set<() => void>();
function until(done: () => boolean, ms = 8000): Promise<void> {
  return new Promise((resolve) => {
    if (done()) return resolve();
    const finish = () => (clearTimeout(timer), settling.delete(check), resolve());
    const check = () => done() && finish();
    const timer = setTimeout(finish, ms);
    settling.add(check);
  });
}

// hold runs fn as control of group, then waits for the status to show settled.
async function hold<T>(group: string, control: string, fn: () => Promise<T>, settled?: () => boolean): Promise<T> {
  busy.set(group, control);
  try {
    refresh();
    const r = await fn();
    if (settled) await until(settled);
    return r;
  } finally {
    busy.delete(group);
    refresh();
  }
}

// held marks a drawn control of group: spinning if it asked, else locked while the group waits.
function held<T extends HTMLButtonElement>(el: T, group: string, spins: boolean): T {
  if (busy.has(group)) el.disabled = true;
  el.setAttribute("aria-busy", String(busy.has(group) && spins));
  return el;
}

// pressing is held for a button that isn't redrawn while it waits (a
// sheet's form): it spins, and the form's other controls are locked.
async function pressing<T>(b: HTMLButtonElement, fn: () => Promise<T>): Promise<T> {
  const scope = b.closest<HTMLElement>(".sheet-body, .setting") ?? b;
  const locked = [...scope.querySelectorAll<HTMLButtonElement>("button, input, textarea")].filter((e) => !e.disabled);
  for (const e of locked) e.disabled = true;
  b.setAttribute("aria-busy", "true");
  try {
    return await fn();
  } finally {
    b.setAttribute("aria-busy", "false");
    for (const e of locked) e.disabled = false;
  }
}

function refresh(): void {
  renderHome();
  if (state.view !== "home" && !(state.view === "settings" && state.confirming === "always")) renderPage();
  if (state.sheet === "exits") renderSheet();
}

// --- Words --------------------------------------------------------------------------------

const protocols: Record<string, string> = {
  wireguard: "WireGuard", amneziawg: "AmneziaWG", openvpn: "OpenVPN", shadowsocks: "Shadowsocks",
  vless: "VLESS", vmess: "VMess", trojan: "Trojan", hysteria2: "Hysteria2", tuic: "TUIC",
  socks: "SOCKS5", http: "HTTP proxy",
};

function exitName(id: string): string {
  return id === "direct" || id === "" ? "Direct" : id === "block" ? "Block all" : state.exits.find((x) => x.id === id)?.name || id;
}

function health(state?: string): "up" | "wait" | "down" | "" {
  switch (state) {
    case "connected":
    case "ready":
      return "up";
    case "connecting":
    case "auth-pending":
      return "wait";
    case "error":
    case "stopped":
      return "down";
  }
  return "";
}

// A rate as a number and its unit, for the big readouts.
function speed(n: number): [string, string] {
  if (n >= 1 << 30) return [(n / (1 << 30)).toFixed(1), "GB/S"];
  if (n >= 1 << 20) return [(n / (1 << 20)).toFixed(1), "MB/S"];
  const kb = n / (1 << 10);
  return [kb > 0 && kb < 10 ? kb.toFixed(1) : String(Math.round(kb)), "KB/S"];
}

function bytes(n: number): string {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
  if (n >= 1 << 10) return `${Math.round(n / (1 << 10))} KB`;
  return `${n} B`;
}

function rate(r?: Rate): string {
  if (!r || r.up + r.down === 0) return "";
  return `↓ ${bytes(r.down)}/s  ↑ ${bytes(r.up)}/s`;
}

// 0..1 on a log scale from 1 KB/s to 100 MB/s.
function level(n: number): number {
  return Math.min(1, Math.log10(1 + n / 1024) / Math.log10(1 + 102400));
}

function reason(rule: string): string {
  if (rule.startsWith("quick-")) return "Site rule";
  if (rule.startsWith("auto-")) return "VPN network";
  if (rule === "default") return "Default";
  if (rule === "lan") return "Local network";
  if (rule === "hint") return "Forced";
  return `Rule ${rule}`;
}

function describeExit(x: Exit): { detail: string; icon: IconName } {
  if (x.id === "direct") return { detail: "No VPN", icon: "direct" };
  if (x.id === "block") return { detail: "No internet without a rule", icon: "block" };
  if (x.kind === "group") {
    const detail = x.group === "fastest" ? `Fastest of ${x.members?.length ?? 0}` : x.selected ? `Via ${x.selected}` : "Group";
    return { detail, icon: "group" };
  }
  const proto = protocols[x.protocol ?? ""] ?? "VPN";
  const st = { wait: " · Connecting", down: " · Unreachable", up: "", "": "" }[health(x.state)];
  return { detail: proto + st, icon: "tunnel" };
}

function describeMatch(m: Match): string {
  const parts = [
    ...(m.domain_suffix ?? []), ...(m.domain ?? []), ...(m.ip_cidr ?? []), ...(m.process_name ?? []),
    ...(m.process_path ?? []), ...(m.domain_keyword ?? []).map((k) => `*${k}*`), ...(m.rule_set ?? []),
    ...(m.port ?? []).map((p) => `port ${p}`), ...(m.domain_regex ?? []).map((r) => `/${r}/`),
  ];
  return parts.length > 3 ? `${parts.slice(0, 3).join(", ")} +${parts.length - 3}` : parts.join(", ");
}

function chipClass(exit: string): string {
  return exit === "direct" || exit === "" ? "exit-chip direct" : exit === "block" ? "exit-chip block" : "exit-chip";
}

// --- Ring ---------------------------------------------------------------------------------
// A ring of 60 lit segments (protected or not) inside 96 fine ticks (how
// much is moving right now).

const SEGS = 60;
const TICKS = 96;

function buildRing(): void {
  const c = 120;
  const segs = $("segs") as unknown as SVGGElement;
  const step = (2 * Math.PI) / SEGS;
  const gap = 0.028;
  const pt = (r: number, a: number) => `${(c + r * Math.sin(a)).toFixed(2)},${(c - r * Math.cos(a)).toFixed(2)}`;
  for (let i = 0; i < SEGS; i++) {
    const a0 = i * step + gap, a1 = (i + 1) * step - gap;
    const p = document.createElementNS(SVG, "polygon");
    p.setAttribute("points", [pt(78, a0), pt(100, a0 - 0.004), pt(100, a1 + 0.004), pt(78, a1)].join(" "));
    p.setAttribute("class", "seg");
    const mid = (a0 + a1) / 2;
    // Brightest at the top, like light falling on it.
    p.style.setProperty("--b", (0.5 + 0.5 * (1 + Math.cos(mid)) / 2).toFixed(3));
    p.style.setProperty("--i", String(i));
    segs.append(p);
  }
  const ticks = $("ticks") as unknown as SVGGElement;
  for (let i = 0; i < TICKS; i++) {
    const a = (i / TICKS) * 2 * Math.PI;
    const major = i % 8 === 0;
    const l = document.createElementNS(SVG, "line");
    const [x1, y1] = pt(major ? 106 : 108, a).split(",");
    const [x2, y2] = pt(113, a).split(",");
    l.setAttribute("x1", x1); l.setAttribute("y1", y1); l.setAttribute("x2", x2); l.setAttribute("y2", y2);
    l.setAttribute("class", major ? "tick major" : "tick");
    ticks.append(l);
  }
}

let litTicks = 0;
function setGauge(n: number): void {
  const want = Math.round(level(n) * TICKS);
  if (want === litTicks) return;
  litTicks = want;
  const ticks = $("ticks").children;
  for (let i = 0; i < TICKS; i++) ticks[i].classList.toggle("lit", i < want);
}

// --- Numbers that glide -------------------------------------------------------------------

const shown = { rx: 0, tx: 0, max: 8 << 10 };
let goal = { rx: 0, tx: 0, max: 8 << 10 };
let frame = 0;

function glide(): void {
  cancelAnimationFrame(frame);
  const from = { ...shown };
  const t0 = performance.now();
  const dur = motion() ? 650 : 0;
  const tick = (now: number) => {
    const k = dur ? Math.min(1, (now - t0) / dur) : 1;
    const e = 1 - Math.pow(1 - k, 3);
    shown.rx = from.rx + (goal.rx - from.rx) * e;
    shown.tx = from.tx + (goal.tx - from.tx) * e;
    shown.max = from.max + (goal.max - from.max) * e;
    for (const k of ["rx", "tx"] as const) {
      const [v, unit] = speed(shown[k]);
      $(k).textContent = v;
      $(`${k}-unit`).textContent = unit;
    }
    if (k < 1) frame = requestAnimationFrame(tick);
  };
  frame = requestAnimationFrame(tick);
}

// --- Chart --------------------------------------------------------------------------------
// The last minute, scrolling: each new second slides in from the right.

const W = 356, H = 52;
const STEP = W / (SAMPLES - 2);

function drawChart(): void {
  const max = goal.max;
  const y = (v: number) => (H - 3 - (Math.min(v, max) / max) * (H - 8)).toFixed(1);
  for (const k of ["rx", "tx"] as const) {
    const pts = state[k].map((v, i) => `${(i * STEP).toFixed(1)} ${y(v)}`);
    const line = `M${pts.join("L")}`;
    $(`line-${k}`).setAttribute("d", line);
    $(`area-${k}`).setAttribute("d", `${line}L${((SAMPLES - 1) * STEP).toFixed(1)} ${H}L0 ${H}Z`);
  }
  const plot = $("plot");
  plot.style.transition = "none";
  plot.style.transform = "translateX(0)";
  if (!motion()) return void (plot.style.transform = `translateX(${-STEP}px)`);
  void plot.getBoundingClientRect();
  plot.style.transition = "transform 1000ms linear";
  plot.style.transform = `translateX(${-STEP}px)`;
}

function sample(t: Traffic | undefined): void {
  state.rx.push(t?.down ?? 0);
  state.tx.push(t?.up ?? 0);
  state.rx.shift();
  state.tx.shift();
  const peak = Math.max(...state.rx, ...state.tx, 8 << 10);
  goal = { rx: t?.down ?? 0, tx: t?.up ?? 0, max: peak * 1.15 };
  glide();
  drawChart();
  setGauge((t?.down ?? 0) + (t?.up ?? 0));
}

// --- Home -----------------------------------------------------------------------------------

// What the hero says: a status word, and on hover why.
type Look = { state: string; title: string; label: string; proto: string; tip: string; test: boolean };

function look(): Look {
  const going = busy.get("power");
  if (state.offline) return { state: "stopped", title: "Moley", label: going ? "Starting" : "Not running", proto: "", tip: "Press the power button to start Moley.", test: false };
  const st = state.status;
  if (!st) return { state: "idle", title: "Moley", label: "", proto: "", tip: "", test: false };
  const d = state.pending || st.default_exit || "direct";
  if (d === "block") return { state: "block", title: "Block all", label: "Blocking", proto: "", tip: "Only sites and apps with a rule can reach the internet.", test: false };
  if (d === "direct") {
    const next = state.exits.find((x) => x.id === lastExit()) ?? state.exits.find((x) => x.kind !== "builtin");
    return {
      state: "off", title: next?.id ?? "No connection", label: going ? "Disconnecting" : "Disconnected", proto: "",
      tip: next ? "Sites and apps with a rule still use their connection." : "Add a VPN connection to get started.", test: false,
    };
  }
  const x = state.exits.find((e) => e.id === d);
  const proto = x?.kind === "group" ? describeExit(x).detail : protocols[x?.protocol ?? ""] ?? "";
  const hl = x?.kind === "profile" ? health(x.state) : "up";
  if (hl === "wait" || going) return { state: "connecting", title: d, label: "Connecting", proto, tip: "", test: false };
  if (hl === "down") {
    const err = st.profiles.find((p) => p.id === d)?.error;
    return { state: "down", title: d, label: "Connection lost", proto, tip: err ? `${err}. Moley keeps retrying.` : "Moley keeps retrying.", test: false };
  }
  return { state: "on", title: d, label: "Connected", proto, tip: "", test: true };
}

function tip(el: HTMLElement, text: string): void {
  if (text) el.dataset.tip = text;
  else delete el.dataset.tip;
}

function renderHome(): void {
  const l = look();
  const hero = $("hero");
  hero.dataset.state = l.state;
  if (state.traffic && state.traffic.up + state.traffic.down > 0) hero.dataset.live = "";
  else delete hero.dataset.live;
  $("title").textContent = exitName(l.title);
  $("state").textContent = l.label;
  $("proto").textContent = l.proto;
  tip($("status"), l.tip);
  const place = $<HTMLButtonElement>("place");
  place.disabled = state.offline || !state.status;
  tip(place, place.disabled ? "" : "Change connection");
  held(place, "power", false);

  const power = $<HTMLButtonElement>("power");
  const labels: Record<string, string> = { stopped: "Start Moley", off: "Connect", idle: "Moley" };
  power.setAttribute("aria-label", labels[l.state] ?? "Disconnect");
  tip(power, power.getAttribute("aria-label")!);
  power.disabled = false;
  held(power, "power", true);

  // The server's address and how quickly it answers.
  const t = l.test && state.test?.exit === l.title ? state.test : undefined;
  const where = $("where");
  where.classList.toggle("quiet", !t?.ok);
  where.textContent = t ? (t.ok ? t.ip ?? "" : "No response") : "";
  tip(where, t?.ok ? "Your IP address" : t?.error ?? "");
  $("country").hidden = !t?.country || !/^[A-Z]{2}$/.test(t.country);
  $("country").textContent = t?.country ?? "";
  $("quality").hidden = !t?.ok;
  if (t?.ok) {
    const [grade, n] = t.ms < 80 ? ["Fast", 5] : t.ms < 160 ? ["Good", 4] : t.ms < 300 ? ["Fair", 3] : ["Slow", 2];
    $("ms").textContent = `${t.ms} ms`;
    $("grade").textContent = grade as string;
    [...$("bars").children].forEach((b, i) => b.classList.toggle("on", i < (n as number)));
  }

  const st = state.status;
  const every = $<HTMLButtonElement>("every");
  const kill = $<HTMLButtonElement>("kill");
  every.disabled = kill.disabled = !st;
  every.classList.toggle("locked", !!st && !st.mode.service);
  kill.classList.toggle("locked", !!st && !st.mode.service);
  every.setAttribute("aria-checked", String(!!st?.mode.tun));
  const ks = st?.mode.kill_switch ?? "off";
  kill.setAttribute("aria-checked", String(ks !== "off"));
  kill.classList.toggle("always", ks === "persistent");
  const changing = busy.get("mode") ?? "";
  held(every, "mode", changing === "tun");
  held(kill, "mode", changing.startsWith("kill:"));
  const service = !!st?.mode.service;
  $("every-note").textContent = !st ? "" : !service ? "Setup needed"
    : changing === "tun" ? (st.mode.tun ? "Turning off" : "Turning on") : st.mode.tun ? "On" : "Browser only";
  $("kill-note").textContent = !st ? "" : !service ? "Setup needed"
    : changing.startsWith("kill:") ? (changing === "kill:off" ? "Turning off" : "Turning on")
    : { off: "Off", on: "On", persistent: "Always on" }[ks];
  const setup = "Needs the Moley service. Click to set it up.";
  tip(every, service ? "Route every app on this PC through Moley, not just your browser." : setup);
  tip(kill, service ? "Block internet traffic that would bypass Moley." : setup);

  if (l.test && state.test?.exit !== l.title) void testExit(l.title);
}

// Measures the default exit, once per exit and then every half minute.
let testing = "";
async function testExit(exit: string): Promise<void> {
  if (testing === exit) return;
  testing = exit;
  try {
    state.test = await rpc<ExitInfo>("profiles.test", { exit });
  } catch {
    state.test = { exit, ok: false, ms: 0, error: "Couldn't measure it" };
  }
  testing = "";
  renderHome();
}
setInterval(() => {
  if (!document.hidden && state.test && look().state === "on") void testExit(state.test.exit);
}, 30000);

// setDefault changes where everything without a rule goes. The ring
// answers at once; the daemon's status confirms it.
async function setDefault(exit: string): Promise<boolean> {
  if (exit !== "direct" && exit !== "block") localStorage.setItem(lastKey, exit);
  state.pending = exit;
  const ok = await act(() => hold("power", exit, () => rpc("default.set", { exit }), () => state.status?.default_exit === exit));
  if (state.pending === exit) {
    state.pending = "";
    refresh();
  }
  return ok;
}

// setMode changes how much Moley routes; control names what's changing.
function setMode(control: string, change: Partial<Mode> & { yes?: boolean }, settled: (m: Mode) => boolean): void {
  void act(() => hold("mode", control, () => rpc("mode.set", change), () => !!state.status && settled(state.status.mode)));
}
const setTun = (tun: boolean) => setMode("tun", { tun }, (m) => m.tun === tun);
const setKill = (ks: Mode["kill_switch"], yes = false) =>
  setMode(`kill:${ks}`, yes ? { kill_switch: ks, yes } : { kill_switch: ks }, (m) => m.kill_switch === ks);

$("power").onclick = () => {
  if (state.offline) return void startDaemon();
  const st = state.status;
  if (!st) return;
  const d = state.pending || st.default_exit || "direct";
  if (d !== "direct") return void setDefault("direct");
  const target = state.exits.find((x) => x.id === lastExit()) ?? state.exits.find((x) => x.kind !== "builtin");
  if (!target) return openSheet("import");
  void setDefault(target.id);
};
$("place").onclick = () => openSheet("exits");

$("every").onclick = () => {
  const st = state.status;
  if (!st) return;
  if (!st.mode.service) return show("settings");
  setTun(!st.mode.tun);
};
$("kill").onclick = () => {
  const st = state.status;
  if (!st) return;
  if (!st.mode.service) return show("settings");
  setKill(st.mode.kill_switch === "off" ? "on" : "off");
};

function startDaemon(): void {
  void act(() => hold("power", "start", () => local("StartDaemon"), () => !state.offline && !!state.status));
}

// --- Navigation -----------------------------------------------------------------------------

const order: View[] = ["home", "activity", "rules", "settings"];

function moveGlow(): void {
  const tab = document.querySelector<HTMLElement>(`[role=tab][data-view="${state.view}"]`)!;
  const glow = $("tab-glow");
  glow.style.width = `${tab.offsetWidth}px`;
  glow.style.translate = `${tab.offsetLeft}px 0`;
}

function show(view: View): void {
  const from = order.indexOf(state.view);
  const changed = view !== state.view;
  state.view = view;
  state.confirming = "";
  for (const tab of document.querySelectorAll<HTMLButtonElement>("[role=tab]")) tab.setAttribute("aria-selected", String(tab.dataset.view === view));
  moveGlow();
  void bridge("WatchConns", view === "activity");
  if (view === "rules") void loadRules();
  const home = $("home"), page = $("page");
  home.hidden = view !== "home";
  page.hidden = view === "home";
  if (view !== "home") renderPage();
  const el = view === "home" ? home : page;
  el.scrollTop = 0;
  if (changed && motion()) {
    const dx = (order.indexOf(view) > from ? 1 : -1) * 18;
    el.animate([{ opacity: 0, transform: `translateX(${dx}px)` }, { opacity: 1, transform: "none" }], { duration: 380, easing: EASE });
  }
}

for (const tab of document.querySelectorAll<HTMLButtonElement>("[role=tab]")) tab.onclick = () => show(tab.dataset.view as View);
addEventListener("resize", moveGlow);

// renderPage redraws the current page. Settings is drawn once per visit
// unless forced, so a pending confirmation isn't wiped by a status tick.
function renderPage(): void {
  if (state.view === "home") return;
  const page = $("page");
  if (state.offline) {
    page.replaceChildren(h("div", { class: "empty" }, ico("power"), h("p", {}, "Moley isn't running. Start it from Home.")));
    return;
  }
  if (!state.status) return;
  const views: Record<Exclude<View, "home">, () => Node[]> = { activity: activityView, rules: rulesView, settings: settingsView };
  const top = page.scrollTop;
  page.replaceChildren(...views[state.view]());
  page.scrollTop = top;
}

function pageHead(title: string, meta: Kid, action?: HTMLElement): HTMLElement {
  return h("div", { class: "page-head" }, h("h1", {}, title), action ?? h("span", { class: "meta" }, meta));
}

// --- Activity -----------------------------------------------------------------------------

function activityView(): Node[] {
  const st = state.status!;
  const n = state.conns.length;
  const head = pageHead("Activity", n ? `${n} active` : "");
  if (n === 0) {
    const empty = h("div", { class: "panel empty" }, ico("pulse"), h("p", {}, "No active connections"));
    tip(empty, st.mode.tun ? "" : "Only your browser is routed. Turn on All apps to see every program.");
    return [head, empty];
  }
  const rows = state.conns.slice(0, 150).map((c) => {
    const exit = c.chain[0] ?? c.exit;
    return h("li", {}, h("div", { class: "row hoverable" },
      tile(c.host),
      h("span", { class: "text" }, h("span", { class: "name" }, c.host),
        h("span", { class: "detail" }, `${reason(c.rule)} · ${bytes(c.down + c.up)}`)),
      h("span", { class: chipClass(exit) }, exitName(exit)),
    ));
  });
  return [head, h("ul", { class: "panel list" }, ...rows)];
}

// --- Rules ----------------------------------------------------------------------------------

async function loadRules(): Promise<void> {
  try {
    state.rules = await rpc<Rules>("rules.list");
    if (state.view === "rules") renderPage();
    renderHome();
  } catch (e) {
    notify(explain(e));
  }
}

function rulesView(): Node[] {
  const r = state.rules;
  const add = h("button", { type: "button", class: "btn small primary", onclick: () => editRule("") }, "Add rule");
  const out: Node[] = [pageHead("Rules", "", add)];
  if (!r) return out;
  const quick = Object.entries(r.quick).sort(([a], [b]) => a.localeCompare(b));
  if (quick.length) {
    out.push(h("p", { class: "eyebrow" }, "Sites"), h("ul", { class: "panel list" }, ...quick.map(([host, exit]) =>
      h("li", {}, h("div", { class: "row hoverable", "data-tip": `${host} and its subdomains` }, tile(host),
        h("span", { class: "text" }, h("span", { class: "name" }, host)),
        h("span", { class: "actions-inline" }, held(iconButton("close", `Remove ${host}`, () => changeRules(`quick:${host}`, () =>
          rpc("quick.set", { host, exit: "" })), "danger"), "rules", doing("rules", `quick:${host}`))),
        h("span", { class: chipClass(exit) }, exitName(exit)))))));
  }
  if (r.auto.length) {
    out.push(h("p", { class: "eyebrow" }, "VPN networks"), h("ul", { class: "panel list" }, ...r.auto.map((id) => {
      const profile = id.replace(/^auto-/, "");
      return h("li", {}, h("div", { class: "row", "data-tip": `Private networks that ${exitName(profile)} routes, such as your company's intranet` }, tile("tunnel"),
        h("span", { class: "text" }, h("span", { class: "name" }, exitName(profile))),
        h("span", { class: "exit-chip" }, exitName(profile))));
    })));
  }
  out.push(h("p", { class: "eyebrow", "data-tip": "The first rule that matches wins" }, "Custom"));
  // A row opens its rule for editing; its own buttons (move, remove) don't.
  const edit = (id: string) => (e: Event) => {
    if (e instanceof KeyboardEvent && e.key !== "Enter" && e.key !== " ") return;
    if (e.target !== e.currentTarget && (e.target as HTMLElement).closest("button")) return;
    e.preventDefault();
    editRule(id);
  };
  // Columns shared by every row (see .rules): the buttons and chips line up
  // whatever each row has. A move that can't happen keeps its place empty.
  const slot = () => h("span", { class: "icon-slot" });
  const list = h("ul", { class: "panel list rules" }, ...r.rules.map((rule, i) => h("li", {}, h("div", {
    class: "row hoverable", role: "button", tabindex: "0", "data-edit": rule.id, "aria-label": `Edit ${ruleName(rule)}`,
    onclick: edit(rule.id), onkeydown: edit(rule.id),
  },
    tile(String(i + 1), "order"),
    h("span", { class: "text" }, h("span", { class: "name" }, ruleName(rule)), h("span", { class: "detail" }, describeMatch(rule.match))),
    h("span", { class: "actions-inline" },
      i > 0 ? moveButton("up", "Move up", rule.id, i - 1) : slot(),
      i < r.rules.length - 1 ? moveButton("below", "Move down", rule.id, i + 1) : slot(),
      removeAction(rule.id, "rules.remove", `Remove ${ruleName(rule)}`),
    ),
    h("span", { class: chipClass(rule.exit) }, exitName(rule.exit)),
  ))));
  list.append(h("li", {}, h("button", { type: "button", class: "row", "data-tip": "Where traffic goes when no rule matches", onclick: () => openSheet("exits") }, tile("direct"),
    h("span", { class: "text" }, h("span", { class: "name" }, "Everything else")),
    h("span", { class: chipClass(r.default_exit) }, exitName(r.default_exit)))));
  out.push(list);
  return out;
}

const ruleName = (r: Rule) => r.name || r.id;

function editRule(id: string): void {
  state.editing = id;
  openSheet("rule");
}

// changeRules runs a change to the rules as control, and reloads them.
function changeRules(control: string, fn: () => Promise<unknown>): void {
  void act(() => hold("rules", control, async () => {
    await fn();
    await loadRules();
  }));
}

function moveButton(name: IconName, label: string, id: string, index: number): HTMLButtonElement {
  const control = `move:${id}:${index}`;
  return held(iconButton(name, label, () => changeRules(control, () => rpc("rules.move", { id, index }))), "rules", doing("rules", control));
}

// removeAction is a row's remove button: the first click asks, the second
// removes. Rules and connections each lock as a group while one goes.
function removeAction(id: string, method: "rules.remove" | "profiles.remove", label: string): HTMLElement {
  const group = method === "rules.remove" ? "rules" : "profiles";
  const control = `remove:${id}`;
  if (state.confirming === `${method}:${id}`) {
    return h("button", { type: "button", class: "confirm", onclick: () => {
      state.confirming = "";
      if (group === "rules") changeRules(control, () => rpc(method, { id, yes: true }));
      else void act(() => hold(group, control, () => rpc(method, { id, yes: true }), () => !state.exits.some((x) => x.id === id)));
    } }, "Remove");
  }
  return h("span", { class: "actions-inline" }, held(iconButton("trash", label, () => {
    state.confirming = `${method}:${id}`;
    if (state.sheet === "exits") renderSheet();
    else renderPage();
  }, "danger"), group, doing(group, control)));
}

// --- Settings ---------------------------------------------------------------------------------

function segmented(label: string, options: [string, string][], value: string, disabled: boolean, pick: (v: string) => void): HTMLElement {
  const seg = h("div", { class: "segmented", role: "radiogroup", "aria-label": label });
  const thumb = h("span", { class: "thumb" });
  seg.append(thumb);
  const place = (b: HTMLElement) => {
    thumb.style.width = `${b.offsetWidth}px`;
    thumb.style.translate = `${b.offsetLeft}px 0`;
  };
  for (const [v, text] of options) {
    const b = h("button", { type: "button", role: "radio", "aria-checked": String(v === value), "data-value": v, disabled }, text);
    b.onclick = () => {
      if (b.getAttribute("aria-checked") === "true") return;
      pick(v);
    };
    seg.append(b);
  }
  // The page is redrawn often: start where the last drawing left the thumb,
  // so it only slides when the value changed.
  requestAnimationFrame(() => {
    const on = seg.querySelector<HTMLElement>('[aria-checked="true"]');
    if (!on) return;
    const last = thumbs.get(label);
    thumb.style.transition = "none";
    if (last) [thumb.style.width, thumb.style.translate] = last;
    else place(on);
    void thumb.offsetWidth; // commit the start before animating from it
    thumb.style.transition = "";
    place(on);
    thumbs.set(label, [thumb.style.width, thumb.style.translate]);
  });
  return seg;
}
const thumbs = new Map<string, [string, string]>(); // segmented label → its thumb's last width and offset

// setting is a row of Settings: a name (its explanation on hover) and a control.
function setting(name: string, about: string, control: Node, extra?: Node): HTMLElement {
  return h("li", { class: "setting" },
    h("span", { class: "text" }, h("span", { class: "name", "data-tip": about || undefined }, name), extra), control);
}

function settingsView(): Node[] {
  const st = state.status!;
  const service = st.mode.service;
  const every = held(h("button", { type: "button", class: "switch", role: "switch", "aria-checked": String(st.mode.tun), "aria-label": "All apps" }),
    "mode", doing("mode", "tun"));
  every.onclick = () => setTun(!state.status!.mode.tun);
  const install = held(h("button", { type: "button", class: "btn small primary", onclick: installService }, "Set up"), "service", true);
  const everyRow = setting("All apps", service
    ? "Route every app on this PC through Moley, not just your browser."
    : "Routing all apps needs the Moley service. Set it up once; it asks for administrator rights.", service ? every : install);

  const kill = st.mode.kill_switch;
  const confirm = h("span", { class: "detail" }); // filled only to confirm Always
  const seg = segmented("Kill switch", [["off", "Off"], ["on", "On"], ["persistent", "Always"]], kill, !service, (v) => {
    if (v === "persistent") return confirmAlways(confirm);
    setKill(v as Mode["kill_switch"]);
  });
  for (const b of seg.querySelectorAll<HTMLButtonElement>("button")) held(b, "mode", doing("mode", `kill:${b.dataset.value}`));
  const killRow = setting("Kill switch", service
    ? "On: blocks traffic that would bypass Moley while it runs. Always: also while Moley is off. Your local network keeps working."
    : "Needs the Moley service. Set it up under All apps.", seg, confirm);

  const login = held(h("button", { type: "button", class: "switch", role: "switch", "aria-checked": "false", "aria-label": "Launch at startup" }),
    "login", true);
  void bridge<boolean>("Autostart").then((on) => login.setAttribute("aria-checked", String(on)));
  login.onclick = () => {
    const on = login.getAttribute("aria-checked") !== "true";
    void act(() => hold("login", "login", () => local("SetAutostart", on)));
  };
  const loginRow = setting("Launch at startup", "Start Moley in the tray when you sign in.", login);

  const version = h("span", { class: "detail" }, st.version);
  const update = h("button", { type: "button", class: "btn small", hidden: true }, "Check for updates");
  void bridge<About>("About").then((a) => (update.hidden = !a.updates));
  update.onclick = () => checkUpdate(update, version);
  const aboutRow = setting("Version", "", update, version);

  return [pageHead("Settings", ""), h("ul", { class: "panel list" }, everyRow, killRow, loginRow, aboutRow)];
}

function confirmAlways(detail: HTMLElement): void {
  state.confirming = "always";
  detail.replaceChildren(
    "Blocks the internet even when Moley is off. ",
    h("button", { type: "button", class: "link", onclick: () => {
      state.confirming = "";
      setKill("persistent", true);
    } }, "Turn on"),
  );
}

async function installService(): Promise<void> {
  const ok = await act(() => hold("service", "install", () => local("InstallService"), () => !!state.status?.mode.service));
  if (ok) notify("Moley service is set up");
}

async function checkUpdate(b: HTMLButtonElement, version: HTMLElement): Promise<void> {
  try {
    const r = await pressing(b, () => bridge<Reply<{ available: boolean; version?: string }>>("CheckUpdate"));
    if (!r.ok) throw new Failure(r.error);
    if (!r.result.available) {
      version.textContent = `${state.status?.version} · Up to date`;
      b.hidden = true;
      return;
    }
    version.textContent = `${r.result.version} available`;
    b.textContent = "Update";
    b.onclick = () => void act(() => pressing(b, () => local("InstallUpdate")));
  } catch (e) {
    notify(explain(e));
  }
}

// --- Sheets -----------------------------------------------------------------------------------

function openSheet(kind: Exclude<Sheet, "">): void {
  const was = state.sheet;
  state.sheet = kind;
  state.confirming = "";
  renderSheet();
  const sheet = $("sheet"), scrim = $("scrim");
  if (was) return;
  sheet.hidden = scrim.hidden = false;
  scrim.onclick = closeSheet;
  if (motion()) {
    sheet.animate([{ transform: "translateY(100%)" }, { transform: "none" }], { duration: 480, easing: EASE });
    scrim.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 300 });
  }
  sheet.querySelector<HTMLElement>("textarea, .pick[aria-checked=true], button")?.focus({ preventScroll: true });
}

function closeSheet(): void {
  if (!state.sheet || $("sheet").querySelector('[aria-busy="true"]')) return;
  closeChoice?.();
  state.sheet = "";
  const sheet = $("sheet"), scrim = $("scrim");
  const done = () => {
    if (state.sheet) return;
    sheet.hidden = scrim.hidden = true;
    sheet.replaceChildren();
  };
  if (!motion()) return done();
  sheet.animate([{ transform: "none" }, { transform: "translateY(100%)" }], { duration: 280, easing: "cubic-bezier(.4, 0, 1, 1)", fill: "forwards" }).onfinish = (e) => {
    (e.target as Animation).cancel();
    done();
  };
  scrim.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 280, fill: "forwards" }).onfinish = (e) => (e.target as Animation).cancel();
}

addEventListener("keydown", (e) => e.key === "Escape" && closeSheet());

function renderSheet(): void {
  const views = { exits: exitsSheet, import: () => importSheet(), rule: ruleSheet, profile: profileSheet, replace: () => importSheet(state.editing) };
  if (state.sheet) $("sheet").replaceChildren(...views[state.sheet]());
}

function sheetHead(title: string, back?: Exclude<Sheet, "">): HTMLElement {
  return h("div", { class: "sheet-head" },
    back ? h("span", { style: "display:flex;align-items:center;gap:4px;margin-left:-8px" }, iconButton("back", "Back", () => openSheet(back)), h("h2", {}, title)) : h("h2", {}, title),
    iconButton("close", "Close", closeSheet));
}

// Exits: where everything without a rule goes.
function exitsSheet(): Node[] {
  const current = state.pending || state.status?.default_exit || "direct";
  const row = (x: Exit) => {
    const d = describeExit(x);
    const selected = x.id === current;
    const meter = h("span", { class: "meter" }, ...Array.from({ length: 5 }, () => h("i")));
    const b = held(h("button", { type: "button", class: "row pick", role: "radio", "aria-checked": String(selected), "data-exit": x.id },
      tile(d.icon, "", x.kind === "profile" ? health(x.state) : ""),
      h("span", { class: "text" }, h("span", { class: "name" }, exitName(x.id)), h("span", { class: "detail", "data-base": d.detail }, d.detail)),
      x.kind === "profile" && h("span", { class: "actions-inline" },
        iconButton("edit", `Edit ${exitName(x.id)}`, () => ((state.editing = x.id), openSheet("profile"))),
        removeAction(x.id, "profiles.remove", `Remove ${exitName(x.id)}`)),
      x.kind !== "builtin" && meter,
      ico("check", "check"),
    ), "power", doing("power", x.id));
    b.onclick = (e) => {
      if ((e.target as HTMLElement).closest(".actions-inline, .confirm")) return;
      if (x.id === current) return closeSheet();
      void setDefault(x.id).then((ok) => ok && setTimeout(closeSheet, 260));
    };
    return h("li", {}, b);
  };
  const tunnels = state.exits.filter((x) => x.kind !== "builtin");
  const builtins = state.exits.filter((x) => x.kind === "builtin");
  const add = h("li", {}, h("button", { type: "button", class: "row", onclick: () => openSheet("import") }, tile("plus", "add"),
    h("span", { class: "text" }, h("span", { class: "name" }, "Add connection"))));
  const body = h("div", { class: "sheet-body" },
    h("p", { class: "eyebrow" }, "VPN"),
    h("ul", { class: "panel list", role: "radiogroup", "aria-label": "Connections" }, ...tunnels.map(row), add),
    h("p", { class: "eyebrow" }, "Other"),
    h("ul", { class: "panel list", role: "radiogroup", "aria-label": "Other" }, ...builtins.map(row)),
  );
  queueMicrotask(updateSheetRates);
  return [sheetHead("Connection"), body];
}

function updateSheetRates(): void {
  if (state.sheet !== "exits") return;
  for (const row of document.querySelectorAll<HTMLElement>(".pick[data-exit]")) {
    const r = state.traffic?.exits[row.dataset.exit!];
    const detail = row.querySelector<HTMLElement>(".detail")!;
    const live = rate(r);
    detail.textContent = live || detail.dataset.base!;
    detail.classList.toggle("rate", !!live);
    const n = r ? Math.ceil(level(r.up + r.down) * 5) : 0;
    row.querySelectorAll(".meter i").forEach((b, i) => b.classList.toggle("on", i < n));
  }
}

// --- Dropdown -------------------------------------------------------------------------------
// A button showing the choice; it opens a list of rows under it (above when
// there's no room). Arrow keys move, Enter picks, Escape closes.

type Item = { value: string; name: string; detail: string; icon: IconName };
let closeChoice: (() => void) | undefined; // the open dropdown, closed with its sheet

function choice(label: string, items: Item[], initial: string): { el: HTMLButtonElement; value: () => string } {
  let value = items.some((i) => i.value === initial) ? initial : items[0]?.value ?? "";
  const face = (it: Item) => [tile(it.icon), h("span", { class: "text" }, h("span", { class: "name" }, it.name), h("span", { class: "detail" }, it.detail))];
  const shown = h("span", { class: "choice-face" });
  const btn = h("button", { type: "button", class: "choice", "aria-haspopup": "listbox", "aria-expanded": "false", "aria-label": label },
    shown, ico("below", "ico chev"));
  const draw = () => shown.replaceChildren(...face(items.find((i) => i.value === value)!));
  draw();

  let list: HTMLElement | undefined;
  let active = 0;
  const rows = () => [...(list?.children ?? [])] as HTMLElement[];
  const highlight = (i: number) => {
    active = (i + items.length) % items.length;
    rows().forEach((r, n) => r.classList.toggle("active", n === active));
    rows()[active]?.scrollIntoView({ block: "nearest" });
  };
  const pick = (i: number) => {
    value = items[i].value;
    draw();
    close();
  };
  // A press outside closes the list, and its click does nothing else (it
  // would close the sheet behind).
  const outside = (e: PointerEvent) => {
    if (btn.contains(e.target as Node) || list?.contains(e.target as Node)) return;
    close();
    const swallow = (c: Event) => (c.stopPropagation(), c.preventDefault());
    addEventListener("click", swallow, { capture: true, once: true });
    setTimeout(() => removeEventListener("click", swallow, true), 500);
  };
  const close = () => {
    if (!list) return;
    const l = list;
    list = undefined;
    closeChoice = undefined;
    btn.setAttribute("aria-expanded", "false");
    removeEventListener("pointerdown", outside, true);
    if (!motion()) return l.remove();
    l.animate([{ opacity: 1 }, { opacity: 0, transform: "translateY(-4px) scale(.98)" }], { duration: 140, easing: "ease-in", fill: "forwards" }).onfinish = () => l.remove();
  };
  const open = () => {
    closeChoice?.();
    active = Math.max(0, items.findIndex((i) => i.value === value));
    list = h("ul", { class: "choice-list", role: "listbox", "aria-label": label },
      ...items.map((it, i) => h("li", {
        role: "option", class: "choice-row", "aria-selected": String(it.value === value),
        onclick: () => pick(i), onpointermove: () => void (active !== i && highlight(i)),
      }, ...face(it), ico("check", "check"))));
    document.body.append(list);
    // Fixed to the viewport, so the sheet's scrolling doesn't clip it.
    const r = btn.getBoundingClientRect();
    const below = innerHeight - r.bottom - 12, above = r.top - 12;
    const up = below < Math.min(list.scrollHeight, 220) && above > below;
    Object.assign(list.style, {
      left: `${r.left}px`, width: `${r.width}px`, maxHeight: `${Math.min(300, up ? above : below)}px`,
      ...(up ? { bottom: `${innerHeight - r.top + 6}px` } : { top: `${r.bottom + 6}px` }),
    });
    list.style.transformOrigin = up ? "bottom" : "top";
    highlight(active);
    btn.setAttribute("aria-expanded", "true");
    addEventListener("pointerdown", outside, true);
    closeChoice = close;
    if (motion()) list.animate([{ opacity: 0, transform: `translateY(${up ? 6 : -6}px) scale(.97)` }, { opacity: 1, transform: "none" }], { duration: 220, easing: EASE });
  };
  btn.onclick = () => (list ? close() : open());
  btn.onkeydown = (e) => {
    const keys: Record<string, () => void> = list
      ? { ArrowDown: () => highlight(active + 1), ArrowUp: () => highlight(active - 1), Home: () => highlight(0), End: () => highlight(items.length - 1),
          Enter: () => pick(active), " ": () => pick(active), Escape: close, Tab: close }
      : { ArrowDown: open, ArrowUp: open };
    const k = keys[e.key];
    if (!k) return;
    if (e.key !== "Tab") e.preventDefault();
    e.stopPropagation(); // Escape closes the list, not the sheet
    k();
  };
  return { el: btn, value: () => value };
}

// A rule, new or edited: one entry per line; each is sorted into the right
// kind of match.
function ruleSheet(): Node[] {
  const old = state.rules?.rules.find((r) => r.id === state.editing);
  // The kinds the box can't write (made with the CLI: exact domains,
  // keywords, ports…) stay as they were.
  const { domain_suffix, ip_cidr, process_name, process_path, ...kept } = old?.match ?? {};
  const name = h("input", { type: "text", placeholder: "Optional", maxlength: "64", spellcheck: "false", value: old?.name ?? "" });
  const entries = h("textarea", { placeholder: "netflix.com\n10.20.0.0/16\nslack.exe", spellcheck: "false" });
  entries.value = [...domain_suffix ?? [], ...ip_cidr ?? [], ...process_name ?? [], ...process_path ?? []].join("\n");
  const exit = choice("Route through", (state.status?.exits ?? []).map((id) => {
    const x = state.exits.find((e) => e.id === id) ?? { id, kind: "builtin" as const };
    const d = describeExit(x);
    return { value: id, name: exitName(id), detail: d.detail, icon: d.icon };
  }), old?.exit ?? state.exits.find((x) => x.kind === "profile")?.id ?? "direct");
  const err = h("p", { class: "error", hidden: true });
  const save = h("button", { type: "button", class: "btn primary" }, old ? "Save" : "Add rule");
  save.onclick = async () => {
    const lines = entries.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    const match = { ...kept, ...classify(lines) };
    if (!Object.keys(match).length) return void ((err.hidden = false), (err.textContent = "Enter a site or app."));
    const rule: Rule = { id: old?.id ?? ruleID(name.value || lines[0]), name: name.value.trim() || undefined, exit: exit.value(), match };
    if (await act(() => pressing(save, async () => (await rpc("rules.put", { rule }), await loadRules())))) {
      closeSheet();
      notify(`${ruleName(rule)} ${old ? "saved" : "added"}`);
    }
  };
  return [sheetHead(old ? "Edit rule" : "Add rule"), h("div", { class: "sheet-body" },
    h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name),
    h("label", { class: "field" }, h("span", { class: "label", "data-tip": "One per line: sites (with their subdomains), IP ranges or app names. Apps need All apps on." }, "Sites or apps"), entries),
    h("div", { class: "field" }, h("span", { class: "label" }, "Route through"), exit.el),
    err,
    h("div", { class: "buttons" }, h("button", { type: "button", class: "btn", onclick: closeSheet }, "Cancel"), save),
  )];
}

function classify(lines: string[]): Match {
  const m: Match = {};
  const add = (k: keyof Omit<Match, "port">, v: string) => ((m[k] ??= []) as string[]).push(v);
  for (const line of lines) {
    if (/^[\d.]+(\/\d+)?$/.test(line) || (line.includes(":") && /^[\da-f:.]+(\/\d+)?$/i.test(line))) add("ip_cidr", line);
    else if (/[\\/]/.test(line) && /\.(exe|app)$|^\//i.test(line)) add("process_path", line);
    else if (/\.exe$/i.test(line) || !line.includes(".")) add("process_name", line);
    else add("domain_suffix", line.replace(/^[a-z]+:\/\//i, "").replace(/[/:?#].*$/, "").replace(/^\*\./, "").toLowerCase());
  }
  return m;
}

function ruleID(first: string): string {
  const base = first.toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/\.(exe|com|net|org)$/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32) || "rule";
  const taken = new Set([...(state.rules?.rules.map((r) => r.id) ?? []), "lan", "default"]);
  let id = /^[a-z0-9]/.test(base) ? base : `r-${base}`;
  for (let n = 2; taken.has(id); n++) id = `${base}-${n}`;
  return id;
}

// A connection: its name, whether its server's networks use it, its config.
function profileSheet(): Node[] {
  const x = state.exits.find((e) => e.id === state.editing);
  const p = state.status?.profiles.find((q) => q.id === state.editing);
  if (!x || !p) return [sheetHead("Connection", "exits")];
  const name = h("input", { type: "text", placeholder: x.id, maxlength: "64", spellcheck: "false", value: x.name ?? "" });
  const networks = h("button", { type: "button", class: "switch", role: "switch", "aria-checked": String(!!p.auto_rule), "aria-label": "Work networks" });
  networks.onclick = () => networks.setAttribute("aria-checked", String(networks.getAttribute("aria-checked") !== "true"));
  const err = h("p", { class: "error", hidden: true });
  const save = h("button", { type: "button", class: "btn primary" }, "Save");
  save.onclick = async () => {
    err.hidden = true;
    try {
      await pressing(save, () => rpc("profiles.update", {
        id: x.id, name: name.value.trim(), ...(p.kind === "openvpn" && { auto_rule: networks.getAttribute("aria-checked") === "true" }),
      }));
      state.exits = await rpc<Exit[]>("exits.list");
      openSheet("exits");
      notify(`${exitName(x.id)} saved`);
    } catch (e) {
      err.hidden = false;
      err.textContent = explain(e);
    }
  };
  const replace = h("li", {}, h("button", { type: "button", class: "row", onclick: () => openSheet("replace") }, tile("file"),
    h("span", { class: "text" }, h("span", { class: "name" }, "Replace config"), h("span", { class: "detail" }, protocols[x.protocol ?? ""] ?? ""))));
  return [sheetHead("Edit connection", "exits"), h("div", { class: "sheet-body" },
    h("label", { class: "field" }, h("span", { class: "label" }, "Name"), name),
    h("ul", { class: "panel list spaced" },
      p.kind === "openvpn" && setting("Work networks", "Send the networks and domains this VPN's server pushes, such as your company's intranet, through it even while disconnected.", networks),
      replace),
    err,
    h("div", { class: "buttons" }, h("button", { type: "button", class: "btn", onclick: () => openSheet("exits") }, "Cancel"), save),
  )];
}

// Add connection: a file (dropped or picked) or a pasted link. With target,
// it replaces that connection's config instead, keeping how it's used.
function importSheet(target = ""): Node[] {
  let file: { name: string; data: string } | undefined;
  const prompt = "Drop a config file";
  const picked = h("span", { class: "name" }, prompt);
  const input = h("input", { type: "file", accept: ".ovpn,.conf,.txt", hidden: true });
  const drop = h("div", { class: "drop", "data-tip": "OpenVPN (.ovpn), WireGuard or AmneziaWG (.conf)" }, ico("file"), picked,
    h("button", { type: "button", class: "link", onclick: () => input.click() }, "or browse"), input);
  const read = async (f: File) => {
    file = { name: f.name, data: await f.text() };
    picked.textContent = f.name;
    drop.classList.add("picked");
    link.value = "";
  };
  input.onchange = () => void (input.files?.[0] && read(input.files[0]));
  // Statements, not expressions: an on* handler that returns false cancels
  // the event, and the input's own click bubbles through here.
  drop.onclick = (e) => {
    if (e.target !== input && !(e.target as Element).closest(".link")) input.click();
  };
  // The drop is ours: the Wails runtime's page-wide handlers (for its native
  // file drop, which this window doesn't use) would refuse it.
  drop.ondragover = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
    drop.classList.add("over");
  };
  drop.ondragenter = drop.ondragover;
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    drop.classList.remove("over");
    const f = e.dataTransfer?.files[0];
    if (f) void read(f);
  };
  const link = h("textarea", { placeholder: "ss://…  vless://…  trojan://…", spellcheck: "false", style: "min-height:64px" });
  link.oninput = () => {
    if (!link.value.trim()) return;
    file = undefined;
    picked.textContent = prompt;
    drop.classList.remove("picked");
  };
  const password = h("input", { type: "password", placeholder: "Private key password", autocomplete: "off" });
  const passwordField = h("label", { class: "field", hidden: true }, h("span", { class: "label" }, "Key password"), password);
  const err = h("p", { class: "error", hidden: true });
  const add = h("button", { type: "button", class: "btn primary" }, target ? "Replace" : "Add");
  add.onclick = async () => {
    const data = file?.data ?? link.value.trim();
    if (!data) return void ((err.hidden = false), (err.textContent = "Add a file or paste a link."));
    err.hidden = true;
    try {
      const res = await pressing(add, () => rpc<{ profiles: { id: string }[]; warnings: string[] }>("profiles.import", {
        data, name: file?.name ?? "", key_password: password.value || undefined, ...(target && { id: target, replace: true }),
      }));
      openSheet(target ? "profile" : "exits");
      notify(`${res.profiles.map((p) => exitName(p.id)).join(", ")} ${target ? "updated" : "added"}${res.warnings.length ? `. ${res.warnings[0]}` : ""}`);
    } catch (e) {
      if (e instanceof Failure && e.error.code === "key_password_required") {
        passwordField.hidden = false;
        password.focus();
        if (password.value) (err.hidden = false), (err.textContent = "Wrong password.");
      } else {
        err.hidden = false;
        err.textContent = explain(e);
      }
    }
  };
  return [sheetHead(target ? "Replace config" : "Add connection", target ? "profile" : "exits"), h("div", { class: "sheet-body" },
    drop,
    h("label", { class: "field" }, h("span", { class: "label" }, "Or paste a link"), link),
    passwordField,
    err,
    h("div", { class: "buttons" }, h("button", { type: "button", class: "btn", onclick: closeSheet }, "Cancel"), add),
  )];
}

// --- Events -------------------------------------------------------------------------------------

async function onStatus(st: Status): Promise<void> {
  const first = !state.status;
  state.status = st;
  state.offline = false;
  if (state.pending === st.default_exit) state.pending = "";
  try {
    state.exits = await rpc<Exit[]>("exits.list");
  } catch {}
  if (first) void loadRules();
  renderHome();
  if (state.view === "rules") void loadRules();
  else if (state.view !== "settings" || state.confirming !== "always") renderPage();
  if (state.sheet === "exits" && !state.confirming) renderSheet();
  for (const check of settling) check();
}

Events.On("status", (e) => void onStatus(e.data));
// The daemon sends traffic only when it changes, so the chart keeps its
// own clock and samples the latest rate every second.
Events.On("traffic", (e) => {
  state.traffic = e.data;
  renderHome();
  updateSheetRates();
});
setInterval(() => sample(state.traffic), 1000);
Events.On("conns", (e) => {
  state.conns = e.data ?? [];
  if (state.view === "activity") renderPage();
});
Events.On("offline", () => {
  state.offline = true;
  state.status = undefined;
  state.traffic = undefined;
  state.test = undefined;
  closeSheet();
  renderHome();
  renderPage();
});

async function main(): Promise<void> {
  buildRing();
  drawChart();
  renderHome();
  moveGlow();
  const snap = await bridge<Record<string, any>>("Snapshot");
  if (snap.offline) {
    state.offline = true;
    renderHome();
  }
  if (snap.traffic) state.traffic = snap.traffic;
  if (snap.status) await onStatus(snap.status);
}

void main();
