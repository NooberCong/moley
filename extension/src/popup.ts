import { icon, type IconName } from "./icons.js";
import { site, type Conn, type Exit, type Msg, type Reply, type Rules, type State } from "./shared.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function send<T>(msg: Msg): Promise<T> {
  return chrome.runtime.sendMessage(msg);
}

async function rpc<T>(method: string, params?: unknown): Promise<T> {
  const r = await send<Reply<T>>({ type: "rpc", method, params });
  if (!r.ok) throw new Error(r.error.message);
  return r.result;
}

const protocols: Record<string, string> = {
  wireguard: "WireGuard", amneziawg: "AmneziaWG", openvpn: "OpenVPN", shadowsocks: "Shadowsocks",
  vless: "VLESS", vmess: "VMess", trojan: "Trojan", hysteria2: "Hysteria2", tuic: "TUIC",
  socks: "SOCKS5", http: "HTTP proxy",
};

type Tone = "tunnel" | "direct" | "block" | "idle" | "off" | "down";

// The card is the answer to "where does this site go?": a route from the
// site to its exit, the exit's name, and why it was chosen.
function card(tone: Tone, title: string, sub: string, opts: { to?: IconName; why?: string } = {}): void {
  $("card").dataset.tone = tone;
  $("title").textContent = title;
  $("sub").textContent = sub;
  const why = $("why");
  why.hidden = !opts.why;
  why.textContent = opts.why ?? "";
  const toIcon: Record<Tone, IconName> = { tunnel: "tunnel", direct: "direct", block: "block", idle: "direct", off: "direct", down: "down" };
  $("to").replaceChildren(icon(opts.to ?? toIcon[tone]));
}

function siteNode(host: string, favicon?: string): void {
  const from = $("from");
  if (!host) return void from.replaceChildren(icon("direct"));
  const letter = document.createElement("span");
  letter.textContent = host[0].toUpperCase();
  from.replaceChildren(letter);
  if (!favicon || !/^(https?|data):/.test(favicon)) return;
  const img = new Image(16, 16);
  img.alt = "";
  img.onload = () => from.replaceChildren(img);
  img.src = favicon;
}

function notice(text: string, actions: { label: string; run: (b: HTMLButtonElement) => void; primary?: boolean }[] = []): void {
  $("notice").hidden = false;
  $("notice-text").hidden = !text;
  // `code` spans render as a command with a copy button.
  $("notice-text").replaceChildren(
    ...text.split(/(`[^`]+`)/).map((part) => {
      if (!part.startsWith("`")) return document.createTextNode(part);
      const cmd = part.slice(1, -1);
      const box = document.createElement("span");
      box.className = "cmd";
      const code = document.createElement("code");
      code.textContent = cmd;
      const copy = document.createElement("button");
      copy.type = "button";
      copy.title = "Copy";
      copy.setAttribute("aria-label", `Copy ${cmd}`);
      copy.append(icon("copy"));
      copy.onclick = async () => {
        await navigator.clipboard.writeText(cmd);
        copy.replaceChildren(icon("check"));
        setTimeout(() => copy.replaceChildren(icon("copy")), 1200);
      };
      box.append(code, copy);
      return box;
    }),
  );
  $("notice-actions").replaceChildren(
    ...actions.map((a) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = a.primary ? "btn primary" : "btn";
      b.textContent = a.label;
      b.onclick = () => a.run(b);
      return b;
    }),
  );
}

async function setEnabled(on: boolean): Promise<void> {
  await send<State>({ type: "enable", on });
  location.reload();
}

function power(st: State): void {
  const sw = $<HTMLButtonElement>("power");
  // Never connected: no proxy was applied, so there is nothing to switch.
  sw.hidden = st.enabled && st.proxyPort === undefined;
  sw.setAttribute("aria-checked", String(st.enabled));
  sw.title = st.enabled ? `On: routing through 127.0.0.1:${st.proxyPort}` : "Off: sites connect directly";
  sw.onclick = () => setEnabled(!st.enabled);
}

function health(x: Exit): "up" | "wait" | "down" | "" {
  switch (x.state) {
    case "connected":
    case "ready":
      return "up";
    case "connecting":
    case "auth-pending":
      return "wait";
    case "error":
    case "stopped":
      return "down";
    default:
      return "";
  }
}

// exitName is how the app shows an exit: a profile's display name if set.
function exitName(id: string, exits: Exit[]): string {
  if (id === "direct") return "Direct";
  if (id === "block") return "Block";
  return exits.find((e) => e.id === id)?.name || id;
}

function describe(x: Exit, exits: Exit[]): { name: string; detail: string; icon: IconName } {
  if (x.id === "direct") return { name: "Direct", detail: "Your own connection", icon: "direct" };
  if (x.id === "block") return { name: "Block", detail: "Don't load this site", icon: "block" };
  if (x.kind === "group") {
    const detail = x.group === "fastest" ? `Fastest of ${x.members?.length ?? 0}` : x.selected ? `Using ${exitName(x.selected, exits)}` : "Group";
    return { name: x.id, detail, icon: "group" };
  }
  const proto = protocols[x.protocol ?? ""] ?? "Tunnel";
  const state = { wait: " · Connecting…", down: " · Offline", up: "", "": "" }[health(x)];
  return { name: exitName(x.id, exits), detail: proto + state, icon: "tunnel" };
}

function reason(rule: string, rules: Rules): string {
  if (rule.startsWith("quick-")) return "Your pick";
  if (rule.startsWith("auto-")) return "VPN route";
  if (rule === "default") return "Default";
  const r = rules.rules.find((x) => x.id === rule);
  return `Rule ${r?.name || rule}`;
}

function showRoute(conns: Conn[], exits: Exit[], rules: Rules, host: string): void {
  const last = conns[0];
  if (!last) {
    const pick = rules.quick[host];
    if (pick) return showExit(pick, exits, "Your pick");
    return card("idle", "No traffic yet", "Load the page to see its route");
  }
  showExit(last.chain[0] ?? last.exit, exits, reason(last.rule, rules));
}

function showExit(id: string, exits: Exit[], why?: string): void {
  if (id === "direct") return card("direct", "Direct", "Not tunneled", { why });
  if (id === "block") return card("block", "Blocked", "Moley stops this site", { why });
  const x = exits.find((e) => e.id === id);
  const d = x ? describe(x, exits) : { name: id, detail: "Tunnel", icon: "tunnel" as IconName };
  card(x && health(x) === "down" ? "down" : "tunnel", d.name, d.detail, { why, to: d.icon });
}

function renderExits(host: string, exits: Exit[], rules: Rules, tabId?: number): void {
  const current = rules.quick[host] ?? "";
  const rows = [
    { id: "", name: "Automatic", detail: `Your rules, else ${exitName(rules.default_exit || "direct", exits)}`, icon: "auto" as IconName, dot: "" },
    ...exits.map((x) => ({ id: x.id, ...describe(x, exits), dot: x.kind === "profile" ? health(x) : "" })),
  ];
  const list = $("exits");
  list.replaceChildren(
    ...rows.map((row) => {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.className = "exit";
      btn.type = "button";
      btn.setAttribute("role", "radio");
      btn.setAttribute("aria-checked", String(row.id === current));
      const tile = document.createElement("span");
      tile.className = `tile ${row.dot}`;
      tile.append(icon(row.icon));
      const text = document.createElement("span");
      text.className = "text";
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = row.name;
      const detail = document.createElement("span");
      detail.className = "detail";
      detail.textContent = row.detail;
      text.append(name, detail);
      const check = document.createElement("span");
      check.className = "check";
      check.append(icon("check"));
      btn.append(tile, text, check);
      btn.onclick = async () => {
        if (btn.getAttribute("aria-checked") === "true") return;
        for (const b of list.querySelectorAll(".exit")) b.setAttribute("aria-checked", String(b === btn));
        row.id ? showExit(row.id, exits, "Your pick") : card("idle", "Automatic", "Reloading…");
        try {
          await rpc("quick.set", { host, exit: row.id });
        } catch (e) {
          return notice(`Couldn't change the route: ${(e as Error).message}`);
        }
        if (tabId !== undefined) await chrome.tabs.reload(tabId);
        setTimeout(() => window.close(), 280);
      };
      li.append(btn);
      if (row.id !== "block") return [li];
      const split = document.createElement("li");
      split.className = "split";
      split.setAttribute("role", "none");
      return [li, split];
    }).flat(),
  );
  $("pick").hidden = false;
  list.querySelector('[aria-checked="true"]')?.scrollIntoView({ block: "nearest" });
}

async function main(): Promise<void> {
  // Opened as a page (automation, keyboard users), ?tab=<id> names the tab.
  const tabParam = Number(new URLSearchParams(location.search).get("tab"));
  const [tab] = tabParam ? [await chrome.tabs.get(tabParam)] : await chrome.tabs.query({ active: true, currentWindow: true });
  let host = "";
  try {
    const url = new URL(tab?.url ?? "");
    if (url.protocol === "http:" || url.protocol === "https:") host = site(url.hostname);
  } catch {}
  $("site").textContent = host || "This tab";
  siteNode(host, tab?.favIconUrl);

  const st = await send<State>({ type: "state" });
  power(st);
  if (!st.enabled) {
    card("off", "Off", "Sites connect directly");
    return notice("", [{ label: "Turn on", primary: true, run: () => setEnabled(true) }]);
  }
  if (st.control === "controlled_by_other_extensions") {
    card("down", "Proxy in use", "Another extension controls this browser's proxy");
    return notice("Turn that extension off to let Moley route this browser.");
  }
  if (!st.connected) {
    const blocked = st.proxyPort !== undefined;
    card("down", "Moley isn't running", blocked ? "Sites won't load until it starts" : "Start it to route this browser");
    return notice(
      "Start it from a terminal: `moley start`",
      blocked ? [{ label: "Turn off for this browser", run: () => setEnabled(false) }] : [],
    );
  }
  if (!host) return card("idle", "No website", "Open a site to choose its route");

  try {
    const isIP = /^[\d.]+$|:/.test(host);
    const [exits, rules, conns] = await Promise.all([
      rpc<Exit[]>("exits.list"),
      rpc<Rules>("rules.list"),
      rpc<Conn[]>("conns.list", { host, closed: true }),
    ]);
    showRoute(conns, exits, rules, host);
    if (isIP) return notice(`Addresses are routed by rules: \`moley rules add <id> --ip-cidr ${host} --exit <exit>\``);
    renderExits(host, exits, rules, tab?.id);
  } catch (e) {
    card("down", "No answer", "Moley didn't respond");
    notice((e as Error).message);
  }
}

void main();
