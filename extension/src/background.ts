// Background worker: points the browser at Moley's local proxy and relays
// popup requests to the daemon over native messaging. It makes no routing
// decisions; the daemon does.

import type { Msg, Reply, State } from "./shared.js";

const HOST = "com.moley.host";
const RECONNECT_MS = 3000;

let port: chrome.runtime.Port | null = null;
let connected = false;
let nextId = 1;
const pending = new Map<number, (r: Reply<unknown>) => void>();

function connect(): void {
  if (port) return;
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener((msg: { id?: number; result?: unknown; error?: { code: string; message: string } }) => {
    const done = msg.id !== undefined ? pending.get(msg.id) : undefined;
    if (!done) return;
    pending.delete(msg.id!);
    done(msg.error ? { ok: false, error: msg.error } : { ok: true, result: msg.result });
  });
  port.onDisconnect.addListener(() => {
    port = null;
    connected = false;
    for (const done of pending.values()) done({ ok: false, error: { code: "daemon_unreachable", message: "Moley is not running" } });
    pending.clear();
    setTimeout(start, RECONNECT_MS);
  });
}

function call<T>(method: string, params?: unknown): Promise<Reply<T>> {
  connect();
  const id = nextId++;
  return new Promise((resolve) => {
    pending.set(id, resolve as (r: Reply<unknown>) => void);
    port!.postMessage({ id, method, params });
  });
}

async function enabled(): Promise<boolean> {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  return enabled as boolean;
}

// applyProxy sends everything to Moley over SOCKS5, so hostnames reach the
// daemon unresolved. Nothing is bypassed: "direct" is a daemon decision.
async function applyProxy(proxyPort: number): Promise<void> {
  await chrome.proxy.settings.set({
    scope: "regular",
    value: { mode: "fixed_servers", rules: { singleProxy: { scheme: "socks5", host: "127.0.0.1", port: proxyPort } } },
  });
  // Without this, WebRTC can send UDP around the proxy.
  await chrome.privacy.network.webRTCIPHandlingPolicy.set({ value: "disable_non_proxied_udp" });
}

async function clearProxy(): Promise<void> {
  await chrome.proxy.settings.clear({ scope: "regular" });
  await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
}

// start connects to the daemon and applies the proxy. If the daemon is
// down, the last proxy setting stays: requests fail rather than leak.
async function start(): Promise<void> {
  if (!(await enabled())) return;
  // Re-apply the last known proxy first: after a browser restart the
  // setting may be gone, and the daemon may not be up yet. Requests then
  // fail until it is, instead of going out directly.
  const { proxyPort } = await chrome.storage.local.get("proxyPort");
  if (typeof proxyPort === "number") await applyProxy(proxyPort);
  const hello = await call<{ proxy_port: number }>("client.hello");
  if (!hello.ok) return;
  connected = true;
  if (hello.result.proxy_port !== proxyPort) {
    await chrome.storage.local.set({ proxyPort: hello.result.proxy_port });
    await applyProxy(hello.result.proxy_port);
  }
}

async function state(): Promise<State> {
  if (!connected) await start();
  const [on, stored, proxy] = await Promise.all([
    enabled(),
    chrome.storage.local.get("proxyPort"),
    chrome.proxy.settings.get({}),
  ]);
  return { enabled: on, connected, proxyPort: stored.proxyPort as number | undefined, control: proxy.levelOfControl };
}

chrome.runtime.onMessage.addListener((msg: Msg, _sender, reply) => {
  (async () => {
    switch (msg.type) {
      case "state":
        return state();
      case "rpc":
        return call(msg.method, msg.params);
      case "enable":
        await chrome.storage.local.set({ enabled: msg.on });
        if (msg.on) await start();
        else await clearProxy();
        return state();
    }
  })().then(reply);
  return true; // async reply
});

chrome.runtime.onStartup.addListener(start);
chrome.runtime.onInstalled.addListener(start);
// Retry once a minute while the daemon is down (the native host stays up
// and answers "not running"); an open native port keeps the worker alive.
chrome.alarms.create("reconnect", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(() => {
  if (!connected) void start();
});
void start();
