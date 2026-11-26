// Messages between the popup and the background worker, and the daemon
// result shapes the popup reads. The daemon owns all routing; these are
// views of it.

export type Msg =
  | { type: "state" }
  | { type: "rpc"; method: string; params?: unknown }
  | { type: "enable"; on: boolean };

export interface State {
  enabled: boolean;   // the user wants this browser routed through Moley
  connected: boolean; // the daemon answered
  proxyPort?: number;
  control?: string;   // chrome.proxy levelOfControl
}

export interface Exit {
  id: string;
  name?: string; // profiles: the display name set in the app
  kind: "builtin" | "profile" | "group";
  protocol?: string; // profiles: wireguard, openvpn, ...
  group?: string;
  members?: string[];
  selected?: string;
  state?: string;
}

export interface Conn {
  host: string;
  rule: string;
  exit: string;
  chain: string[];
  start: string;
  end?: string;
}

export interface Rules {
  rules: { id: string; name?: string }[];
  quick: Record<string, string>;
  default_exit: string;
}

export type Reply<T> = { ok: true; result: T } | { ok: false; error: { code: string; message: string } };

// site picks the name a quick pick should cover: the registrable domain,
// so "www.netflix.com" routes netflix.com and every subdomain. A short
// list of common second-level suffixes stands in for the public suffix list.
const secondLevel = new Set(["co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"]);

export function site(hostname: string): string {
  const labels = hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2 || /^\d+$/.test(labels[labels.length - 1])) return labels.join(".");
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  const keep = tld.length === 2 && secondLevel.has(sld) ? 3 : 2;
  return labels.slice(-keep).join(".");
}
