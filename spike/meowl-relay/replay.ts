/**
 * Replays the REQ/COUNT shapes Meowl's e2e suite actually sent (harness frames.jsonl) against two
 * relays seeded with the same corpus, plus a fixed list of behaviour probes, and reports every
 * difference.
 *
 *   bun replay.ts shapes <frames.jsonl>                      shape statistics only
 *   bun replay.ts replay <frames.jsonl> <wsA> <wsB> <out.json>
 *   bun replay.ts probe <wsA> <wsB> <out.json>
 */

import { readFileSync, writeFileSync } from "node:fs";

import { finalizeEvent, getPublicKey } from "@qntx/nostr/core";
import type { Event } from "@qntx/nostr/core";

type Frame = { t: number; c: number; p: string; d: string; f?: string };
type Filter = Record<string, unknown>;

const PROBE_KEY = "11".repeat(32);
const TEST_KEY = "42".repeat(32);

function readFrames(path: string): Frame[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as Frame);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).toSorted(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

type Request = { verb: "REQ" | "COUNT"; path: string; filters: Filter[] };

function clientRequests(frames: Frame[]): { all: Request[]; frames: Frame[] } {
  const all: Request[] = [];
  const used: Frame[] = [];
  for (const frame of frames) {
    if (frame.d !== "c2r" || frame.f === undefined) {
      continue;
    }
    let message: unknown;
    try {
      message = JSON.parse(frame.f);
    } catch {
      continue;
    }
    if (!Array.isArray(message) || (message[0] !== "REQ" && message[0] !== "COUNT")) {
      continue;
    }
    all.push({ verb: message[0], path: frame.p, filters: message.slice(2) as Filter[] });
    used.push(frame);
  }
  return { all, frames: used };
}

function shapeOf(filter: Filter): string {
  return Object.keys(filter)
    .map((key) => {
      const value = filter[key];
      if (key === "limit" || key === "since" || key === "until") {
        return key;
      }
      return Array.isArray(value) ? `${key}[${value.length > 1 ? "n" : value.length}]` : key;
    })
    .toSorted()
    .join(",");
}

function stats(frames: Frame[]): Record<string, unknown> {
  const { all, frames: reqFrames } = clientRequests(frames);
  const verbs: Record<string, number> = {};
  for (const frame of frames) {
    if (frame.d === "c2r" && frame.f !== undefined) {
      const verb = String((JSON.parse(frame.f) as unknown[])[0]);
      verbs[verb] = (verbs[verb] ?? 0) + 1;
    }
  }
  const distinct = new Set(all.map((r) => `${r.verb} ${r.path} ${canonical(r.filters)}`));
  const shapes: Record<string, number> = {};
  const keys: Record<string, number> = {};
  const limits: number[] = [];
  let noLimit = 0;
  let maxFilters = 0;
  let maxTagConds = 0;
  let maxList = 0;
  let maxFrame = 0;
  const lists: Record<string, number> = {};
  for (const [i, r] of all.entries()) {
    maxFilters = Math.max(maxFilters, r.filters.length);
    maxFrame = Math.max(maxFrame, reqFrames[i]?.f?.length ?? 0);
    for (const f of r.filters) {
      const shape = shapeOf(f);
      shapes[shape] = (shapes[shape] ?? 0) + 1;
      for (const [k, v] of Object.entries(f)) {
        keys[k] = (keys[k] ?? 0) + 1;
        if (Array.isArray(v)) {
          maxList = Math.max(maxList, v.length);
          lists[k] = Math.max(lists[k] ?? 0, v.length);
        }
      }
      maxTagConds = Math.max(maxTagConds, Object.keys(f).filter((k) => k.startsWith("#")).length);
      if (typeof f["limit"] === "number") {
        limits.push(f["limit"]);
      } else if (r.verb === "REQ") {
        noLimit += 1;
      }
    }
  }
  // Peak REQ rate per connection and per process (one IP): max REQs in any 1 s window.
  const perConn = new Map<number, number[]>();
  for (const frame of reqFrames) {
    const list = perConn.get(frame.c) ?? [];
    list.push(frame.t);
    perConn.set(frame.c, list);
  }
  const peak = (times: number[]): number => {
    let best = 0;
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while ((times[end] ?? 0) - (times[start] ?? 0) >= 1000) {
        start += 1;
      }
      best = Math.max(best, end - start + 1);
    }
    return best;
  };
  // Peak simultaneously open subscriptions on one connection.
  let maxOpen = 0;
  const open = new Map<number, Set<string>>();
  for (const frame of frames) {
    if (frame.d !== "c2r" || frame.f === undefined) {
      continue;
    }
    const m = JSON.parse(frame.f) as unknown[];
    const set = open.get(frame.c) ?? new Set<string>();
    if (m[0] === "REQ") {
      set.add(String(m[1]));
    } else if (m[0] === "CLOSE") {
      set.delete(String(m[1]));
    }
    open.set(frame.c, set);
    maxOpen = Math.max(maxOpen, set.size);
  }
  const conns = new Set(frames.filter((f) => f.d === "open").map((f) => f.c));
  const paths: Record<string, number> = {};
  for (const r of all) {
    paths[r.path] = (paths[r.path] ?? 0) + 1;
  }
  return {
    verbs,
    requests: all.length,
    distinctRequests: distinct.size,
    connections: conns.size,
    paths,
    filterKeys: keys,
    maxListLengthByKey: lists,
    filterShapes: Object.fromEntries(Object.entries(shapes).toSorted(([, a], [, b]) => b - a)),
    maxFiltersPerReq: maxFilters,
    maxTagConditionsPerFilter: maxTagConds,
    maxListLength: maxList,
    maxReqFrameBytes: maxFrame,
    filtersWithoutLimit: noLimit,
    limitMax: limits.length === 0 ? null : Math.max(...limits),
    limitsOver500: limits.filter((l) => l > 500).length,
    peakReqsPerSecondOneConnection: Math.max(0, ...[...perConn.values()].map(peak)),
    peakReqsPerSecondAllConnections: peak(reqFrames.map((f) => f.t).toSorted((a, b) => a - b)),
    peakOpenSubsOneConnection: maxOpen,
  };
}

type Outcome = {
  end: "EOSE" | "CLOSED" | "COUNT" | "NOTICE" | "TIMEOUT";
  reason?: string;
  ids: string[];
  count?: unknown;
  ms: number;
};

class Conn {
  readonly #ws: WebSocket;
  readonly #listeners = new Set<(m: unknown[]) => void>();
  readonly ready: Promise<void>;
  readonly notices: string[] = [];

  constructor(url: string) {
    this.#ws = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.#ws.addEventListener("open", () => resolve());
      this.#ws.addEventListener("error", () => reject(new Error(`cannot connect ${url}`)));
    });
    this.#ws.addEventListener("message", (e) => {
      const m = JSON.parse(String(e.data)) as unknown[];
      if (m[0] === "NOTICE") {
        this.notices.push(String(m[1]));
      }
      for (const l of this.#listeners) {
        l(m);
      }
    });
  }

  send(m: unknown[]): void {
    this.#ws.send(JSON.stringify(m));
  }

  until<T>(pick: (m: unknown[]) => T | undefined, timeoutMs = 5000): Promise<T | undefined> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.#listeners.delete(listener);
        resolve(undefined);
      }, timeoutMs);
      const listener = (m: unknown[]): void => {
        const hit = pick(m);
        if (hit !== undefined) {
          clearTimeout(timer);
          this.#listeners.delete(listener);
          resolve(hit);
        }
      };
      this.#listeners.add(listener);
    });
  }

  async request(verb: "REQ" | "COUNT", filters: Filter[], sub = "r"): Promise<Outcome> {
    const ids: string[] = [];
    const started = performance.now();
    const collect = (m: unknown[]): void => {
      if (m[0] === "EVENT" && m[1] === sub) {
        ids.push((m[2] as Event).id);
      }
    };
    this.#listeners.add(collect);
    const noticeBefore = this.notices.length;
    this.send([verb, sub, ...filters]);
    const end = await this.until<Outcome["end"] | { r: string; c?: unknown }>((m) => {
      if (m[1] !== sub && m[0] !== "NOTICE") {
        return undefined;
      }
      if (m[0] === "EOSE") {
        return "EOSE";
      }
      if (m[0] === "CLOSED") {
        return { r: `CLOSED:${String(m[2])}` };
      }
      if (m[0] === "COUNT") {
        return { r: "COUNT", c: m[2] };
      }
      if (m[0] === "NOTICE") {
        return { r: `NOTICE:${String(m[1])}` };
      }
      return undefined;
    });
    this.#listeners.delete(collect);
    if (verb === "REQ") {
      this.send(["CLOSE", sub]);
    }
    const ms = Math.round(performance.now() - started);
    if (end === undefined) {
      return { end: "TIMEOUT", ids, ms, ...(this.notices.length > noticeBefore ? { reason: this.notices.at(-1) } : {}) };
    }
    if (end === "EOSE") {
      return { end, ids, ms };
    }
    if (typeof end === "object" && end.r === "COUNT") {
      return { end: "COUNT", ids, count: end.c, ms };
    }
    const r = typeof end === "object" ? end.r : String(end);
    const [kind, ...rest] = r.split(":");
    return { end: kind as Outcome["end"], reason: rest.join(":"), ids, ms };
  }

  async publish(event: Event): Promise<{ ok: unknown; reason: unknown } | undefined> {
    this.send(["EVENT", event]);
    return this.until((m) =>
      m[0] === "OK" && m[1] === event.id ? { ok: m[2], reason: m[3] } : undefined,
    );
  }

  close(): void {
    this.#ws.close();
  }
}

function compare(a: Outcome, b: Outcome): string {
  if (a.end !== b.end) {
    return "outcome";
  }
  if (a.end === "COUNT") {
    return canonical(a.count) === canonical(b.count) ? "same" : "count";
  }
  if (a.ids.length === b.ids.length && a.ids.every((id, i) => id === b.ids[i])) {
    return "same";
  }
  const setA = new Set(a.ids);
  if (a.ids.length === b.ids.length && b.ids.every((id) => setA.has(id))) {
    return "order";
  }
  return "set";
}

async function replay(framesPath: string, wsA: string, wsB: string, out: string): Promise<void> {
  const { all } = clientRequests(readFrames(framesPath));
  const distinct = new Map<string, Request & { n: number }>();
  for (const r of all) {
    const key = `${r.verb} ${r.path} ${canonical(r.filters)}`;
    const hit = distinct.get(key);
    if (hit === undefined) {
      distinct.set(key, { ...r, n: 1 });
    } else {
      hit.n += 1;
    }
  }
  const results: unknown[] = [];
  const tally: Record<string, number> = {};
  const conns = new Map<string, [Conn, Conn]>();
  for (const r of distinct.values()) {
    let pair = conns.get(r.path);
    if (pair === undefined) {
      pair = [new Conn(`${wsA}${r.path}`), new Conn(`${wsB}${r.path}`)];
      await Promise.all(pair.map((c) => c.ready));
      conns.set(r.path, pair);
    }
    const [ca, cb] = pair;
    const a = await ca.request(r.verb, r.filters);
    const b = await cb.request(r.verb, r.filters);
    const verdict = compare(a, b);
    tally[verdict] = (tally[verdict] ?? 0) + 1;
    results.push({
      verb: r.verb,
      path: r.path,
      occurrences: r.n,
      filters: r.filters,
      verdict,
      a: { end: a.end, reason: a.reason, n: a.ids.length, count: a.count, ms: a.ms },
      b: { end: b.end, reason: b.reason, n: b.ids.length, count: b.count, ms: b.ms },
      ...(verdict === "set" || verdict === "order"
        ? {
            onlyA: a.ids.filter((id) => !b.ids.includes(id)).slice(0, 10),
            onlyB: b.ids.filter((id) => !a.ids.includes(id)).slice(0, 10),
            firstOrderDiff: a.ids.findIndex((id, i) => id !== b.ids[i]),
          }
        : {}),
    });
  }
  for (const [ca, cb] of conns.values()) {
    ca.close();
    cb.close();
  }
  writeFileSync(out, JSON.stringify({ tally, distinct: distinct.size, results }, null, 2));
  console.log(JSON.stringify({ tally, distinct: distinct.size }));
}

const now = (): number => Math.floor(Date.now() / 1000);

function sign(template: { kind: number; content?: string; tags?: string[][]; created_at?: number }, key = PROBE_KEY): Event {
  return finalizeEvent(
    {
      kind: template.kind,
      content: template.content ?? "",
      tags: template.tags ?? [],
      created_at: template.created_at ?? now(),
    },
    key,
  );
}

type Probe = { name: string; run: (c: Conn) => Promise<unknown> };

const HEX = "ab".repeat(32);
const TEST_PUB = getPublicKey(TEST_KEY);

const reqProbe = (name: string, filters: Filter[]): Probe => ({
  name,
  run: async (c) => {
    const o = await c.request("REQ", filters);
    return { end: o.end, reason: o.reason, n: o.ids.length };
  },
});

function probes(tag: string): Probe[] {
  const old = sign({ kind: 1, content: `probe-old-${tag}`, created_at: 1_700_000_000 });
  const future = sign({ kind: 1, content: `probe-future-${tag}`, created_at: now() + 3600 });
  const fresh = sign({ kind: 1, content: `probe-fresh-${tag}` });
  const meta1 = sign({ kind: 0, content: `{"name":"a-${tag}"}`, created_at: now() - 10 });
  const meta0 = sign({ kind: 0, content: `{"name":"b-${tag}"}`, created_at: now() - 20 });
  const authEvt = sign({ kind: 22242, tags: [["relay", "ws://127.0.0.1"], ["challenge", "x"]] });
  const badP = sign({ kind: 1, content: `probe-badp-${tag}`, tags: [["p", "npub1notahexkey"]] });
  const protectedEvt = sign({ kind: 1, content: `probe-protected-${tag}`, tags: [["-"]] });
  const target = sign({ kind: 1, content: `probe-del-${tag}` });
  const deletion = sign({ kind: 5, tags: [["e", target.id]] });
  const ephemeral = sign({ kind: 20001, content: `probe-eph-${tag}` });
  const dm = sign({ kind: 1059, content: "x", tags: [["p", getPublicKey(PROBE_KEY)]] });
  const pub = async (c: Conn, e: Event): Promise<unknown> => c.publish(e);
  return [
    reqProbe("search filter", [{ kinds: [1], search: "dev-seed", limit: 5 }]),
    reqProbe("kinds:[1] no limit", [{ kinds: [1] }]),
    reqProbe("kinds:[1] limit 1000", [{ kinds: [1], limit: 1000 }]),
    reqProbe("empty filter {} no limit", [{}]),
    reqProbe("4 tag conditions", [{ "#t": ["a"], "#p": [HEX], "#e": [HEX], "#k": ["1"] }]),
    reqProbe("uppercase hex author", [{ authors: [TEST_PUB.toUpperCase()], limit: 1 }]),
    reqProbe("hex prefix author", [{ authors: [TEST_PUB.slice(0, 8)], limit: 1 }]),
    reqProbe("empty authors list", [{ authors: [], limit: 5 }]),
    reqProbe("unknown key", [{ kinds: [1], foo: 1, limit: 1 }]),
    reqProbe("kinds 1059 only (restricted)", [{ kinds: [1059], limit: 5 }]),
    reqProbe("kinds 4 only (restricted)", [{ kinds: [4], limit: 5 }]),
    reqProbe("201 filters", Array.from({ length: 201 }, () => ({ ids: [HEX] }))),
    {
      name: "sub id 65 chars",
      run: async (c) => c.request("REQ", [{ limit: 1 }], "s".repeat(65)),
    },
    {
      name: "COUNT kinds:[1]",
      run: async (c) => {
        const o = await c.request("COUNT", [{ kinds: [1] }], "cnt");
        return { end: o.end, reason: o.reason, count: o.count };
      },
    },
    {
      name: "COUNT #p hll-eligible",
      run: async (c) => {
        const o = await c.request("COUNT", [{ kinds: [3], "#p": [TEST_PUB] }], "cnt2");
        return { end: o.end, reason: o.reason, count: o.count };
      },
    },
    { name: "EVENT created_at 1700000000 (fixture era)", run: async (c) => pub(c, old) },
    { name: "EVENT created_at now+3600", run: async (c) => pub(c, future) },
    { name: "EVENT fresh kind 1", run: async (c) => pub(c, fresh) },
    { name: "EVENT duplicate", run: async (c) => pub(c, fresh) },
    {
      name: "replaceable: newer then older kind 0",
      run: async (c) => [await pub(c, meta1), await pub(c, meta0)],
    },
    { name: "EVENT kind 22242", run: async (c) => pub(c, authEvt) },
    { name: "EVENT p tag not hex", run: async (c) => pub(c, badP) },
    { name: "EVENT protected (NIP-70) unauthenticated", run: async (c) => pub(c, protectedEvt) },
    { name: "EVENT kind 1059 then REQ it", run: async (c) => [await pub(c, dm), await c.request("REQ", [{ ids: [dm.id] }])] },
    {
      name: "NIP-09: delete then REQ then republish",
      run: async (c) => {
        const a = await pub(c, target);
        const b = await pub(c, deletion);
        const q = await c.request("REQ", [{ ids: [target.id] }]);
        const again = await pub(c, target);
        return { publish: a, delete: b, reqAfter: q.ids.length, republish: again };
      },
    },
    {
      name: "ephemeral: publish then REQ",
      run: async (c) => {
        const ok = await pub(c, ephemeral);
        const q = await c.request("REQ", [{ ids: [ephemeral.id] }]);
        return { ok, stored: q.ids.length };
      },
    },
    {
      name: "AUTH challenge on connect",
      run: async (c) => {
        await c.ready;
        return c.until((m) => (m[0] === "AUTH" ? m[1] : undefined), 1000).then((v) => v ?? "none");
      },
    },
  ];
}

async function probe(wsA: string, wsB: string, out: string): Promise<void> {
  const tag = String(Date.now());
  const results: unknown[] = [];
  for (const p of probes(tag)) {
    const row: Record<string, unknown> = { name: p.name };
    for (const [label, url] of [
      ["a", wsA],
      ["b", wsB],
    ] as const) {
      const c = new Conn(url);
      await c.ready;
      try {
        row[label] = await p.run(c);
      } finally {
        if (c.notices.length > 0) {
          row[`${label}Notices`] = c.notices;
        }
        c.close();
      }
    }
    results.push(row);
    console.log(JSON.stringify(row));
  }
  const nip11: Record<string, unknown> = {};
  for (const [label, url] of [
    ["a", wsA],
    ["b", wsB],
  ] as const) {
    const res = await fetch(url.replace(/^ws/, "http"), { headers: { accept: "application/nostr+json" } });
    nip11[label] = { status: res.status, type: res.headers.get("content-type"), body: (await res.text()).slice(0, 600) };
  }
  results.push({ name: "NIP-11 GET /", ...nip11 });
  writeFileSync(out, JSON.stringify(results, null, 2));
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === "shapes" && args[0] !== undefined) {
  console.log(JSON.stringify(stats(readFrames(args[0])), null, 2));
} else if (cmd === "replay" && args.length === 4) {
  await replay(args[0]!, args[1]!, args[2]!, args[3]!);
} else if (cmd === "probe" && args.length === 3) {
  await probe(args[0]!, args[1]!, args[2]!);
} else {
  console.error("usage: replay.ts shapes <frames> | replay <frames> <wsA> <wsB> <out> | probe <wsA> <wsB> <out>");
  process.exit(2);
}
