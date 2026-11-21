/**
 * Relay harness for the nosfry-as-meowl-dev-relay spike.
 *
 * Two HTTP servers:
 *   :<port>     WebSocket proxy — each client upgrade opens an upstream socket
 *               to the backend with the same path+query and pipes text frames
 *               both ways; non-upgrade requests are forwarded to the backend's
 *               own port unchanged. Every frame and open/close is recorded as
 *               one JSON line in --record.
 *   :<port+1>   Fixture HTTP — "ts" mode forwards everything to the TS dev
 *               relay's HTTP half (7621); "nosfry" mode answers /dev/publish
 *               and /dev/reset itself (live note into nosfry, nosfry restart
 *               with a pristine db clone) and forwards the rest to 7621.
 *
 * Usage:
 *   bun harness.ts --backend ts|nosfry --port 7630 --record <frames.jsonl>
 *     [--nosfry-bin <path> --nosfry-config <path> --pristine <dir> --db <dir>]
 */

import { appendFileSync } from "node:fs";

import { FilterError, finalizeEvent, matchFilter } from "@qntx/nostr/core";
import type { Event, Filter } from "@qntx/nostr/core";

const SECRET_KEY = "42".repeat(32);
const TS_WS = "ws://127.0.0.1:7620";
const TS_HTTP = "http://127.0.0.1:7621";
const NOSFRY_WS = "ws://127.0.0.1:7640";
const NOSFRY_PORT = 7640;

// Same rule as tools/dev-relay/server.ts: an open REQ is "settled" 500 ms after
// first seen, and no REQ matching the note may have arrived in the last 1200 ms.
const SUB_SETTLE_MS = 500;
const REQ_QUIESCE_MS = 1200;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const backend = arg("--backend");
const port = Number(arg("--port"));
const recordPath = arg("--record");
const nosfryBin = arg("--nosfry-bin");
const nosfryConfig = arg("--nosfry-config");
const pristineDir = arg("--pristine");
const dbDir = arg("--db");
if (
  (backend !== "ts" && backend !== "nosfry") ||
  !Number.isInteger(port) ||
  recordPath === undefined ||
  (backend === "nosfry" &&
    (nosfryBin === undefined ||
      nosfryConfig === undefined ||
      pristineDir === undefined ||
      dbDir === undefined))
) {
  console.error(
    "usage: bun harness.ts --backend ts|nosfry --port <p> --record <file> " +
      "[--nosfry-bin <path> --nosfry-config <path> --pristine <dir> --db <dir>]",
  );
  process.exit(1);
}

const upstreamWs = backend === "ts" ? TS_WS : NOSFRY_WS;
const upstreamHttp = backend === "ts" ? "http://127.0.0.1:7620" : "http://127.0.0.1:7640";

const record = (line: Record<string, unknown>): void => {
  appendFileSync(recordPath, JSON.stringify(line) + "\n");
};

// Open client subscriptions reconstructed from proxied c2r REQ/CLOSE frames,
// keyed by conn+subId so two connections sharing an id cannot clobber each other.
const openReqs = new Map<string, { filters: Filter[]; seenAt: number }>();
let lastMatchingReqAt = 0;
// The event /dev/publish is currently holding for; REQs matching it restart the
// quiescence window (same as the TS relay's inbox scan).
let pendingEvent: Event | undefined;

function filterMatches(filter: Filter, event: Event): boolean {
  try {
    return matchFilter(filter, event);
  } catch (error) {
    if (error instanceof FilterError) {
      return false;
    }
    throw error;
  }
}

function noteClientFrame(conn: number, raw: string): void {
  let frame: unknown;
  try {
    frame = JSON.parse(raw);
  } catch {
    return;
  }
  if (!Array.isArray(frame) || typeof frame[1] !== "string") {
    return;
  }
  if (frame[0] === "REQ") {
    const filters = frame.slice(2) as Filter[];
    openReqs.set(`${conn}:${frame[1]}`, { filters, seenAt: Date.now() });
    if (pendingEvent !== undefined && filters.some((f) => filterMatches(f, pendingEvent))) {
      lastMatchingReqAt = Date.now();
    }
  } else if (frame[0] === "CLOSE") {
    openReqs.delete(`${conn}:${frame[1]}`);
  }
}

function liveSubscribersSettled(event: Event): boolean {
  const now = Date.now();
  if (now - lastMatchingReqAt < REQ_QUIESCE_MS) {
    return false;
  }
  const settledBefore = now - SUB_SETTLE_MS;
  let matched = false;
  for (const sub of openReqs.values()) {
    if (!sub.filters.some((filter) => filterMatches(filter, event))) {
      continue;
    }
    if (sub.seenAt > settledBefore) {
      return false;
    }
    matched = true;
  }
  return matched;
}

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

async function waitForPort(p: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await fetch(`http://127.0.0.1:${p}/`, { signal: AbortSignal.timeout(1000) });
      return;
    } catch (error) {
      if (Date.now() > deadline) {
        throw error;
      }
      if (error instanceof Error && error.name === "TimeoutError") {
        return; // port accepts; the endpoint is just slow
      }
      await sleep(25);
    }
  }
}

// nosfry lifecycle (nosfry backend only).
let nosfryProc: ReturnType<typeof Bun.spawn> | undefined;

async function cloneDb(): Promise<void> {
  const rm = Bun.spawn(["rm", "-rf", dbDir!]);
  if ((await rm.exited) !== 0) {
    throw new Error(`rm -rf ${dbDir} failed`);
  }
  const cp = Bun.spawn(["cp", "-cR", pristineDir!, dbDir!]);
  if ((await cp.exited) !== 0) {
    throw new Error(`cp -cR ${pristineDir} ${dbDir} failed`);
  }
}

async function startNosfry(): Promise<void> {
  nosfryProc = Bun.spawn([nosfryBin!, "--config", nosfryConfig!, "relay"], {
    stdout: "inherit",
    stderr: "inherit",
  });
  await waitForPort(NOSFRY_PORT, 30_000);
}

async function stopNosfry(): Promise<void> {
  if (nosfryProc === undefined) {
    return;
  }
  nosfryProc.kill("SIGTERM");
  await nosfryProc.exited;
  nosfryProc = undefined;
}

if (backend === "nosfry") {
  await cloneDb();
  await startNosfry();
  console.log(`nosfry up on ${NOSFRY_WS} (db ${dbDir})`);
}

let connSeq = 0;
const upstreams = new Set<WebSocket>();

type ConnData = {
  conn: number;
  path: string;
  upstream: WebSocket;
  pending: string[];
  upstreamOpen: boolean;
  closeRecorded: boolean;
};

function recordClose(data: ConnData): void {
  if (data.closeRecorded) {
    return;
  }
  data.closeRecorded = true;
  record({ t: Date.now(), c: data.conn, p: data.path, d: "close" });
}

const relayServer = Bun.serve<ConnData>({
  port,
  hostname: "127.0.0.1",
  fetch(req, server) {
    const url = new URL(req.url);
    if (
      server.upgrade(req, {
        data: {
          conn: 0,
          path: url.pathname + url.search,
          upstream: undefined as unknown as WebSocket,
          pending: [],
          upstreamOpen: false,
          closeRecorded: false,
        },
      })
    ) {
      return undefined;
    }
    return forward(upstreamHttp, req);
  },
  websocket: {
    open(ws) {
      const conn = ++connSeq;
      const { path } = ws.data;
      ws.data.conn = conn;
      record({ t: Date.now(), c: conn, p: path, d: "open" });
      const upstream = new WebSocket(`${upstreamWs}${path}`);
      upstreams.add(upstream);
      ws.data.upstream = upstream;
      upstream.onopen = () => {
        ws.data.upstreamOpen = true;
        for (const frame of ws.data.pending.splice(0)) {
          upstream.send(frame);
        }
      };
      upstream.onmessage = (msg) => {
        const raw = typeof msg.data === "string" ? msg.data : String(msg.data);
        let ev: [string, string, number] | undefined;
        if (raw.startsWith('["EVENT"')) {
          try {
            const frame = JSON.parse(raw) as [string, string, { id: string; kind: number }];
            ev = [frame[1], frame[2].id, frame[2].kind];
          } catch {
            ev = undefined;
          }
        }
        record(
          ev === undefined
            ? { t: Date.now(), c: conn, p: path, d: "r2c", f: raw }
            : { t: Date.now(), c: conn, p: path, d: "r2c", ev },
        );
        try {
          ws.send(raw);
        } catch {
          // client already gone
        }
      };
      let dropped = false;
      const drop = (): void => {
        if (dropped) {
          return;
        }
        dropped = true;
        upstreams.delete(upstream);
        recordClose(ws.data);
        try {
          ws.close();
        } catch {
          // already closed
        }
      };
      upstream.onclose = drop;
      upstream.onerror = drop;
    },
    message(ws, message) {
      const raw = typeof message === "string" ? message : Buffer.from(message).toString();
      noteClientFrame(ws.data.conn, raw);
      record({ t: Date.now(), c: ws.data.conn, p: ws.data.path, d: "c2r", f: raw });
      if (ws.data.upstreamOpen) {
        try {
          ws.data.upstream.send(raw);
        } catch {
          // upstream gone
        }
      } else {
        ws.data.pending.push(raw);
      }
    },
    close(ws) {
      recordClose(ws.data);
      try {
        ws.data.upstream.close();
      } catch {
        // upstream gone
      }
      upstreams.delete(ws.data.upstream);
    },
  },
});

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "content-encoding",
]);

async function forward(base: string, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const headers = new Headers();
  for (const [name, value] of req.headers) {
    if (!HOP_BY_HOP.has(name)) {
      headers.set(name, value);
    }
  }
  const upstream = await fetch(`${base}${url.pathname}${url.search}`, {
    method: req.method,
    headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer(),
    redirect: "manual",
  });
  const out = new Headers();
  for (const [name, value] of upstream.headers) {
    if (!HOP_BY_HOP.has(name)) {
      out.set(name, value);
    }
  }
  return new Response(upstream.body, {
    status: upstream.status,
    headers: out,
  });
}

let publishSeq = 0;

async function publishLive(): Promise<Response> {
  publishSeq += 1;
  const event = finalizeEvent(
    {
      kind: 1,
      content: `dev-live-${publishSeq}`,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
    },
    SECRET_KEY,
  );
  const deadline = Date.now() + 10_000;
  pendingEvent = event;
  try {
    while (!liveSubscribersSettled(event) && Date.now() < deadline) {
      await sleep(25);
    }
  } finally {
    pendingEvent = undefined;
  }
  const ok = await new Promise<{ accepted: boolean; reason: string }>((resolve) => {
    const ws = new WebSocket(NOSFRY_WS);
    const timer = setTimeout(() => {
      ws.close();
      resolve({ accepted: false, reason: "timeout waiting for OK" });
    }, 10_000);
    ws.onopen = () => {
      ws.send(JSON.stringify(["EVENT", event]));
    };
    ws.onmessage = (msg) => {
      const frame = JSON.parse(String(msg.data)) as unknown[];
      if (frame[0] === "OK" && frame[1] === event.id) {
        clearTimeout(timer);
        ws.close();
        resolve({ accepted: frame[2] === true, reason: String(frame[3] ?? "") });
      }
    };
    ws.onerror = () => {
      clearTimeout(timer);
      resolve({ accepted: false, reason: "nosfry unreachable" });
    };
  });
  if (!ok.accepted) {
    return new Response(JSON.stringify({ error: ok.reason }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ id: event.id }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

async function resetRelay(): Promise<Response> {
  const start = Date.now();
  // The fixture HTTP half (Blossom blobs, wallet) still lives on the TS relay —
  // reset it first so both halves agree on empty state.
  const fixture = await fetch(`${TS_HTTP}/dev/reset`, { method: "POST" });
  if (!fixture.ok && fixture.status !== 204) {
    return new Response(`fixture reset failed: ${fixture.status}`, { status: 502 });
  }
  for (const upstream of [...upstreams]) {
    upstream.close();
  }
  await stopNosfry();
  await cloneDb();
  await startNosfry();
  console.log(`reset took ${((Date.now() - start) / 1000).toFixed(3)}s`);
  return new Response(undefined, { status: 204 });
}

const fixtureServer = Bun.serve({
  port: port + 1,
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url);
    if (backend === "nosfry" && url.pathname === "/dev/publish" && req.method === "POST") {
      return publishLive();
    }
    if (backend === "nosfry" && url.pathname === "/dev/reset" && req.method === "POST") {
      return resetRelay();
    }
    return forward(TS_HTTP, req);
  },
});

console.log(
  `harness backend=${backend} ws=http://127.0.0.1:${port} -> ${upstreamWs}; fixtures=http://127.0.0.1:${port + 1} -> ${TS_HTTP}`,
);

process.on("SIGTERM", () => {
  void (async () => {
    await stopNosfry();
    process.exit(0);
  })();
});
process.on("SIGINT", () => {
  void (async () => {
    await stopNosfry();
    process.exit(0);
  })();
});
