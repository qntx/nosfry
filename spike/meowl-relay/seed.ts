/**
 * Seeds a relay with a JSONL fixture over the wire: sends every line as
 * ["EVENT", <event>] on one connection, keeps at most 50 unacknowledged
 * publishes in flight, and waits for each OK. Prints total wall time,
 * accepted count, and every distinct rejection reason with its count.
 *
 * Usage: bun seed.ts <ws-url> <fixture.jsonl>
 */

const MAX_INFLIGHT = 50;

const [url, file] = process.argv.slice(2);
if (url === undefined || file === undefined) {
  console.error("usage: bun seed.ts <ws-url> <fixture.jsonl>");
  process.exit(1);
}

const lines = (await Bun.file(file).text())
  .split("\n")
  .filter((l) => l.trim() !== "");

const accepted = { n: 0 };
const rejected = new Map<string, number>();
const pending = new Map<string, { ok: boolean }>();
let idx = 0;
let resolveDrain: (() => void) | undefined;

const ws = new WebSocket(url);
await new Promise<void>((resolve, reject) => {
  ws.onopen = () => resolve();
  ws.onerror = () => reject(new Error("ws connect failed"));
});
const start = performance.now();

ws.onmessage = (m) => {
  const msg = JSON.parse(String(m.data));
  if (msg[0] !== "OK") {
    return;
  }
  const id = String(msg[1]);
  pending.delete(id);
  if (msg[2] === true) {
    accepted.n += 1;
  } else {
    const reason = String(msg[3] ?? "");
    rejected.set(reason, (rejected.get(reason) ?? 0) + 1);
  }
  pump();
};

function pump(): void {
  while (idx < lines.length && pending.size < MAX_INFLIGHT) {
    const ev = JSON.parse(lines[idx]);
    idx += 1;
    pending.set(String(ev.id), { ok: false });
    ws.send(JSON.stringify(["EVENT", ev]));
  }
  if (idx >= lines.length && pending.size === 0) {
    resolveDrain?.();
  }
}

const watchdog = setTimeout(() => process.exit(2), 300_000);
await new Promise<void>((resolve) => {
  resolveDrain = resolve;
  pump();
});
clearTimeout(watchdog);
const secs = (performance.now() - start) / 1000;
ws.close();

console.log(
  `seeded ${lines.length} events in ${secs.toFixed(1)}s: accepted=${accepted.n} rejected=${idx - accepted.n}`,
);
for (const [reason, n] of rejected) {
  console.log(`  rejected ${n}x: ${reason}`);
}
