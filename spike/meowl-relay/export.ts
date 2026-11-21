/**
 * Dumps every stored event of a relay to a JSONL file: sends ["REQ","x",{}],
 * collects EVENT frames until EOSE, writes one event JSON per line and prints
 * the count plus a kind histogram. Answers a NIP-42 AUTH challenge when the
 * relay sends one, re-issuing the REQ after the auth OK.
 *
 * Usage: bun export.ts <ws-url> <out.jsonl>
 */

import { finalizeEvent } from "@qntx/nostr/core";

const SECRET_KEY = "42".repeat(32);

const [url, out] = process.argv.slice(2);
if (url === undefined || out === undefined) {
  console.error("usage: bun export.ts <ws-url> <out.jsonl>");
  process.exit(1);
}

const events: string[] = [];
const histogram = new Map<number, number>();

const ws = new WebSocket(url);
const sendReq = (): void => {
  ws.send(JSON.stringify(["REQ", "x", {}]));
};
let authId: string | undefined;
const done = new Promise<void>((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("timeout waiting for EOSE")), 240_000);
  ws.onopen = sendReq;
  ws.onmessage = (msg) => {
    const frame = JSON.parse(String(msg.data)) as unknown[];
    if (frame[0] === "EVENT") {
      const event = frame[2] as { kind: number };
      events.push(JSON.stringify(event));
      histogram.set(event.kind, (histogram.get(event.kind) ?? 0) + 1);
    } else if (frame[0] === "EOSE") {
      clearTimeout(timer);
      resolve();
    } else if (frame[0] === "OK" && authId !== undefined && frame[1] === authId && frame[2] === true) {
      sendReq();
    } else if (frame[0] === "AUTH") {
      const auth = finalizeEvent(
        {
          kind: 22242,
          content: "",
          created_at: Math.floor(Date.now() / 1000),
          tags: [
            ["relay", url],
            ["challenge", String(frame[1])],
          ],
        },
        SECRET_KEY,
      );
      authId = auth.id;
      ws.send(JSON.stringify(["AUTH", auth]));
    }
  };
  ws.onerror = () => {
    clearTimeout(timer);
    reject(new Error(`websocket error on ${url}`));
  };
});

await done;
ws.close();
await Bun.write(out, events.join("\n") + (events.length > 0 ? "\n" : ""));
console.log(
  `${events.length} events -> ${out}; kinds: ${[...histogram.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([kind, count]) => `${kind}:${count}`)
    .join(" ")}`,
);
